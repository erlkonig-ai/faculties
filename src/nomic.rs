//! The durable nomic embedder seam — weights AND tokenizer load from the
//! dedicated model piles, with NO Hugging Face hub dependency at runtime.
//!
//! One loader per modality of the shared 768-d space
//! ([`crate::schemas::embeddings`]): [`load_text_embedder`] for
//! nomic-embed-text-v1.5 and [`load_vision_embedder`] for
//! nomic-embed-vision-v1.5, shared by every faculty that embeds (`memory
//! embed/similar`, `wiki embed/similar`, …) so the seam lives in ONE place.
//!
//! Why the pile and not the HF cache: the cache is an EVICTABLE download
//! artifact — `tokenizer.json` fell out of it once and silently broke
//! `memory similar` on a machine whose weights pile was fine. The model pile
//! is the durable store, so everything the embedder needs at runtime lives
//! there: mary's `embed_persist` writes the weight graph, and the tokenizer
//! lives beside it as a NATIVE TOKENIZER GRAPH (`mary::tokenizer`) — vocab,
//! merges, added tokens, and the normalizer/pre-tok/decoder config tail all
//! as tribles. Loading is construct-from-graph
//! (`mary::persist::load_tokenizer_from_pile`): the parts are queried and fed
//! to the `tokenizers` builders — no JSON parse, no temp file, no network.
//!
//! The graph is the CANONICAL tokenizer source. The `tokenizer.json` blob
//! ([`attr::tokenizer_json`], via [`import_tokenizer`]) is retained as import
//! provenance and as a fallback: if a pile predates the graph,
//! [`load_text_embedder`] warns on stderr and materializes the blob to a temp
//! file — run [`ingest_tokenizer_graph`] (`memory ingest-tokenizer`) once to
//! build the graph and retire the fallback.
//!
//! Vision needs no tokenizer today (its pile is weights-only), but any future
//! side-asset follows the same pattern: a graph (or at minimum a blob) in the
//! model pile, never a hub-cache side-file.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::Repository;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

/// HF model ids — provenance only; nothing is fetched from the hub here.
pub const NOMIC_TEXT_MODEL: &str = "nomic-ai/nomic-embed-text-v1.5";
pub const NOMIC_VISION_MODEL: &str = "nomic-ai/nomic-embed-vision-v1.5";

/// Default model-pile filenames (resolved under [`crate::model_dir`]);
/// `NOMIC_TEXT_PILE` / `NOMIC_VISION_PILE` env vars override the full path so
/// the faculty isn't pinned to one machine's layout.
pub const NOMIC_TEXT_PILE_FILE: &str = "nomic_text.pile";
pub const NOMIC_VISION_PILE_FILE: &str = "nomic_vision.pile";

pub mod attr {
    use triblespace::prelude::*;

    attributes! {
        /// The model's `tokenizer.json` (HF tokenizers format), stored beside
        /// the weight graph in the SAME model pile. Attached to an entity that
        /// also carries mary's `model_name` for provenance. Minted 2026-07-18.
        "7B8D68E86EEC09D7096D40D65FBA7026" as tokenizer_json: inlineencodings::Handle<blobencodings::LongString>;
    }
}

/// The text model pile path (env override, else the model-dir default).
pub fn text_pile() -> PathBuf {
    match std::env::var_os("NOMIC_TEXT_PILE") {
        Some(p) => PathBuf::from(p),
        None => crate::model_dir().join(NOMIC_TEXT_PILE_FILE),
    }
}

/// The vision model pile path (env override, else the model-dir default).
pub fn vision_pile() -> PathBuf {
    match std::env::var_os("NOMIC_VISION_PILE") {
        Some(p) => PathBuf::from(p),
        None => crate::model_dir().join(NOMIC_VISION_PILE_FILE),
    }
}

/// Open a model pile read/append. Mirrors the faculties' non-amputating open:
/// a corrupt tail fails LOUD — truncation is an explicit operator decision,
/// never a side effect of loading an embedder.
fn open_model_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile = Pile::open(path).map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.refresh() {
        let _ = pile.close();
        return Err(anyhow!(
            "refresh model pile {}: {err:?} — refusing to auto-repair on a read path; if, and \
             only if, the tail is a genuinely torn write, amputate explicitly with `trible pile \
             amputate`",
            path.display()
        ));
    }
    Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .map_err(|err| anyhow!("create repository: {err:?}"))
}

/// The stored tokenizer.json handle on the model pile's `main` branch, if any.
fn stored_tokenizer(
    repo: &mut Repository<Pile>,
) -> Result<Option<(triblespace::core::repo::Workspace<Pile>, Inline<Handle<LongString>>)>> {
    let branch_id = repo
        .lookup_branch("main")
        .map_err(|e| anyhow!("lookup main: {e:?}"))?
        .ok_or_else(|| anyhow!("model pile has no 'main' branch"))?;
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull main: {e:?}"))?;
    let space = ws.checkout(..).context("checkout model pile main")?;
    let handle = find!(
        h: Inline<Handle<LongString>>,
        pattern!(&space, [{ _?e @ attr::tokenizer_json: ?h }])
    )
    .next();
    Ok(handle.map(|h| (ws, h)))
}

/// Append a model's `tokenizer.json` to its pile, once. Idempotent: if the
/// pile already carries a tokenizer blob, this is a no-op. `model_name` is
/// recorded beside it (mary's provenance attribute) so the entity is
/// self-describing.
pub fn import_tokenizer(pile_path: &Path, tokenizer_json: &Path, model_name: &str) -> Result<()> {
    let content = std::fs::read_to_string(tokenizer_json)
        .map_err(|e| anyhow!("read {}: {e}", tokenizer_json.display()))?;
    // Shallow shape check — enough to catch an accidentally-passed weights or
    // config file without pulling in a JSON parser.
    if !(content.trim_start().starts_with('{') && content.contains("\"model\"")) {
        bail!(
            "{} does not look like a HF tokenizer.json (expected a JSON object with a \"model\" key)",
            tokenizer_json.display()
        );
    }

    let mut repo = open_model_repo(pile_path)?;
    let result = (|| {
        if stored_tokenizer(&mut repo)?.is_some() {
            println!(
                "tokenizer.json already present in {} — nothing to do",
                pile_path.display()
            );
            return Ok(());
        }
        let branch_id = repo
            .lookup_branch("main")
            .map_err(|e| anyhow!("lookup main: {e:?}"))?
            .ok_or_else(|| anyhow!("model pile has no 'main' branch"))?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull main: {e:?}"))?;
        let bytes = content.len();
        let tok_handle = ws.put(content);
        let name_handle = ws.put(model_name.to_owned());
        let ent = ufoid();
        let mut change = TribleSet::new();
        change += entity! { &ent @
            attr::tokenizer_json: tok_handle,
            mary::format::attrs::model_name: name_handle,
        };
        ws.commit(change, "import tokenizer.json");
        repo.push(&mut ws)
            .map_err(|e| anyhow!("push tokenizer import: {e:?}"))?;
        println!(
            "imported tokenizer.json ({bytes} bytes) for {model_name} into {}",
            pile_path.display()
        );
        Ok(())
    })();
    let close_res = repo.close().map_err(|e| anyhow!("close pile: {e:?}"));
    result.and(close_res)?;
    // The blob is provenance; the GRAPH is the canonical source — build it in
    // the same breath so a fresh import is immediately graph-loadable.
    ingest_tokenizer_graph(pile_path)
}

/// Build the tokenizer GRAPH in a model pile from its stored `tokenizer.json`
/// blob — the one-time step that makes the graph the canonical tokenizer
/// source (the blob stays as import provenance). Append-only and idempotent:
/// a pile that already carries a tokenizer graph is left untouched.
///
/// The graph fragment's blobs (token pieces, patterns) are staged in the
/// workspace and shipped with the commit; the tokenizer root is linked from
/// the blob entity via `mary::tokenizer::attrs::tokenizer` so provenance
/// (source blob → derived graph) is explicit.
pub fn ingest_tokenizer_graph(pile_path: &Path) -> Result<()> {
    let mut repo = open_model_repo(pile_path)?;
    let result = (|| {
        let branch_id = repo
            .lookup_branch("main")
            .map_err(|e| anyhow!("lookup main: {e:?}"))?
            .ok_or_else(|| anyhow!("model pile has no 'main' branch"))?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull main: {e:?}"))?;
        let space = ws.checkout(..).context("checkout model pile main")?;
        if let Some(root) = mary::tokenizer::find_tokenizer(space.facts()) {
            println!(
                "tokenizer graph already present in {} (root {root:X}) — nothing to do",
                pile_path.display()
            );
            return Ok(());
        }
        let Some((blob_entity, handle)) = find!(
            (e: Id, h: Inline<Handle<LongString>>),
            pattern!(space.facts(), [{ ?e @ attr::tokenizer_json: ?h }])
        )
        .next() else {
            bail!(
                "no tokenizer.json blob in {} — import one first with \
                 `memory import-tokenizer <path/to/tokenizer.json>`",
                pile_path.display()
            );
        };
        let json: View<str> = ws
            .get(handle)
            .map_err(|e| anyhow!("read tokenizer blob: {e:?}"))?;

        let frag = mary::tokenizer::save_tokenizer_json(
            json.as_bytes(),
            NOMIC_TEXT_MODEL,
            &mut ws.staged,
        )
        .map_err(|e| anyhow!("build tokenizer graph: {e}"))?;
        let root = frag
            .root()
            .ok_or_else(|| anyhow!("tokenizer fragment has no root"))?;
        let facts: TribleSet = frag.into_facts();

        // Report what the graph holds before committing it.
        use mary::tokenizer::attrs as tok;
        let n_vocab = find!((v: Id), pattern!(&facts, [{ root @ tok::vocab: ?v }])).count();
        let n_merges = find!((m: Id), pattern!(&facts, [{ root @ tok::merge: ?m }])).count();
        let n_added = find!((a: Id), pattern!(&facts, [{ root @ tok::added: ?a }])).count();
        let n_tribles = facts.len();

        let mut change = facts;
        change += entity! { ExclusiveId::force_ref(&blob_entity) @
            tok::tokenizer: root,
        };
        ws.commit(change, "ingest tokenizer graph from stored tokenizer.json");
        repo.push(&mut ws)
            .map_err(|e| anyhow!("push tokenizer graph: {e:?}"))?;
        println!(
            "ingested tokenizer graph into {}: root {root:X}, {n_vocab} vocab + {n_merges} \
             merges + {n_added} added tokens, {n_tribles} tribles (+1 provenance link)",
            pile_path.display()
        );
        Ok(())
    })();
    let close_res = repo.close().map_err(|e| anyhow!("close pile: {e:?}"));
    result.and(close_res)
}

/// FALLBACK PATH ONLY (the canonical source is the tokenizer graph):
/// materialize the pile-stored tokenizer.json blob to a content-addressed
/// temp file (mary's json loader wants a path). Cheap when already
/// materialized; regenerates from the pile whenever the temp dir is cleaned.
fn materialize_tokenizer(pile_path: &Path) -> Result<PathBuf> {
    let mut repo = open_model_repo(pile_path)?;
    let result = (|| {
        let Some((mut ws, handle)) = stored_tokenizer(&mut repo)? else {
            bail!(
                "no tokenizer.json blob in model pile {} — import it once with \
                 `memory import-tokenizer <path/to/tokenizer.json>`",
                pile_path.display()
            );
        };
        let hex: String = handle.raw.iter().map(|b| format!("{b:02x}")).collect();
        let target = std::env::temp_dir().join(format!("nomic-tokenizer-{}.json", &hex[..16]));
        if target.is_file() {
            return Ok(target);
        }
        let content: View<str> = ws
            .get(handle)
            .map_err(|e| anyhow!("read tokenizer blob: {e:?}"))?;
        // Write-then-rename so a concurrent loader never sees a torn file.
        let staging = target.with_extension(format!("tmp.{}", std::process::id()));
        std::fs::write(&staging, content.as_bytes())
            .map_err(|e| anyhow!("write {}: {e}", staging.display()))?;
        std::fs::rename(&staging, &target)
            .map_err(|e| anyhow!("rename {} → {}: {e}", staging.display(), target.display()))?;
        Ok(target)
    })();
    let close_res = repo.close().map_err(|e| anyhow!("close pile: {e:?}"));
    match close_res {
        Ok(()) => result,
        Err(err) => result.and(Err(err)),
    }
}

/// nomic-embed-text-v1.5, fully from the text model pile: weight graph AND
/// tokenizer GRAPH. Self-contained and eviction-proof — no HF hub, no cache,
/// no tokenizer.json in the runtime path.
///
/// The tokenizer is constructed from the graph
/// (`mary::persist::load_tokenizer_from_pile`). Piles that predate the graph
/// fall back to the stored tokenizer.json blob with a stderr warning — run
/// `memory ingest-tokenizer` once to build the graph and silence it.
pub fn load_text_embedder() -> Result<mary::embed::NomicTextEmbedder<mary::nn::backend::B>> {
    let pile = text_pile();
    let device = mary::embed::default_device();
    let keymap = mary::persist::load_keymap_from_pile(&pile)
        .map_err(|e| anyhow!("load nomic text weights from pile {}: {e:?}", pile.display()))?;
    match mary::persist::load_tokenizer_from_pile(&pile) {
        Ok(tokenizer) => mary::embed::nomic_text_from_parts(keymap, tokenizer, device)
            .map_err(|e| anyhow!("build nomic text embedder from pile {}: {e:?}", pile.display())),
        Err(err) => {
            eprintln!(
                "memory: no tokenizer graph in {} ({err}); falling back to the stored \
                 tokenizer.json blob — run `memory ingest-tokenizer` once to build the graph",
                pile.display()
            );
            let tokenizer = materialize_tokenizer(&pile)?;
            mary::embed::load_nomic_text_from_keymap(keymap, &tokenizer, device).map_err(|e| {
                anyhow!("load nomic text embedder from pile {}: {e:?}", pile.display())
            })
        }
    }
}

/// nomic-embed-vision-v1.5 from the vision model pile — co-embedded into the
/// SAME 768-d space as the text model, so an image's vector is directly
/// comparable to a text query's. Weights-only (a ViT has no tokenizer).
pub fn load_vision_embedder() -> Result<mary::embed::NomicVisionEmbedder<mary::nn::backend::B>> {
    let pile = vision_pile();
    mary::embed::load_nomic_vision_from_pile(&pile, mary::embed::default_device()).map_err(|e| {
        anyhow!(
            "load nomic vision embedder from pile {}: {e:?}",
            pile.display()
        )
    })
}
