//! The durable Nomic embedder seam.
//!
//! The nomic models live in the working pile itself, as roots of its
//! `mary-model-graph` collection, and replication carries them to every
//! machine (JP, 2026-09-13: "I wouldn't load it from a separate pile, I'd just
//! put it into self.pile because it's small enough and then let replication
//! take care of the rest"; and: "let's not fall back to a model directory, we
//! shouldn't need structure outside our pile"). Ordinary inference reads one
//! immutable native Mary collection snapshot of that pile. Weight and
//! tokenizer selection then happen against the same frozen facts and blob
//! reader, so a concurrent append cannot give one component a different
//! authority set from the other. There is no model directory, Repository
//! branch, mutable Workspace, tokenizer JSON, temporary file, or Hugging Face
//! fallback in this runtime path.
//!
//! Import and packing belong in Mary (`nomic_pack ... --out <pile> --append`).
//! A pile without the model fails loudly here instead of silently switching
//! storage models.

use std::path::{Path, PathBuf};
use triblespace::core::repo::pile::PileSnapshot;

use crate::schemas::embeddings::Embedding768;
use anybytes::View;
use anyhow::{anyhow, Context, Result};
use mary::model_collection::ModelPileSnapshot;
use mary::selection::{ModelSelector, TokenizerSelector};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::id::ExclusiveId;
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

/// Hugging Face model ids are provenance only; runtime never fetches them.
pub const NOMIC_TEXT_MODEL: &str = "nomic-ai/nomic-embed-text-v1.5";
pub const NOMIC_VISION_MODEL: &str = "nomic-ai/nomic-embed-vision-v1.5";

/// The working pile: `PILE`, the path every faculty takes. The models are in
/// it or nowhere.
fn working_pile() -> Result<PathBuf> {
    std::env::var_os("PILE")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("PILE is not set; the nomic models are read from the working pile"))
}

fn load_model_snapshot(path: &Path, model: &str) -> Result<ModelPileSnapshot> {
    // Discover the sole policy descriptor and freeze its admitted cover from
    // one observed prefix. Selection and attachment reads then share that
    // exact pile snapshot.
    let snapshot =
        mary::model_collection::load_model_collection_local_latest(path).with_context(|| {
            format!(
                "discover and freeze the sole native Mary collection for {model} in {}",
                path.display()
            )
        })?;
    Ok(snapshot)
}

/// The weight roots a pile may carry for one source, most wanted first: the
/// calibrated packed NVFP4 model (`mary::calibrate`, label
/// `nvfp4-calibrated`) when the pile has one, else the native f32 import.
/// Both decode to the same f32 keymap for the embedder; the packed one is a
/// seventh of the bytes on disk.
const NOMIC_QUANTIZATIONS: [&str; 2] = ["nvfp4-calibrated", mary::persist::QUANTIZATION_NATIVE];

/// The first root of `source` in the pile, in [`NOMIC_QUANTIZATIONS`] order.
fn select_weights(
    snapshot: &ModelPileSnapshot,
    source: &str,
    pile: &Path,
) -> Result<std::collections::HashMap<String, (Vec<f32>, Vec<usize>)>> {
    let quantization = NOMIC_QUANTIZATIONS
        .iter()
        .copied()
        .find(|quantization| {
            mary::selection::select_model_roots(
                snapshot.facts(),
                snapshot.store(),
                ModelSelector::Source {
                    source,
                    quantization,
                },
            )
            .is_ok()
        })
        .with_context(|| {
            format!(
                "{} carries no {source} root labelled {} (pack it in with nomic_pack --append)",
                pile.display(),
                NOMIC_QUANTIZATIONS.join(" or ")
            )
        })?;
    mary::selection::load_keymap_from_graph(
        snapshot.facts(),
        snapshot.store(),
        ModelSelector::Source {
            source,
            quantization,
        },
    )
    .with_context(|| {
        format!(
            "select {quantization} {source} weights from {}",
            pile.display()
        )
    })
}

/// Load nomic-embed-text-v1.5 from the working pile's model collection.
///
/// Absence or ambiguity of either the weight graph or tokenizer graph is an
/// error. Pack the model into the pile with Mary's `nomic_pack --append`
/// rather than adding a compatibility path to ordinary inference.
pub fn load_text_embedder() -> Result<mary::embed::NomicTextEmbedder<mary::nn::backend::B>> {
    let pile = working_pile()?;
    let snapshot = load_model_snapshot(&pile, NOMIC_TEXT_MODEL)?;
    text_embedder_from(&snapshot, &pile)
}

/// [`load_text_embedder`] from a pile snapshot the caller already holds (a
/// command that has the working pile open should not open it twice).
pub fn load_text_embedder_in(
    store: &PileSnapshot,
) -> Result<mary::embed::NomicTextEmbedder<mary::nn::backend::B>> {
    let snapshot = mary::model_collection::snapshot_model_collection_in(store)
        .context("freeze the working pile's model collection for nomic-embed-text")?;
    text_embedder_from(&snapshot, Path::new("the working pile"))
}

fn text_embedder_from(
    snapshot: &ModelPileSnapshot,
    pile: &Path,
) -> Result<mary::embed::NomicTextEmbedder<mary::nn::backend::B>> {
    let keymap = select_weights(snapshot, NOMIC_TEXT_MODEL, pile)?;
    let tokenizer = mary::selection::load_tokenizer_from_graph(
        snapshot.facts(),
        snapshot.store(),
        TokenizerSelector::Name(NOMIC_TEXT_MODEL),
    )
    .with_context(|| format!("select native Nomic text tokenizer from {}", pile.display()))?;

    mary::embed::nomic_text_from_parts(keymap, tokenizer, mary::embed::default_device())
        .with_context(|| {
            format!(
                "build Nomic text embedder from native collection {}",
                pile.display()
            )
        })
}

/// Load nomic-embed-vision-v1.5 from the working pile's model collection.
pub fn load_vision_embedder() -> Result<mary::embed::NomicVisionEmbedder<mary::nn::backend::B>> {
    let pile = working_pile()?;
    let snapshot = load_model_snapshot(&pile, NOMIC_VISION_MODEL)?;
    vision_embedder_from(&snapshot, &pile)
}

/// [`load_vision_embedder`] from a pile snapshot the caller already holds.
pub fn load_vision_embedder_in(
    store: &PileSnapshot,
) -> Result<mary::embed::NomicVisionEmbedder<mary::nn::backend::B>> {
    let snapshot = mary::model_collection::snapshot_model_collection_in(store)
        .context("freeze the working pile's model collection for nomic-embed-vision")?;
    vision_embedder_from(&snapshot, Path::new("the working pile"))
}

fn vision_embedder_from(
    snapshot: &ModelPileSnapshot,
    pile: &Path,
) -> Result<mary::embed::NomicVisionEmbedder<mary::nn::backend::B>> {
    let keymap = select_weights(snapshot, NOMIC_VISION_MODEL, pile)?;

    mary::embed::load_nomic_vision_from_keymap(keymap, mary::embed::default_device()).with_context(
        || {
            format!(
                "build Nomic vision embedder from native collection {}",
                pile.display()
            )
        },
    )
}

/// The models the semantic index embeds with, as the index pins them: the
/// member archives of the working pile's model collection (exact bytes) and
/// the one root this loader would select for each of the two nomic models,
/// packed preferred.
pub struct IndexModels {
    pub archives: Vec<[u8; 32]>,
    pub text_root: triblespace::core::id::Id,
    pub vision_root: triblespace::core::id::Id,
}

/// [`IndexModels`] from a pile snapshot the caller already holds.
///
/// The pinned archives are the member archives of the model collection that
/// carry the two selected roots with their tensors, and the one that carries
/// the text tokenizer; not every member. Until 2026-09-14 every member was
/// pinned, so any later commit into the model collection (a golden vector
/// recorded on a root, another model packed) re-keyed the index and every
/// `files` command addressed a new, empty one. The index is a function of
/// the models it embeds with, and of nothing else in that collection.
pub fn index_models_in(store: &PileSnapshot) -> Result<IndexModels> {
    use triblespace::core::repo::BlobStoreGet;
    let snapshot = mary::model_collection::snapshot_model_collection_in(store)
        .context("freeze the working pile's model collection for the semantic index")?;
    let text_root = preferred_root(&snapshot, NOMIC_TEXT_MODEL)?;
    let vision_root = preferred_root(&snapshot, NOMIC_VISION_MODEL)?;
    let trace = std::env::var_os("SEMANTIC_TRACE").is_some();
    let mut archives = Vec::new();
    for member in snapshot.support().members() {
        let raw = member.raw;
        let archive: TribleSet = store
            .get(Inline::<Handle<SimpleArchive>>::new(raw))
            .map_err(|error| {
                anyhow!(
                    "read model collection member {}: {error:?}",
                    hex::encode_upper(raw)
                )
            })?;
        let text =
            mary::selection::select_model_root(&archive, store, ModelSelector::Root(text_root))
                .is_ok();
        let vision =
            mary::selection::select_model_root(&archive, store, ModelSelector::Root(vision_root))
                .is_ok();
        let tokenizer = mary::selection::select_tokenizer_root(
            &archive,
            store,
            TokenizerSelector::Name(NOMIC_TEXT_MODEL),
        )
        .is_ok();
        if trace {
            eprintln!(
                "model archive {}: {} facts; text {text}, vision {vision}, tokenizer {tokenizer}",
                hex::encode_upper(raw),
                archive.len()
            );
        }
        if text || vision || tokenizer {
            archives.push(raw);
        }
    }
    if archives.is_empty() {
        anyhow::bail!("no member of the model collection carries the nomic roots {text_root:X} and {vision_root:X}");
    }
    Ok(IndexModels {
        archives,
        text_root,
        vision_root,
    })
}

/// The root [`select_weights`] would load for `source`: the first label in
/// [`NOMIC_QUANTIZATIONS`] that has exactly one root.
fn preferred_root(snapshot: &ModelPileSnapshot, source: &str) -> Result<triblespace::core::id::Id> {
    for quantization in NOMIC_QUANTIZATIONS {
        let roots = match mary::selection::select_model_roots(
            snapshot.facts(),
            snapshot.store(),
            ModelSelector::Source {
                source,
                quantization,
            },
        ) {
            Ok(roots) => roots,
            Err(_) => continue,
        };
        match roots.as_slice() {
            [root] => return Ok(*root),
            [] => continue,
            many => {
                return Err(anyhow!(
                    "the working pile carries {} {quantization} roots of {source}; one is needed",
                    many.len()
                ))
            }
        }
    }
    Err(anyhow!(
        "the working pile carries no {source} root labelled {} (pack it in with nomic_pack --append)",
        NOMIC_QUANTIZATIONS.join(" or ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mary::format::{attrs, F32Array, U64Array};
    use tempfile::NamedTempFile;
    use triblespace::core::repo::pile::Pile;
    use triblespace::prelude::blobencodings::UTF8String;
    use triblespace::prelude::*;

    const WORDPIECE: &str = r###"{
      "added_tokens": [],
      "normalizer": {"type": "BertNormalizer", "clean_text": true,
                     "handle_chinese_chars": true, "strip_accents": null,
                     "lowercase": true},
      "pre_tokenizer": {"type": "BertPreTokenizer"},
      "decoder": {"type": "WordPiece", "prefix": "##", "cleanup": true},
      "model": {"type": "WordPiece", "unk_token": "[UNK]",
                "continuing_subword_prefix": "##",
                "max_input_chars_per_word": 100,
                "vocab": {"[UNK]": 0, "hello": 1}}
    }"###;

    fn weight_fragment(source: &str, tensor_name: &str, value: f32) -> Fragment {
        let mut fragment = Fragment::empty();
        let data = fragment.put::<F32Array, _>(vec![value]);
        let shape = fragment.put::<U64Array, _>(vec![1_u64]);
        let leaf = entity! { _ @ attrs::data: data, attrs::shape: shape };
        let leaf_id = leaf.root().expect("tensor leaf root");
        fragment += leaf;

        let tensor_name = fragment.put::<UTF8String, _>(tensor_name.to_owned());
        let member = entity! { _ @
            attrs::safetensor_path: tensor_name,
            attrs::weight: &leaf_id,
        };
        let member_id = member.root().expect("model member root");
        fragment += member;

        let model_name = fragment.put::<UTF8String, _>(format!("{source}.safetensors"));
        let source = fragment.put::<UTF8String, _>(source.to_owned());
        fragment += entity! { _ @
            attrs::model_name: model_name,
            attrs::source: source,
            attrs::quantization: mary::persist::QUANTIZATION_NATIVE,
            attrs::member: &member_id,
        };
        fragment
    }

    fn tokenizer_fragment() -> Fragment {
        let mut fragment = Fragment::empty();
        let tokenizer = mary::tokenizer::save_tokenizer_json(
            WORDPIECE.as_bytes(),
            NOMIC_TEXT_MODEL,
            fragment.blobs_mut(),
        )
        .expect("build synthetic tokenizer graph");
        fragment += tokenizer;
        fragment
    }

    fn publish(path: &Path, fragments: impl IntoIterator<Item = Fragment>) {
        let mut fragments = fragments.into_iter();
        let Some(first) = fragments.next() else {
            return;
        };
        // One descriptor may admit several independent authors. Preserve that
        // invariant explicitly: the policy root publishes the first fragment,
        // making the descriptor discoverable through its native COMMIT, and
        // grants every later fixture signer before they publish into it.
        let root = SigningKey::from_bytes(&[0x30; 32]);
        let mut pile = Pile::open(path).expect("open synthetic model pile");
        mary::model_collection::publish_model_fragment(&mut pile, &root, first)
            .expect("publish fixture root fragment");
        for (index, fragment) in fragments.enumerate() {
            let signer = SigningKey::from_bytes(&[0x31 + index as u8; 32]);
            let collection =
                mary::model_collection::model_graph_collection_or_create(&mut pile, &root)
                    .expect("open synthetic model policy collection");
            triblespace::core::collection::grant_collection_write(
                &mut pile,
                collection.handle(),
                &root,
                signer.verifying_key(),
            )
            .expect("grant fixture writer");
            mary::model_collection::publish_model_fragment(&mut pile, &signer, fragment)
                .expect("publish native model fragment");
        }
        pile.close().expect("close synthetic model pile");
    }

    #[test]
    fn one_native_snapshot_selects_each_nomic_runtime_graph() {
        let text_file = NamedTempFile::new().expect("create text pile");
        publish(
            text_file.path(),
            [
                weight_fragment(NOMIC_TEXT_MODEL, "text.weight", 1.25),
                tokenizer_fragment(),
            ],
        );

        let text = load_model_snapshot(text_file.path(), NOMIC_TEXT_MODEL)
            .expect("load one text collection snapshot");
        assert_eq!(text.support().len(), 2);

        // Freeze really means freeze: a later same-coordinate model commit
        // cannot change the facts used for either half of this text load.
        publish(
            text_file.path(),
            [weight_fragment(NOMIC_TEXT_MODEL, "text.weight", 9.0)],
        );
        let text_keymap = mary::selection::load_keymap_from_graph(
            text.facts(),
            text.store(),
            ModelSelector::Source {
                source: NOMIC_TEXT_MODEL,
                quantization: mary::persist::QUANTIZATION_NATIVE,
            },
        )
        .expect("select text weights from frozen snapshot");
        assert_eq!(text_keymap["text.weight"], (vec![1.25], vec![1]));
        let tokenizer = mary::selection::load_tokenizer_from_graph(
            text.facts(),
            text.store(),
            TokenizerSelector::Name(NOMIC_TEXT_MODEL),
        )
        .expect("select tokenizer from the same frozen snapshot");
        assert_eq!(tokenizer.token_to_id("hello"), Some(1));

        let widened = load_model_snapshot(text_file.path(), NOMIC_TEXT_MODEL)
            .expect("load later widened text snapshot");
        let collision = mary::selection::load_keymap_from_graph(
            widened.facts(),
            widened.store(),
            ModelSelector::Source {
                source: NOMIC_TEXT_MODEL,
                quantization: mary::persist::QUANTIZATION_NATIVE,
            },
        )
        .expect_err("later shard with a duplicate tensor must fail closed");
        assert!(
            collision.to_string().contains("appears in both root"),
            "unexpected collision diagnostic: {collision}"
        );

        let vision_file = NamedTempFile::new().expect("create vision pile");
        publish(
            vision_file.path(),
            [weight_fragment(NOMIC_VISION_MODEL, "vision.weight", 2.5)],
        );
        let vision = load_model_snapshot(vision_file.path(), NOMIC_VISION_MODEL)
            .expect("load one vision collection snapshot");
        assert_eq!(vision.support().len(), 1);
        let vision_keymap = mary::selection::load_keymap_from_graph(
            vision.facts(),
            vision.store(),
            ModelSelector::Source {
                source: NOMIC_VISION_MODEL,
                quantization: mary::persist::QUANTIZATION_NATIVE,
            },
        )
        .expect("select vision weights from frozen snapshot");
        assert_eq!(vision_keymap["vision.weight"], (vec![2.5], vec![1]));
    }

    #[test]
    fn ordinary_runtime_source_has_no_legacy_storage_or_json_path() {
        let source = include_str!("nomic.rs");
        let runtime = source
            .split("#[cfg(test)]")
            .next()
            .expect("runtime source precedes tests");
        for forbidden in [
            concat!("repo::", "Repository"),
            concat!("Repository", "::"),
            concat!("Workspace", "<"),
            concat!("tokenizer", "_json"),
            concat!("load_keymap_from_", "pile"),
            concat!("load_tokenizer_from_", "pile"),
            concat!("materialize_", "tokenizer"),
        ] {
            assert!(
                !runtime.contains(forbidden),
                "ordinary Nomic runtime regained forbidden legacy seam {forbidden}"
            );
        }

        let memory = include_str!("bin/memory.rs");
        assert!(!memory.contains(concat!("import-", "tokenizer")));
        assert!(!memory.contains(concat!("ingest-", "tokenizer")));
    }
}

// ── golden vectors ─────────────────────────────────────────────────────────
//
// What the canonical compute embeds two fixed inputs to, recorded on each
// model root in the working pile's model collection. A device about to
// publish semantic rows embeds the same inputs first and compares, so a
// driver or a kernel that computes something else refuses instead of
// splitting the index in two without anyone noticing. JP, 2026-09-10: the
// hardware in the type and the Sparks canonical; "keep the golden vector".

pub mod golden {
    use triblespace::prelude::*;

    attributes! {
        /// nomic-embed-text embeds [`TEXT`] to this vector on the canonical
        /// compute. Minted 2026-09-14.
        "18AD4630637E03D4A8214A7464D06AAC" as text_embedding: inlineencodings::Handle<crate::schemas::embeddings::Embedding768>;
        /// nomic-embed-vision embeds [`image_png`] to this vector on the
        /// canonical compute. Minted 2026-09-14.
        "7415B83D46A1EDD8EE02BE1EBCEE6304" as image_embedding: inlineencodings::Handle<crate::schemas::embeddings::Embedding768>;
    }

    /// The fixed text every publishing device embeds.
    pub const TEXT: &str = "Golden text for the Files semantic index, recorded 2026-09-14: every device that publishes rows embeds this sentence first, and the vector it makes is compared to the one recorded on the model root.";

    /// The fixed image every publishing device embeds: 224 by 224, each
    /// pixel a function of its coordinates, encoded as PNG in memory, so no
    /// machine has to fetch anything to make it.
    pub fn image_png() -> Vec<u8> {
        let image = image::RgbImage::from_fn(224, 224, |x, y| {
            image::Rgb([
                ((x * 37 + y * 11) % 256) as u8,
                ((x ^ y) % 256) as u8,
                ((x * y / 197) % 256) as u8,
            ])
        });
        let mut png = std::io::Cursor::new(Vec::new());
        image
            .write_to(&mut png, image::ImageFormat::Png)
            .expect("encode the golden image as PNG in memory");
        png.into_inner()
    }

    /// Below this cosine between the vector this device computes and the
    /// recorded one, the device does not publish. The port agreed with the
    /// reference implementation to four nines (2026-09-12); a wrong kernel
    /// lands near 0.9.
    pub const FLOOR: f32 = 0.999;
}

/// One model root's golden comparison: what this device computes for the
/// fixed input and what the model collection records.
pub struct GoldenRow {
    /// `text` or `image`.
    pub model: &'static str,
    pub root: triblespace::core::id::Id,
    pub computed: Vec<f32>,
    pub recorded: Option<Vec<f32>>,
}

impl GoldenRow {
    pub fn cosine(&self) -> Option<f32> {
        self.recorded
            .as_ref()
            .map(|recorded| cosine(&self.computed, recorded))
    }
}

/// The golden comparison for every model the semantic index embeds with.
pub struct GoldenReport {
    pub rows: Vec<GoldenRow>,
}

impl GoldenReport {
    /// Admit this device as a publisher: every recorded golden vector is
    /// reproduced to at least [`golden::FLOOR`]. A root with no recorded
    /// vector admits with a warning on stderr; nothing was claimed yet.
    pub fn admit(&self) -> Result<()> {
        for row in &self.rows {
            match row.cosine() {
                Some(cos) if cos < golden::FLOOR => anyhow::bail!(
                    "this device embeds the golden {} input to cosine {cos:.5} of the vector recorded on root {:X} (floor {}); it does not publish rows into an index computed elsewhere",
                    row.model,
                    row.root,
                    golden::FLOOR
                ),
                Some(_) => {}
                None => eprintln!(
                    "warning: no golden vector recorded on {} root {:X}; rows publish unverified (`files golden --publish` on the canonical device records one)",
                    row.model, row.root
                ),
            }
        }
        Ok(())
    }
}

/// Cosine of two vectors of any norm.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

/// Embed the golden inputs with the models the index pins and read what the
/// model collection records for them.
pub fn golden_report(store: &PileSnapshot) -> Result<GoldenReport> {
    use mary::embed::LocalEmbedder as _;
    use triblespace::core::repo::BlobStoreGet;
    let snapshot = mary::model_collection::snapshot_model_collection_in(store)
        .context("freeze the working pile's model collection for the golden vectors")?;
    let roots = index_models_in(store)?;
    let text = text_embedder_from(&snapshot, Path::new("the working pile"))?;
    let vision = vision_embedder_from(&snapshot, Path::new("the working pile"))?;
    let computed_text = crate::memory_cover::l2_normalize(
        text.embed_document(golden::TEXT)
            .context("embed the golden text")?,
    );
    let computed_image = crate::memory_cover::l2_normalize(
        vision
            .embed_image(&golden::image_png())
            .context("embed the golden image")?,
    );
    let facts = snapshot.facts();
    let text_root = roots.text_root;
    let vision_root = roots.vision_root;
    let recorded_text: Option<Inline<Handle<Embedding768>>> = find!(
        h: Inline<Handle<Embedding768>>,
        pattern!(facts, [{ text_root @ golden::text_embedding: ?h }])
    )
    .next();
    let recorded_image: Option<Inline<Handle<Embedding768>>> = find!(
        h: Inline<Handle<Embedding768>>,
        pattern!(facts, [{ vision_root @ golden::image_embedding: ?h }])
    )
    .next();
    let read = |handle: Option<Inline<Handle<Embedding768>>>| -> Result<Option<Vec<f32>>> {
        handle
            .map(|h| {
                let view: View<[f32]> = store
                    .get(h)
                    .map_err(|error| anyhow!("read a recorded golden vector: {error:?}"))?;
                Ok(view.as_ref().to_vec())
            })
            .transpose()
    };
    Ok(GoldenReport {
        rows: vec![
            GoldenRow {
                model: "text",
                root: text_root,
                computed: computed_text,
                recorded: read(recorded_text)?,
            },
            GoldenRow {
                model: "image",
                root: vision_root,
                computed: computed_image,
                recorded: read(recorded_image)?,
            },
        ],
    })
}

/// Record this device's golden vectors on the roots that have none, as one
/// signed commit into the model collection. Returns the report taken before
/// publishing and the models recorded now; a root that already carries a
/// vector is left as it is, the report says how close this device came.
pub fn golden_publish(
    store: &mut crate::storage::FacultyStore,
    signer: &ed25519_dalek::SigningKey,
) -> Result<(GoldenReport, Vec<&'static str>)> {
    use triblespace::core::repo::SnapshotSource;
    let snapshot = store
        .snapshot()
        .context("freeze the pile for the golden vectors")?;
    let report = golden_report(&snapshot)?;
    drop(snapshot);
    let mut fragment = Fragment::empty();
    let mut recorded = Vec::new();
    for row in &report.rows {
        if row.recorded.is_some() {
            continue;
        }
        let handle = fragment.put::<Embedding768, _>(row.computed.clone());
        let root = row.root;
        match row.model {
            "text" => {
                fragment +=
                    entity! { ExclusiveId::force_ref(&root) @ golden::text_embedding: handle }
            }
            _ => {
                fragment +=
                    entity! { ExclusiveId::force_ref(&root) @ golden::image_embedding: handle }
            }
        }
        recorded.push(row.model);
    }
    if !recorded.is_empty() {
        let mut pile = store.store();
        mary::model_collection::publish_model_fragment(&mut pile, signer, fragment)
            .context("record the golden vectors on the model roots")?;
    }
    Ok((report, recorded))
}

#[cfg(test)]
mod golden_tests {
    use super::*;
    use triblespace::macros::id_hex;

    #[test]
    fn golden_image_for_files_index_is_deterministic_and_decodes() {
        let first = golden::image_png();
        let second = golden::image_png();
        assert_eq!(first, second);
        let decoded = image::load_from_memory(&first).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (224, 224));
    }

    #[test]
    fn golden_files_admission_refuses_below_the_floor() {
        let root = id_hex!("18AD4630637E03D4A8214A7464D06AAC");
        let unit = |i: usize| {
            let mut v = vec![0.0f32; 768];
            v[i] = 1.0;
            v
        };
        let row = |recorded: Option<Vec<f32>>| GoldenRow {
            model: "text",
            root,
            computed: unit(0),
            recorded,
        };
        assert!(GoldenReport {
            rows: vec![row(Some(unit(0)))]
        }
        .admit()
        .is_ok());
        assert!(GoldenReport {
            rows: vec![row(None)]
        }
        .admit()
        .is_ok());
        let off = GoldenReport {
            rows: vec![row(Some(unit(1)))],
        };
        let error = off.admit().unwrap_err().to_string();
        assert!(error.contains("cosine 0.00000"), "{error}");
        assert!((cosine(&unit(0), &unit(0)) - 1.0).abs() < 1e-6);
    }
}
