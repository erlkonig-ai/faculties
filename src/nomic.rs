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
use triblespace::core::collection::CollectionHandle;
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

/// Explicit model references used by the semantic index. Physical member
/// archives and unrelated facts in this collection are not model identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexModels {
    pub collection: CollectionHandle,
    pub text_root: triblespace::core::id::Id,
    pub vision_root: triblespace::core::id::Id,
    pub tokenizer_root: triblespace::core::id::Id,
}

/// [`IndexModels`] from a pile snapshot the caller already holds.
///
/// Discovery selects the roots once, with packed weights preferred, and
/// records the containing collection handle. The descriptor does not change
/// when the same selected roots acquire observations, share an archive with
/// another model, or are packaged into different collection support.
pub fn index_models_in(store: &PileSnapshot) -> Result<IndexModels> {
    let snapshot = mary::model_collection::snapshot_model_collection_in(store)
        .context("freeze the working pile's model collection for the semantic index")?;
    index_models_from(&snapshot)
}

fn index_models_from(snapshot: &ModelPileSnapshot) -> Result<IndexModels> {
    let text_root = preferred_root(snapshot, NOMIC_TEXT_MODEL)?;
    let vision_root = preferred_root(snapshot, NOMIC_VISION_MODEL)?;
    let tokenizer_root = mary::selection::select_tokenizer_root(
        snapshot.facts(),
        snapshot.store(),
        TokenizerSelector::Name(NOMIC_TEXT_MODEL),
    )
    .context("select the semantic index's text tokenizer root")?;
    Ok(IndexModels {
        collection: snapshot.support().collection().handle(),
        text_root,
        vision_root,
        tokenizer_root,
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
// What the canonical compute embeds two fixed inputs to, recorded as separate
// observations referring to the model roots. A device about to
// publish semantic rows embeds the same inputs first and compares, so a
// driver or a kernel that computes something else refuses instead of
// splitting the index in two without anyone noticing. JP, 2026-09-10: the
// hardware in the type and the Sparks canonical; "keep the golden vector".

pub mod golden {
    pub use crate::schemas::embeddings::golden::{image_embedding, text_embedding};

    /// The fixed text every publishing device embeds. Its historical wording
    /// remains byte-for-byte unchanged so existing observations still compare.
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
    /// Every matching observation, including historical root-owned facts.
    pub recorded: Vec<Vec<f32>>,
}

impl GoldenRow {
    pub fn cosine(&self) -> Option<f32> {
        self.recorded
            .iter()
            .map(|recorded| cosine(&self.computed, recorded))
            .min_by(f32::total_cmp)
    }
}

/// The golden comparison for every model the semantic index embeds with.
pub struct GoldenReport {
    pub model_collection: CollectionHandle,
    pub rows: Vec<GoldenRow>,
}

impl GoldenReport {
    fn unrecorded_observations(&self) -> (Fragment, Vec<&'static str>) {
        let mut fragment = Fragment::empty();
        let mut recorded = Vec::new();
        for row in &self.rows {
            if !row.recorded.is_empty() {
                continue;
            }
            let handle = fragment.put::<Embedding768, _>(row.computed.clone());
            fragment += match row.model {
                "text" => entity! {
                    mary::format::attrs::model_root: row.root,
                    golden::text_embedding: handle,
                },
                _ => entity! {
                    mary::format::attrs::model_root: row.root,
                    golden::image_embedding: handle,
                },
            };
            recorded.push(row.model);
        }
        (fragment, recorded)
    }

    /// Admit this device as a publisher: every recorded golden vector is
    /// reproduced to at least [`golden::FLOOR`]. A root with no recorded
    /// vector admits with a warning on stderr; nothing was claimed yet.
    pub fn admit(&self) -> Result<()> {
        for row in &self.rows {
            match row.cosine() {
                Some(cos) if cos < golden::FLOOR => anyhow::bail!(
                    "this device embeds the golden {} input to cosine {cos:.5} of a vector recorded for root {:X} (floor {}); it does not publish rows into an index computed elsewhere",
                    row.model,
                    row.root,
                    golden::FLOOR
                ),
                Some(_) => {}
                None => eprintln!(
                    "warning: no golden vector recorded for {} root {:X}; rows publish unverified (`files golden --publish` on the canonical device records one)",
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
    let roots = index_models_from(&snapshot)?;
    let facts = snapshot.facts();
    let text = mary::embed::nomic_text_from_parts(
        mary::selection::load_keymap_from_graph(
            facts,
            store,
            ModelSelector::Root(roots.text_root),
        )?,
        mary::selection::load_tokenizer_from_graph(
            facts,
            store,
            TokenizerSelector::Root(roots.tokenizer_root),
        )?,
        mary::embed::default_device(),
    )
    .context("load the semantic index's selected text model for golden comparison")?;
    let vision = mary::embed::load_nomic_vision_from_keymap(
        mary::selection::load_keymap_from_graph(
            facts,
            store,
            ModelSelector::Root(roots.vision_root),
        )?,
        mary::embed::default_device(),
    )
    .context("load the semantic index's selected vision model for golden comparison")?;
    let computed_text = crate::memory_cover::l2_normalize(
        text.embed_document(golden::TEXT)
            .context("embed the golden text")?,
    );
    let computed_image = crate::memory_cover::l2_normalize(
        vision
            .embed_image(&golden::image_png())
            .context("embed the golden image")?,
    );
    let text_root = roots.text_root;
    let vision_root = roots.vision_root;
    let recorded_text: std::collections::BTreeSet<Inline<Handle<Embedding768>>> = find!(
        h: Inline<Handle<Embedding768>>,
        pattern!(facts, [{ _?observation @
            mary::format::attrs::model_root: text_root,
            golden::text_embedding: ?h,
        }])
    )
    .chain(find!(
        h: Inline<Handle<Embedding768>>,
        pattern!(facts, [{ text_root @ golden::text_embedding: ?h }])
    ))
    .collect();
    let recorded_image: std::collections::BTreeSet<Inline<Handle<Embedding768>>> = find!(
        h: Inline<Handle<Embedding768>>,
        pattern!(facts, [{ _?observation @
            mary::format::attrs::model_root: vision_root,
            golden::image_embedding: ?h,
        }])
    )
    .chain(find!(
        h: Inline<Handle<Embedding768>>,
        pattern!(facts, [{ vision_root @ golden::image_embedding: ?h }])
    ))
    .collect();
    // Historical vectors remain readable in place; only new publications use
    // observation subjects. Compare every matching value rather than choosing
    // one by archive order or requiring single-valued facts.
    let read = |handles: std::collections::BTreeSet<Inline<Handle<Embedding768>>>| -> Result<Vec<Vec<f32>>> {
        handles
            .into_iter()
            .map(|h| {
                let view: View<[f32]> = store
                    .get(h)
                    .map_err(|error| anyhow!("read a recorded golden vector: {error:?}"))?;
                Ok(view.as_ref().to_vec())
            })
            .collect()
    };
    Ok(GoldenReport {
        model_collection: roots.collection,
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

/// Record separate golden-vector observations for roots that have none, as
/// one signed commit into the explicitly observed model collection. Historical
/// root-owned facts remain untouched and readable; no model entity is owned or
/// annotated by this publication.
pub fn golden_publish(
    store: &mut crate::storage::FacultyStore,
    signer: &ed25519_dalek::SigningKey,
) -> Result<(GoldenReport, Vec<&'static str>)> {
    use triblespace::core::repo::SnapshotSource;
    let snapshot = store
        .snapshot()
        .context("freeze the pile for the golden vectors")?;
    let report = golden_report(&snapshot)?;
    let collection =
        mary::model_collection::ModelCollection::open(&snapshot, report.model_collection)
            .context("open the golden report's model collection")?;
    drop(snapshot);
    let (fragment, recorded) = report.unrecorded_observations();
    if !recorded.is_empty() {
        store
            .commit(collection, signer, fragment)
            .context("record golden observations referring to the model roots")?;
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
        let row = |recorded: Vec<Vec<f32>>| GoldenRow {
            model: "text",
            root,
            computed: unit(0),
            recorded,
        };
        assert!(GoldenReport {
            model_collection: Inline::new([7; 32]),
            rows: vec![row(vec![unit(0)])]
        }
        .admit()
        .is_ok());
        assert!(GoldenReport {
            model_collection: Inline::new([7; 32]),
            rows: vec![row(vec![])]
        }
        .admit()
        .is_ok());
        let off = GoldenReport {
            model_collection: Inline::new([7; 32]),
            rows: vec![row(vec![unit(0), unit(1)])],
        };
        let error = off.admit().unwrap_err().to_string();
        assert!(error.contains("cosine 0.00000"), "{error}");
        assert!((cosine(&unit(0), &unit(0)) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn golden_observations_reference_models_without_owning_their_facts() {
        let text = triblespace::core::id::fucid();
        let vision = triblespace::core::id::fucid();
        let report = GoldenReport {
            model_collection: Inline::new([7; 32]),
            rows: vec![
                GoldenRow {
                    model: "text",
                    root: *text,
                    computed: vec![1.0; 768],
                    recorded: Vec::new(),
                },
                GoldenRow {
                    model: "image",
                    root: *vision,
                    computed: vec![2.0; 768],
                    recorded: Vec::new(),
                },
            ],
        };
        let (observations, recorded) = report.unrecorded_observations();
        assert_eq!(recorded, ["text", "image"]);
        assert!(observations
            .facts()
            .iter()
            .all(|fact| fact.e() != &*text && fact.e() != &*vision));
        let text_subjects: Vec<Id> = find!(
            observation: Id,
            pattern!(observations.facts(), [{ ?observation @
                mary::format::attrs::model_root: *text,
                golden::text_embedding: _?vector,
            }])
        )
        .collect();
        let vision_subjects: Vec<Id> = find!(
            observation: Id,
            pattern!(observations.facts(), [{ ?observation @
                mary::format::attrs::model_root: *vision,
                golden::image_embedding: _?vector,
            }])
        )
        .collect();
        assert_eq!(text_subjects.len(), 1);
        assert_eq!(vision_subjects.len(), 1);
        assert_ne!(text_subjects[0], vision_subjects[0]);
        assert_eq!(observations, report.unrecorded_observations().0);

        // A historical observation satisfies the publication precondition in
        // place: no migration or duplicate observation is silently authored.
        let historical = GoldenReport {
            model_collection: report.model_collection,
            rows: report
                .rows
                .into_iter()
                .map(|mut row| {
                    row.recorded.push(row.computed.clone());
                    row
                })
                .collect(),
        };
        let (unchanged, recorded) = historical.unrecorded_observations();
        assert!(unchanged.facts().is_empty());
        assert!(recorded.is_empty());
    }
}
