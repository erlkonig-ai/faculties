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

use anyhow::{anyhow, Context, Result};
use mary::model_collection::ModelPileSnapshot;
use mary::selection::{ModelSelector, TokenizerSelector};

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
pub fn index_models_in(store: &PileSnapshot) -> Result<IndexModels> {
    let snapshot = mary::model_collection::snapshot_model_collection_in(store)
        .context("freeze the working pile's model collection for the semantic index")?;
    let archives = snapshot
        .support()
        .members()
        .map(|member| member.raw)
        .collect();
    Ok(IndexModels {
        archives,
        text_root: preferred_root(&snapshot, NOMIC_TEXT_MODEL)?,
        vision_root: preferred_root(&snapshot, NOMIC_VISION_MODEL)?,
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
