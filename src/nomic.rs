//! The durable Nomic embedder seam.
//!
//! Ordinary inference reads one immutable native Mary collection snapshot per
//! model pile. Weight and tokenizer selection then happen against the same
//! frozen facts and blob reader, so a concurrent append cannot give one
//! component a different authority set from the other. There is no Repository
//! branch, mutable Workspace, tokenizer JSON, temporary file, or Hugging Face
//! fallback in this runtime path.
//!
//! Import and schema-epoch migration belong in Mary. A model pile without the
//! canonical native graph fails loudly here instead of silently switching
//! storage models.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mary::model_collection::ModelPileSnapshot;
use mary::selection::{ModelSelector, TokenizerSelector};

/// Hugging Face model ids are provenance only; runtime never fetches them.
pub const NOMIC_TEXT_MODEL: &str = "nomic-ai/nomic-embed-text-v1.5";
pub const NOMIC_VISION_MODEL: &str = "nomic-ai/nomic-embed-vision-v1.5";

/// Default model-pile filenames (resolved under [`crate::model_dir`]).
/// `NOMIC_TEXT_PILE` / `NOMIC_VISION_PILE` override the full path.
pub const NOMIC_TEXT_PILE_FILE: &str = "nomic_text.pile";
pub const NOMIC_VISION_PILE_FILE: &str = "nomic_vision.pile";

/// The text model pile path (env override, else the model-dir default).
pub fn text_pile() -> PathBuf {
    match std::env::var_os("NOMIC_TEXT_PILE") {
        Some(path) => PathBuf::from(path),
        None => crate::model_dir().join(NOMIC_TEXT_PILE_FILE),
    }
}

/// The vision model pile path (env override, else the model-dir default).
pub fn vision_pile() -> PathBuf {
    match std::env::var_os("NOMIC_VISION_PILE") {
        Some(path) => PathBuf::from(path),
        None => crate::model_dir().join(NOMIC_VISION_PILE_FILE),
    }
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

/// Load nomic-embed-text-v1.5 entirely from one canonical collection snapshot.
///
/// Absence or ambiguity of either the native weight graph or tokenizer graph
/// is an error. Migrate the pile with Mary's model migration CLI rather than
/// adding a compatibility path to ordinary inference.
pub fn load_text_embedder() -> Result<mary::embed::NomicTextEmbedder<mary::nn::backend::B>> {
    let pile = text_pile();
    let snapshot = load_model_snapshot(&pile, NOMIC_TEXT_MODEL)?;
    let keymap = mary::selection::load_keymap_from_graph(
        snapshot.facts(),
        snapshot.store(),
        ModelSelector::Source {
            source: NOMIC_TEXT_MODEL,
            quantization: mary::persist::QUANTIZATION_NATIVE,
        },
    )
    .with_context(|| format!("select native Nomic text weights from {}", pile.display()))?;
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

/// Load nomic-embed-vision-v1.5 from one canonical collection snapshot.
pub fn load_vision_embedder() -> Result<mary::embed::NomicVisionEmbedder<mary::nn::backend::B>> {
    let pile = vision_pile();
    let snapshot = load_model_snapshot(&pile, NOMIC_VISION_MODEL)?;
    let keymap = mary::selection::load_keymap_from_graph(
        snapshot.facts(),
        snapshot.store(),
        ModelSelector::Source {
            source: NOMIC_VISION_MODEL,
            quantization: mary::persist::QUANTIZATION_NATIVE,
        },
    )
    .with_context(|| format!("select native Nomic vision weights from {}", pile.display()))?;

    mary::embed::load_nomic_vision_from_keymap(keymap, mary::embed::default_device()).with_context(
        || {
            format!(
                "build Nomic vision embedder from native collection {}",
                pile.display()
            )
        },
    )
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
        assert_eq!(text.cover().len(), 2);

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
        assert_eq!(vision.cover().len(), 1);
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
