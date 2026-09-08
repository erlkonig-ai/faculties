//! Fallible preflight for the configuration files Mary's FLUX loaders reopen.
//! This validates the known JSON shapes, not tensor geometry or GPU execution.
//! The files must remain stable until generation finishes: Mary still opens
//! their paths itself. Tokenizer JSON gets syntax/object validation only;
//! its private loader can still reject a semantically invalid tokenizer.
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize};
use std::path::Path;

fn read_json<T: DeserializeOwned>(directory: &Path, relative: &str) -> Result<T> {
    let path = directory.join(relative);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("read FLUX configuration {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse FLUX configuration {}", path.display()))
}

// Mary exposes Deserialize for the other three configurations, but its
// Mistral3Config projection and deserializable wrapper are respectively
// non-Deserialize and private. Keep this validation-only shape aligned with
// mary::models::flux::mistral_encoder::config; no values drive model execution.
#[derive(Deserialize)]
#[allow(dead_code)]
struct MistralConfig {
    text_config: MistralTextConfig,
}
#[derive(Deserialize)]
#[allow(dead_code)]
struct MistralTextConfig {
    hidden_size: usize,
    num_hidden_layers: usize,
    num_attention_heads: usize,
    num_key_value_heads: usize,
    head_dim: usize,
    intermediate_size: usize,
    #[serde(default)]
    rms_norm_eps: f64,
    #[serde(default)]
    rope_theta: f64,
    vocab_size: usize,
}

#[cfg(feature = "imagine")]
pub(super) fn preflight(directory: &Path, variant: super::Variant) -> Result<()> {
    use mary::models::flux::{
        text_encoder::config::Qwen3Config, transformer::config::Flux2TransformerConfig,
        vae::config::VaeConfig,
    };
    let _: Flux2TransformerConfig = read_json(directory, "transformer/config.json")?;
    let _: VaeConfig = read_json(directory, "vae/config.json")?;
    match variant {
        super::Variant::Klein => {
            let _: Qwen3Config = read_json(directory, "text_encoder/config.json")?;
        }
        super::Variant::Dev => {
            let _: MistralConfig = read_json(directory, "text_encoder/config.json")?;
        }
    }
    let _: serde_json::Map<String, serde_json::Value> =
        read_json(directory, "tokenizer/tokenizer.json")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_config() -> serde_json::Value {
        serde_json::json!({
            "hidden_size": 16, "num_hidden_layers": 1, "num_attention_heads": 2,
            "num_key_value_heads": 1, "head_dim": 8, "intermediate_size": 32,
            "vocab_size": 64
        })
    }

    #[test]
    fn mistral_validation_matches_required_fields_and_optional_defaults() {
        let text = text_config();
        serde_json::from_value::<MistralConfig>(serde_json::json!({"text_config": text})).unwrap();
        for name in ["hidden_size", "head_dim", "vocab_size"] {
            let mut text = text_config();
            text.as_object_mut().unwrap().remove(name);
            assert!(serde_json::from_value::<MistralConfig>(
                serde_json::json!({"text_config": text})
            )
            .is_err());
        }
        let mut text = text_config();
        text["rms_norm_eps"] = serde_json::Value::Null;
        assert!(
            serde_json::from_value::<MistralConfig>(serde_json::json!({"text_config": text}))
                .is_err()
        );
    }

    #[test]
    fn missing_and_malformed_configurations_are_errors_with_the_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.json");
        let missing = read_json::<MistralConfig>(directory.path(), "config.json")
            .err()
            .unwrap();
        assert!(missing.to_string().contains("config.json"));
        std::fs::write(&path, b"{").unwrap();
        let malformed = read_json::<MistralConfig>(directory.path(), "config.json")
            .err()
            .unwrap();
        assert!(malformed.to_string().contains("config.json"));
        std::fs::write(&path, b"{\"text_config\":{}}").unwrap();
        assert!(read_json::<MistralConfig>(directory.path(), "config.json").is_err());
    }

    #[test]
    #[cfg(feature = "imagine")]
    fn all_known_configs_are_checked_before_model_acquisition() {
        let directory = tempfile::tempdir().unwrap();
        let fixtures = [
            (
                "transformer/config.json",
                serde_json::json!({
                    "num_attention_heads":2, "attention_head_dim":8, "num_layers":1,
                    "num_single_layers":1, "joint_attention_dim":16, "in_channels":4,
                    "mlp_ratio":4.0, "axes_dims_rope":[2,2,4]
                }),
            ),
            (
                "vae/config.json",
                serde_json::json!({
                    "in_channels":3, "out_channels":3, "latent_channels":4
                }),
            ),
            ("text_encoder/config.json", {
                let mut value = text_config();
                value["rms_norm_eps"] = serde_json::json!(1e-5);
                value["rope_theta"] = serde_json::json!(10000.0);
                value
            }),
            ("tokenizer/tokenizer.json", serde_json::json!({})),
        ];
        for (relative, value) in &fixtures {
            let path = directory.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
        }
        // These fixtures validate configuration shape only, not a usable model.
        preflight(directory.path(), super::super::Variant::Klein).unwrap();
        for (relative, value) in &fixtures {
            let path = directory.path().join(relative);
            std::fs::write(&path, b"[]").unwrap();
            let error = preflight(directory.path(), super::super::Variant::Klein).unwrap_err();
            assert!(error.to_string().contains(relative), "{error:#}");
            std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
        }
        std::fs::write(
            directory.path().join("text_encoder/config.json"),
            serde_json::to_vec(&serde_json::json!({"text_config":text_config()})).unwrap(),
        )
        .unwrap();
        preflight(directory.path(), super::super::Variant::Dev).unwrap();
    }
}
