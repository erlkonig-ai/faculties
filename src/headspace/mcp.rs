//! Independent MCP schemas and typed resident-data conversion for Headspace.
//! The trusted launcher owns pile/key paths. show_secrets is an explicit output
//! disclosure; no other tool prints credential plaintext or opens ambient secrets.
use super::{AddProfileOptions, Credential, OptionalProfileField, ProfileEdit};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;
use zeroize::Zeroizing;

pub struct Headspace {
    operations: super::Headspace,
}
impl Headspace {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            operations: super::Headspace::with_storage(storage),
        }
    }
}
static TOOLS: &[Tool] = &[
Tool { name: "headspace_show", description: "Show current fork-visible configuration and profiles. Credentials are redacted by default; show_secrets explicitly decrypts only exact active-profile/global credential references into this tool response.", input_schema: r#"{"type":"object","properties":{"show_secrets":{"type":"boolean","default":false}},"required":[],"additionalProperties":false}"# },
Tool { name: "headspace_list", description: "List current profile anchors, agreement/fork status, and active profile without decrypting credentials.", input_schema: r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"# },
Tool { name: "headspace_use", description: "Switch to a settled profile name/anchor without arbitrating forks.", input_schema: r#"{"type":"object","properties":{"profile":{"type":"string"}},"required":["profile"],"additionalProperties":false}"# },
Tool { name: "headspace_add", description: "Create a fresh profile anchor and activate it in one Headspace commit, inheriting the current settled profile defaults. All strings are resident literal values.", input_schema: r#"{"type":"object","properties":{"name":{"type":"string","minLength":1},"model":{"type":"string"},"base_url":{"type":"string"},"model_secret_version":{"type":"string"},"reasoning_effort":{"type":"string"},"stream":{"type":"boolean"},"context_window_tokens":{"type":"integer","minimum":0},"max_output_tokens":{"type":"integer","minimum":0},"context_safety_margin_tokens":{"type":"integer","minimum":0},"chars_per_token":{"type":"integer","minimum":0}},"required":["name"],"additionalProperties":false}"# },
Tool { name: "headspace_set", description: "Set one typed non-secret field of the settled active profile. Text is literal; booleans and counts are JSON boolean/integer, not CLI text.", input_schema: r#"{"type":"object","properties":{"field":{"type":"string","enum":["model","base-url","reasoning-effort","stream","context-window-tokens","max-output-tokens","prompt-safety-margin-tokens","prompt-chars-per-token"]},"value":{}},"required":["field","value"],"additionalProperties":false,"oneOf":[{"properties":{"field":{"const":"model"},"value":{"type":"string"}}},{"properties":{"field":{"const":"base-url"},"value":{"type":"string"}}},{"properties":{"field":{"const":"reasoning-effort"},"value":{"type":"string"}}},{"properties":{"field":{"const":"stream"},"value":{"type":"boolean"}}},{"properties":{"field":{"const":"context-window-tokens"},"value":{"type":"integer","minimum":0}}},{"properties":{"field":{"const":"max-output-tokens"},"value":{"type":"integer","minimum":0}}},{"properties":{"field":{"const":"prompt-safety-margin-tokens"},"value":{"type":"integer","minimum":0}}},{"properties":{"field":{"const":"prompt-chars-per-token"},"value":{"type":"integer","minimum":0}}}]}"# },
Tool { name: "headspace_unset", description: "Clear the active profile's optional reasoning-effort field.", input_schema: r#"{"type":"object","properties":{"field":{"type":"string","enum":["reasoning-effort"]}},"required":["field"],"additionalProperties":false}"# },
Tool { name: "headspace_secret_set", description: "Reference an exact existing Secrets version or seal literal resident credential text first. Exactly one of value/version is required. After partial publication, use the reported exact version; do not resend plaintext automatically. Plaintext is never echoed.", input_schema: r#"{"type":"object","properties":{"role":{"type":"string","enum":["model","tavily","exa"]},"value":{"type":"string","minLength":1},"version":{"type":"string"}},"required":["role"],"additionalProperties":false,"oneOf":[{"required":["value"],"not":{"required":["version"]}},{"required":["version"],"not":{"required":["value"]}}]}"# },
Tool { name: "headspace_secret_unset", description: "Remove one exact credential reference from a complete successor; does not delete the immutable Secrets version.", input_schema: r#"{"type":"object","properties":{"role":{"type":"string","enum":["model","tavily","exa"]}},"required":["role"],"additionalProperties":false}"# },
Tool { name: "headspace_reconcile", description: "Choose one retained complete snapshot and join every live head on that track, preserving fork evidence.", input_schema: r#"{"type":"object","properties":{"snapshot":{"type":"string"}},"required":["snapshot"],"additionalProperties":false}"# },
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Show {
    show_secrets: Option<bool>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Use {
    profile: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Add {
    name: String,
    model: Option<String>,
    base_url: Option<String>,
    model_secret_version: Option<String>,
    reasoning_effort: Option<String>,
    stream: Option<bool>,
    context_window_tokens: Option<u64>,
    max_output_tokens: Option<u64>,
    context_safety_margin_tokens: Option<u64>,
    chars_per_token: Option<u64>,
}
#[derive(Deserialize)]
#[serde(
    tag = "field",
    content = "value",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
enum Set {
    Model(String),
    BaseUrl(String),
    ReasoningEffort(String),
    Stream(bool),
    ContextWindowTokens(u64),
    MaxOutputTokens(u64),
    PromptSafetyMarginTokens(u64),
    PromptCharsPerToken(u64),
}
impl From<Set> for ProfileEdit {
    fn from(value: Set) -> Self {
        match value {
            Set::Model(value) => Self::Model(value),
            Set::BaseUrl(value) => Self::BaseUrl(value),
            Set::ReasoningEffort(value) => Self::ReasoningEffort(value),
            Set::Stream(value) => Self::Stream(value),
            Set::ContextWindowTokens(value) => Self::ContextWindowTokens(value),
            Set::MaxOutputTokens(value) => Self::MaxOutputTokens(value),
            Set::PromptSafetyMarginTokens(value) => Self::PromptSafetyMarginTokens(value),
            Set::PromptCharsPerToken(value) => Self::PromptCharsPerToken(value),
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum OptionalField {
    ReasoningEffort,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Unset {
    field: OptionalField,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Role {
    Model,
    Tavily,
    Exa,
}
impl From<Role> for super::SecretRole {
    fn from(role: Role) -> Self {
        match role {
            Role::Model => Self::Model,
            Role::Tavily => Self::Tavily,
            Role::Exa => Self::Exa,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretSet {
    role: Role,
    value: Option<String>,
    version: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretUnset {
    role: Role,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reconcile {
    snapshot: String,
}
impl Faculty for Headspace {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        let headspace = &self.operations;
        match name {
            "headspace_show" => {
                let args: Show = decode_arguments(arguments)?;
                headspace.show(args.show_secrets.unwrap_or(false), out)
            }
            "headspace_list" => {
                let _: Empty = decode_arguments(arguments)?;
                headspace.list(out)
            }
            "headspace_use" => {
                let args: Use = decode_arguments(arguments)?;
                headspace.use_profile(&args.profile, out)
            }
            "headspace_add" => {
                let args: Add = decode_arguments(arguments)?;
                let options = AddProfileOptions {
                    name: args.name,
                    model: args.model,
                    base_url: args.base_url,
                    model_secret_version: args.model_secret_version,
                    reasoning_effort: args.reasoning_effort,
                    stream: args.stream,
                    context_window_tokens: args.context_window_tokens,
                    max_output_tokens: args.max_output_tokens,
                    context_safety_margin_tokens: args.context_safety_margin_tokens,
                    chars_per_token: args.chars_per_token,
                };
                headspace.add(&options, out).map(|_| ())
            }
            "headspace_set" => {
                let args: Set = decode_arguments(arguments)?;
                headspace.set(&args.into(), out)
            }
            "headspace_unset" => {
                let args: Unset = decode_arguments(arguments)?;
                match args.field {
                    OptionalField::ReasoningEffort => {
                        headspace.unset(OptionalProfileField::ReasoningEffort, out)
                    }
                }
            }
            "headspace_secret_set" => {
                let args: SecretSet = decode_arguments(arguments)?;
                let credential = match (args.value, args.version) {
                    (Some(value), None) => Credential::Plaintext(Zeroizing::new(value)),
                    (None, Some(version)) => Credential::Version(version),
                    _ => {
                        return Err(invalid_arguments(
                            "exactly one of value or version is required",
                        ))
                    }
                };
                headspace
                    .secret_set(args.role.into(), credential, out)
                    .map(|_| ())
            }
            "headspace_secret_unset" => {
                let args: SecretUnset = decode_arguments(arguments)?;
                headspace.secret_unset(args.role.into(), out)
            }
            "headspace_reconcile" => {
                let args: Reconcile = decode_arguments(arguments)?;
                headspace.reconcile(&args.snapshot, out)
            }
            _ => bail!("unknown Headspace MCP tool {name}"),
        }
    }
}
