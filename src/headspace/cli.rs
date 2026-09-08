//! Explicit Headspace CLI grammar. Only this adapter expands @file/@-/@@.
use super::{AddProfileOptions, Credential, Headspace, OptionalProfileField, ProfileEdit};
use crate::out::Out;
use anyhow::{anyhow, bail, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "headspace",
    bin_name = "headspace",
    about = "Manage fork-visible Headspace configuration and model profiles."
)]
pub struct Cli {
    /// Existing pile file. Reads and writes never create it.
    #[arg(long, env = "PILE")]
    pub(super) pile: PathBuf,
    /// Existing durable collection signer. Ordinary commands never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    pub(super) key: Option<PathBuf>,
    #[command(subcommand)]
    pub(super) command: Option<Command>,
}

#[derive(Subcommand)]
pub(super) enum Command {
    /// Show the resolved active Headspace and available profiles.
    Show {
        /// Decrypt the exact referenced credential versions.
        #[arg(long, default_value_t = false)]
        show_secrets: bool,
    },
    /// List profile anchors and their current resolution.
    List,
    /// Switch the active profile by anchor id or settled profile name.
    Use {
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
    /// Author a fresh profile anchor and activate it in one signed COMMIT.
    Add(AddArgs),
    /// Set one non-secret field on the resolved active profile.
    Set {
        #[arg(value_enum, value_name = "FIELD")]
        field: SetField,
        #[arg(value_name = "VALUE", help = "Literal value, @path, or @- for stdin.")]
        value: String,
    },
    /// Clear one optional non-secret field on the active profile.
    Unset {
        #[arg(value_enum, value_name = "FIELD")]
        field: UnsetField,
    },
    /// Manage an exact immutable Secrets reference.
    Secret {
        #[arg(value_enum)]
        role: SecretRole,
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Choose an existing complete snapshot and join every live head on its track.
    Reconcile {
        #[arg(value_name = "SNAPSHOT")]
        snapshot: String,
    },
}

#[derive(Args)]
pub(super) struct AddArgs {
    #[arg(value_name = "NAME")]
    pub(super) name: String,
    #[arg(long)]
    pub(super) model: Option<String>,
    #[arg(long = "base-url")]
    pub(super) base_url: Option<String>,
    /// Exact existing Secrets version for the new profile's model credential.
    #[arg(long)]
    pub(super) model_secret_version: Option<String>,
    #[arg(long = "reasoning-effort")]
    pub(super) reasoning_effort: Option<String>,
    #[arg(long)]
    pub(super) stream: Option<bool>,
    #[arg(long = "context-window-tokens")]
    pub(super) context_window_tokens: Option<u64>,
    #[arg(long = "max-output-tokens")]
    pub(super) max_output_tokens: Option<u64>,
    #[arg(long = "prompt-safety-margin-tokens")]
    pub(super) context_safety_margin_tokens: Option<u64>,
    #[arg(long = "prompt-chars-per-token")]
    pub(super) chars_per_token: Option<u64>,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
#[value(rename_all = "kebab-case")]
pub(super) enum SetField {
    Model,
    BaseUrl,
    ReasoningEffort,
    Stream,
    ContextWindowTokens,
    MaxOutputTokens,
    PromptSafetyMarginTokens,
    PromptCharsPerToken,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
#[value(rename_all = "kebab-case")]
pub(super) enum UnsetField {
    ReasoningEffort,
}

#[derive(ValueEnum, Debug, Clone, Copy, Eq, PartialEq)]
#[value(rename_all = "kebab-case")]
pub(super) enum SecretRole {
    Model,
    Tavily,
    Exa,
}

#[derive(Subcommand)]
pub(super) enum SecretCommand {
    /// Point the role at an exact existing version, or seal one version first.
    Set(SecretSetArgs),
    /// Remove the role's exact credential reference in a complete successor.
    Unset,
}

#[derive(Args)]
pub(super) struct SecretSetArgs {
    /// Plaintext credential as a literal, @path, or @-.
    #[arg(long, conflicts_with = "version", required_unless_present = "version")]
    pub(super) value: Option<String>,
    /// Exact existing Secrets version. This repairs an interrupted Secrets-first update.
    #[arg(long, conflicts_with = "value", required_unless_present = "value")]
    pub(super) version: Option<String>,
}

impl From<SecretRole> for super::SecretRole {
    fn from(role: SecretRole) -> Self {
        match role {
            SecretRole::Model => Self::Model,
            SecretRole::Tavily => Self::Tavily,
            SecretRole::Exa => Self::Exa,
        }
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    crate::cli::with_output("headspace", |out| execute(cli, out))
}
pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let Some(command) = cli.command else {
        return out.line(Cli::command().render_long_help().to_string());
    };
    let headspace = Headspace::new(cli.pile, cli.key);
    match command {
        Command::Show { show_secrets } => headspace.show(show_secrets, out),
        Command::List => headspace.list(out),
        Command::Use { profile } => headspace.use_profile(&profile, out),
        Command::Add(args) => {
            let literal = |value: Option<String>, label: &str| {
                value
                    .map(|value| crate::text_arg(&value, label))
                    .transpose()
            };
            let options = AddProfileOptions {
                name: crate::text_arg(&args.name, "profile name")?,
                model: literal(args.model, "model name")?,
                base_url: literal(args.base_url, "model base URL")?,
                model_secret_version: args.model_secret_version,
                reasoning_effort: literal(args.reasoning_effort, "reasoning effort")?,
                stream: args.stream,
                context_window_tokens: args.context_window_tokens,
                max_output_tokens: args.max_output_tokens,
                context_safety_margin_tokens: args.context_safety_margin_tokens,
                chars_per_token: args.chars_per_token,
            };
            headspace.add(&options, out).map(|_| ())
        }
        Command::Set { field, value } => {
            let edit = match field {
                SetField::Model => ProfileEdit::Model(crate::text_arg(&value, "model name")?),
                SetField::BaseUrl => {
                    ProfileEdit::BaseUrl(crate::text_arg(&value, "model base URL")?)
                }
                SetField::ReasoningEffort => {
                    ProfileEdit::ReasoningEffort(crate::text_arg(&value, "model reasoning effort")?)
                }
                SetField::Stream => ProfileEdit::Stream(parse_bool(&value, "model_stream")?),
                SetField::ContextWindowTokens => ProfileEdit::ContextWindowTokens(parse_u64(
                    &value,
                    "model_context_window_tokens",
                )?),
                SetField::MaxOutputTokens => {
                    ProfileEdit::MaxOutputTokens(parse_u64(&value, "model_max_output_tokens")?)
                }
                SetField::PromptSafetyMarginTokens => ProfileEdit::PromptSafetyMarginTokens(
                    parse_u64(&value, "model_context_safety_margin_tokens")?,
                ),
                SetField::PromptCharsPerToken => {
                    ProfileEdit::PromptCharsPerToken(parse_u64(&value, "model_chars_per_token")?)
                }
            };
            headspace.set(&edit, out)
        }
        Command::Unset {
            field: UnsetField::ReasoningEffort,
        } => headspace.unset(OptionalProfileField::ReasoningEffort, out),
        Command::Secret { role, command } => match command {
            SecretCommand::Set(args) => {
                let credential = match (args.value, args.version) {
                    (Some(value), None) => Credential::Plaintext(Zeroizing::new(crate::text_arg(
                        &value,
                        "credential",
                    )?)),
                    (None, Some(version)) => Credential::Version(version),
                    _ => bail!("exactly one of --value or --version is required"),
                };
                headspace
                    .secret_set(role.into(), credential, out)
                    .map(|_| ())
            }
            SecretCommand::Unset => headspace.secret_unset(role.into(), out),
        },
        Command::Reconcile { snapshot } => headspace.reconcile(&snapshot, out),
    }
}

fn parse_u64(raw: &str, label: &str) -> Result<u64> {
    raw.parse::<u64>()
        .map_err(|_| anyhow!("invalid {label} {raw}"))
}

fn parse_bool(raw: &str, label: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => bail!("invalid {label} {raw} (expected true/false)"),
    }
}
