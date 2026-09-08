//! Tailored Teams CLI: host input, interactive login, and filesystem export stay here.
use super::{operations::*, render};
use crate::out::Out;
use crate::schemas::teams::DEFAULT_DELTA_URL;
use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};
use triblespace::prelude::Id;

#[derive(Parser)]
#[command(version = crate::GIT_VERSION, name = "teams", about = "Ingest Microsoft Teams messages into TribleSpace")]
pub struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it;
    /// initialize explicitly with `trible pile signing-key init <pile>`.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Concrete Microsoft Entra tenant used to select a collection auth
    /// profile. It may be omitted only when exactly one profile source exists.
    #[arg(long, env = "TEAMS_TENANT")]
    tenant: Option<String>,
    /// Microsoft Graph delta endpoint.
    #[arg(long, default_value = DEFAULT_DELTA_URL)]
    delta_url: String,
    /// Explicit external presentation identity for Teams mutations.
    #[arg(long = "as", global = true)]
    present_as: Option<String>,
    #[command(subcommand)]
    command: Option<CommandMode>,
}

#[derive(Subcommand)]
enum CommandMode {
    /// Sync from Graph and read messages from the local pile.
    Read {
        /// Teams chat id (external id).
        chat_id: Option<String>,
        /// Only show messages at or after this timestamp (RFC3339 or Graph format).
        #[arg(long)]
        since: Option<String>,
        /// Maximum number of messages to return (0 = no limit).
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Show newest messages first.
        #[arg(long)]
        descending: bool,
    },
    /// Send a message into a Teams chat.
    Send {
        chat_id: String,
        #[arg(help = "Message text. Use @path for file input or @- for stdin.")]
        text: String,
    },
    /// Users directory commands.
    Users {
        #[command(subcommand)]
        command: UsersCommand,
    },
    /// Presence commands.
    Presence {
        #[command(subcommand)]
        command: PresenceCommand,
    },
    /// Chat commands.
    Chat {
        #[command(subcommand)]
        command: ChatCommand,
    },
    /// Attachment commands.
    Attachments {
        #[command(subcommand)]
        command: AttachmentsCommand,
    },
    /// Configure or inspect the professional Teams presentation context.
    Context {
        #[command(subcommand)]
        command: ContextCommand,
    },
    /// Inspect Teams authentication state without printing credentials.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Interactive device-code login that publishes encrypted credential versions.
    Login {
        /// Tenant id or domain (default: common).
        #[arg(long, default_value = "common")]
        tenant: String,
        /// Azure app client id.
        #[arg(long)]
        client_id: String,
        /// Non-argv source for an Azure app client secret to encrypt as a new
        /// Secrets version. Use `@path` or `@-`; alternatively set
        /// `TEAMS_CLIENT_SECRET`.
        #[arg(
            long = "client-secret",
            value_name = "@PATH|@-",
            conflicts_with = "client_secret_version",
            help = "Read the Azure app client secret from @path or @- and encrypt it into the configured Secrets collection. TEAMS_CLIENT_SECRET is the environment alternative."
        )]
        client_secret_source: Option<String>,
        /// Exact existing Secrets version for the app client secret.
        #[arg(long, value_parser = parse_id, conflicts_with = "client_secret_source")]
        client_secret_version: Option<Id>,
        /// Space-delimited scopes (defaults to chat + presence + user read + offline_access).
        #[arg(
            long,
            help = "Space-delimited scopes. Use @path for file input or @- for stdin."
        )]
        scopes: Option<String>,
    },
}

#[derive(Subcommand)]
enum ContextCommand {
    /// Set the identity and privacy boundary used for professional Teams work.
    Set {
        /// Name to present externally (for example, Bulti).
        present_as: String,
        /// Work-context reminder shown before Teams activity.
        #[arg(long)]
        boundary: String,
    },
    /// Show the current professional Teams presentation context.
    Show,
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Show safe profile metadata and exact secret-version references.
    Status,
    /// Publish a complete profile from exact existing Secrets versions. This
    /// is also the repair/reconciliation path after an interrupted login.
    Set {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        user_id: String,
        #[arg(long)]
        scopes: String,
        #[arg(long, value_parser = parse_id)]
        client_secret_version: Option<Id>,
        #[arg(long, value_parser = parse_id)]
        delegated_token_version: Option<Id>,
    },
}

#[derive(Subcommand)]
enum UsersCommand {
    /// List directory users by display name prefix.
    List {
        /// Name/email prefix to search for.
        prefix: Option<String>,
        /// Maximum number of users to return (0 = no limit).
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum CliPresenceAvailability {
    #[value(name = "Available", alias = "available")]
    Available,
    #[value(name = "Busy", alias = "busy")]
    Busy,
    #[value(name = "Away", alias = "away")]
    Away,
    #[value(
        name = "DoNotDisturb",
        alias = "do-not-disturb",
        alias = "donotdisturb",
        alias = "dnd"
    )]
    DoNotDisturb,
}

impl CliPresenceAvailability {
    fn native(self) -> PresenceAvailability {
        match self {
            Self::Available => PresenceAvailability::Available,
            Self::Busy => PresenceAvailability::Busy,
            Self::Away => PresenceAvailability::Away,
            Self::DoNotDisturb => PresenceAvailability::DoNotDisturb,
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum CliPresenceActivity {
    #[value(name = "Available", alias = "available")]
    Available,
    #[value(
        name = "InACall",
        alias = "in-a-call",
        alias = "inacall",
        alias = "call"
    )]
    InACall,
    #[value(
        name = "InAConferenceCall",
        alias = "in-a-conference-call",
        alias = "inaconferencecall",
        alias = "conference"
    )]
    InAConferenceCall,
    #[value(name = "Away", alias = "away")]
    Away,
    #[value(name = "Presenting", alias = "presenting")]
    Presenting,
}

impl CliPresenceActivity {
    fn native(self) -> PresenceActivity {
        match self {
            Self::Available => PresenceActivity::Available,
            Self::InACall => PresenceActivity::InACall,
            Self::InAConferenceCall => PresenceActivity::InAConferenceCall,
            Self::Away => PresenceActivity::Away,
            Self::Presenting => PresenceActivity::Presenting,
        }
    }
}

#[derive(Subcommand)]
enum PresenceCommand {
    /// Set the Teams presence for the logged-in user.
    Set {
        /// Availability (Available, Busy, Away, DoNotDisturb).
        availability: CliPresenceAvailability,
        /// Activity (Available, InACall, InAConferenceCall, Away, Presenting).
        #[arg(long)]
        activity: Option<CliPresenceActivity>,
        /// Expiration in minutes (5-240).
        #[arg(long, default_value_t = 60)]
        duration_mins: u32,
        /// Optional session id override (defaults to app client id).
        #[arg(long)]
        session_id: Option<String>,
    },
    /// Get presence for one or more users (by id).
    Get {
        /// One or more user ids to query.
        user_ids: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ChatCommand {
    /// Invite a user into an existing chat.
    Invite {
        chat_id: String,
        user_id: String,
        /// Add as owner.
        #[arg(long)]
        owner: bool,
    },
    /// Create a new chat with users (by id).
    Create {
        /// User ids to include (self is added automatically).
        user_ids: Vec<String>,
        /// Force a group chat even for 1:1.
        #[arg(long)]
        group: bool,
        /// Optional group chat topic.
        #[arg(
            long,
            help = "Optional group chat topic. Use @path for file input or @- for stdin."
        )]
        topic: Option<String>,
    },
}

#[derive(Subcommand)]
enum AttachmentsCommand {
    /// List attachments stored in the pile.
    List {
        /// Filter by Teams chat id (external id).
        #[arg(long)]
        chat_id: Option<String>,
        /// Filter by Teams message id (external id).
        #[arg(long)]
        message_id: Option<String>,
        /// Maximum number of attachments to return (0 = no limit).
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Show newest attachments first.
        #[arg(long)]
        descending: bool,
    },
    /// Export a stored attachment to a local file.
    Export {
        /// Attachment source id (as shown in attachments list).
        source_id: String,
        /// Filter by Teams chat id (external id).
        #[arg(long)]
        chat_id: Option<String>,
        /// Filter by Teams message id (external id).
        #[arg(long)]
        message_id: Option<String>,
        /// Output directory (created if missing).
        out_dir: Option<PathBuf>,
        /// Override filename (defaults to attachment name or source id).
        #[arg(long)]
        filename: Option<String>,
        /// Overwrite if the file already exists.
        #[arg(long)]
        overwrite: bool,
    },
}

fn host_activity<T>(result: Activity<T>) -> T {
    eprint!("{}", render::context_banner(&result.context));
    for notice in result.notices {
        eprintln!("{notice}");
    }
    result.value
}

pub fn execute(mut cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let mode = cli
        .command
        .take()
        .ok_or_else(|| anyhow::anyhow!("no Teams command"))?;
    let delta_url = std::env::var("TEAMS_DELTA_URL")
        .ok()
        .unwrap_or(cli.delta_url);
    let operations = Teams::new(cli.pile, cli.key)
        .with_tenant(cli.tenant.clone())
        .with_delta_url(delta_url);
    let present_as = cli.present_as.as_deref().unwrap_or("");
    match mode {
        CommandMode::Read {
            chat_id,
            since,
            limit,
            descending,
        } => {
            let value = host_activity(operations.read(
                ReadOptions {
                    chat_id,
                    since,
                    limit,
                    descending,
                },
                ArchiveAccess::Synchronize,
            )?);
            render::messages(&value, out)
        }
        CommandMode::Send { chat_id, text } => {
            let text = crate::text_arg(&text, "message text")?;
            host_activity(operations.send(present_as, &chat_id, &text)?);
            Ok(())
        }
        CommandMode::Users {
            command: UsersCommand::List { prefix, limit },
        } => render::users(
            &host_activity(operations.users_list(prefix.as_deref(), limit)?),
            out,
        ),
        CommandMode::Presence { command } => match command {
            PresenceCommand::Set {
                availability,
                activity,
                duration_mins,
                session_id,
            } => {
                host_activity(operations.presence_set(
                    present_as,
                    availability.native(),
                    activity.map(CliPresenceActivity::native),
                    duration_mins,
                    session_id,
                )?);
                Ok(())
            }
            PresenceCommand::Get { user_ids } => {
                render::presence(&host_activity(operations.presence_get(user_ids)?), out)
            }
        },
        CommandMode::Chat { command } => match command {
            ChatCommand::Invite {
                chat_id,
                user_id,
                owner,
            } => {
                host_activity(operations.chat_invite(present_as, &chat_id, &user_id, owner)?);
                Ok(())
            }
            ChatCommand::Create {
                user_ids,
                group,
                topic,
            } => {
                let topic = topic
                    .as_deref()
                    .map(|raw| load_value_or_file(raw, "chat topic"))
                    .transpose()?;
                out.line(host_activity(
                    operations.chat_create(present_as, user_ids, group, topic)?,
                ))
            }
        },
        CommandMode::Attachments { command } => match command {
            AttachmentsCommand::List {
                chat_id,
                message_id,
                limit,
                descending,
            } => render::attachments(
                &host_activity(operations.attachments_list(
                    AttachmentListOptions {
                        chat_id,
                        message_id,
                        limit,
                        descending,
                    },
                    ArchiveAccess::Synchronize,
                )?),
                out,
            ),
            AttachmentsCommand::Export {
                source_id,
                chat_id,
                message_id,
                out_dir,
                filename,
                overwrite,
            } => {
                let value = host_activity(operations.attachment_get(
                    AttachmentGetOptions {
                        source_id,
                        chat_id,
                        message_id,
                    },
                    ArchiveAccess::Synchronize,
                )?);
                export_attachment(
                    value,
                    out_dir
                        .as_deref()
                        .unwrap_or_else(|| Path::new("./attachments")),
                    filename.as_deref(),
                    overwrite,
                    out,
                )
            }
        },
        CommandMode::Context { command } => match command {
            ContextCommand::Set {
                present_as,
                boundary,
            } => {
                let tenant = cli.tenant.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "`teams context set` requires --tenant for an explicit source identity"
                    )
                })?;
                render::context(
                    &operations
                        .context_set(tenant, &present_as, &boundary)?
                        .value,
                    out,
                )
            }
            ContextCommand::Show => render::context(&operations.context_show()?, out),
        },
        CommandMode::Auth { command } => match command {
            AuthCommand::Status => out.text(host_activity(operations.auth_status()?)),
            AuthCommand::Set {
                tenant,
                client_id,
                user_id,
                scopes,
                client_secret_version,
                delegated_token_version,
            } => {
                let scopes = load_value_or_file(&scopes, "Teams scopes")?;
                render::auth_set(
                    &operations.auth_set(AuthProfileInput {
                        tenant,
                        client_id,
                        user_id,
                        scopes,
                        client_secret_version,
                        delegated_token_version,
                    })?,
                    out,
                )
            }
        },
        CommandMode::Login {
            tenant,
            client_id,
            client_secret_source,
            client_secret_version,
            scopes,
        } => {
            eprint!(
                "{}",
                render::context_banner(&PresentationContext::default())
            );
            let scopes = scopes
                .as_deref()
                .map(|raw| load_value_or_file(raw, "scopes"))
                .transpose()?
                .unwrap_or_else(default_scopes);
            let client_secret =
                load_client_secret(client_secret_source.as_deref(), client_secret_version)?;
            let receipt = operations.login(
                LoginInput {
                    tenant: &tenant,
                    client_id: &client_id,
                    scopes: &scopes,
                    client_secret: client_secret.as_deref(),
                    client_secret_version,
                },
                &mut |message| out.line(message),
            )?;
            for notice in &receipt.notices {
                eprintln!("{notice}");
            }
            render::login(&receipt, out)
        }
    }
}

/// Export a completed resident observation. It never performs a Graph request.
/// Filename conventions and overwrite policy belong to the host CLI, not MCP.
pub fn export_attachment(
    value: AttachmentLookup,
    out_dir: &Path,
    filename: Option<&str>,
    overwrite: bool,
    out: &mut Out<'_>,
) -> Result<()> {
    match value {
        AttachmentLookup::Missing { reference } => render::attachment_missing(&reference, out),
        AttachmentLookup::Ambiguous(matches) => {
            out.line("Multiple attachments matched; add --chat-id/--message-id:")?;
            render::attachment_matches(&matches, out)
        }
        AttachmentLookup::Found(data) => {
            let mut filename = sanitize_filename(filename.unwrap_or(&data.name));
            if !filename.contains('.') {
                if let Some(extension) = infer_extension(data.media_type.as_deref()) {
                    filename.push('.');
                    filename.push_str(extension);
                }
            }
            fs::create_dir_all(out_dir)
                .with_context(|| format!("create output dir {}", out_dir.display()))?;
            let path = out_dir.join(filename);
            if path.exists() && !overwrite {
                bail!("output file exists: {} (use --overwrite)", path.display());
            }
            fs::write(&path, data.bytes.as_ref())
                .with_context(|| format!("write attachment {}", path.display()))?;
            out.line(path.display().to_string())
        }
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("teams", |out| execute(cli, out))
}

fn parse_id(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim())
        .ok_or_else(|| format!("'{raw}' is not one exact nonzero 32-digit hexadecimal id"))
}

fn sanitize_filename(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "attachment".to_string();
    }

    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        let cleaned = match ch {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ if ch.is_control() => '_',
            _ => ch,
        };
        out.push(cleaned);
    }

    let mut out = out.trim().trim_matches('.').to_string();
    if out.is_empty() || out == "." || out == ".." {
        out = "attachment".to_string();
    }
    out
}

fn infer_extension(media_type: Option<&str>) -> Option<&'static str> {
    match media_type? {
        "image/jpeg" | "image/jpg" | "image/pjpeg" => Some("jpg"),
        "image/png" => Some("png"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        "image/bmp" => Some("bmp"),
        "image/tiff" => Some("tif"),
        "image/svg+xml" => Some("svg"),
        "application/pdf" => Some("pdf"),
        "text/plain" => Some("txt"),
        "text/markdown" => Some("md"),
        "text/html" => Some("html"),
        "application/json" => Some("json"),
        "application/zip" => Some("zip"),
        "application/msword" => Some("doc"),
        "application/vnd.ms-excel" => Some("xls"),
        "application/vnd.ms-powerpoint" => Some("ppt"),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => Some("docx"),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Some("xlsx"),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => Some("pptx"),
        "audio/mpeg" => Some("mp3"),
        "audio/mp4" | "audio/x-m4a" => Some("m4a"),
        "audio/wav" | "audio/x-wav" => Some("wav"),
        "video/mp4" => Some("mp4"),
        "video/quicktime" => Some("mov"),
        _ => None,
    }
}

fn load_value_or_file(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_string())
}

fn load_value_or_file_trimmed(raw: &str, label: &str) -> Result<String> {
    Ok(load_value_or_file(raw, label)?.trim().to_string())
}

fn load_client_secret(
    source: Option<&str>,
    existing_version: Option<Id>,
) -> Result<Option<String>> {
    let sourced = source
        .map(|source| {
            if !source.starts_with('@') {
                bail!(
                    "--client-secret accepts only @path or @-; use TEAMS_CLIENT_SECRET for environment input"
                );
            }
            load_value_or_file_trimmed(source, "client secret")
        })
        .transpose()?;
    let environment = match std::env::var("TEAMS_CLIENT_SECRET") {
        Ok(value) => Some(value.trim().to_owned()),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("TEAMS_CLIENT_SECRET is not valid Unicode")
        }
    };

    if sourced.is_some() && environment.is_some() {
        bail!("provide the client secret through only one non-argv source");
    }
    let secret = sourced.or(environment);
    if existing_version.is_some() && secret.is_some() {
        bail!("an existing client-secret version conflicts with a new client secret");
    }
    if secret.as_deref().is_some_and(str::is_empty) {
        bail!("Teams client secret must not be empty");
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_PILE: &str = "/tmp/never-opened-teams-cli-test.pile";
    const TEST_ID: &str = "01010101010101010101010101010101";
    #[test]
    fn credential_surface_uses_configured_secrets_and_rejects_legacy_selectors() {
        assert!(Cli::try_parse_from([
            "teams",
            "--pile",
            TEST_PILE,
            "login",
            "--tenant",
            "tenant.example",
            "--client-id",
            "client",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "teams",
            "--pile",
            TEST_PILE,
            "login",
            "--tenant",
            "tenant.example",
            "--client-id",
            "client",
            "--vault",
            TEST_ID,
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "teams",
            "--pile",
            TEST_PILE,
            "--secrets-identity",
            "legacy",
            "auth",
            "status",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "teams",
            "--pile",
            TEST_PILE,
            "login",
            "--tenant",
            "tenant.example",
            "--client-id",
            "client",
            "--vault",
            TEST_ID,
            "--secret-scope",
            "legacy",
        ])
        .is_err());
    }
}
