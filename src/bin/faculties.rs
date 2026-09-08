//! Local MCP stdio entrypoint. Only natively ported commands are registered.

use anyhow::Result;
use clap::{Parser, Subcommand};
use faculties::mcp::{Faculty, Server};
use faculties::{
    archive, atlas, body, bootstrap, cognition, compass, decide, discord, duplex, files, gauge,
    habits, headspace, hear, imagine, linkedin, mail, memory, message, orient, patience, planner,
    posture, reason, relations, secrets, status, teams, triage, viewer, voice, web, wiki,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, about = "Native Faculties frontends")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the native faculty tools together over local MCP stdio.
    Mcp {
        /// Pile configured by the local launcher, never an MCP tool argument.
        #[arg(long, env = "PILE")]
        pile: PathBuf,
        /// Existing durable signing-key path, configured by the local launcher.
        #[arg(long, env = "TRIBLESPACE_KEY")]
        key: Option<PathBuf>,
        /// Optional bot credential owned by the launcher, never a tool input.
        #[arg(long, env = "DISCORD_TOKEN", hide_env_values = true)]
        discord_token: Option<String>,
        /// Optional LinkedIn DMA bearer credential, owned by the launcher.
        #[arg(long, env = "LINKEDIN_TOKEN", hide_env_values = true)]
        linkedin_token: Option<String>,
        /// Optional existing Duplex session directory, never a tool input.
        #[arg(long, env = "DUPLEX_SESSION")]
        duplex_session: Option<PathBuf>,
        /// Hear model pile; configuring Hear requires both JSON assets below.
        #[arg(long, env = "HEAR_MODEL_PILE", requires_all = ["hear_config_json", "hear_tokenizer_json"])]
        hear_model_pile: Option<PathBuf>,
        #[arg(long, env = "HEAR_MODEL", default_value = hear::DEFAULT_MODEL)]
        hear_model: String,
        /// Local Gemma configuration; never downloaded during discovery.
        #[arg(long, env = "HEAR_CONFIG_JSON", requires = "hear_model_pile")]
        hear_config_json: Option<PathBuf>,
        #[arg(long, env = "HEAR_TOKENIZER_JSON", requires = "hear_model_pile")]
        hear_tokenizer_json: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let Cli { command } = Cli::parse();
    match command {
        Command::Mcp {
            pile,
            key,
            discord_token,
            linkedin_token,
            duplex_session,
            hear_model_pile,
            hear_model,
            hear_config_json,
            hear_tokenizer_json,
        } => {
            let archive = archive::mcp::Archive::new(pile.clone(), key.clone());
            let atlas = atlas::mcp::Atlas::new(pile.clone(), key.clone());
            let body = body::mcp::Body::new(pile.clone(), key.clone());
            let bootstrap = bootstrap::mcp::Bootstrap::new(pile.clone(), key.clone());
            let cognition = cognition::mcp::Cognition::new(pile.clone(), key.clone());
            let compass = compass::mcp::Compass::new(pile.clone(), key.clone());
            let decide = decide::mcp::Decide::new(pile.clone(), key.clone());
            let duplex = duplex::mcp::Duplex::new(duplex_session);
            let files = files::mcp::Files::new(pile.clone(), key.clone());
            let gauge = gauge::mcp::Gauge::new(pile.clone(), key.clone());
            let habits = habits::mcp::Habits::new(pile.clone(), key.clone());
            let headspace = headspace::mcp::Headspace::new(pile.clone(), key.clone());
            let hear = hear::mcp::Hear::new(match (hear_model_pile, hear_config_json, hear_tokenizer_json) {
                (None, None, None) => None,
                (Some(pile), Some(config_json), Some(tokenizer_json)) => Some(hear::ModelConfig {
                    pile, model: hear_model, config_json, tokenizer_json,
                }),
                _ => anyhow::bail!("Hear requires its model pile, configuration JSON, and tokenizer JSON together"),
            });
            let imagine = imagine::mcp::Imagine::new(pile.clone(), key.clone());
            let linkedin = linkedin::mcp::LinkedIn::new(pile.clone(), key.clone());
            let linkedin = match linkedin_token {
                Some(token) => linkedin.with_token(token),
                None => linkedin,
            };
            let mail = mail::mcp::Mail::new(pile.clone(), key.clone());
            let memory = memory::mcp::Memory::new(pile.clone(), key.clone());
            let message = message::mcp::Message::new(pile.clone(), key.clone());
            let patience = patience::mcp::Patience::new(pile.clone(), key.clone());
            let posture = posture::mcp::Posture::new(pile.clone(), key.clone());
            let reason = reason::mcp::Reason::new(pile.clone(), key.clone());
            let relations = relations::mcp::Relations::new(pile.clone(), key.clone());
            let status = status::mcp::Status::new(pile.clone(), key.clone());
            let triage = triage::mcp::Triage::new(pile.clone(), key.clone());
            let planner = planner::mcp::Planner::new(pile.clone(), key.clone());
            let secrets = secrets::mcp::Secrets::new(pile.clone(), key.clone());
            let teams = teams::mcp::Teams::new(pile.clone(), key.clone());
            let orient = orient::mcp::Orient::new(pile.clone(), key.clone());
            let web = web::mcp::Web::new(pile.clone(), key.clone());
            let voice = voice::mcp::Voice::new(pile.clone(), key.clone());
            let discord = discord::mcp::Discord::new(pile.clone(), key.clone());
            let discord = match discord_token {
                Some(token) => discord.with_token(token),
                None => discord,
            };
            let viewer = viewer::mcp::Viewer::new(pile.clone(), key.clone());
            let wiki = wiki::mcp::Wiki::new(pile, key);
            let registrations: &[&dyn Faculty] = &[
                &archive, &atlas, &body, &bootstrap, &cognition, &compass, &decide, &discord,
                &duplex, &files, &gauge, &habits, &headspace, &hear, &imagine, &linkedin, &mail,
                &memory, &message, &orient, &patience, &planner, &posture, &reason, &relations,
                &secrets, &status, &teams, &triage, &viewer, &voice, &web, &wiki,
            ];
            serve_stdio(registrations)
        }
    }
}

/// Take ownership of the process transport before handlers or their children
/// run. Ordinary stdin is EOF and ordinary stdout is diagnostic stderr: neither
/// a stray print nor a /dev/std{in,out} file path may consume/corrupt JSON-RPC.
/// This is stdio hygiene, not a filesystem sandbox against arbitrary fd access.
#[cfg(unix)]
fn serve_stdio(registrations: &[&dyn Faculty]) -> Result<()> {
    use std::fs::File;
    use std::io::{BufReader, Write};
    use std::os::fd::{AsFd, AsRawFd};

    use anyhow::Context;

    // OwnedFd clones are close-on-exec; subprocesses must not inherit the
    // private protocol descriptors and keep a disconnected transport alive.
    let input = File::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    let output = File::from(std::io::stdout().as_fd().try_clone_to_owned()?);
    let empty = File::open("/dev/null").context("open empty handler stdin")?;
    std::io::stdout().flush()?;
    for (from, to) in [
        (empty.as_raw_fd(), libc::STDIN_FILENO),
        (libc::STDERR_FILENO, libc::STDOUT_FILENO),
    ] {
        // SAFETY: called once from main before any handler/runtime is started.
        // The source descriptors stay open through both calls; dup2 changes
        // only the process's standard streams, not our owned transport clones.
        if unsafe { libc::dup2(from, to) } == -1 {
            return Err(std::io::Error::last_os_error()).context("detach handler stdio");
        }
    }
    Server::new(registrations)?.serve(BufReader::new(input), output)
}

#[cfg(not(unix))]
fn serve_stdio(registrations: &[&dyn Faculty]) -> Result<()> {
    Server::new(registrations)?.serve(std::io::stdin().lock(), std::io::stdout().lock())
}
