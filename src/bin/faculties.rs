//! Native aggregate MCP entrypoint with explicit stdio or HTTP transport.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use faculties::hear;
use faculties::mcp::catalog::{Catalog, Config as CatalogConfig};
use faculties::mcp::http;
use faculties::mcp::{Faculty, Server};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, about = "Native Faculties frontends")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve native faculty tools over stdio, or opt into authenticated HTTP.
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
        /// Bind a Streamable HTTP listener instead of using stdio.
        #[arg(long, value_name = "ADDR", requires = "http_token_file")]
        http_listen: Option<SocketAddr>,
        /// Read the HTTP bearer credential from this launcher-owned file.
        #[arg(
            long,
            env = "FACULTIES_MCP_TOKEN_FILE",
            hide_env_values = true,
            value_name = "PATH",
            requires = "http_listen"
        )]
        http_token_file: Option<PathBuf>,
        /// Allow this exact browser origin; repeat for additional origins.
        #[arg(long, value_name = "URL", requires = "http_listen")]
        http_origin: Vec<String>,
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
            http_listen,
            http_token_file,
            http_origin,
        } => {
            let hear = match (hear_model_pile, hear_config_json, hear_tokenizer_json) {
                (None, None, None) => None,
                (Some(pile), Some(config_json), Some(tokenizer_json)) => Some(hear::ModelConfig {
                    pile,
                    model: hear_model,
                    config_json,
                    tokenizer_json,
                }),
                _ => anyhow::bail!(
                    "Hear requires its model pile, configuration JSON, and tokenizer JSON together"
                ),
            };
            let catalog = Catalog::new(CatalogConfig {
                pile,
                key,
                discord_token,
                linkedin_token,
                duplex_session,
                hear,
            });
            let registrations = catalog.registrations();
            let result = match http_listen {
                Some(bind) => {
                    let token_file = http_token_file
                        .as_deref()
                        .context("HTTP requires --http-token-file")?;
                    let token = http::BearerToken::from_file(token_file)?;
                    let mut config = http::Config::new(bind, token);
                    config.allowed_origins = http_origin;
                    detach_handler_stdio()?;
                    http::serve(&registrations, config)
                }
                None => serve_stdio(&registrations),
            };
            catalog.finish(result)
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
    use std::io::BufReader;
    use std::os::fd::AsFd;

    // OwnedFd clones are close-on-exec; subprocesses must not inherit the
    // private protocol descriptors and keep a disconnected transport alive.
    let input = File::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    let output = File::from(std::io::stdout().as_fd().try_clone_to_owned()?);
    detach_handler_stdio()?;
    Server::new(registrations)?.serve(BufReader::new(input), output)
}

/// Both executable transports isolate handlers from launcher input before
/// starting threads. The reusable library API does not change process fds.
#[cfg(unix)]
fn detach_handler_stdio() -> Result<()> {
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::AsRawFd;

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
    Ok(())
}

#[cfg(not(unix))]
fn detach_handler_stdio() -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn serve_stdio(registrations: &[&dyn Faculty]) -> Result<()> {
    Server::new(registrations)?.serve(std::io::stdin().lock(), std::io::stdout().lock())
}
