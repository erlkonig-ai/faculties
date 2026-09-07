//! Local MCP stdio entrypoint. Only natively ported commands are registered.

use anyhow::Result;
use clap::{Parser, Subcommand};
use faculties::mcp::{Faculty, Server};
use faculties::{atlas, files};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, about = "Native Faculties frontends")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve native Atlas and Files commands over local MCP stdio.
    Mcp {
        /// Pile configured by the local launcher, never an MCP tool argument.
        #[arg(long, env = "PILE")]
        pile: PathBuf,
        /// Existing durable signing-key path, configured by the local launcher.
        #[arg(long, env = "TRIBLESPACE_KEY")]
        key: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let Cli { command } = Cli::parse();
    match command {
        Command::Mcp { pile, key } => {
            let atlas = atlas::mcp::Atlas::new(pile.clone(), key.clone());
            let files = files::mcp::Files::new(pile, key);
            let registrations: [&dyn Faculty; 2] = [&atlas, &files];
            serve_stdio(&registrations)
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
