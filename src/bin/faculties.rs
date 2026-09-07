//! Local MCP stdio entrypoint. Only natively ported commands are registered.

use anyhow::Result;
use clap::{Parser, Subcommand};
use faculties::atlas::command;
use faculties::mcp::{Registration, Server};
use faculties::spec::Arguments;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, about = "Native Faculties frontends")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve atlas_list and atlas_show over local MCP stdio.
    Mcp {
        /// Pile configured by the local launcher, never an MCP tool argument.
        #[arg(long, env = "PILE")]
        pile: String,
        /// Existing durable signing-key path, configured by the local launcher.
        #[arg(long, env = "TRIBLESPACE_KEY")]
        key: Option<String>,
    },
}

fn main() -> Result<()> {
    let Cli { command } = Cli::parse();
    match command {
        Command::Mcp { pile, key } => {
            let mut ambient = Arguments::new().with("pile", pile);
            if let Some(key) = key {
                ambient.insert("key", key)?;
            }
            let registrations = [Registration {
                spec: &command::SPEC,
                invoke: command::execute,
                ambient,
            }];
            Server::new(&registrations)?.serve(std::io::stdin().lock(), std::io::stdout().lock())
        }
    }
}
