//! `egress` — the broker: the one process on the outside of the sandbox.
//!
//! # Who runs this
//!
//! Not the mind. A resident mind's shell commands run inside a sandbox with no
//! internet; it calls `web request` and `web result`, which open no socket and
//! read no vault. This binary is the other side: it holds the network route
//! and the credentials, polls the Egress ledger for requests nobody has
//! answered, performs them, and writes the answer back.
//!
//! It is deliberately a **separate process from whatever enforces the
//! sandbox**. The jailer owns the decision and the lifecycle: it decides
//! whether a given tenant may reach outside at all, and supervises this
//! process with that tenant's pile, that tenant's credentials and that
//! tenant's policy flags. So there is still one service to start, and there is
//! still exactly one policy point — but the component whose only job is
//! containment never grows a pile snapshot, an HTTP client, or an API key, which
//! is the wrong direction for the attack surface of a jailer.
//!
//! # Faculty-generic
//!
//! The loop knows nothing about URLs. A request names its target faculty by
//! that faculty's collection scope and an operation from that faculty's
//! vocabulary; the broker dispatches to a registered handler. Web is the
//! first handler and today the only one. Adding `mail`, `linkedin` or
//! `discord` means writing a handler and registering it here — no change to
//! the ledger schema, and no second daemon to start.
//!
//! # Everything it does leaves a fact
//!
//! There is no path through a sweep that consumes a request without recording
//! an outcome. Success writes the faculty-native observation and a fulfilment
//! naming it. Every refusal — a URL that is not http(s), a host off the allow
//! list, no credential for the requested provider, a provider error, a rate
//! limit, a faculty this broker does not serve — writes a denial carrying its
//! category and reason. A silently dropped request would be indistinguishable
//! from a slow one, and an unrecorded denial would destroy the auditability
//! the whole design exists for.
//!
//! Denials are terminal: a request that already has any response is never
//! re-served. A mind that wants another attempt files another request, and
//! both attempts stay on the record.

use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::clock;
use faculties::egress::{self, Broker, Sweep};
use faculties::schemas::egress as egress_schema;
use faculties::schemas::web::DEFAULT_SCOPE_ID as WEB_SCOPE_ID;
use faculties::web::{self, ApiKeys, LiveBackend, Policy, WebHandler};
use triblespace::prelude::*;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "egress", about = "Broker sandboxed egress requests: perform them, or record why not")]
struct Cli {
    /// Existing pile file. Reads and writes never create it.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable collection signer. Ordinary commands never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve unanswered requests: perform them, or record why not.
    Serve {
        /// One sweep, then exit. Without it, sweep forever.
        #[arg(long)]
        once: bool,
        /// How long to wait between sweeps.
        #[arg(long, default_value = "5s")]
        poll: String,
        /// Only these hosts may be fetched. Repeatable. Empty means any host.
        #[arg(long = "allow-host")]
        allow_hosts: Vec<String>,
        /// These hosts may never be fetched. Repeatable. Always wins.
        #[arg(long = "deny-host")]
        deny_hosts: Vec<String>,
        /// Override the exact Tavily credential referenced by Headspace. Use
        /// @path for file input or @- for stdin.
        #[arg(long)]
        tavily_api_key: Option<String>,
        /// Override the exact Exa credential referenced by Headspace. Use
        /// @path for file input or @- for stdin.
        #[arg(long)]
        exa_api_key: Option<String>,
    },
    /// The audit query: every crossing this pile has ever been asked for.
    List {
        /// Only requests nobody has answered yet.
        #[arg(long)]
        pending: bool,
        /// Only requests for one faculty, by scope id hex. `web` is accepted
        /// as a name.
        #[arg(long)]
        faculty: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command.as_ref() else {
        let mut help = Cli::command();
        help.print_help()?;
        println!();
        return Ok(());
    };

    match command {
        Command::Serve {
            once,
            poll,
            allow_hosts,
            deny_hosts,
            tavily_api_key,
            exa_api_key,
        } => {
            let poll = humantime::parse_duration(poll)
                .with_context(|| format!("parse --poll duration '{poll}'"))?;
            cmd_serve(
                &cli,
                *once,
                poll,
                Policy {
                    allow_hosts: allow_hosts.clone(),
                    deny_hosts: deny_hosts.clone(),
                },
                tavily_api_key.as_deref(),
                exa_api_key.as_deref(),
            )
        }
        Command::List { pending, faculty } => cmd_list(&cli, *pending, faculty.as_deref()),
    }
}

fn cmd_serve(
    cli: &Cli,
    once: bool,
    poll: Duration,
    policy: Policy,
    tavily_api_key: Option<&str>,
    exa_api_key: Option<&str>,
) -> Result<()> {
    // The one place in this design that touches a vault. It happens here,
    // outside the sandbox, in a process the mind cannot invoke.
    let configured = web::open_web_secrets(&cli.pile, cli.key.as_deref()).unwrap_or_default();
    let keys = ApiKeys {
        tavily: tavily_api_key
            .map(|value| load_value_or_file_trimmed(value, "tavily api key"))
            .transpose()?
            .or(configured.tavily),
        exa: exa_api_key
            .map(|value| load_value_or_file_trimmed(value, "exa api key"))
            .transpose()?
            .or(configured.exa),
    };

    let mut broker = Broker::new(&cli.pile, cli.key.as_deref());
    broker.register(Box::new(WebHandler::new(
        LiveBackend::new(keys)?,
        policy.clone(),
    )));

    eprintln!("egress: serving web");
    if !policy.allow_hosts.is_empty() {
        eprintln!("egress: fetch allow-list {}", policy.allow_hosts.join(", "));
    }
    if !policy.deny_hosts.is_empty() {
        eprintln!("egress: fetch deny-list {}", policy.deny_hosts.join(", "));
    }
    if once {
        eprintln!("egress: one sweep");
    } else {
        eprintln!(
            "egress: sweeping every {}",
            humantime::format_duration(poll)
        );
    }

    broker.run(poll, once, clock::point_now, report)
}

fn report(sweep: &Sweep) {
    for id in &sweep.fulfilled {
        println!("fulfilled {id:X}");
    }
    for (id, denial, reason) in &sweep.denied {
        println!("denied {id:X} {}: {reason}", denial.label());
    }
}

fn cmd_list(cli: &Cli, pending_only: bool, faculty: Option<&str>) -> Result<()> {
    let faculty = match faculty.map(str::trim) {
        None => None,
        Some("web") => Some(WEB_SCOPE_ID),
        Some(raw) => Some(
            Id::from_hex(raw).ok_or_else(|| anyhow::anyhow!("invalid faculty scope id '{raw}'"))?,
        ),
    };

    egress::with_view(
        &cli.pile,
        cli.key.as_deref(),
        egress_schema::DEFAULT_SCOPE_ID,
        |facts, snapshot| {
            let answered = egress::answered(facts);
            let records = egress::requests(facts, snapshot, faculty)?;
            let mut shown = 0usize;
            for record in &records {
                let has_answer = answered.contains(&record.id);
                if pending_only && has_answer {
                    continue;
                }
                shown += 1;
                let name = faculties::collection_names::name_for(record.faculty)
                    .unwrap_or("<unknown faculty>");
                println!("{:X}  {name}", record.id);
                println!("  operation: {:X}", record.operation);
                println!("  target: {}", record.target);
                for (key, value) in &record.parameters {
                    println!("  {key}: {value}");
                }
                if let Some(requester) = record.requester {
                    println!("  requester: {requester:X}");
                }
                if has_answer {
                    for response in egress::responses_for(facts, snapshot, record.id)? {
                        match response.status {
                            egress::Status::Fulfilled => println!(
                                "  -> fulfilled, observation {}",
                                response
                                    .observation
                                    .map(|id| format!("{id:X}"))
                                    .unwrap_or_else(|| "<unrecorded>".to_owned())
                            ),
                            egress::Status::Denied => println!(
                                "  -> denied ({}): {}",
                                response
                                    .denial
                                    .map(egress::Denial::label)
                                    .unwrap_or("unrecorded"),
                                response.reason.as_deref().unwrap_or("<none recorded>")
                            ),
                        }
                    }
                } else {
                    println!("  -> pending");
                }
            }
            println!();
            println!("{shown} of {} requests shown", records.len());
            Ok(())
        },
    )
}

fn load_value_or_file_trimmed(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value.trim().to_owned());
        }
        return Ok(fs::read_to_string(path)
            .with_context(|| format!("read {label} from {path}"))?
            .trim()
            .to_owned());
    }
    Ok(raw.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_broker_cli_is_well_formed_and_separate_from_the_requesting_one() {
        let command = Cli::command();
        command.clone().debug_assert();
        // Credentials belong to `serve` alone. They are not global flags,
        // because nothing else in this binary is allowed to want them.
        let global = command
            .get_arguments()
            .map(|argument| argument.get_id().as_str().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(!global.contains("tavily_api_key"));
        assert!(!global.contains("exa_api_key"));
        assert!(command
            .get_subcommands()
            .any(|sub| sub.get_name() == "serve"));
        assert!(command
            .get_subcommands()
            .any(|sub| sub.get_name() == "list"));
    }
}
