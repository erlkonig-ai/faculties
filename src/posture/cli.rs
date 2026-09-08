//! Local paths, Git/hook actions, and @file/stdin conventions live here.
use super::{presentation, ListOptions, Posture};
use crate::out::Out;
use anyhow::{anyhow, bail, Result};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;
use triblespace::prelude::Id;

#[derive(Parser)]
#[command(version = crate::GIT_VERSION, name = "posture",
          about = "Find candidate redaction points in a corpus")]
pub struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Walk a path and record candidate redaction points
    Scan {
        /// File or directory to examine
        path: PathBuf,
        /// Print findings without writing them to the pile
        #[arg(long)]
        dry_run: bool,
    },
    /// Show findings, grouped by modality
    List {
        /// Restrict to one scan (hex id)
        #[arg(long)]
        scan: Option<String>,
        /// Show at most this many examples per group
        #[arg(long, default_value_t = 3)]
        examples: usize,
        /// Include findings classified benign by a resolved Decide decision.
        #[arg(long)]
        all: bool,
        /// Print the content-located finding ids `decide propose --about` names.
        #[arg(long)]
        ids: bool,
    },
    /// What a scan did NOT examine — read this before trusting a quiet result
    Coverage {
        /// Scan id (hex); defaults to the most recent
        scan: Option<String>,
    },
    /// Recent scans
    Scans,
    /// Install git hooks so the audit runs without being remembered
    Hook {
        /// Repository to install into
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Channel to audit against
        #[arg(long, default_value = "github-public")]
        channel: String,
        /// Only audit pushes whose remote URL contains this substring. A
        /// channel describes a DESTINATION, so auditing every remote against
        /// one channel is a category error — it blocked a push to a private
        /// archive using the public vocabulary. Omit to audit every remote,
        /// which is the fail-closed default. Applies to the pre-push gate
        /// only: a commit has no destination yet.
        #[arg(long)]
        remote_match: Option<String>,
        /// Install only the pre-push GATE, which refuses a push.
        #[arg(long)]
        pre_push: bool,
        /// Install only the post-commit SMOKE ALARM, which refuses nothing and
        /// tells you while `git commit --amend` is still cheap.
        #[arg(long)]
        post_commit: bool,
    },
    /// Store a passage of protected material, embedded, for the semantic tier
    Exemplar {
        /// The passage. Use @path for a file or @- for stdin.
        text: String,
        #[arg(long, default_value = "github-public")]
        channel: String,
        /// Mark as ORDINARY material for this channel, to be subtracted rather
        /// than matched. Without a benign set the score measures register
        /// ("thoughtful prose") instead of content.
        #[arg(long)]
        benign: bool,
    },
    /// Scan text files for material that RESEMBLES an exemplar, spelling none
    /// of the protected terms. This is the tier that reaches the case lexical
    /// matching structurally cannot.
    Semantic {
        path: PathBuf,
        #[arg(long, default_value = "github-public")]
        channel: String,
        /// Cosine floor for reporting. Chunks, not documents, are scored.
        #[arg(long, default_value_t = 0.55)]
        threshold: f32,
    },
    /// Audit every git repo under a directory whose remote is reachable by a
    /// channel. Answers "which repositories can leak, and do they" in one pass.
    Sweep {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long, default_value = "github-public")]
        channel: String,
        /// Audit every repo, not only those whose remote `gh` reports PUBLIC.
        #[arg(long)]
        all: bool,
        /// Audit each repo's WHOLE reachable history, not only what is ahead
        /// of its remote. A leak is a leak whether it landed today or a year
        /// ago; the push gate can only block what is still preventable, so
        /// this is where "existing or not" is actually checked.
        #[arg(long)]
        history: bool,
    },
    /// Manage the protected vocabulary, scoped to a channel
    Vocab {
        #[command(subcommand)]
        command: VocabCommand,
    },
    /// Audit a git commit range before it leaves for a channel.
    ///
    /// Checks what a file scan cannot: commit MESSAGES. A message is the one
    /// part of a commit that is not in the commit's own diff, so it gets no
    /// review by the normal mechanism — and it is written in the register you
    /// use for your own notes, moments after the work, to a reader you imagine
    /// as yourself. That combination is how internal vocabulary reaches a public
    /// remote. It also checks added and removed Rust lines for changes to
    /// literal-pinned `unsafe as` attribute declarations, independently of
    /// channel vocabulary.
    Git {
        /// Revision arguments, passed to `git log` as written. Usually a range
        /// (`origin/main..HEAD`), but any git revision selection works — and
        /// for a branch the remote has never seen there IS no two-dot range,
        /// so `HEAD --not --remotes=origin` is the honest expression of "what
        /// this push adds". Named options must come BEFORE these.
        #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
        range: Vec<String>,
        /// Channel whose vocabulary to apply
        #[arg(long, default_value = "github-public")]
        channel: String,
        /// Repository path
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
}

#[derive(Subcommand)]
enum VocabCommand {
    /// Protect a term from a channel
    Add {
        term: String,
        #[arg(long, default_value = "github-public")]
        channel: String,
        /// Why this is protected. Recorded because a wordlist without reasons
        /// rots: nobody dares delete an entry nobody can justify.
        #[arg(long)]
        why: Option<String>,
    },
    /// List protected terms
    List {
        #[arg(long)]
        channel: Option<String>,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("posture", |out| execute(cli, out))
}

fn scan_id(raw: Option<&str>) -> Result<Option<Id>> {
    raw.map(|raw| Id::from_hex(raw.trim()).ok_or_else(|| anyhow!("invalid scan id '{raw}'")))
        .transpose()
}

/// A parsed CLI invocation is only a frontend input. Every operation below is
/// separately callable without Clap, argv, process output, or this enum.
pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<()> {
    let Some(command) = cli.command else {
        return out.text(Cli::command().render_help().to_string());
    };
    let posture = Posture::new(cli.pile, cli.key);
    match command {
        Command::Scan { path, dry_run } => {
            presentation::scan(&posture.scan_path(&path, dry_run)?, out)
        }
        Command::List {
            scan,
            examples,
            all,
            ids,
        } => presentation::list(
            &posture.list(ListOptions {
                scan: scan_id(scan.as_deref())?,
                examples,
                include_resolved: all,
            })?,
            ids,
            out,
        ),
        Command::Coverage { scan } => {
            presentation::coverage(posture.coverage(scan_id(scan.as_deref())?)?.as_ref(), out)
        }
        Command::Scans => presentation::scans(&posture.scans()?, out),
        Command::Vocab { command } => match command {
            VocabCommand::Add { term, channel, why } => {
                presentation::policy(&posture.vocab_add(&term, &channel, why.as_deref())?, out)
            }
            VocabCommand::List { channel } => {
                presentation::vocabulary(&posture.vocab_list(channel.as_deref())?, out)
            }
        },
        Command::Exemplar {
            text,
            channel,
            benign,
        } => {
            #[cfg(feature = "local-embed")]
            let text = crate::text_arg(&text, "exemplar text")?;
            #[cfg(feature = "local-embed")]
            super::validate_exemplar(&text, &channel)?;
            #[cfg(feature = "local-embed")]
            out.line("posture: loading nomic-embed-text (once)…")?;
            presentation::policy(&posture.exemplar(&text, &channel, benign)?, out)
        }
        Command::Semantic {
            path,
            channel,
            threshold,
        } => {
            #[cfg(feature = "local-embed")]
            out.line(
                "posture: semantic scan will load nomic-embed-text after selecting its policy",
            )?;
            presentation::semantic(&posture.semantic_path(&path, &channel, threshold)?, out)
        }
        Command::Git {
            range,
            channel,
            repo,
        } => {
            let report = posture.git(&repo, &range, &channel)?;
            presentation::git(&report, out)?;
            if report.blocked() {
                bail!("Posture audit blocks this range: unresolved findings or missing lexical vocabulary");
            }
            Ok(())
        }
        Command::Sweep {
            root,
            channel,
            all,
            history,
        } => {
            let report = posture.sweep(&root, &channel, all, history)?;
            presentation::sweep(&report, out)?;
            if report.blocked() {
                bail!("Posture sweep blocks: unresolved findings or missing lexical vocabulary");
            }
            Ok(())
        }
        Command::Hook {
            repo,
            channel,
            remote_match,
            pre_push,
            post_commit,
        } => {
            let executable = std::env::current_exe()
                .map_err(|error| anyhow!("locate posture binary: {error}"))?;
            presentation::hooks(
                &posture.install_hooks(
                    &repo,
                    &executable,
                    &channel,
                    remote_match.as_deref(),
                    pre_push,
                    post_commit,
                )?,
                out,
            )
        }
    }
}
