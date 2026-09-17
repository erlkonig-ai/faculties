//! Shell syntax and local wall-clock parsing for Orient.
use super::{Orient, ShowOptions, WaitOptions, WakeOptions};
use anyhow::{anyhow, bail, Result};
use chrono::{
    DateTime, Duration as ChronoDuration, Local, LocalResult, NaiveDateTime, NaiveTime, TimeZone,
};
use clap::{CommandFactory, Parser, Subcommand};
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

#[path = "callback.rs"]
mod callback;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "orient",
    about = "Orient the agent with local swarm health, recent messages and goals"
)]
pub struct Cli {
    /// Path to the pile file to use
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Contact/routing selector for directed news (Relations label or
    /// 32-char hex ID). Receipt history belongs to the signing zooid's key,
    /// not to this selector.
    #[arg(long, env = "PERSONA")]
    persona: Option<String>,
    /// Zooid identity and durable signing key. Defaults to the pile-adjacent key.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Maximum age of a current local health report, in seconds (reader policy).
    #[arg(
        long,
        global = true,
        env = "TRIBLESPACE_HEALTH_MAX_AGE_SECS",
        default_value_t = crate::schemas::swarm_health::DEFAULT_MAX_AGE.as_secs(),
        value_name = "SECONDS"
    )]
    health_max_age: u64,
    #[command(subcommand)]
    command: Option<Command>,
}

/// The orientation modes, and which is for what (operator, 2026-07-28 — stated
/// after a window inferred it wrong from the fact that `show` is the cheap one):
///
/// - `wake`  — **session start, after a compaction.** The whole self: memory
///   cover + cover-tagged beliefs + goals. Deliberately large; the point is
///   wholeness, not efficiency, so it is read whole.
/// - `show`  — a general overview mid-session, for "what's up right now".
///   **Neither memories nor wiki entries belong here** — it is a situation
///   snapshot, not a self. Keeping it cheap is what makes it runnable often.
/// - `wait`  — blocking. Things you might want to deal with, so it wakes you
///   out of idling. Terse by design: the reasons plus what changed.
/// - `poll`  — the same content as `wait`, returned immediately. For per-turn
///   hooks that cannot block.
/// - `daemon` — one persistent observer, delivering complete reports through
///   an executable callback instead of stdout or per-turn hooks.
///
/// The distinction that is easy to get backwards: `wake` and `show` are not
/// long and short versions of one thing. `wake` answers "who am I", `show`
/// answers "what is happening" — which is why the belief set lives in one and
/// is out of place in the other however cheap it would be to add.
///
/// These modes eagerly maintain their inputs when the existing signer has
/// derived WRITE authority, then query one immutable observation. Other
/// readers attach the resident targets without acquiring new authority.
/// Background maintenance remains useful, but is not the freshness boundary
/// for an authorized foreground read. Accepted output publishes Presented
/// receipt COMMITs; `--peek` performs upkeep but never records presentation.
#[derive(Subcommand)]
enum Command {
    /// Mid-session overview, with resident local swarm health first (no memories, no wiki)
    Show {
        /// Max local messages to show
        #[arg(long, default_value_t = 10)]
        message_limit: usize,
        /// Max doing goals to show
        #[arg(long, default_value_t = 5)]
        doing_limit: usize,
        /// Max todo goals to show
        #[arg(long, default_value_t = 5)]
        todo_limit: usize,
    },
    /// Session start after a compaction: the whole self — memory cover +
    /// cover-tagged beliefs + goals
    Wake {
        /// CHARACTER budget for the memory cover — the wake ritual is for
        /// wholeness, so the default is generous (matches the SessionStart hook);
        /// on a pile whose coarsest cover exceeds it, this errors with repair
        /// instructions rather than dropping memories.
        #[arg(long, default_value_t = 800_000)]
        chars: usize,
        /// Max doing goals to show
        #[arg(long, default_value_t = 5)]
        doing_limit: usize,
        /// Max todo goals to show
        #[arg(long, default_value_t = 5)]
        todo_limit: usize,
    },
    /// Wait for directed news, an actionable local health alert, or a stale report
    Wait {
        #[command(subcommand)]
        target: Option<WaitTarget>,
        /// Poll interval for the append-only pile growth gate
        #[arg(long, default_value_t = 1000)]
        poll_ms: u64,
    },
    /// Keep the pile open and deliver each news report to one executable's stdin.
    /// Callback success records presentation, not completion of the reported work.
    Daemon {
        /// Delivery executable, invoked directly without a shell
        #[arg(long, value_name = "EXECUTABLE")]
        callback: PathBuf,
        /// Literal argument to the callback (repeat; use = for arguments starting with -)
        #[arg(long = "callback-arg", value_name = "ARG")]
        callback_args: Vec<OsString>,
        /// Maximum time for each callback, including writing its input
        #[arg(long, default_value = "30s", value_parser = parse_positive_duration)]
        callback_timeout: Duration,
        /// Stop observing after this duration (otherwise run until interrupted)
        #[arg(long, value_parser = parse_positive_duration)]
        run_for: Option<Duration>,
        /// Poll interval for the append-only pile growth gate
        #[arg(long, default_value_t = 1000)]
        poll_ms: u64,
    },
    /// Non-blocking news check for per-turn hooks: if there are unpresented
    /// directed events, print the same terse report `wait` prints (News:
    /// reasons + new message bodies), then record those exact events as
    /// presented; otherwise print nothing and exit 0
    Poll {
        /// Print news WITHOUT recording it as presented. For harnesses that
        /// fire hooks identically
        /// for root and subagents (e.g. Codex, openai/codex#16226): a
        /// peeking hook can never consume the root watcher's receipt
        /// history from a worker turn. Peek may re-print the same news on
        /// consecutive turns until the watcher fires or messages are
        /// acked — lossless by design; acks are the real handled-marker.
        #[arg(long)]
        peek: bool,
    },
    /// Mark every attention event currently visible to this routing selector
    /// in the signing zooid's receipt history. This is an explicit subscription
    /// baseline for operators who do not want existing backlog reported.
    Baseline,
    /// Import resident legacy receipt facts into this key's private history.
    /// Keeps existing IDs and timestamps; does not baseline unseen events or
    /// maintain either projection.
    ImportReceipts {
        /// Exact legacy routing selector (Relations label or 32-char hex ID).
        /// Required explicitly here; neither PERSONA nor the top-level
        /// --persona supplies the historical ownership choice.
        #[arg(long, value_name = "LEGACY_SELECTOR")]
        persona: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub(super) enum WaitTarget {
    /// Wait for a duration (e.g. 30s, 15m, 9h)
    For {
        /// Duration to wait
        duration: String,
    },
    /// Wait until a specific time (e.g. 09:00, 9am, or 2026-02-13T09:00:00+01:00)
    Until {
        /// Time to wake up
        when: String,
    },
}

fn parse_positive_duration(raw: &str) -> Result<Duration, String> {
    let value = humantime::parse_duration(raw).map_err(|error| error.to_string())?;
    if value.is_zero() {
        return Err("duration must be greater than zero".into());
    }
    Ok(value)
}

pub(super) fn parse_wait_target(target: Option<&WaitTarget>) -> Result<Option<Duration>> {
    let Some(target) = target else {
        return Ok(None);
    };
    match target {
        WaitTarget::For { duration } => {
            let duration = duration.trim();
            if duration.is_empty() {
                bail!("wait for requires a duration (e.g. 30s, 15m, 9h)");
            }
            let parsed = humantime::parse_duration(duration)
                .map_err(|e| anyhow!("invalid wait duration '{duration}': {e}"))?;
            if parsed.is_zero() {
                bail!("wait duration must be greater than zero");
            }
            Ok(Some(parsed))
        }
        WaitTarget::Until { when } => {
            let (parsed, _) = parse_until_spec(when)?;
            Ok(Some(parsed))
        }
    }
}

fn parse_until_spec(raw: &str) -> Result<(Duration, DateTime<Local>)> {
    let when = raw.trim();
    if when.is_empty() {
        bail!("wait until requires a time (e.g. 09:00, 9am, 2026-02-13T09:00:00+01:00)");
    }

    if let Ok(system_time) = humantime::parse_rfc3339_weak(when) {
        let target_local = DateTime::<Local>::from(system_time);
        let timeout = system_time
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        return Ok((timeout, target_local));
    }

    if let Some(local_datetime) = parse_local_datetime_spec(when)? {
        let timeout = chrono_duration_to_std(local_datetime.signed_duration_since(Local::now()));
        return Ok((timeout, local_datetime));
    }

    if let Some(local_time) = parse_local_time_spec(when) {
        let now = Local::now();
        let mut target_naive = now.date_naive().and_time(local_time);
        let mut target_local = localize_naive_datetime(target_naive)?;
        if target_local <= now {
            target_naive += ChronoDuration::days(1);
            target_local = localize_naive_datetime(target_naive)?;
        }
        let timeout = chrono_duration_to_std(target_local.signed_duration_since(now));
        return Ok((timeout, target_local));
    }

    bail!(
        "invalid wait until value '{when}'. Use HH:MM, 9am, local datetime, or RFC3339 timestamp"
    );
}

fn parse_local_datetime_spec(raw: &str) -> Result<Option<DateTime<Local>>> {
    for fmt in [
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(raw, fmt) {
            return Ok(Some(localize_naive_datetime(naive)?));
        }
    }
    Ok(None)
}

fn parse_local_time_spec(raw: &str) -> Option<NaiveTime> {
    for fmt in [
        "%H:%M", "%H:%M:%S", "%I:%M %P", "%I:%M%P", "%I %P", "%I%P", "%I:%M %p", "%I:%M%p",
        "%I %p", "%I%p",
    ] {
        if let Ok(time) = NaiveTime::parse_from_str(raw, fmt) {
            return Some(time);
        }
    }
    None
}

fn localize_naive_datetime(naive: NaiveDateTime) -> Result<DateTime<Local>> {
    match Local.from_local_datetime(&naive) {
        LocalResult::Single(dt) => Ok(dt),
        LocalResult::Ambiguous(a, b) => Ok(if a <= b { a } else { b }),
        LocalResult::None => bail!(
            "local time '{}' does not exist (likely DST transition)",
            naive.format("%Y-%m-%d %H:%M:%S")
        ),
    }
}

fn chrono_duration_to_std(duration: ChronoDuration) -> Duration {
    if duration <= ChronoDuration::zero() {
        Duration::ZERO
    } else {
        duration.to_std().unwrap_or(Duration::MAX)
    }
}

pub fn execute(cli: Cli, out: &mut crate::out::Out<'_>) -> Result<()> {
    let Some(command) = cli.command else {
        out.line(Cli::command().render_help().to_string())?;
        return Ok(());
    };
    let orient =
        Orient::new(cli.pile, cli.key).with_health_max_age(Duration::from_secs(cli.health_max_age));
    match command {
        Command::Show {
            message_limit,
            doing_limit,
            todo_limit,
        } => orient.show(
            cli.persona.as_deref(),
            &ShowOptions {
                message_limit,
                doing_limit,
                todo_limit,
                evaluate_habits: true,
            },
            out,
        ),
        Command::Wake {
            chars,
            doing_limit,
            todo_limit,
        } => orient.wake(
            cli.persona.as_deref(),
            &WakeOptions {
                chars,
                doing_limit,
                todo_limit,
            },
            out,
        ),
        Command::Poll { peek } => orient.poll(
            cli.persona.as_deref().ok_or_else(|| {
                anyhow!("poll requires a persona (pass --persona <label-or-hex> or set $PERSONA)")
            })?,
            peek,
            out,
        ),
        Command::Baseline => {
            let persona = cli.persona.as_deref().ok_or_else(|| {
                anyhow!(
                    "baseline requires a persona (pass --persona <label-or-hex> or set $PERSONA)"
                )
            })?;
            let receipt = orient.baseline(persona)?;
            out.line(format!(
                "Baselined {} current attention event(s) for {persona}.",
                receipt.events
            ))
        }
        Command::ImportReceipts { persona } => {
            let events = orient.import_receipts(&persona)?;
            out.line(format!(
                "Imported {events} distinct resident legacy event(s) for {persona} into this key's receipt source. Projection maintenance remains separate."
            ))
        }
        Command::Wait { target, poll_ms } => orient.wait(
            cli.persona.as_deref().ok_or_else(|| {
                anyhow!("wait requires a persona (pass --persona <label-or-hex> or set $PERSONA)")
            })?,
            &WaitOptions {
                timeout: parse_wait_target(target.as_ref())?,
                poll_interval: Duration::from_millis(poll_ms.max(1)),
            },
            out,
        ),
        Command::Daemon {
            callback,
            callback_args,
            callback_timeout,
            run_for,
            poll_ms,
        } => {
            let persona = cli.persona.as_deref().ok_or_else(|| {
                anyhow!("daemon requires a persona (pass --persona <label-or-hex> or set $PERSONA)")
            })?;
            let mut deliver = |part| match part {
                crate::out::Part::Text { text } if text.starts_with("note: ") => {
                    // Maintenance diagnostics are not attention reports and
                    // must not become another queued user message.
                    use std::io::Write;
                    std::io::stderr().lock().write_all(text.as_bytes())?;
                    Ok(())
                }
                crate::out::Part::Text { text } => {
                    callback::deliver(&callback, &callback_args, callback_timeout, &text)
                }
                _ => bail!("Orient daemon callback requires a complete text report"),
            };
            orient.daemon(
                persona,
                &WaitOptions {
                    timeout: run_for,
                    poll_interval: Duration::from_millis(poll_ms.max(1)),
                },
                &mut crate::out::Out::new(&mut deliver),
            )
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
    crate::cli::with_output("orient", |out| execute(cli, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_requires_a_callback() {
        assert!(Cli::try_parse_from(["orient", "--pile", "unused.pile", "daemon"]).is_err());
    }

    #[test]
    fn daemon_preserves_literal_arguments_and_parses_bounds() {
        let cli = Cli::try_parse_from([
            "orient",
            "--pile",
            "unused.pile",
            "--persona",
            "agent",
            "daemon",
            "--callback",
            "/path with spaces/deliver",
            "--callback-arg=--thread",
            "--callback-arg",
            "literal $(not-a-command)",
            "--callback-timeout",
            "2s",
            "--run-for",
            "1m",
            "--poll-ms",
            "25",
        ])
        .unwrap();
        let Some(Command::Daemon {
            callback,
            callback_args,
            callback_timeout,
            run_for,
            poll_ms,
        }) = cli.command
        else {
            panic!("expected daemon command");
        };
        assert_eq!(callback, PathBuf::from("/path with spaces/deliver"));
        assert_eq!(
            callback_args,
            [
                OsString::from("--thread"),
                OsString::from("literal $(not-a-command)")
            ]
        );
        assert_eq!(callback_timeout, Duration::from_secs(2));
        assert_eq!(run_for, Some(Duration::from_secs(60)));
        assert_eq!(poll_ms, 25);
    }

    #[test]
    fn daemon_rejects_zero_callback_or_run_duration() {
        for option in ["--callback-timeout", "--run-for"] {
            assert!(Cli::try_parse_from([
                "orient",
                "--pile",
                "unused.pile",
                "daemon",
                "--callback",
                "/bin/true",
                option,
                "0s",
            ])
            .is_err());
        }
    }

    #[test]
    fn receipt_import_requires_its_own_explicit_persona() {
        let missing = Cli::try_parse_from([
            "orient",
            "--pile",
            "unused.pile",
            "--persona",
            "ordinary-routing-selector",
            "import-receipts",
        ])
        .err()
        .expect("top-level routing selection cannot choose a legacy import");
        assert_eq!(
            missing.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn receipt_import_accepts_the_explicit_legacy_selector() {
        let cli = Cli::try_parse_from([
            "orient",
            "--pile",
            "unused.pile",
            "import-receipts",
            "--persona",
            "legacy-alias",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::ImportReceipts { persona }) if persona == "legacy-alias"
        ));
    }
}
