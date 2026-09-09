//! Shell syntax and local wall-clock parsing for Orient.
use super::{Orient, ShowOptions, WaitOptions, WakeOptions};
use anyhow::{anyhow, bail, Result};
use chrono::{
    DateTime, Duration as ChronoDuration, Local, LocalResult, NaiveDateTime, NaiveTime, TimeZone,
};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

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
    /// Persona identity for the message inbox (relations label or
    /// 32-char hex id). Per-process so multiple agents can share one pile
    /// under distinct identities.
    #[arg(long, env = "PERSONA")]
    persona: Option<String>,
    /// Durable collection signing key. Defaults to the pile-adjacent key.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

/// The four orientation modes, and which is for what (operator, 2026-07-28 — stated
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
///
/// The distinction that is easy to get backwards: `wake` and `show` are not
/// long and short versions of one thing. `wake` answers "who am I", `show`
/// answers "what is happening" — which is why the belief set lives in one and
/// is out of place in the other however cheap it would be to add.
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
    /// Wait for directed news or a local health alert/recovery/report expiry
    Wait {
        #[command(subcommand)]
        target: Option<WaitTarget>,
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
        /// peeking hook can never consume the root persona's attention
        /// events from a worker turn. Peek may re-print the same news on
        /// consecutive turns until the watcher fires or messages are
        /// acked — lossless by design; acks are the real handled-marker.
        #[arg(long)]
        peek: bool,
    },
    /// Mark every attention event currently visible to this persona as
    /// presented. This is an explicit subscription baseline for cutovers or
    /// operators who do not want existing backlog reported on first use.
    Baseline,
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
    let orient = Orient::new(cli.pile, cli.key);
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
