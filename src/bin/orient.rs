use anyhow::{anyhow, bail, Result};
use chrono::{
    DateTime, Duration as ChronoDuration, Local, LocalResult, NaiveDateTime, NaiveTime, TimeZone,
};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::memory_cover::{render_cover, CoverOpts};
use faculties::schemas::compass::latest_status_event;
use faculties::schemas::memory::DEFAULT_MEMORY_BRANCH;
use faculties::schemas::wiki::{cover_fragments, WIKI_BRANCH_NAME};
use faculties::schemas::mail::{mail, KIND_MESSAGE as KIND_MAIL_MESSAGE, KIND_SPAM};
use faculties::schemas::message::is_inbox_message;
use faculties::schemas::orient::{
    board, local, orient_state, KIND_GOAL_ID, KIND_MESSAGE_ID, KIND_NOTE_ID,
    KIND_ORIENT_CHECKPOINT_ID, KIND_READ_ID, KIND_STATUS_ID,
};
use faculties::schemas::relations::{groups_for_member, relations as rel_attrs};
use faculties::schemas::status::{KIND_STATUS_UPDATE, status as status_attrs};
use hifitime::Epoch;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::{find, pattern};
use triblespace::prelude::*;

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
type CommitHandle = Inline<inlineencodings::Handle<SimpleArchive>>;
type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval.try_from_inline().unwrap();
    lower
}

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "orient",
    about = "Orient the agent with recent messages and goals"
)]
struct Cli {
    /// Path to the pile file to use
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Persona identity for the message inbox (relations label or
    /// 32-char hex id). Per-process so multiple agents can share one pile
    /// under distinct identities.
    #[arg(long, env = "PERSONA")]
    persona: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show an orientation snapshot
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
    /// Assemble the full wake bundle: memory cover + cover-tagged beliefs + goals
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
    /// Wait until relevant branches change, then show orientation
    Wait {
        #[command(subcommand)]
        target: Option<WaitTarget>,
        /// Max local messages to show
        #[arg(long, default_value_t = 10)]
        message_limit: usize,
        /// Max doing goals to show
        #[arg(long, default_value_t = 5)]
        doing_limit: usize,
        /// Max todo goals to show
        #[arg(long, default_value_t = 5)]
        todo_limit: usize,
        /// Poll interval while waiting for branch changes
        #[arg(long, default_value_t = 1000)]
        poll_ms: u64,
    },
    /// Non-blocking news check for per-turn hooks: if there is directed
    /// news since the persona's checkpoint, print the same terse report
    /// `wait` prints (News: reasons + new message bodies) and advance the
    /// checkpoint; otherwise print nothing and exit 0
    Poll {
        /// Print news WITHOUT advancing the checkpoint (and without
        /// bootstrapping one). For harnesses that fire hooks identically
        /// for root and subagents (e.g. Codex, openai/codex#16226): a
        /// peeking hook can never steal the root persona's checkpoint
        /// from a worker turn. Peek may re-print the same news on
        /// consecutive turns until the watcher fires or messages are
        /// acked — lossless by design; acks are the real handled-marker.
        #[arg(long)]
        peek: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum WaitTarget {
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

#[derive(Debug, Clone)]
struct MessageRow {
    id: Id,
    from: Id,
    to: Id,
    created_at: i128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchedHeads {
    local: Option<CommitHandle>,
    compass: Option<CommitHandle>,
    relations: Option<CommitHandle>,
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> Inline<inlineencodings::NsTAIInterval> {
    (epoch, epoch).try_to_inline().unwrap()
}

fn format_age(now_key: i128, past_key: i128) -> String {
    let delta_ns = now_key.saturating_sub(past_key);
    let delta_s = (delta_ns / 1_000_000_000).max(0) as i64;
    if delta_s < 60 {
        format!("{delta_s}s")
    } else if delta_s < 60 * 60 {
        format!("{}m", delta_s / 60)
    } else if delta_s < 60 * 60 * 24 {
        format!("{}h", delta_s / (60 * 60))
    } else {
        format!("{}d", delta_s / (60 * 60 * 24))
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn person_label(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    person_id: Id,
) -> String {
    find!(h: TextHandle, pattern!(space, [{ person_id @ metadata::name: ?h }]))
        .next()
        .and_then(|h| read_text(ws, h).ok())
        .unwrap_or_else(|| fmt_id(person_id))
}

fn read_text(ws: &mut Workspace<Pile>, handle: TextHandle) -> Result<String> {
    let view: View<str> = ws
        .get::<View<str>, blobencodings::LongString>(handle)
        .map_err(|e| anyhow!("load longstring: {e:?}"))?;
    Ok(view.to_string())
}

/// Load messages without resolving body blobs — sorted newest first.
fn load_message_ids(space: &TribleSet) -> Vec<MessageRow> {
    let mut messages: Vec<MessageRow> = find!(
        (message_id: Id, from: Id, to: Id, created_at: Inline<inlineencodings::NsTAIInterval>),
        pattern!(space, [{
            ?message_id @
            metadata::tag: &KIND_MESSAGE_ID,
            local::from: ?from,
            local::to: ?to,
            metadata::created_at: ?created_at,
        }])
    )
    .map(|(id, from, to, created_at)| MessageRow {
        id,
        from,
        to,
        created_at: interval_key(created_at),
    })
    .collect();
    messages.sort_by_key(|msg| std::cmp::Reverse(msg.created_at));
    messages
}

fn resolve_message_body(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    msg_id: Id,
) -> String {
    find!(h: TextHandle, pattern!(space, [{ msg_id @ local::body: ?h }]))
        .next()
        .and_then(|h| read_text(ws, h).ok())
        .unwrap_or_default()
}

fn load_reads(space: &TribleSet) -> HashMap<(Id, Id), i128> {
    let mut reads = HashMap::new();
    for (_read_id, message_id, reader_id, read_at) in find!(
        (
            read_id: Id,
            message_id: Id,
            reader_id: Id,
            read_at: Inline<inlineencodings::NsTAIInterval>
        ),
        pattern!(&space, [{
            ?read_id @
            metadata::tag: &KIND_READ_ID,
            local::about_message: ?message_id,
            local::reader: ?reader_id,
            local::read_at: ?read_at,
        }])
    ) {
        let key = (message_id, reader_id);
        let ts = interval_key(read_at);
        reads
            .entry(key)
            .and_modify(|existing| {
                if ts > *existing {
                    *existing = ts;
                }
            })
            .or_insert(ts);
    }
    reads
}

/// Resolve the mail-faculty self identity: the relations entry
/// whose `email` attribute matches `$MAIL_USER` (case-folded).
/// Returns None if `MAIL_USER` isn't set or if no relations entry
/// has been auto-registered for it yet.
fn find_mail_self(relations_space: &TribleSet) -> Option<(String, Id)> {
    let user = std::env::var("MAIL_USER").ok()?;
    let needle = user.trim().to_ascii_lowercase();
    let id = find!(
        (id: Id, e: String),
        pattern!(relations_space, [{
            ?id @ rel_attrs::email: ?e,
        }])
    )
    .find_map(|(id, e)| {
        if e.to_ascii_lowercase() == needle {
            Some(id)
        } else {
            None
        }
    })?;
    Some((user, id))
}

/// Render the "Mail (unread inbox for ...)" section. Treats absence
/// of the `mail` branch or `MAIL_USER` env var as a graceful "skip"
/// rather than an error — orient is a snapshot, not a config tool.
fn render_unread_mail(
    repo: &mut Repository<Pile>,
    relations_branch_id: Id,
    message_limit: usize,
    now_key: i128,
) -> Result<()> {
    // Need a relations workspace to resolve the self identity.
    let mut rws = repo
        .pull(relations_branch_id)
        .map_err(|e| anyhow!("pull relations: {e:?}"))?;
    let rel_space = rws
        .checkout(..)
        .map_err(|e| anyhow!("checkout relations: {e:?}"))?;

    let Some((user, self_id)) = find_mail_self(&rel_space) else {
        // Either MAIL_USER isn't set or the auto-registration hasn't
        // happened yet (no fetch/send has run). Either way, render
        // a brief note rather than crashing.
        println!("Mail:");
        match std::env::var("MAIL_USER") {
            Ok(u) => println!("- No relations entry for {u} yet (run `mail fetch` or `mail send` once)"),
            Err(_) => println!("- MAIL_USER env var not set; skipping"),
        }
        return Ok(());
    };

    let mail_branch_id = match repo.ensure_branch("mail", None) {
        Ok(id) => id,
        Err(_) => {
            println!("Mail (unread for {user}):");
            println!("- mail branch not present yet");
            return Ok(());
        }
    };
    let mut mws = repo
        .pull(mail_branch_id)
        .map_err(|e| anyhow!("pull mail: {e:?}"))?;
    let mail_space = mws.checkout(..).map_err(|e| anyhow!("checkout mail: {e:?}"))?;

    let mut rows: Vec<(i128, Id, Option<Id>, String)> = find!(
        (id: Id, from: Id, sent_at: IntervalValue, subject_h: TextHandle),
        pattern!(&mail_space, [{
            ?id @
            metadata::tag: KIND_MAIL_MESSAGE,
            mail::from: ?from,
            mail::sent_at: ?sent_at,
            mail::subject: ?subject_h,
        }])
    )
    .filter(|&(_, from, _, _)| from != self_id)
    .filter(|&(id, _, _, _)| !exists!(pattern!(&mail_space, [{ id @ metadata::tag: &KIND_SPAM }])))
    .filter(|&(id, _, _, _)| !exists!(pattern!(&mail_space, [{
        _?r @
        metadata::tag: KIND_READ_ID,
        local::about_message: id,
        local::reader: self_id,
    }])))
    .map(|(id, from, sent_at, subject_h)| {
        let subject = read_text(&mut mws, subject_h).unwrap_or_default();
        (interval_key(sent_at), id, Some(from), subject)
    })
    .collect();
    // Newest first.
    rows.sort_by(|a, b| b.0.cmp(&a.0));

    println!("Mail (unread for {user}):");
    if rows.is_empty() {
        println!("- None");
    } else {
        for (sent_at_key, id, from_id, subject) in rows.into_iter().take(message_limit) {
            let from_email = from_id
                .and_then(|rid| {
                    find!(
                        e: String,
                        pattern!(&rel_space, [{ rid @ rel_attrs::email: ?e }])
                    )
                    .next()
                })
                .unwrap_or_else(|| "?".into());
            let age = format_age(now_key, sent_at_key);
            println!("- [{}] {} {} — {}", fmt_id(id), age, from_email, subject);
        }
    }
    Ok(())
}

fn task_title(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    task_id: Id,
) -> String {
    find!(h: TextHandle, pattern!(space, [{ task_id @ board::title: ?h }]))
        .next()
        .and_then(|h| read_text(ws, h).ok())
        .unwrap_or_default()
}

fn entity_tags(space: &TribleSet, entity_id: Id) -> Vec<String> {
    let mut tags: Vec<String> =
        find!(tag: String, pattern!(space, [{ entity_id @ board::tag: ?tag }])).collect();
    tags.sort();
    tags.dedup();
    tags
}

fn visible_notes(
    space: &TribleSet,
    persona_id: Id,
    persona_keys: &HashSet<String>,
    relevant_goals: &HashSet<Id>,
) -> BTreeMap<Id, Id> {
    let mut notes = BTreeMap::new();
    for (note_id, goal_id) in find!(
        (note_id: Id, goal_id: Id),
        pattern!(space, [
            {
                ?note_id @
                metadata::tag: &KIND_NOTE_ID,
                board::task: ?goal_id,
                board::note: _?body,
            },
            { ?goal_id @ metadata::tag: &KIND_GOAL_ID },
        ])
    ) {
        let own_note = exists!(pattern!(space, [{ note_id @ board::by: &persona_id }]));
        if own_note {
            continue;
        }
        let directly_addressed = entity_tags(space, note_id).iter().any(|tag| {
            tag.eq_ignore_ascii_case("colony")
                || persona_keys.contains(&tag.to_ascii_lowercase())
        });
        if directly_addressed || relevant_goals.contains(&goal_id) {
            insert_note_goal(&mut notes, note_id, goal_id);
        }
    }
    notes
}

fn task_latest_status(space: &TribleSet, task_id: Id) -> Option<(String, IntervalValue)> {
    latest_status_event(space, task_id).map(|(_, status, at)| (status, at))
}

/// Render the `Compass:` goal block (Doing/Todo, most-recent first, capped by
/// the two limits) exactly as the orient snapshot shows it, into a string.
/// Shared by `cmd_show` (which prints it) and `cmd_wake` (which appends it to
/// the wake bundle) so the two can never drift.
fn render_compass_goals(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    doing_limit: usize,
    todo_limit: usize,
) -> String {
    use std::fmt::Write as _;

    let mut doing: Vec<(i128, Id)> = Vec::new();
    let mut todo: Vec<(i128, Id)> = Vec::new();
    for task_id in find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &KIND_GOAL_ID }])) {
        let (status, status_at) = task_latest_status(space, task_id)
            .map(|(s, at)| (s.to_lowercase(), Some(interval_key(at))))
            .unwrap_or_else(|| ("todo".to_string(), None));
        let created_key: i128 = find!(s: IntervalValue, pattern!(space, [{ task_id @ metadata::created_at: ?s }]))
            .next().map(interval_key).unwrap_or(0);
        let sort_key = status_at.unwrap_or(created_key);
        if status == "doing" {
            doing.push((sort_key, task_id));
        } else if status == "todo" {
            todo.push((sort_key, task_id));
        }
    }

    doing.sort_by(|a, b| b.0.cmp(&a.0));
    todo.sort_by(|a, b| b.0.cmp(&a.0));

    let mut out = String::new();
    writeln!(out, "Compass:").unwrap();
    if doing.is_empty() && todo.is_empty() {
        writeln!(out, "- No goals.").unwrap();
    } else {
        writeln!(out, "Doing:").unwrap();
        if doing.is_empty() {
            writeln!(out, "- None").unwrap();
        } else {
            for (_key, task_id) in doing.into_iter().take(doing_limit) {
                let title = task_title(ws, space, task_id);
                let tag_suffix = render_tags(&entity_tags(space, task_id));
                writeln!(out, "- [{}] {}{}", fmt_id(task_id), title, tag_suffix).unwrap();
            }
        }
        writeln!(out, "Todo:").unwrap();
        if todo.is_empty() {
            writeln!(out, "- None").unwrap();
        } else {
            for (_key, task_id) in todo.into_iter().take(todo_limit) {
                let title = task_title(ws, space, task_id);
                let tag_suffix = render_tags(&entity_tags(space, task_id));
                writeln!(out, "- [{}] {}{}", fmt_id(task_id), title, tag_suffix).unwrap();
            }
        }
    }
    out
}

/// Resolve a persona given as 32-char hex id or a relations label/alias
/// (matched against the pre-normalized `label_norm` / `alias_norm` fields,
/// same semantics as `message`).
fn resolve_persona(relations_space: &TribleSet, input: &str) -> Result<Id> {
    let trimmed = input.trim();
    if let Some(id) = Id::from_hex(trimmed) {
        return Ok(id);
    }
    let key = trimmed.to_ascii_lowercase();
    let matches: Vec<Id> = find!(
        person_id: Id,
        pattern!(relations_space, [{ ?person_id @ metadata::tag: &faculties::schemas::relations::KIND_PERSON_ID }])
    )
    .filter(|&person_id| {
        exists!(pattern!(relations_space, [{ person_id @ rel_attrs::label_norm: key.as_str() }]))
            || exists!(pattern!(relations_space, [{ person_id @ rel_attrs::alias_norm: key.as_str() }]))
    })
    .collect();
    match matches.len() {
        0 => bail!("unknown persona label '{trimmed}' (no relations entry; try the hex id)"),
        1 => Ok(matches[0]),
        _ => bail!("multiple relations entries match persona label '{trimmed}'"),
    }
}

fn cmd_show(
    pile: &Path,
    persona: Option<&str>,
    message_limit: usize,
    doing_limit: usize,
    todo_limit: usize,
) -> Result<()> {
    with_repo(pile, |repo| {
        let compass_branch_id = repo
            .ensure_branch("compass", None)
            .map_err(|e| anyhow::anyhow!("ensure compass branch: {e:?}"))?;
        let local_branch_id = repo
            .ensure_branch("message", None)
            .map_err(|e| anyhow::anyhow!("ensure message branch: {e:?}"))?;
        let relations_branch_id = repo
            .ensure_branch("relations", None)
            .map_err(|e| anyhow::anyhow!("ensure relations branch: {e:?}"))?;
        let orient_state_branch_id = repo
            .ensure_branch("orient-state", None)
            .map_err(|e| anyhow::anyhow!("ensure orient-state branch: {e:?}"))?;
        let current_heads = load_watched_heads(
            repo,
            local_branch_id,
            compass_branch_id,
            relations_branch_id,
        )?;

        let mut local_ws = repo
            .pull(local_branch_id)
            .map_err(|e| anyhow!("pull local workspace: {e:?}"))?;
        let local_space = local_ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout local: {e:?}"))?;
        let reads = load_reads(&local_space);
        let all_messages = load_message_ids(&local_space);

        let now_key = interval_key(epoch_interval(now_epoch()));

        // Persona is strictly per-process (flag / $PERSONA): multiple
        // agents share one pile but must not share one identity, so there
        // is deliberately no pile-level fallback.
        let effective_persona = match persona {
            Some(input) => {
                let mut relations_ws = repo
                    .pull(relations_branch_id)
                    .map_err(|e| anyhow!("pull relations workspace: {e:?}"))?;
                let relations_space = relations_ws
                    .checkout(..)
                    .map_err(|e| anyhow!("checkout relations: {e:?}"))?;
                Some(resolve_persona(&relations_space, input)?)
            }
            None => None,
        };

        println!("Orient");
        match effective_persona {
            Some(reader_id) => {
                let mut relations_ws = repo
                    .pull(relations_branch_id)
                    .map_err(|e| anyhow!("pull relations workspace: {e:?}"))?;
                let relations_space = relations_ws
                    .checkout(..)
                    .map_err(|e| anyhow!("checkout relations: {e:?}"))?;
                let reader_groups = groups_for_member(&relations_space, reader_id);

                let unread: Vec<&MessageRow> = all_messages
                    .iter()
                    .filter(|msg| {
                        is_inbox_message(msg.from, msg.to, reader_id, &reader_groups)
                            && !reads.contains_key(&(msg.id, reader_id))
                    })
                    .take(message_limit)
                    .collect();

                let reader_label = person_label(&mut relations_ws, &relations_space, reader_id);
                println!("Local messages (unread inbox for {}):", reader_label);
                if unread.is_empty() {
                    println!("- None");
                } else {
                    for msg in &unread {
                        let from_label =
                            person_label(&mut relations_ws, &relations_space, msg.from);
                        let to_label = person_label(&mut relations_ws, &relations_space, msg.to);
                        let age = format_age(now_key, msg.created_at);
                        println!(
                            "- [{}] {} {} -> {} ({})",
                            fmt_id(msg.id),
                            age,
                            from_label,
                            to_label,
                            "unread",
                        );
                        // Resolve body lazily — only for displayed messages.
                        let body = resolve_message_body(&mut local_ws, &local_space, msg.id);
                        if body.is_empty() {
                            println!("    ");
                        } else {
                            for line in body.lines() {
                                println!("    {}", line.trim_end_matches('\r'));
                            }
                        }
                    }
                }
            }
            None => {
                println!("Local messages:");
                println!(
                    "- Unavailable: no persona (pass --persona <label-or-hex> or set $PERSONA)"
                );
            }
        }

        drop(local_ws);

        // ── Mail (unread inbox for the address in $MAIL_USER) ────
        render_unread_mail(repo, relations_branch_id, message_limit, now_key)?;

        let mut compass_ws = repo
            .pull(compass_branch_id)
            .map_err(|e| anyhow!("pull compass workspace: {e:?}"))?;
        let compass_space = compass_ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout compass: {e:?}"))?;

        println!();
        print!(
            "{}",
            render_compass_goals(&mut compass_ws, &compass_space, doing_limit, todo_limit)
        );

        drop(compass_ws);

        // Colony: each zooid's current status (latest-per-window).
        let status_branch_id = repo
            .ensure_branch("status", None)
            .map_err(|e| anyhow!("ensure status branch: {e:?}"))?;
        let mut status_ws = repo
            .pull(status_branch_id)
            .map_err(|e| anyhow!("pull status: {e:?}"))?;
        let status_space = status_ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout status: {e:?}"))?;
        let mut latest_status: HashMap<Id, (TextHandle, i128)> = HashMap::new();
        for (window, text, at) in find!(
            (window: Id, text: TextHandle, at: IntervalValue),
            pattern!(&status_space, [{ _?ev @
                metadata::tag: &KIND_STATUS_UPDATE,
                status_attrs::window: ?window,
                status_attrs::text: ?text,
                metadata::created_at: ?at,
            }])
        ) {
            let k = interval_key(at);
            latest_status
                .entry(window)
                .and_modify(|e| {
                    if k > e.1 {
                        *e = (text, k);
                    }
                })
                .or_insert((text, k));
        }
        let mut rel_ws = repo
            .pull(relations_branch_id)
            .map_err(|e| anyhow!("pull relations: {e:?}"))?;
        let rel_space = rel_ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout relations: {e:?}"))?;
        let zooids: Vec<Id> = find!(
            id: Id,
            pattern!(&rel_space, [{ ?id @
                metadata::tag: &faculties::schemas::relations::KIND_PERSON_ID,
                rel_attrs::affinity: "zooid",
            }])
        )
        .collect();
        let mut lines: Vec<(String, Option<String>)> = Vec::new();
        for id in zooids {
            let label = person_label(&mut rel_ws, &rel_space, id);
            let text = latest_status
                .get(&id)
                .map(|(h, _)| *h)
                .and_then(|h| read_text(&mut status_ws, h).ok());
            lines.push((label, text));
        }
        lines.sort_by(|a, b| a.0.cmp(&b.0));
        println!("Colony:");
        if lines.is_empty() {
            println!("- (no zooids)");
        }
        for (label, text) in lines {
            match text {
                Some(t) => println!("- {label}: {t}"),
                None => println!("- {label}: —"),
            }
        }

        let persona_view = match effective_persona {
            Some(persona_id) => {
                let view = load_watched_view(
                    repo,
                    persona_id,
                    local_branch_id,
                    compass_branch_id,
                    relations_branch_id,
                )?;
                let seen_notes = if let Some(checkpoint) =
                    load_checkpoint_view(repo, orient_state_branch_id, persona_id)?
                {
                    checkpoint.view.notes
                } else {
                    BTreeMap::new()
                };
                let notes_delta = newly_seen_notes(&view.notes, &seen_notes);
                Some((persona_id, view, notes_delta))
            }
            None => None,
        };
        save_checkpoint_heads(
            repo,
            orient_state_branch_id,
            &current_heads,
            persona_view
                .as_ref()
                .map(|(pid, view, notes_delta)| (*pid, view, notes_delta)),
        )?;
        Ok(())
    })
}

fn load_watched_heads(
    repo: &mut Repository<Pile>,
    local_branch_id: Id,
    compass_branch_id: Id,
    relations_branch_id: Id,
) -> Result<WatchedHeads> {
    Ok(WatchedHeads {
        local: branch_head_by_id(repo, local_branch_id)?,
        compass: branch_head_by_id(repo, compass_branch_id)?,
        relations: branch_head_by_id(repo, relations_branch_id)?,
    })
}

/// The persona-relevant view of the watched branches: what counts as
/// NEWS for one zooid. Raw branch movement that doesn't change this
/// view — the persona's own acks and sends, another persona's reads —
/// is not news and must not wake the persona's watcher.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchedView {
    unread: BTreeSet<Id>,
    goals_view: String,
    roster: BTreeSet<Id>,
    // Cumulative seen note ids mapped to their goal for compact wake text.
    // `load_watched_view` starts with the currently visible set; callers
    // union the checkpoint history into it before comparing or saving.
    notes: BTreeMap<Id, Id>,
}

#[derive(Debug, Clone)]
struct CheckpointView {
    view: WatchedView,
    // False only for checkpoints written before notes_view existed. That
    // transition establishes a quiet baseline instead of replaying history.
    has_notes_view: bool,
}

fn insert_note_goal(notes: &mut BTreeMap<Id, Id>, note_id: Id, goal_id: Id) {
    notes
        .entry(note_id)
        .and_modify(|existing| {
            if goal_id < *existing {
                *existing = goal_id;
            }
        })
        .or_insert(goal_id);
}

fn union_note_views(target: &mut BTreeMap<Id, Id>, source: &BTreeMap<Id, Id>) {
    for (&note_id, &goal_id) in source {
        insert_note_goal(target, note_id, goal_id);
    }
}

fn newly_seen_notes(
    visible: &BTreeMap<Id, Id>,
    seen: &BTreeMap<Id, Id>,
) -> BTreeMap<Id, Id> {
    visible
        .iter()
        .filter(|(note_id, _)| !seen.contains_key(*note_id))
        .map(|(&note_id, &goal_id)| (note_id, goal_id))
        .collect()
}

fn serialize_notes_view(notes: &BTreeMap<Id, Id>) -> String {
    notes
        .iter()
        .map(|(note_id, goal_id)| format!("{note_id:x}:{goal_id:x}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_notes_view(text: &str) -> Result<BTreeMap<Id, Id>> {
    let mut notes = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let (note, goal) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid notes_view line {}: missing ':'", index + 1))?;
        let note_id = Id::from_hex(note)
            .ok_or_else(|| anyhow!("invalid note id on notes_view line {}", index + 1))?;
        let goal_id = Id::from_hex(goal)
            .ok_or_else(|| anyhow!("invalid goal id on notes_view line {}", index + 1))?;
        insert_note_goal(&mut notes, note_id, goal_id);
    }
    Ok(notes)
}

/// Canonicalize a current visibility snapshot against the cumulative seen
/// history. A legacy checkpoint has no note baseline, so all notes visible at
/// upgrade time become seen without producing news.
fn carry_seen_notes(
    seen: &mut WatchedView,
    current: &mut WatchedView,
    has_notes_view: bool,
) {
    if !has_notes_view {
        seen.notes = current.notes.clone();
    }
    union_note_views(&mut current.notes, &seen.notes);
}

fn load_watched_view(
    repo: &mut Repository<Pile>,
    persona_id: Id,
    local_branch_id: Id,
    compass_branch_id: Id,
    relations_branch_id: Id,
) -> Result<WatchedView> {
    let mut local_ws = repo
        .pull(local_branch_id)
        .map_err(|e| anyhow!("pull local workspace: {e:?}"))?;
    let local_space = local_ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout local: {e:?}"))?;
    let reads = load_reads(&local_space);
    let message_rows = load_message_ids(&local_space);

    let mut relations_ws = repo
        .pull(relations_branch_id)
        .map_err(|e| anyhow!("pull relations workspace: {e:?}"))?;
    let relations_space = relations_ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout relations: {e:?}"))?;
    let my_groups = groups_for_member(&relations_space, persona_id);
    let unread = message_rows
        .into_iter()
        .filter(|msg| {
            is_inbox_message(msg.from, msg.to, persona_id, &my_groups)
                && !reads.contains_key(&(msg.id, persona_id))
        })
        .map(|msg| msg.id)
        .collect();

    // Only zooid personas count toward the watched roster. Bulk contact
    // imports must not wake every watcher.
    let roster = find!(
        person_id: Id,
        pattern!(&relations_space, [{
            ?person_id @
                metadata::tag: &faculties::schemas::relations::KIND_PERSON_ID,
                rel_attrs::affinity: "zooid",
        }])
    )
    .collect();

    // A goal tagged with one of this persona's normalized labels or aliases is
    // explicitly addressed to them.
    let persona_keys: HashSet<String> = find!(
        key: String,
        pattern!(&relations_space, [{ persona_id @ rel_attrs::label_norm: ?key }])
    )
    .chain(find!(
        key: String,
        pattern!(&relations_space, [{ persona_id @ rel_attrs::alias_norm: ?key }])
    ))
    .collect();

    let mut compass_ws = repo
        .pull(compass_branch_id)
        .map_err(|e| anyhow!("pull compass workspace: {e:?}"))?;
    let compass_space = compass_ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout compass: {e:?}"))?;

    // One line per goal: "id:status:author:flags". Author is the acting
    // persona on the latest status event. Flags are i = this persona has
    // authored a status or note on the goal, p = explicitly persona-tagged, and
    // c = colony-tagged.
    let mut goal_lines = Vec::new();
    let mut relevant_goals = HashSet::new();
    for id in
        find!(id: Id, pattern!(&compass_space, [{ ?id @ metadata::tag: &KIND_GOAL_ID }]))
    {
        let authored_status = exists!(pattern!(&compass_space, [{
            _?evt @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &id,
            board::by: &persona_id,
        }]));
        let authored_note = exists!(pattern!(&compass_space, [{
            _?evt @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &id,
            board::note: _?body,
            board::by: &persona_id,
        }]));
        let involved = authored_status || authored_note;
        let tags = entity_tags(&compass_space, id);
        let persona_tagged = tags
            .iter()
            .any(|tag| persona_keys.contains(&tag.to_ascii_lowercase()));
        let colony_tagged = tags
            .iter()
            .any(|tag| tag.eq_ignore_ascii_case("colony"));
        let mut flags = String::new();
        if involved {
            flags.push('i');
        }
        if persona_tagged {
            flags.push('p');
        }
        if colony_tagged {
            flags.push('c');
        }
        if involved || persona_tagged || colony_tagged {
            relevant_goals.insert(id);
        }

        let line = match latest_status_event(&compass_space, id) {
            Some((event, status, _)) => {
                let by = find!(
                    by: Id,
                    pattern!(&compass_space, [{ event @ board::by: ?by }])
                )
                .next()
                .map(fmt_id)
                .unwrap_or_default();
                format!("{id:x}:{status}:{by}:{flags}")
            }
            None => format!("{id:x}:::{flags}"),
        };
        goal_lines.push(line);
    }
    goal_lines.sort();

    // Notes are neutral ledger records. A foreign or unattributed note is
    // visible when its goal is already relevant to this persona, or when the
    // note itself carries a persona/colony attention tag. Own attributed
    // notes remain quiet; absence of attribution is deliberately not treated
    // as ownership.
    let notes = visible_notes(
        &compass_space,
        persona_id,
        &persona_keys,
        &relevant_goals,
    );

    Ok(WatchedView {
        unread,
        goals_view: goal_lines.join("\n"),
        roster,
        notes,
    })
}

/// What news is in `new` relative to `old`? Returns one line per
/// item, empty = no news. Unread and roster are growth-only. Goal status
/// changes wake only when the goal is relevant to this persona; a new goal
/// wakes only when explicitly addressed by persona or colony tag.
fn view_news(old: &WatchedView, new: &WatchedView, persona_id: Id) -> Vec<String> {
    let mut reasons = Vec::new();
    for msg in new.unread.difference(&old.unread) {
        reasons.push(format!("new message [{}]", fmt_id(*msg)));
    }

    let parse = |view: &str| -> HashMap<String, (String, String, String)> {
        view.lines()
            .filter_map(|line| {
                let mut parts = line.splitn(4, ':');
                Some((
                    parts.next()?.to_owned(),
                    (
                        parts.next().unwrap_or("").to_owned(),
                        parts.next().unwrap_or("").to_owned(),
                        parts.next().unwrap_or("").to_owned(),
                    ),
                ))
            })
            .collect()
    };
    let old_goals = parse(&old.goals_view);
    let new_goals = parse(&new.goals_view);
    let me = fmt_id(persona_id);

    for (id, (status, by, flags)) in &new_goals {
        let own_edit = *by == me;
        let addressed = flags.contains('p') || flags.contains('c');
        let relevant = flags.contains('i') || addressed;
        match old_goals.get(id) {
            None if !own_edit && addressed => {
                reasons.push(format!("new goal [{id}] ({status})"));
            }
            Some((previous, _, _)) if previous != status && !own_edit && relevant => {
                reasons.push(format!("goal [{id}]: {previous} → {status}"));
            }
            _ => {}
        }
    }

    for person in new.roster.difference(&old.roster) {
        reasons.push(format!("new person [{}]", fmt_id(*person)));
    }
    for (note_id, goal_id) in &new.notes {
        if !old.notes.contains_key(note_id) {
            reasons.push(format!(
                "new note [{}] on goal [{}]",
                fmt_id(*note_id),
                fmt_id(*goal_id)
            ));
        }
    }
    reasons
}

fn load_checkpoint_heads(
    repo: &mut Repository<Pile>,
    orient_state_branch_id: Id,
) -> Result<Option<WatchedHeads>> {
    let Some(_head) = repo
        .storage_mut()
        .head(orient_state_branch_id)
        .map_err(|e| anyhow!("orient state branch head: {e:?}"))?
    else {
        return Ok(None);
    };
    let mut ws = repo
        .pull(orient_state_branch_id)
        .map_err(|e| anyhow!("pull orient state workspace: {e:?}"))?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout orient state: {e:?}"))?;

    let mut latest: Option<(Id, i128)> = None;
    for (checkpoint_id, at) in find!(
        (checkpoint_id: Id, at: Inline<inlineencodings::NsTAIInterval>),
        pattern!(&space, [{
            ?checkpoint_id @
            metadata::tag: &KIND_ORIENT_CHECKPOINT_ID,
            orient_state::at: ?at,
        }])
    ) {
        let key = interval_key(at);
        if latest.is_none_or(|(_, current)| key > current) {
            latest = Some((checkpoint_id, key));
        }
    }

    let Some((checkpoint_id, _)) = latest else {
        return Ok(None);
    };

    Ok(Some(WatchedHeads {
        local: load_optional_commit_head(&space, checkpoint_id, &orient_state::local_head),
        compass: load_optional_commit_head(&space, checkpoint_id, &orient_state::compass_head),
        relations: load_optional_commit_head(&space, checkpoint_id, &orient_state::relations_head),
    }))
}

fn load_optional_commit_head(
    space: &TribleSet,
    checkpoint_id: Id,
    attr: &Attribute<inlineencodings::Handle<blobencodings::SimpleArchive>>,
) -> Option<CommitHandle> {
    find!(
        value: CommitHandle,
        pattern!(space, [{ checkpoint_id @ attr: ?value }])
    )
    .next()
}

/// Latest checkpoint VIEW saved by this persona, if any. Old-style
/// checkpoints (no persona attribute) never match — each zooid's
/// watch state is its own.
fn load_checkpoint_view(
    repo: &mut Repository<Pile>,
    orient_state_branch_id: Id,
    persona_id: Id,
) -> Result<Option<CheckpointView>> {
    let Some(_head) = repo
        .storage_mut()
        .head(orient_state_branch_id)
        .map_err(|e| anyhow!("orient state branch head: {e:?}"))?
    else {
        return Ok(None);
    };
    let mut ws = repo
        .pull(orient_state_branch_id)
        .map_err(|e| anyhow!("pull orient state workspace: {e:?}"))?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout orient state: {e:?}"))?;

    let mut checkpoints = Vec::new();
    for (checkpoint_id, at) in find!(
        (checkpoint_id: Id, at: Inline<inlineencodings::NsTAIInterval>),
        pattern!(&space, [{
            ?checkpoint_id @
            metadata::tag: &KIND_ORIENT_CHECKPOINT_ID,
            orient_state::persona: &persona_id,
            orient_state::at: ?at,
        }])
    ) {
        let key = interval_key(at);
        checkpoints.push((checkpoint_id, key));
    }
    let Some((checkpoint_id, _)) = checkpoints
        .iter()
        .copied()
        .max_by_key(|(checkpoint_id, key)| (*key, *checkpoint_id))
    else {
        return Ok(None);
    };

    let unread: BTreeSet<Id> = find!(
        msg: Id,
        pattern!(&space, [{ checkpoint_id @ orient_state::unread_msg: ?msg }])
    )
    .collect();
    let goals_view = find!(
        h: TextHandle,
        pattern!(&space, [{ checkpoint_id @ orient_state::goals_view: ?h }])
    )
    .next()
    .map(|h| read_text(&mut ws, h))
    .transpose()?
    .unwrap_or_default();
    let roster: BTreeSet<Id> = find!(
        person: Id,
        pattern!(&space, [{ checkpoint_id @ orient_state::roster_member: ?person }])
    )
    .collect();

    // notes_view is a per-checkpoint delta, unlike the latest-snapshot fields
    // above. Union every persona checkpoint so two divergent committed
    // checkpoints cannot cause either one's seen note IDs to replay later.
    let mut notes = BTreeMap::new();
    let mut has_notes_view = false;
    for (checkpoint_id, _) in checkpoints {
        let handles: Vec<TextHandle> = find!(
            handle: TextHandle,
            pattern!(&space, [{ checkpoint_id @ orient_state::notes_view: ?handle }])
        )
        .collect();
        if !handles.is_empty() {
            has_notes_view = true;
        }
        for handle in handles {
            let encoded = read_text(&mut ws, handle)?;
            union_note_views(&mut notes, &parse_notes_view(&encoded)?);
        }
    }

    Ok(Some(CheckpointView {
        view: WatchedView {
            unread,
            goals_view,
            roster,
            notes,
        },
        has_notes_view,
    }))
}

fn save_checkpoint_heads(
    repo: &mut Repository<Pile>,
    orient_state_branch_id: Id,
    heads: &WatchedHeads,
    persona_view: Option<(Id, &WatchedView, &BTreeMap<Id, Id>)>,
) -> Result<()> {
    let mut ws = repo
        .pull(orient_state_branch_id)
        .map_err(|e| anyhow!("pull orient state workspace: {e:?}"))?;

    let checkpoint_id = ufoid();
    let now = epoch_interval(now_epoch());
    let mut change = TribleSet::new();
    change += entity! { &checkpoint_id @
        metadata::tag: &KIND_ORIENT_CHECKPOINT_ID,
        orient_state::at: now,
        orient_state::local_head?: heads.local,
        orient_state::compass_head?: heads.compass,
        orient_state::relations_head?: heads.relations,
    };
    if let Some((persona_id, view, notes_delta)) = persona_view {
        let goals_handle = ws.put(view.goals_view.clone());
        // Persist only newly seen pairs. Presence of this handle, even when
        // empty, marks the checkpoint as notes-aware. Readers union all
        // committed deltas, so divergent checkpoints cannot replay an ID
        // after both are visible; this is not a simultaneous-delivery lock.
        let notes_handle = ws.put(serialize_notes_view(notes_delta));
        change += entity! { &checkpoint_id @
            orient_state::persona: &persona_id,
            orient_state::goals_view: goals_handle,
            orient_state::notes_view: notes_handle,
            orient_state::unread_msg*: view.unread.iter(),
            orient_state::roster_member*: view.roster.iter(),
        };
    }

    ws.commit(change, "orient checkpoint");
    repo.push(&mut ws)
        .map_err(|e| anyhow!("push orient checkpoint: {e:?}"))?;
    Ok(())
}

fn branch_head_by_id(
    repo: &mut Repository<Pile>,
    branch_id: Id,
) -> Result<Option<CommitHandle>> {
    repo.storage_mut()
        .head(branch_id)
        .map_err(|e| anyhow!("branch head {:x}: {e:?}", branch_id))
}

fn parse_wait_target(target: Option<&WaitTarget>) -> Result<Option<Duration>> {
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

/// Print only the *novel* content behind the news — new messages (sender +
/// body) and newly-arrived zooids — so a woken watcher gets what actually
/// changed, not a full re-dump of the snapshot. The `News:` reason lines
/// are printed by the caller; this fills in the detail worth reading.
fn print_news_detail(
    repo: &mut Repository<Pile>,
    old: &WatchedView,
    new: &WatchedView,
    local_branch_id: Id,
    relations_branch_id: Id,
) -> Result<()> {
    let new_msgs: Vec<Id> = new.unread.difference(&old.unread).copied().collect();
    if !new_msgs.is_empty() {
        let mut local_ws = repo
            .pull(local_branch_id)
            .map_err(|e| anyhow!("pull local: {e:?}"))?;
        let local_space = local_ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout local: {e:?}"))?;
        let mut rel_ws = repo
            .pull(relations_branch_id)
            .map_err(|e| anyhow!("pull relations: {e:?}"))?;
        let rel_space = rel_ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout relations: {e:?}"))?;
        let rows = load_message_ids(&local_space);
        println!("\nNew messages:");
        for id in &new_msgs {
            if let Some(row) = rows.iter().find(|r| r.id == *id) {
                let from = person_label(&mut rel_ws, &rel_space, row.from);
                let body = resolve_message_body(&mut local_ws, &local_space, *id);
                println!("- {from}: {body}");
            }
        }
    }
    let new_people: Vec<Id> = new.roster.difference(&old.roster).copied().collect();
    if !new_people.is_empty() {
        let mut rel_ws = repo
            .pull(relations_branch_id)
            .map_err(|e| anyhow!("pull relations: {e:?}"))?;
        let rel_space = rel_ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout relations: {e:?}"))?;
        println!("\nNew zooid(s):");
        for id in &new_people {
            println!("- {}", person_label(&mut rel_ws, &rel_space, *id));
        }
    }
    Ok(())
}

/// Outcome of one shot of the wait fire-path (`check_news_once`).
enum NewsCheck {
    /// News was printed tersely and the checkpoint advanced.
    Fired,
    /// A checkpoint exists and nothing is new. Carries the freshly
    /// loaded view so `wait` can use it as its loop baseline.
    Quiet(WatchedView),
    /// No checkpoint for this persona yet — the caller decides how to
    /// establish the baseline (`wait` and non-peeking `poll` save it
    /// silently; peeking remains read-only).
    NoCheckpoint(WatchedView),
}

/// One shot of the wait fire-path for a persona: load the current
/// watched view, diff it against the persona's last checkpoint, and if
/// there is news print the terse report (`News:` reasons + the novel
/// message bodies / zooids) and advance the checkpoint. Shared by
/// `wait` (pre-loop check) and `poll` (the whole command) — one code
/// path, blocking vs non-blocking only in the caller.
fn check_news_once(
    repo: &mut Repository<Pile>,
    persona_id: Id,
    heads: &WatchedHeads,
    local_branch_id: Id,
    compass_branch_id: Id,
    relations_branch_id: Id,
    orient_state_branch_id: Id,
    peek: bool,
) -> Result<NewsCheck> {
    let mut view = load_watched_view(
        repo,
        persona_id,
        local_branch_id,
        compass_branch_id,
        relations_branch_id,
    )?;
    let Some(mut seen) = load_checkpoint_view(repo, orient_state_branch_id, persona_id)? else {
        return Ok(NewsCheck::NoCheckpoint(view));
    };
    let legacy_upgrade = !seen.has_notes_view;
    let notes_delta = newly_seen_notes(&view.notes, &seen.view.notes);
    carry_seen_notes(&mut seen.view, &mut view, seen.has_notes_view);
    let reasons = view_news(&seen.view, &view, persona_id);
    if reasons.is_empty() {
        // Quiet changes still update the comparison baseline. Peek remains
        // strictly read-only.
        if !peek && (legacy_upgrade || view != seen.view) {
            save_checkpoint_heads(
                repo,
                orient_state_branch_id,
                heads,
                Some((persona_id, &view, &notes_delta)),
            )?;
        }
        return Ok(NewsCheck::Quiet(view));
    }
    for reason in &reasons {
        println!("News: {reason}");
    }
    print_news_detail(
        repo,
        &seen.view,
        &view,
        local_branch_id,
        relations_branch_id,
    )?;
    // Advance the checkpoint — the terse path skips cmd_show, which is
    // what normally saves it. Without this the checkpoint never moves
    // and every re-arm / next poll instantly re-fires on the same news.
    // Peek mode skips the save: report without consuming, for hooks that
    // can't tell whose turn they fire on (root vs subagent).
    if !peek {
        save_checkpoint_heads(
            repo,
            orient_state_branch_id,
            heads,
            Some((persona_id, &view, &notes_delta)),
        )?;
    }
    Ok(NewsCheck::Fired)
}

/// One-shot, non-blocking `wait`: report news since the persona's
/// checkpoint tersely, or print nothing and exit 0. Meant for per-turn
/// harness hooks (UserPromptSubmit and friends) so busy sessions
/// passively ingest colony news at every turn boundary, while `wait`
/// keeps its job of waking idle ones.
fn cmd_poll(pile: &Path, persona: Option<&str>, peek: bool) -> Result<()> {
    with_repo(pile, |repo| {
        let compass_branch_id = repo
            .ensure_branch("compass", None)
            .map_err(|e| anyhow!("ensure compass branch: {e:?}"))?;
        let local_branch_id = repo
            .ensure_branch("message", None)
            .map_err(|e| anyhow!("ensure message branch: {e:?}"))?;
        let relations_branch_id = repo
            .ensure_branch("relations", None)
            .map_err(|e| anyhow!("ensure relations branch: {e:?}"))?;
        let orient_state_branch_id = repo
            .ensure_branch("orient-state", None)
            .map_err(|e| anyhow!("ensure orient-state branch: {e:?}"))?;

        let Some(input) = persona else {
            bail!("poll requires a persona (pass --persona <label-or-hex> or set $PERSONA)");
        };
        let persona_id = {
            let mut relations_ws = repo
                .pull(relations_branch_id)
                .map_err(|e| anyhow!("pull relations workspace: {e:?}"))?;
            let relations_space = relations_ws
                .checkout(..)
                .map_err(|e| anyhow!("checkout relations: {e:?}"))?;
            resolve_persona(&relations_space, input)?
        };

        let heads = load_watched_heads(
            repo,
            local_branch_id,
            compass_branch_id,
            relations_branch_id,
        )?;
        match check_news_once(
            repo,
            persona_id,
            &heads,
            local_branch_id,
            compass_branch_id,
            relations_branch_id,
            orient_state_branch_id,
            peek,
        )? {
            // News printed (+ checkpoint advanced unless peeking).
            NewsCheck::Fired => {}
            // No news: print nothing, write nothing.
            NewsCheck::Quiet(_) => {}
            // First poll for this persona: establish a baseline silently.
            // Dumping "everything currently unread" is a snapshot's job
            // (`orient show`), not a turn-boundary hook's; subsequent
            // polls diff against this checkpoint. Peek writes NOTHING —
            // not even a baseline (a worker turn must not initialize the
            // root persona's checkpoint).
            NewsCheck::NoCheckpoint(view) => {
                if !peek {
                    let notes_delta = view.notes.clone();
                    save_checkpoint_heads(
                        repo,
                        orient_state_branch_id,
                        &heads,
                        Some((persona_id, &view, &notes_delta)),
                    )?;
                }
                let _ = view;
            }
        }
        Ok(())
    })
}

fn cmd_wait(
    pile: &Path,
    persona: Option<&str>,
    target: Option<WaitTarget>,
    message_limit: usize,
    doing_limit: usize,
    todo_limit: usize,
    poll_ms: u64,
) -> Result<()> {
    let timeout = parse_wait_target(target.as_ref())?;
    let (detected_change_before_wait, changed, news_printed) = with_repo(pile, |repo| {
        let compass_branch_id = repo
            .ensure_branch("compass", None)
            .map_err(|e| anyhow::anyhow!("ensure compass branch: {e:?}"))?;
        let local_branch_id = repo
            .ensure_branch("message", None)
            .map_err(|e| anyhow::anyhow!("ensure message branch: {e:?}"))?;
        let relations_branch_id = repo
            .ensure_branch("relations", None)
            .map_err(|e| anyhow::anyhow!("ensure relations branch: {e:?}"))?;
        let orient_state_branch_id = repo
            .ensure_branch("orient-state", None)
            .map_err(|e| anyhow::anyhow!("ensure orient-state branch: {e:?}"))?;

        let mut baseline_heads = load_watched_heads(
            repo,
            local_branch_id,
            compass_branch_id,
            relations_branch_id,
        )?;

        // With a persona, the wake condition is NEWS for that persona
        // (a new unread message, a goals change) — not raw branch
        // movement, which would fire on the persona's own acks/sends.
        let persona_id = match persona {
            Some(input) => {
                let mut relations_ws = repo
                    .pull(relations_branch_id)
                    .map_err(|e| anyhow!("pull relations workspace: {e:?}"))?;
                let relations_space = relations_ws
                    .checkout(..)
                    .map_err(|e| anyhow!("checkout relations: {e:?}"))?;
                Some(resolve_persona(&relations_space, input)?)
            }
            None => None,
        };

        let mut baseline_view = match persona_id {
            Some(pid) => match check_news_once(
                repo,
                pid,
                &baseline_heads,
                local_branch_id,
                compass_branch_id,
                relations_branch_id,
                orient_state_branch_id,
                false,
            )? {
                NewsCheck::Fired => return Ok((true, true, true)),
                NewsCheck::Quiet(view) => Some(view),
                NewsCheck::NoCheckpoint(view) => {
                    // A wait may run for hours before another watched branch
                    // moves. Persist its quiet initial note baseline now; if
                    // only a later delta were saved, these pre-existing IDs
                    // could replay after the watcher restarted.
                    let notes_delta = view.notes.clone();
                    save_checkpoint_heads(
                        repo,
                        orient_state_branch_id,
                        &baseline_heads,
                        Some((pid, &view, &notes_delta)),
                    )?;
                    Some(view)
                }
            },
            None => {
                if let Some(last_seen) = load_checkpoint_heads(repo, orient_state_branch_id)? {
                    if baseline_heads != last_seen {
                        return Ok((true, true, false));
                    }
                }
                None
            }
        };

        let poll = Duration::from_millis(poll_ms.max(1));
        let start = Instant::now();

        loop {
            if let Some(timeout) = timeout {
                if start.elapsed() >= timeout {
                    return Ok((false, false, false));
                }
            }
            std::thread::sleep(poll);
            let current_heads = load_watched_heads(
                repo,
                local_branch_id,
                compass_branch_id,
                relations_branch_id,
            )?;
            if current_heads == baseline_heads {
                continue;
            }
            match (persona_id, baseline_view.as_mut()) {
                (Some(pid), Some(view)) => {
                    let mut current_view = load_watched_view(
                        repo,
                        pid,
                        local_branch_id,
                        compass_branch_id,
                        relations_branch_id,
                    )?;
                    let notes_delta = newly_seen_notes(&current_view.notes, &view.notes);
                    union_note_views(&mut current_view.notes, &view.notes);
                    let reasons = view_news(view, &current_view, pid);
                    if !reasons.is_empty() {
                        for reason in &reasons {
                            println!("News: {reason}");
                        }
                        print_news_detail(
                            repo,
                            view,
                            &current_view,
                            local_branch_id,
                            relations_branch_id,
                        )?;
                        // Advance the checkpoint (terse path skips cmd_show).
                        save_checkpoint_heads(
                            repo,
                            orient_state_branch_id,
                            &current_heads,
                            Some((pid, &current_view, &notes_delta)),
                        )?;
                        return Ok((false, true, true));
                    }
                    // Movement without news (an own edit or another persona's
                    // traffic) is absorbed while the watcher keeps waiting.
                    if *view != current_view {
                        save_checkpoint_heads(
                            repo,
                            orient_state_branch_id,
                            &current_heads,
                            Some((pid, &current_view, &notes_delta)),
                        )?;
                    }
                    baseline_heads = current_heads;
                    *view = current_view;
                }
                _ => return Ok((false, true, false)),
            }
        }
    })?;
    if news_printed {
        // Terse path: the News: reasons and the novel detail were already
        // printed inside the wait loop — don't re-dump the full snapshot.
        return Ok(());
    }
    if detected_change_before_wait {
        println!("Detected branch changes since last orientation snapshot; returning immediately.");
    }
    if !changed {
        println!("No change detected since wait started; showing current snapshot.");
    }
    cmd_show(pile, persona, message_limit, doing_limit, todo_limit)
}

fn render_tags(tags: &[String]) -> String {
    if tags.is_empty() {
        return String::new();
    }
    let mut sorted = tags.to_vec();
    sorted.sort();
    sorted.dedup();
    format!(
        " {}",
        sorted
            .iter()
            .map(|tag| {
                if tag.starts_with('#') {
                    tag.to_string()
                } else {
                    format!("#{}", tag)
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile = Pile::open(path)
        .map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.refresh() {
        // Avoid Drop warnings on early errors.
        let _ = pile.close();
        return Err(match err {
            triblespace::core::repo::pile::ReadError::CorruptPile { valid_length } => anyhow!(
                "pile corrupt at byte {valid_length}: refusing to auto-repair (a stale binary \
                 could truncate newer data). If, and only if, the tail is a genuinely torn write, truncate it explicitly (DESTRUCTIVE) with: trible pile amputate {}",
                path.display()
            ),
            other => anyhow!("refresh pile {}: {other:?}", path.display()),
        });
    }
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow!("create repository: {err:?}"))
}

fn with_repo<T>(
    pile: &Path,
    f: impl FnOnce(&mut Repository<Pile>) -> Result<T>,
) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let result = f(&mut repo);
    let close_res = repo.close().map_err(|e| anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

/// `orient wake` — assemble the full wake bundle a fresh face reads to come
/// into itself: the memory cover (coarse → fine over ALL memories), then the
/// cover-tagged wiki beliefs (the ambient always-true set), then the compass
/// goals. READ-ONLY: it pulls and checks out, never writes to any branch.
fn cmd_wake(
    pile: &Path,
    chars: usize,
    doing_limit: usize,
    todo_limit: usize,
) -> Result<()> {
    with_repo(pile, |repo| {
        // (1) Memory cover — the same render `memory context` produces.
        let memory_branch_id = repo
            .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
            .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;
        let mut memory_ws = repo
            .pull(memory_branch_id)
            .map_err(|e| anyhow!("pull memory workspace: {e:?}"))?;
        let memory_space = memory_ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout memory: {e:?}"))?;
        print!(
            "{}",
            render_cover(&memory_space, &mut memory_ws, &CoverOpts::plain(chars))?
        );
        drop(memory_ws);

        // (2) Cover-tagged wiki beliefs — the ambient always-true set.
        println!();
        println!("Beliefs (cover):");
        let wiki_branch_id = repo
            .ensure_branch(WIKI_BRANCH_NAME, None)
            .map_err(|e| anyhow!("ensure wiki branch: {e:?}"))?;
        let mut wiki_ws = repo
            .pull(wiki_branch_id)
            .map_err(|e| anyhow!("pull wiki workspace: {e:?}"))?;
        let wiki_space = wiki_ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout wiki: {e:?}"))?;
        let beliefs = cover_fragments(&wiki_space, &mut wiki_ws);
        if beliefs.is_empty() {
            println!("- None");
        } else {
            for (title, content) in &beliefs {
                println!("- {title}");
                for line in content.lines() {
                    println!("    {line}");
                }
            }
        }
        drop(wiki_ws);

        // (3) Compass goals — exactly as the orient snapshot renders them.
        println!();
        let compass_branch_id = repo
            .ensure_branch("compass", None)
            .map_err(|e| anyhow!("ensure compass branch: {e:?}"))?;
        let mut compass_ws = repo
            .pull(compass_branch_id)
            .map_err(|e| anyhow!("pull compass workspace: {e:?}"))?;
        let compass_space = compass_ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout compass: {e:?}"))?;
        print!(
            "{}",
            render_compass_goals(&mut compass_ws, &compass_space, doing_limit, todo_limit)
        );
        drop(compass_ws);

        Ok(())
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(cmd) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    match cmd {
        Command::Show {
            message_limit,
            doing_limit,
            todo_limit,
        } => cmd_show(
            &cli.pile,
            cli.persona.as_deref(),
            message_limit,
            doing_limit,
            todo_limit,
        ),
        Command::Wait {
            target,
            message_limit,
            doing_limit,
            todo_limit,
            poll_ms,
        } => cmd_wait(
            &cli.pile,
            cli.persona.as_deref(),
            target,
            message_limit,
            doing_limit,
            todo_limit,
            poll_ms,
        ),
        Command::Wake {
            chars,
            doing_limit,
            todo_limit,
        } => cmd_wake(&cli.pile, chars, doing_limit, todo_limit),
        Command::Poll { peek } => cmd_poll(&cli.pile, cli.persona.as_deref(), peek),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEST_PILE: AtomicU64 = AtomicU64::new(0);

    fn view(goals_view: impl Into<String>) -> WatchedView {
        WatchedView {
            unread: BTreeSet::new(),
            goals_view: goals_view.into(),
            roster: BTreeSet::new(),
            notes: BTreeMap::new(),
        }
    }

    struct TestPile {
        dir: PathBuf,
        path: PathBuf,
    }

    impl TestPile {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sequence = NEXT_TEST_PILE.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "faculties-orient-note-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("test.pile");
            fs::File::create(&path).unwrap();
            Self { dir, path }
        }
    }

    impl Drop for TestPile {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn addressed_new_goal_wakes() {
        let me = ufoid().id;
        let goal = ufoid().id;
        let news = view_news(&view(""), &view(format!("{goal:x}:todo::p")), me);
        assert_eq!(news, [format!("new goal [{goal:x}] (todo)")]);
    }

    #[test]
    fn unaddressed_new_goal_is_quiet() {
        let me = ufoid().id;
        let goal = ufoid().id;
        assert!(view_news(&view(""), &view(format!("{goal:x}:todo::")), me).is_empty());
    }

    #[test]
    fn own_status_change_is_quiet() {
        let me = ufoid().id;
        let goal = ufoid().id;
        let old = view(format!("{goal:x}:todo:{me:x}:ip"));
        let new = view(format!("{goal:x}:doing:{me:x}:ip"));
        assert!(view_news(&old, &new, me).is_empty());
    }

    #[test]
    fn relevant_peer_status_change_wakes() {
        let me = ufoid().id;
        let peer = ufoid().id;
        let goal = ufoid().id;
        let old = view(format!("{goal:x}:todo:{peer:x}:p"));
        let new = view(format!("{goal:x}:doing:{peer:x}:p"));
        assert_eq!(
            view_news(&old, &new, me),
            [format!("goal [{goal:x}]: todo → doing")]
        );
    }

    #[test]
    fn unread_message_and_new_roster_member_wake() {
        let me = ufoid().id;
        let message = ufoid().id;
        let person = ufoid().id;
        let old = view("");
        let mut new = view("");
        new.unread.insert(message);
        new.roster.insert(person);
        let news = view_news(&old, &new, me);
        assert_eq!(
            news,
            [
                format!("new message [{message:x}]"),
                format!("new person [{person:x}]"),
            ]
        );
    }

    #[test]
    fn newly_visible_note_wakes_with_its_goal() {
        let me = ufoid().id;
        let goal = ufoid().id;
        let note = ufoid().id;
        let old = view("");
        let mut new = view("");
        new.notes.insert(note, goal);
        assert_eq!(
            view_news(&old, &new, me),
            [format!("new note [{note:x}] on goal [{goal:x}]")]
        );
    }

    #[test]
    fn legacy_checkpoint_establishes_a_quiet_note_baseline() {
        let me = ufoid().id;
        let goal = ufoid().id;
        let existing = ufoid().id;
        let later = ufoid().id;
        let mut seen = view("");
        let mut current = view("");
        current.notes.insert(existing, goal);

        carry_seen_notes(&mut seen, &mut current, false);
        assert!(view_news(&seen, &current, me).is_empty());

        let baseline = current;
        let mut next = baseline.clone();
        next.notes.insert(later, goal);
        assert_eq!(
            view_news(&baseline, &next, me),
            [format!("new note [{later:x}] on goal [{goal:x}]")]
        );
    }

    #[test]
    fn divergent_committed_note_deltas_union_without_later_replay() {
        let me = ufoid().id;
        let goal = ufoid().id;
        let first = ufoid().id;
        let second = ufoid().id;
        let left = BTreeMap::from([(first, goal)]);
        let right = BTreeMap::from([(second, goal)]);
        let visible = BTreeMap::from([(first, goal), (second, goal)]);
        assert_eq!(newly_seen_notes(&visible, &left), right);
        let mut union = left;
        union_note_views(&mut union, &right);

        let encoded = serialize_notes_view(&union);
        let decoded = parse_notes_view(&encoded).unwrap();
        assert_eq!(decoded, BTreeMap::from([(first, goal), (second, goal)]));

        let mut seen = view("");
        seen.notes = decoded;
        let mut current = view("");
        current.notes = BTreeMap::from([(first, goal), (second, goal)]);
        carry_seen_notes(&mut seen, &mut current, true);
        assert!(view_news(&seen, &current, me).is_empty());
    }

    #[test]
    fn stored_legacy_and_divergent_checkpoint_deltas_upgrade_and_union() {
        let pile = TestPile::new();
        let persona = ufoid().id;
        let goal = ufoid().id;
        let existing = ufoid().id;
        let concurrent = ufoid().id;
        let mut repo = open_repo(&pile.path).unwrap();
        let branch_id = repo.ensure_branch("orient-state", None).unwrap();

        // Write the old shape directly: persona view, but no notes_view.
        let mut ws = repo.pull(branch_id).unwrap();
        let checkpoint = ufoid();
        let at = epoch_interval(now_epoch());
        let goals = ws.put(String::new());
        let mut change = TribleSet::new();
        change += entity! { &checkpoint @
            metadata::tag: &KIND_ORIENT_CHECKPOINT_ID,
            orient_state::at: at,
            orient_state::persona: &persona,
            orient_state::goals_view: goals,
        };
        ws.commit(change, "legacy orient checkpoint");
        repo.push(&mut ws).unwrap();

        let mut loaded = load_checkpoint_view(&mut repo, branch_id, persona)
            .unwrap()
            .unwrap();
        assert!(!loaded.has_notes_view);
        let mut current = view("");
        current.notes.insert(existing, goal);
        carry_seen_notes(&mut loaded.view, &mut current, loaded.has_notes_view);
        assert!(view_news(&loaded.view, &current, persona).is_empty());

        let heads = WatchedHeads {
            local: None,
            compass: None,
            relations: None,
        };
        let initial_delta = BTreeMap::from([(existing, goal)]);
        save_checkpoint_heads(
            &mut repo,
            branch_id,
            &heads,
            Some((persona, &current, &initial_delta)),
        )
        .unwrap();

        // Model a stale concurrent writer that only carried its own note.
        let mut stale = view("");
        stale.notes.insert(concurrent, goal);
        let concurrent_delta = BTreeMap::from([(concurrent, goal)]);
        save_checkpoint_heads(
            &mut repo,
            branch_id,
            &heads,
            Some((persona, &stale, &concurrent_delta)),
        )
        .unwrap();

        let mut ws = repo.pull(branch_id).unwrap();
        let space = ws.checkout(..).unwrap();
        let mut persisted_deltas: Vec<String> = find!(
            handle: TextHandle,
            pattern!(&space, [{
                _?checkpoint @
                orient_state::persona: &persona,
                orient_state::notes_view: ?handle,
            }])
        )
        .map(|handle| read_text(&mut ws, handle).unwrap())
        .collect();
        persisted_deltas.sort();
        let mut expected_deltas = vec![
            serialize_notes_view(&initial_delta),
            serialize_notes_view(&concurrent_delta),
        ];
        expected_deltas.sort();
        assert_eq!(persisted_deltas, expected_deltas);

        let loaded = load_checkpoint_view(&mut repo, branch_id, persona)
            .unwrap()
            .unwrap();
        assert!(loaded.has_notes_view);
        assert_eq!(
            loaded.view.notes,
            BTreeMap::from([(existing, goal), (concurrent, goal)])
        );
        repo.close().unwrap();
    }

    #[test]
    fn visibility_includes_foreign_and_unattributed_but_not_own_notes() {
        let me = ufoid().id;
        let peer = ufoid().id;
        let relevant_goal = ufoid().id;
        let unrelated_goal = ufoid().id;
        let foreign = ufoid();
        let unattributed = ufoid();
        let own = ufoid();
        let direct = ufoid();
        let unrelated = ufoid();
        let malformed = ufoid();
        let non_goal_target = ufoid().id;
        let wrong_target = ufoid();
        let body = "body".to_blob().get_handle();
        let mut space = TribleSet::new();
        space += entity! { ExclusiveId::force_ref(&relevant_goal) @
            metadata::tag: &KIND_GOAL_ID,
        };
        space += entity! { ExclusiveId::force_ref(&unrelated_goal) @
            metadata::tag: &KIND_GOAL_ID,
        };
        space += entity! { &foreign @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &relevant_goal,
            board::note: body,
            board::by: &peer,
        };
        space += entity! { &unattributed @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &relevant_goal,
            board::note: body,
        };
        space += entity! { &own @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &relevant_goal,
            board::note: body,
            board::by: &me,
        };
        space += entity! { &direct @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &unrelated_goal,
            board::note: body,
            board::by: &peer,
            board::tag: "me",
        };
        space += entity! { &unrelated @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &unrelated_goal,
            board::note: body,
            board::by: &peer,
        };
        space += entity! { &malformed @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &relevant_goal,
            board::by: &peer,
        };
        space += entity! { &wrong_target @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &non_goal_target,
            board::note: body,
            board::by: &peer,
            board::tag: "me",
        };

        let visible = visible_notes(
            &space,
            me,
            &HashSet::from(["me".to_string()]),
            &HashSet::from([relevant_goal]),
        );
        assert_eq!(
            visible,
            BTreeMap::from([
                (foreign.id, relevant_goal),
                (unattributed.id, relevant_goal),
                (direct.id, unrelated_goal),
            ])
        );
        assert!(!visible.contains_key(&own.id));
        assert!(!visible.contains_key(&unrelated.id));
        assert!(!visible.contains_key(&malformed.id));
        assert!(!visible.contains_key(&wrong_target.id));
    }
}
