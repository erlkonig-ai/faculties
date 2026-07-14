use anyhow::{anyhow, bail, Result};
use chrono::{
    DateTime, Duration as ChronoDuration, Local, LocalResult, NaiveDateTime, NaiveTime, TimeZone,
};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::schemas::compass::{
    active_attestation_ids_for_reviewer, evaluate_goal, evaluate_request, latest_status_event,
    outstanding_review_requests, review_request, ReviewGateState, ReviewProjection,
    VERDICT_REQUEST_CHANGES,
};
use faculties::schemas::mail::{mail, KIND_MESSAGE as KIND_MAIL_MESSAGE, KIND_SPAM};
use faculties::schemas::message::is_inbox_message;
use faculties::schemas::orient::{
    KIND_GOAL_ID, KIND_MESSAGE_ID, KIND_ORIENT_CHECKPOINT_ID, KIND_READ_ID,
    KIND_REVIEW_WATERMARK_ID, KIND_STATUS_ID, board, local, orient_state,
};
use faculties::schemas::relations::{groups_for_member, person_ids, relations as rel_attrs};
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

fn task_tags(space: &TribleSet, task_id: Id) -> Vec<String> {
    let mut tags: Vec<String> = find!(
        tag: String,
        pattern!(space, [{ task_id @ metadata::tag: &KIND_GOAL_ID, board::tag: ?tag }])
    )
    .collect();
    tags.sort();
    tags.dedup();
    tags
}

fn task_latest_status(space: &TribleSet, task_id: Id) -> Option<(String, IntervalValue)> {
    latest_status_event(space, task_id).map(|(_, status, at)| (status, at))
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

        let mut doing: Vec<(i128, Id)> = Vec::new();
        let mut todo: Vec<(i128, Id)> = Vec::new();
        for task_id in
            find!(id: Id, pattern!(&compass_space, [{ ?id @ metadata::tag: &KIND_GOAL_ID }]))
        {
            let (status, status_at) = task_latest_status(&compass_space, task_id)
                .map(|(s, at)| (s.to_lowercase(), Some(interval_key(at))))
                .unwrap_or_else(|| ("todo".to_string(), None));
            let created_key: i128 = find!(s: IntervalValue, pattern!(&compass_space, [{ task_id @ metadata::created_at: ?s }]))
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

        println!();
        println!("Compass:");
        if doing.is_empty() && todo.is_empty() {
            println!("- No goals.");
        } else {
            println!("Doing:");
            if doing.is_empty() {
                println!("- None");
            } else {
                for (_key, task_id) in doing.into_iter().take(doing_limit) {
                    let title = task_title(&mut compass_ws, &compass_space, task_id);
                    let tag_suffix = render_tags(&task_tags(&compass_space, task_id));
                    println!("- [{}] {}{}", fmt_id(task_id), title, tag_suffix);
                }
            }
            println!("Todo:");
            if todo.is_empty() {
                println!("- None");
            } else {
                for (_key, task_id) in todo.into_iter().take(todo_limit) {
                    let title = task_title(&mut compass_ws, &compass_space, task_id);
                    let tag_suffix = render_tags(&task_tags(&compass_space, task_id));
                    println!("- [{}] {}{}", fmt_id(task_id), title, tag_suffix);
                }
            }
        }

        println!("Reviews:");
        match effective_persona {
            Some(persona_id) => {
                let mut relations_ws = repo
                    .pull(relations_branch_id)
                    .map_err(|e| anyhow!("pull relations: {e:?}"))?;
                let relations_space = relations_ws
                    .checkout(..)
                    .map_err(|e| anyhow!("checkout relations: {e:?}"))?;
                let known_people = person_ids(&relations_space);
                let actions =
                    persona_review_actions(&compass_space, &known_people, persona_id);
                if actions.is_empty() {
                    println!("- None");
                } else {
                    for (goal_id, review) in actions.into_iter().take(10) {
                        let title = task_title(&mut compass_ws, &compass_space, goal_id);
                        println!("- [{}] {}", fmt_id(goal_id), title);
                        for request_id in review.assignments.into_keys() {
                            let target = review_request(&compass_space, request_id)
                                .and_then(|request| request.target())
                                .and_then(|handle| read_text(&mut compass_ws, handle).ok())
                                .unwrap_or_else(|| "<malformed target>".to_string());
                            println!(
                                "    {} request [{}] {}",
                                ReviewAction::Review.label(),
                                fmt_id(request_id),
                                target
                            );
                        }
                        if let Some(author) = review.author {
                            for request_id in author.requests {
                                let target = review_request(&compass_space, request_id)
                                    .and_then(|request| request.target())
                                    .and_then(|handle| read_text(&mut compass_ws, handle).ok())
                                    .unwrap_or_else(|| "<malformed target>".to_string());
                                println!(
                                    "    {} request [{}] {}",
                                    author.action.label(),
                                    fmt_id(request_id),
                                    target
                                );
                            }
                        }
                    }
                }
            }
            None => println!("- Unavailable: no persona"),
        }

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
            Some(persona_id) => Some((
                persona_id,
                load_watched_view(
                    repo,
                    persona_id,
                    local_branch_id,
                    compass_branch_id,
                    relations_branch_id,
                    orient_state_branch_id,
                )?,
            )),
            None => None,
        };
        save_checkpoint_heads(
            repo,
            orient_state_branch_id,
            &current_heads,
            persona_view.as_ref().map(|(pid, view)| (*pid, view)),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReviewAction {
    Review,
    Revise,
    Settle,
    Repair,
}

impl ReviewAction {
    fn label(self) -> &'static str {
        match self {
            Self::Review => "REVIEW",
            Self::Revise => "REVISE",
            Self::Settle => "SETTLE",
            Self::Repair => "REPAIR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorReviewAction {
    action: ReviewAction,
    requests: BTreeSet<Id>,
    /// Active attestation heads are part of the author's wake token. A
    /// replacement blocker is actionable even if the gate remains BLOCKED.
    heads: BTreeSet<Id>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PersonaGoalReview {
    /// Exact requests for which this persona still owes an attestation,
    /// paired with their active head sets. The heads are part of the wake
    /// token so no-head → malformed/forked transitions re-notify the reviewer.
    assignments: BTreeMap<Id, BTreeSet<Id>>,
    /// Work owned by the request author after the reviewers have acted.
    author: Option<AuthorReviewAction>,
}

/// Derive the review work this persona can act on now. Reviewer assignments
/// and author actions intentionally coexist: an author may still owe their own
/// attestation while also needing to repair malformed or forked review state.
fn persona_review_actions(
    compass_space: &TribleSet,
    known_people: &HashSet<Id>,
    persona_id: Id,
) -> BTreeMap<Id, PersonaGoalReview> {
    let mut actions = BTreeMap::<Id, PersonaGoalReview>::new();
    for (goal, request) in
        outstanding_review_requests(compass_space, known_people, persona_id)
    {
        let heads = active_attestation_ids_for_reviewer(compass_space, request, persona_id)
            .into_iter()
            .collect();
        actions
            .entry(goal)
            .or_default()
            .assignments
            .insert(request, heads);
    }

    let goals: BTreeSet<Id> = find!(
        goal: Id,
        pattern!(compass_space, [{ ?goal @ metadata::tag: &KIND_GOAL_ID }])
    )
    .collect();
    for goal in goals {
        let author_action = match evaluate_goal(compass_space, goal, known_people) {
            ReviewProjection::Unbound => None,
            ReviewProjection::Bound(evaluation) => {
                // `contains` deliberately keeps a malformed multi-author
                // request visible to every named author as REPAIR work.
                if !evaluation.request.authors.contains(&persona_id) {
                    None
                } else {
                    let has_change_request = evaluation.slots.iter().any(|slot| {
                        matches!(slot.heads.as_slice(), [head]
                            if head.is_canonical()
                                && head.request() == Some(evaluation.request.id)
                                && head.reviewer() == Some(slot.reviewer)
                                && head.verdict() == Some(VERDICT_REQUEST_CHANGES))
                    });
                    let action = match &evaluation.state {
                        ReviewGateState::Blocked { .. } if has_change_request => {
                            Some(ReviewAction::Revise)
                        }
                        ReviewGateState::Blocked { .. } => Some(ReviewAction::Repair),
                        ReviewGateState::Ready => Some(ReviewAction::Settle),
                        ReviewGateState::Invalid { .. } => Some(ReviewAction::Repair),
                        ReviewGateState::Pending { .. } | ReviewGateState::Settled { .. } => None,
                    };
                    action.map(|action| AuthorReviewAction {
                        action,
                        requests: [evaluation.request.id].into_iter().collect(),
                        heads: evaluation
                            .slots
                            .iter()
                            .flat_map(|slot| slot.heads.iter().map(|head| head.id))
                            .collect(),
                    })
                }
            }
            ReviewProjection::Forked { request_ids } => {
                let authored = request_ids.iter().any(|request_id| {
                    evaluate_request(compass_space, *request_id, known_people)
                        .is_some_and(|evaluation| {
                            evaluation.request.authors.contains(&persona_id)
                        })
                });
                authored.then(|| AuthorReviewAction {
                    action: ReviewAction::Repair,
                    requests: request_ids.into_iter().collect(),
                    heads: BTreeSet::new(),
                })
            }
        };
        if let Some(author_action) = author_action {
            actions.entry(goal).or_default().author = Some(author_action);
        }
    }
    actions
}

fn ids_token(ids: &BTreeSet<Id>) -> String {
    ids.iter().map(|id| fmt_id(*id)).collect::<Vec<_>>().join(",")
}

fn assignment_state_token(assignments: &BTreeMap<Id, BTreeSet<Id>>) -> String {
    assignments
        .iter()
        .map(|(request, heads)| {
            let heads = if heads.is_empty() {
                "-".to_string()
            } else {
                heads
                    .iter()
                    .map(|head| fmt_id(*head))
                    .collect::<Vec<_>>()
                    .join("+")
            };
            format!("{}@{heads}", fmt_id(*request))
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn author_action_token(action: Option<&AuthorReviewAction>) -> String {
    action
        .map(|action| {
            format!(
                "{}@{}@{}",
                action.action.label(),
                ids_token(&action.requests),
                ids_token(&action.heads)
            )
        })
        .unwrap_or_default()
}

/// The persona-relevant view of the watched branches: what counts as
/// NEWS for one zooid. Raw branch movement that doesn't change this
/// view — the persona's own acks and sends, another persona's reads —
/// is not news and must not wake the persona's watcher.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchedView {
    unread: std::collections::BTreeSet<Id>,
    goals_view: String,
    roster: std::collections::BTreeSet<Id>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoadedWatchedView {
    view: WatchedView,
    /// Exact orient-state head whose watermark snapshot contributed to this
    /// view. `wait` tracks it only as a scheduler invalidation signal; it is
    /// deliberately absent from semantic `WatchedHeads`.
    orient_state_head: Option<CommitHandle>,
    /// Exact latest orient-state watermark events observed while constructing
    /// `view`. Delivery writes compare these during CAS retries so they cannot
    /// overwrite a concurrently-issued explicit ack or snooze.
    review_watermark_ids: BTreeMap<Id, Id>,
    /// Earliest live snooze deadline among review assignments suppressed from
    /// `view`. Unlike branch movement, the passage of this deadline is itself a
    /// wake edge, so `wait` uses it as an additional scheduler input.
    next_review_deadline: Option<i128>,
}

fn load_watched_snapshot(
    repo: &mut Repository<Pile>,
    persona_id: Id,
    local_branch_id: Id,
    compass_branch_id: Id,
    relations_branch_id: Id,
    orient_state_branch_id: Id,
) -> Result<LoadedWatchedView> {
    load_watched_snapshot_inner(
        repo,
        persona_id,
        local_branch_id,
        compass_branch_id,
        relations_branch_id,
        orient_state_branch_id,
        |_| Ok(()),
    )
}

/// Load one persona view with a causal watermark -> Compass acquisition order.
///
/// An explicit ack/snooze snapshots Compass before it appends orient-state. By
/// reading orient-state first here, an explicit event is therefore either:
///
/// - already observed, in which case the later Compass pull sees the same or a
///   newer review state; or
/// - appended after our watermark snapshot, in which case the delivery CAS
///   observes a different event id and preserves that explicit intent.
///
/// `after_watermark_snapshot` is a no-op in production and a deterministic race
/// seam in tests.
fn load_watched_snapshot_inner<F>(
    repo: &mut Repository<Pile>,
    persona_id: Id,
    local_branch_id: Id,
    compass_branch_id: Id,
    relations_branch_id: Id,
    orient_state_branch_id: Id,
    after_watermark_snapshot: F,
) -> Result<LoadedWatchedView>
where
    F: FnOnce(&mut Repository<Pile>) -> Result<()>,
{
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
    // Groups this persona belongs to — a message addressed to one of them
    // is news for the persona too (this is how broadcasts/colony work,
    // replacing the old liora-cc magic id).
    let my_groups = groups_for_member(&relations_space, persona_id);
    let unread: std::collections::BTreeSet<Id> = message_rows
        .into_iter()
        .filter(|msg| {
            // your own sends never wake you — including to a group you're in.
            is_inbox_message(msg.from, msg.to, persona_id, &my_groups)
                && !reads.contains_key(&(msg.id, persona_id))
        })
        .map(|msg| msg.id)
        .collect();
    // Only zooid personas count toward the watched roster. A new colony
    // member is news; bulk contact/lead imports (hundreds of KIND_PERSON
    // entries from e.g. a LinkedIn pull) must NOT wake every watcher.
    // Gate on affinity = "zooid".
    let roster: std::collections::BTreeSet<Id> = find!(
        person_id: Id,
        pattern!(&relations_space, [{
            ?person_id @
                metadata::tag: &faculties::schemas::relations::KIND_PERSON_ID,
                rel_attrs::affinity: "zooid",
        }])
    )
    .collect();
    // The persona's normalized labels/aliases — goals tagged with one of
    // these are "addressed to" the persona for wake purposes.
    let persona_keys: std::collections::HashSet<String> = find!(
        key: String,
        pattern!(&relations_space, [{ persona_id @ rel_attrs::label_norm: ?key }])
    )
    .chain(find!(
        key: String,
        pattern!(&relations_space, [{ persona_id @ rel_attrs::alias_norm: ?key }])
    ))
    .collect();

    // Watermarks MUST precede the Compass pull below. See the acquisition-order
    // proof on `load_watched_snapshot_inner` and the save-time event-id CAS.
    let (orient_state_head, watermarks) =
        load_review_watermark_snapshot(repo, orient_state_branch_id, persona_id)?;
    let review_watermark_ids = watermarks
        .iter()
        .map(|(request, watermark)| (*request, watermark.id))
        .collect();
    after_watermark_snapshot(repo)?;

    let mut compass_ws = repo
        .pull(compass_branch_id)
        .map_err(|e| anyhow!("pull compass workspace: {e:?}"))?;
    let compass_space = compass_ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout compass: {e:?}"))?;
    // Review actions are derived from the exact same request/attestation heads
    // that close the Compass gate. No parallel notification ledger is needed.
    let known_people = person_ids(&relations_space);
    let mut review_actions = persona_review_actions(&compass_space, &known_people, persona_id);

    // Watermark filter (delivery/ack/snooze): drop owed reviewer assignments
    // the persona has already seen at this exact attestation head-set, while an
    // optional live snooze deadline still defers it. `wait` appends delivery
    // watermarks atomically with its checkpoint; explicit ack/snooze uses the
    // same state. A later head change, fresh successor request id, or expired
    // snooze breaks the match and re-adds the assignment → wake. Author actions
    // are never suppressed — a review the persona OWNS still needs their eyes.
    let next_review_deadline = apply_review_watermarks(
        &mut review_actions,
        &watermarks,
        interval_key(epoch_interval(now_epoch())),
    );

    // One line per goal:
    // "id:status:author:flags:review-assignments:author-action:assignment-state".
    // Author = persona hex
    // on the latest status event (empty when unattributed), so own
    // edits can be absorbed. Flags carry the relevance bits view_news
    // scopes wakes by: i = persona is involved (authored any status
    // event on the goal), p = goal carries one of the persona's
    // labels as a tag, c = goal tagged "colony" (wakes everyone), r = one
    // or more concrete review/author actions for this persona.
    let mut goal_lines: Vec<String> =
        find!(id: Id, pattern!(&compass_space, [{ ?id @ metadata::tag: &KIND_GOAL_ID }]))
            .map(|id| {
                let latest = latest_status_event(&compass_space, id);

                let involved = exists!(pattern!(&compass_space, [{
                    _?evt @
                    metadata::tag: &KIND_STATUS_ID,
                    board::task: &id,
                    board::by: &persona_id,
                }]));
                let tags = task_tags(&compass_space, id);
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
                let assignments_token = review_actions
                    .get(&id)
                    .map(|review| {
                        ids_token(&review.assignments.keys().copied().collect())
                    })
                    .unwrap_or_default();
                let assignment_state = review_actions
                    .get(&id)
                    .map(|review| assignment_state_token(&review.assignments))
                    .unwrap_or_default();
                let author_token = author_action_token(
                    review_actions
                        .get(&id)
                        .and_then(|review| review.author.as_ref()),
                );
                if !assignments_token.is_empty() || !author_token.is_empty() {
                    flags.push('r');
                }

                match latest {
                    Some((evt, status, _)) => {
                        let by = find!(
                            by: Id,
                            pattern!(&compass_space, [{ evt @ board::by: ?by }])
                        )
                        .next()
                        .map(fmt_id)
                        .unwrap_or_default();
                        format!(
                            "{:x}:{status}:{by}:{flags}:{assignments_token}:{author_token}:{assignment_state}",
                            id
                        )
                    }
                    None => format!(
                        "{:x}:::{flags}:{assignments_token}:{author_token}:{assignment_state}",
                        id
                    ),
                }
            })
            .collect();
    goal_lines.sort();
    let goals_view = goal_lines.join("\n");

    Ok(LoadedWatchedView {
        view: WatchedView {
            unread,
            goals_view,
            roster,
        },
        orient_state_head,
        review_watermark_ids,
        next_review_deadline,
    })
}

fn load_watched_view(
    repo: &mut Repository<Pile>,
    persona_id: Id,
    local_branch_id: Id,
    compass_branch_id: Id,
    relations_branch_id: Id,
    orient_state_branch_id: Id,
) -> Result<WatchedView> {
    Ok(load_watched_snapshot(
        repo,
        persona_id,
        local_branch_id,
        compass_branch_id,
        relations_branch_id,
        orient_state_branch_id,
    )?
    .view)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReviewNotice {
    goal: String,
    request: String,
    updated: bool,
    /// Exact active attestation head-set at delivery time. `None` is only
    /// possible for an old checkpoint encoding that did not carry head state;
    /// such a notice is shown but deliberately not auto-watermarked.
    delivery: Option<(Id, BTreeSet<Id>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NewsItem {
    Text(String),
    Review(ReviewNotice),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NewsReport {
    items: Vec<NewsItem>,
}

impl NewsReport {
    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Render all review assignments as one digest while leaving message,
    /// roster, goal-status, and author-action reasons independent. A large
    /// review backlog therefore consumes one watcher fire, not one per item.
    fn reasons(&self) -> Vec<String> {
        let reviews: Vec<&ReviewNotice> = self
            .items
            .iter()
            .filter_map(|item| match item {
                NewsItem::Review(review) => Some(review),
                NewsItem::Text(_) => None,
            })
            .collect();
        let review_digest = (!reviews.is_empty()).then(|| {
            let updated = reviews.iter().filter(|review| review.updated).count();
            let labels = reviews
                .iter()
                .map(|review| {
                    let short = &review.request[..review.request.len().min(8)];
                    let suffix = if review.updated { " updated" } else { "" };
                    format!("[{}] request {short}{suffix}", review.goal)
                })
                .collect::<Vec<_>>()
                .join(", ");
            let updated_suffix = if updated == 0 {
                String::new()
            } else {
                format!("; {updated} updated")
            };
            format!(
                "REVIEWS ({} pending{updated_suffix}): {labels}",
                reviews.len()
            )
        });

        let mut rendered = Vec::new();
        let mut digest_rendered = false;
        for item in &self.items {
            match item {
                NewsItem::Text(reason) => rendered.push(reason.clone()),
                NewsItem::Review(_) if !digest_rendered => {
                    rendered.push(review_digest.clone().expect("reviews are non-empty"));
                    digest_rendered = true;
                }
                NewsItem::Review(_) => {}
            }
        }
        rendered
    }

    /// Per-request delivery watermarks to append in the same commit as the
    /// checkpoint. Conflicting encodings fail open: if one request somehow
    /// carries two different head-sets, omit its watermark so the malformed
    /// edge can wake again instead of being hidden.
    fn review_deliveries(&self) -> BTreeMap<Id, BTreeSet<Id>> {
        let mut deliveries = BTreeMap::<Id, BTreeSet<Id>>::new();
        let mut conflicts = BTreeSet::<Id>::new();
        for notice in self.items.iter().filter_map(|item| match item {
            NewsItem::Review(review) => Some(review),
            NewsItem::Text(_) => None,
        }) {
            let Some((request, heads)) = &notice.delivery else {
                continue;
            };
            if conflicts.contains(request) {
                continue;
            }
            match deliveries.get(request) {
                Some(existing) if existing != heads => {
                    deliveries.remove(request);
                    conflicts.insert(*request);
                }
                Some(_) => {}
                None => {
                    deliveries.insert(*request, heads.clone());
                }
            }
        }
        deliveries
    }
}

fn parse_delivery(request: &str, heads: Option<&String>) -> Option<(Id, BTreeSet<Id>)> {
    let request = Id::from_hex(request)?;
    let heads = heads?;
    if heads == "-" {
        return Some((request, BTreeSet::new()));
    }
    let parsed: Option<BTreeSet<Id>> = heads.split('+').map(Id::from_hex).collect();
    Some((request, parsed?))
}

/// What news is in `new` relative to `old`? Unread and roster are growth-only: a
/// message leaving the unread set (the persona acked it) is not
/// news, an arriving message is; a NEW person is news, enrichment
/// of an existing entry is not (so another zooid's multi-commit
/// contact-editing burst wakes at most once). Goals wake on relevant
/// status changes and review-action token changes. Reviewer assignments remain
/// structured until rendering so one wait can coalesce them and atomically mark
/// the exact delivered head-sets as seen.
fn view_news_report(old: &WatchedView, new: &WatchedView, persona_id: Id) -> NewsReport {
    let mut report = NewsReport::default();
    for msg in new.unread.difference(&old.unread) {
        report
            .items
            .push(NewsItem::Text(format!("new message [{}]", fmt_id(*msg))));
    }
    // Goal lines are
    // "id:status:author:flags:review-assignments:author-action:assignment-state".
    // Older four-, five-, and six-field checkpoints parse with empty trailing
    // tokens. Scope:
    // a change the persona itself authored is never news; a change by
    // someone else is news only when the goal is RELEVANT to the
    // persona — involved (i: persona authored a status event on it),
    // persona-tagged (p), colony-tagged (c), or review-assigned (r). A brand-new goal is
    // news only when tagged for the persona or the colony — tagging a
    // goal with a persona's label is the "summon that zooid" primitive;
    // unclaimed work is discovered at snapshots, not via wakes.
    let me = fmt_id(persona_id);
    let parse_ids = |token: &str| -> BTreeSet<String> {
        token
            .split(',')
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let parse_assignment_state = |token: &str| -> HashMap<String, String> {
        token
            .split(',')
            .filter_map(|entry| entry.split_once('@'))
            .map(|(request, heads)| (request.to_owned(), heads.to_owned()))
            .collect()
    };
    let parse = |view: &str| -> BTreeMap<
        String,
        (
            String,
            String,
            String,
            BTreeSet<String>,
            String,
            Option<HashMap<String, String>>,
        ),
    > {
        view.lines()
            .filter_map(|line| {
                let mut parts = line.splitn(7, ':');
                let id = parts.next()?.to_owned();
                let status = parts.next().unwrap_or("").to_owned();
                let by = parts.next().unwrap_or("").to_owned();
                let flags = parts.next().unwrap_or("").to_owned();
                let assignments = parse_ids(parts.next().unwrap_or(""));
                let author_action = parts.next().unwrap_or("").to_owned();
                let assignment_state = parts.next().map(parse_assignment_state);
                Some((
                    id,
                    (
                        status,
                        by,
                        flags,
                        assignments,
                        author_action,
                        assignment_state,
                    ),
                ))
            })
            .collect()
    };
    let old_goals = parse(&old.goals_view);
    let new_goals = parse(&new.goals_view);
    for (id, (status, by, flags, assignments, author_action, assignment_state)) in &new_goals {
        let own_edit = *by == me;
        let addressed = flags.contains('p') || flags.contains('c') || flags.contains('r');
        let relevant = flags.contains('i') || addressed;
        let previous_assignments = old_goals
            .get(id)
            .map(|(_, _, _, assignments, _, _)| assignments)
            .cloned()
            .unwrap_or_default();
        let mut action_notified = false;
        if !own_edit {
            // Assignment tokens are sets, not opaque strings. Only additions
            // wake a reviewer: fulfilling/removing `a` from `a,b` must not
            // make the still-present `b` look like a refreshed candidate.
            for request in assignments.difference(&previous_assignments) {
                report.items.push(NewsItem::Review(ReviewNotice {
                    goal: id.clone(),
                    request: request.clone(),
                    updated: false,
                    delivery: parse_delivery(
                        request,
                        assignment_state
                            .as_ref()
                            .and_then(|current| current.get(request)),
                    ),
                }));
                action_notified = true;
            }
            for request in assignments.intersection(&previous_assignments) {
                let changed = old_goals
                    .get(id)
                    .and_then(|(_, _, _, _, _, states)| states.as_ref())
                    .is_some_and(|states| {
                        states.get(request)
                            != assignment_state
                                .as_ref()
                                .and_then(|current| current.get(request))
                });
                if changed {
                    report.items.push(NewsItem::Review(ReviewNotice {
                        goal: id.clone(),
                        request: request.clone(),
                        updated: true,
                        delivery: parse_delivery(
                            request,
                            assignment_state
                                .as_ref()
                                .and_then(|current| current.get(request)),
                        ),
                    }));
                    action_notified = true;
                }
            }
        }

        let previous_author_action = old_goals
            .get(id)
            .map(|(_, _, _, _, action, _)| action.as_str())
            .unwrap_or("");
        if !author_action.is_empty() && author_action != previous_author_action {
            let mut parts = author_action.splitn(3, '@');
            let action = parts.next().unwrap_or("REPAIR");
            let request = parts
                .next()
                .unwrap_or("")
                .split(',')
                .next()
                .unwrap_or("");
            let short = &request[..request.len().min(8)];
            let updated = if previous_author_action.is_empty() {
                ""
            } else {
                " updated"
            };
            report.items.push(NewsItem::Text(format!(
                "{action}{updated} [{id}] (request {short})"
            )));
            action_notified = true;
        }

        if action_notified {
            continue;
        }
        match old_goals.get(id) {
            None if !own_edit && addressed => {
                report
                    .items
                    .push(NewsItem::Text(format!("new goal [{id}] ({status})")))
            }
            Some((prev, _, _, _, _, _)) if prev != status && !own_edit && relevant => {
                report.items.push(NewsItem::Text(format!(
                    "goal [{id}]: {prev} → {status}"
                )))
            }
            _ => {}
        }
    }
    for person in new.roster.difference(&old.roster) {
        report
            .items
            .push(NewsItem::Text(format!("new person [{}]", fmt_id(*person))));
    }
    report
}

#[cfg(test)]
fn view_news(old: &WatchedView, new: &WatchedView, persona_id: Id) -> Vec<String> {
    view_news_report(old, new, persona_id).reasons()
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
) -> Result<Option<WatchedView>> {
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
            orient_state::persona: &persona_id,
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

    let unread: std::collections::BTreeSet<Id> = find!(
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
    let roster: std::collections::BTreeSet<Id> = find!(
        person: Id,
        pattern!(&space, [{ checkpoint_id @ orient_state::roster_member: ?person }])
    )
    .collect();

    Ok(Some(WatchedView {
        unread,
        goals_view,
        roster,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReviewWatermark {
    id: Id,
    heads: BTreeSet<Id>,
    deadline: Option<i128>,
}

/// Should an owed-review assignment be suppressed given the persona's
/// watermark? `acked_heads` + `deadline` are the state recorded at
/// delivery/ack/snooze time; `heads` is the assignment's *current* attestation
/// head-set; `now` is the current interval key. Quiet iff the acked head-set
/// still matches AND either it was a plain ack (no deadline) or the snooze
/// deadline is still in the future. Any head change (malformed/forked
/// transition, a fresh attestation) breaks the match and re-surfaces the review
/// regardless of a live snooze — state changes always win over a timer.
fn watermark_quiet(
    acked_heads: &BTreeSet<Id>,
    deadline: Option<i128>,
    heads: &BTreeSet<Id>,
    now: i128,
) -> bool {
    *acked_heads == *heads
        && match deadline {
            None => true,         // plain ack: quiet until the head-set changes
            Some(d) => now <= d,  // snooze: quiet until the deadline passes
        }
}

/// Apply delivery/ack/snooze watermarks to the derived review assignments and
/// return the earliest deadline whose passage can change the filtered view.
/// Only a live snooze with an exactly matching active head-set is relevant:
/// stale-head watermarks are already visible edges, plain acks have no clock
/// edge, and fulfilled/stale requests are absent from `actions` altogether.
fn apply_review_watermarks(
    actions: &mut BTreeMap<Id, PersonaGoalReview>,
    watermarks: &BTreeMap<Id, ReviewWatermark>,
    now: i128,
) -> Option<i128> {
    let mut next_deadline: Option<i128> = None;
    for review in actions.values_mut() {
        review.assignments.retain(|request, heads| {
            let Some(watermark) = watermarks.get(request) else {
                return true;
            };
            if !watermark_quiet(&watermark.heads, watermark.deadline, heads, now) {
                return true;
            }
            if let Some(deadline) = watermark.deadline {
                next_deadline = Some(next_deadline.map_or(deadline, |next| next.min(deadline)));
            }
            false
        });
    }
    next_deadline
}

/// Load this persona's review watermarks (delivery/ack/snooze) from the
/// orient-state branch, reduced latest-wins per request. Returns
/// `request -> { event id, acked head-set, optional snooze deadline key }`.
/// Empty when the branch has no head yet.
#[cfg(test)]
fn load_review_watermarks(
    repo: &mut Repository<Pile>,
    orient_state_branch_id: Id,
    persona_id: Id,
) -> Result<BTreeMap<Id, ReviewWatermark>> {
    Ok(load_review_watermark_snapshot(repo, orient_state_branch_id, persona_id)?.1)
}

fn load_review_watermark_snapshot(
    repo: &mut Repository<Pile>,
    orient_state_branch_id: Id,
    persona_id: Id,
) -> Result<(Option<CommitHandle>, BTreeMap<Id, ReviewWatermark>)> {
    let Some(_head) = repo
        .storage_mut()
        .head(orient_state_branch_id)
        .map_err(|e| anyhow!("orient state branch head: {e:?}"))?
    else {
        return Ok((None, BTreeMap::new()));
    };
    let mut ws = repo
        .pull(orient_state_branch_id)
        .map_err(|e| anyhow!("pull orient state workspace: {e:?}"))?;
    let head = ws.head();
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout orient state: {e:?}"))?;

    Ok((head, review_watermarks_from_space(&space, persona_id)))
}

fn review_watermarks_from_space(
    space: &TribleSet,
    persona_id: Id,
) -> BTreeMap<Id, ReviewWatermark> {
    // Latest watermark event per request. Explicit reader intent wins an
    // equal-timestamp offline merge against automatic delivery; the intrinsic
    // event id remains the deterministic final tie-break within each class.
    let mut latest: BTreeMap<Id, (i128, bool, Id)> = BTreeMap::new();
    for (wm_id, request, at) in find!(
        (wm_id: Id, request: Id, at: IntervalValue),
        pattern!(space, [{
            ?wm_id @
            metadata::tag: &KIND_REVIEW_WATERMARK_ID,
            orient_state::persona: &persona_id,
            orient_state::wm_request: ?request,
            orient_state::at: ?at,
        }])
    ) {
        let key = interval_key(at);
        let explicit = !exists!(pattern!(space, [{
            wm_id @ orient_state::wm_delivery_checkpoint: _?checkpoint
        }]));
        latest
            .entry(request)
            .and_modify(|entry| {
                if (key, explicit, wm_id) > *entry {
                    *entry = (key, explicit, wm_id);
                }
            })
            .or_insert((key, explicit, wm_id));
    }

    // Read the winning watermark's acked head-set + optional snooze deadline.
    let mut out = BTreeMap::new();
    for (request, (_at, _explicit, wm_id)) in latest {
        let heads: BTreeSet<Id> = find!(
            h: Id,
            pattern!(space, [{ wm_id @ orient_state::wm_head: ?h }])
        )
        .collect();
        let deadline: Option<i128> = find!(
            d: IntervalValue,
            pattern!(space, [{ wm_id @ orient_state::wm_deadline: ?d }])
        )
        .next()
        .map(interval_key);
        out.insert(
            request,
            ReviewWatermark {
                id: wm_id,
                heads,
                deadline,
            },
        );
    }
    out
}

fn save_checkpoint_heads(
    repo: &mut Repository<Pile>,
    orient_state_branch_id: Id,
    heads: &WatchedHeads,
    persona_view: Option<(Id, &WatchedView)>,
) -> Result<Option<CommitHandle>> {
    save_checkpoint(
        repo,
        orient_state_branch_id,
        heads,
        persona_view,
        &BTreeMap::new(),
        &BTreeMap::new(),
    )
}

/// Advance the persona checkpoint and append every surfaced review's exact
/// active head-set in one orient-state commit. This makes delivery itself the
/// reader watermark: re-arming sees unchanged pending work as standing state,
/// while a successor request or any head-set change breaks the match and wakes
/// again. The orient-state branch is not a watched input, so this own write is
/// absorbed rather than becoming a fresh wake.
fn save_checkpoint_with_review_deliveries(
    repo: &mut Repository<Pile>,
    orient_state_branch_id: Id,
    heads: &WatchedHeads,
    persona_id: Id,
    view: &WatchedView,
    review_deliveries: &BTreeMap<Id, BTreeSet<Id>>,
    observed_review_watermarks: &BTreeMap<Id, Id>,
) -> Result<Option<CommitHandle>> {
    save_checkpoint(
        repo,
        orient_state_branch_id,
        heads,
        Some((persona_id, view)),
        review_deliveries,
        observed_review_watermarks,
    )
}

fn save_checkpoint(
    repo: &mut Repository<Pile>,
    orient_state_branch_id: Id,
    heads: &WatchedHeads,
    persona_view: Option<(Id, &WatchedView)>,
    review_deliveries: &BTreeMap<Id, BTreeSet<Id>>,
    observed_review_watermarks: &BTreeMap<Id, Id>,
) -> Result<Option<CommitHandle>> {
    save_checkpoint_inner(
        repo,
        orient_state_branch_id,
        heads,
        persona_view,
        review_deliveries,
        observed_review_watermarks,
        |_, _| Ok(()),
    )
}

/// Checkpoint implementation with a deterministic pre-push seam used to prove
/// that a real orient-state CAS conflict cannot overwrite explicit reader
/// intent. Production supplies a no-op.
fn save_checkpoint_inner<F>(
    repo: &mut Repository<Pile>,
    orient_state_branch_id: Id,
    heads: &WatchedHeads,
    persona_view: Option<(Id, &WatchedView)>,
    review_deliveries: &BTreeMap<Id, BTreeSet<Id>>,
    observed_review_watermarks: &BTreeMap<Id, Id>,
    mut before_push: F,
) -> Result<Option<CommitHandle>>
where
    F: FnMut(&mut Repository<Pile>, usize) -> Result<()>,
{
    if !review_deliveries.is_empty() && persona_view.is_none() {
        bail!("review deliveries require a persona-scoped checkpoint");
    }
    let mut ws = repo
        .pull(orient_state_branch_id)
        .map_err(|e| anyhow!("pull orient state workspace: {e:?}"))?;
    let mut attempt = 0usize;

    loop {
        // Only auto-watermark against the orient-state snapshot used to build
        // the digest. If an explicit ack/snooze (or another delivery) landed
        // concurrently, the latest event id differs and wins; retrying never
        // overwrites that newer reader intent.
        let eligible_deliveries: BTreeMap<Id, BTreeSet<Id>> =
            if let Some((persona_id, _)) = persona_view {
                if review_deliveries.is_empty() {
                    BTreeMap::new()
                } else {
                    let current_space = ws
                        .checkout(..)
                        .map_err(|e| anyhow!("checkout orient state for delivery: {e:?}"))?;
                    let current = review_watermarks_from_space(&current_space, persona_id);
                    review_deliveries
                        .iter()
                        .filter(|(request, _)| {
                            current.get(*request).map(|watermark| watermark.id)
                                == observed_review_watermarks.get(*request).copied()
                        })
                        .map(|(request, heads)| (*request, heads.clone()))
                        .collect()
                }
            } else {
                BTreeMap::new()
            };

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
        if let Some((persona_id, view)) = persona_view {
            let goals_handle = ws.put(view.goals_view.clone());
            change += entity! { &checkpoint_id @
                orient_state::persona: &persona_id,
                orient_state::goals_view: goals_handle,
                orient_state::unread_msg*: view.unread.iter(),
                orient_state::roster_member*: view.roster.iter(),
            };
            for (request, review_heads) in &eligible_deliveries {
                let watermark_id = ufoid();
                change += entity! { &watermark_id @
                    metadata::tag: &KIND_REVIEW_WATERMARK_ID,
                    orient_state::persona: &persona_id,
                    orient_state::wm_request: request,
                    orient_state::wm_head*: review_heads.iter(),
                    orient_state::wm_delivery_checkpoint: &checkpoint_id,
                    orient_state::at: now,
                };
            }
        }

        let message = if eligible_deliveries.is_empty() {
            "orient checkpoint"
        } else {
            "orient checkpoint and review delivery"
        };
        ws.commit(change, message);
        before_push(repo, attempt)?;
        attempt += 1;
        match repo
            .try_push(&mut ws)
            .map_err(|e| anyhow!("push orient checkpoint: {e:?}"))?
        {
            None => return Ok(ws.head()),
            Some(conflict) => ws = conflict,
        }
    }
}

fn branch_head_by_id(
    repo: &mut Repository<Pile>,
    branch_id: Id,
) -> Result<Option<CommitHandle>> {
    repo.storage_mut()
        .head(branch_id)
        .map_err(|e| anyhow!("branch head {:x}: {e:?}", branch_id))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitBoundary {
    Timeout,
    ReviewDeadline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WaitStep {
    delay: Duration,
    /// Earliest non-poll boundary planned before sleeping. Retaining this is
    /// what lets a coarse Poll overshoot dispatch timeout vs review in their
    /// original order instead of whichever clock is checked first afterward.
    semantic_boundary: Option<WaitBoundary>,
}

/// Duration until `now > deadline`, matching `watermark_quiet`'s inclusive
/// deadline. At exact equality this is one nanosecond, never a zero-delay busy
/// loop; an already-expired deadline is immediately due.
fn duration_until_after(now: i128, deadline: i128) -> Duration {
    let nanos = deadline.saturating_sub(now).saturating_add(1);
    if nanos <= 0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

/// Pick the next sleep duration while preserving the earliest semantic edge
/// independently of a shorter coarse poll. Timeout wins an exact tie; a
/// strictly earlier review deadline remains authoritative even if sleep
/// overshoots both semantic boundaries.
fn plan_wait_step(
    poll: Duration,
    timeout_remaining: Option<Duration>,
    now: i128,
    review_deadline: Option<i128>,
) -> WaitStep {
    let mut step = WaitStep {
        delay: poll,
        semantic_boundary: None,
    };
    if let Some(remaining) = timeout_remaining {
        step.semantic_boundary = Some(WaitBoundary::Timeout);
        step.delay = step.delay.min(remaining);
    }
    if let Some(deadline) = review_deadline {
        let remaining = duration_until_after(now, deadline);
        let review_is_semantically_first =
            timeout_remaining.is_none_or(|timeout| remaining < timeout);
        if review_is_semantically_first {
            step.semantic_boundary = Some(WaitBoundary::ReviewDeadline);
        }
        step.delay = step.delay.min(remaining);
    }
    step
}

/// Resolve semantic edges that are actually due after a possibly-overshooting
/// sleep. When both clocks passed during a coarse Poll, use their order from
/// the pre-sleep plan; timeout wins an exact tie.
fn due_wait_boundary(
    step: WaitStep,
    timeout_due: bool,
    review_deadline_due: bool,
) -> Option<WaitBoundary> {
    match (timeout_due, review_deadline_due) {
        (true, true) => step.semantic_boundary.or(Some(WaitBoundary::Timeout)),
        (true, false) => Some(WaitBoundary::Timeout),
        (false, true) => Some(WaitBoundary::ReviewDeadline),
        (false, false) => None,
    }
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
#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchBaseline {
    view: WatchedView,
    orient_state_head: Option<CommitHandle>,
    next_review_deadline: Option<i128>,
}

enum NewsCheck {
    /// News was printed tersely and the checkpoint advanced.
    Fired,
    /// A checkpoint exists and nothing is new. Carries the freshly
    /// loaded view so `wait` can use it as its loop baseline.
    Quiet(WatchBaseline),
    /// No checkpoint for this persona yet — the caller decides how to
    /// establish the baseline (`wait` loops on the view; `poll` saves
    /// it silently).
    NoCheckpoint(WatchBaseline),
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
    let LoadedWatchedView {
        view,
        mut orient_state_head,
        review_watermark_ids,
        next_review_deadline,
    } = load_watched_snapshot(
        repo,
        persona_id,
        local_branch_id,
        compass_branch_id,
        relations_branch_id,
        orient_state_branch_id,
    )?;
    let Some(seen) = load_checkpoint_view(repo, orient_state_branch_id, persona_id)? else {
        return Ok(NewsCheck::NoCheckpoint(WatchBaseline {
            view,
            orient_state_head,
            next_review_deadline,
        }));
    };
    let report = view_news_report(&seen, &view, persona_id);
    if report.is_empty() {
        // Quiet removals still change the comparison baseline. Persist them so
        // a fulfilled assignment that is later re-added wakes even if the
        // watcher/poller restarted in between. Peek remains strictly read-only.
        if !peek && view != seen {
            orient_state_head = save_checkpoint_heads(
                repo,
                orient_state_branch_id,
                heads,
                Some((persona_id, &view)),
            )?;
        }
        return Ok(NewsCheck::Quiet(WatchBaseline {
            view,
            orient_state_head,
            next_review_deadline,
        }));
    }
    for reason in report.reasons() {
        println!("News: {reason}");
    }
    print_news_detail(repo, &seen, &view, local_branch_id, relations_branch_id)?;
    // Advance the checkpoint — the terse path skips cmd_show, which is
    // what normally saves it. Without this the checkpoint never moves
    // and every re-arm / next poll instantly re-fires on the same news.
    // Peek mode skips the save: report without consuming, for hooks that
    // can't tell whose turn they fire on (root vs subagent).
    if !peek {
        let deliveries = report.review_deliveries();
        save_checkpoint_with_review_deliveries(
            repo,
            orient_state_branch_id,
            heads,
            persona_id,
            &view,
            &deliveries,
            &review_watermark_ids,
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
            NewsCheck::NoCheckpoint(baseline) => {
                if !peek {
                    save_checkpoint_heads(
                        repo,
                        orient_state_branch_id,
                        &heads,
                        Some((persona_id, &baseline.view)),
                    )?;
                }
                let _ = baseline;
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
    cmd_wait_inner(
        pile,
        persona,
        target,
        (message_limit, doing_limit, todo_limit),
        poll_ms,
        |_| Ok(()),
    )
}

fn cmd_wait_inner<F>(
    pile: &Path,
    persona: Option<&str>,
    target: Option<WaitTarget>,
    limits: (usize, usize, usize),
    poll_ms: u64,
    after_baseline: F,
) -> Result<()>
where
    F: FnOnce(&mut Repository<Pile>) -> Result<()>,
{
    // Production supplies a no-op. Tests use this seam to append orient-state
    // immediately after the wait has frozen its baseline/head, without a
    // scheduler race or arbitrary thread sleep.
    let (message_limit, doing_limit, todo_limit) = limits;
    let timeout = parse_wait_target(target.as_ref())?;
    let (detected_change_before_wait, changed, news_printed) = with_repo(pile, move |repo| {
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
                NewsCheck::Quiet(baseline) | NewsCheck::NoCheckpoint(baseline) => {
                    Some(baseline)
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
        let mut baseline_orient_head = baseline_view
            .as_ref()
            .and_then(|baseline| baseline.orient_state_head);
        after_baseline(repo)?;

        let poll = Duration::from_millis(poll_ms.max(1));
        let start = Instant::now();

        loop {
            let timeout_remaining = timeout.map(|limit| limit.saturating_sub(start.elapsed()));
            let now = interval_key(epoch_interval(now_epoch()));
            let review_deadline = baseline_view
                .as_ref()
                .and_then(|baseline| baseline.next_review_deadline);
            let step = plan_wait_step(poll, timeout_remaining, now, review_deadline);
            if !step.delay.is_zero() {
                std::thread::sleep(step.delay);
            }
            let timeout_due = timeout.is_some_and(|limit| start.elapsed() >= limit);
            let now = interval_key(epoch_interval(now_epoch()));
            let review_deadline_due = baseline_view
                .as_ref()
                .and_then(|baseline| baseline.next_review_deadline)
                .is_some_and(|deadline| now > deadline);
            if due_wait_boundary(step, timeout_due, review_deadline_due)
                == Some(WaitBoundary::Timeout)
            {
                return Ok((false, false, false));
            }
            let current_heads = load_watched_heads(
                repo,
                local_branch_id,
                compass_branch_id,
                relations_branch_id,
            )?;
            let current_orient_head = if persona_id.is_some() {
                branch_head_by_id(repo, orient_state_branch_id)?
            } else {
                None
            };
            let orient_state_changed = current_orient_head != baseline_orient_head;
            if current_heads == baseline_heads
                && !review_deadline_due
                && !orient_state_changed
            {
                continue;
            }
            match (persona_id, baseline_view.as_mut()) {
                (Some(pid), Some(baseline)) => {
                    let LoadedWatchedView {
                        view: current_view,
                        orient_state_head,
                        review_watermark_ids,
                        next_review_deadline,
                    } = load_watched_snapshot(
                        repo,
                        pid,
                        local_branch_id,
                        compass_branch_id,
                        relations_branch_id,
                        orient_state_branch_id,
                    )?;
                    let report = view_news_report(&baseline.view, &current_view, pid);
                    if !report.is_empty() {
                        for reason in report.reasons() {
                            println!("News: {reason}");
                        }
                        print_news_detail(
                            repo,
                            &baseline.view,
                            &current_view,
                            local_branch_id,
                            relations_branch_id,
                        )?;
                        // Advance the checkpoint and mark every review included
                        // in the digest delivered at its exact active head-set.
                        let deliveries = report.review_deliveries();
                        save_checkpoint_with_review_deliveries(
                            repo,
                            orient_state_branch_id,
                            &current_heads,
                            pid,
                            &current_view,
                            &deliveries,
                            &review_watermark_ids,
                        )?;
                        return Ok((false, true, true));
                    }
                    // Movement without news (own ack/send, another
                    // persona's traffic, fulfilled review work) — absorb it
                    // and keep waiting. Persist changed quiet views so a
                    // removal followed by a restart and re-add still wakes.
                    let mut refreshed_orient_head = orient_state_head;
                    if baseline.view != current_view {
                        refreshed_orient_head = save_checkpoint_heads(
                            repo,
                            orient_state_branch_id,
                            &current_heads,
                            Some((pid, &current_view)),
                        )?;
                    }
                    baseline_heads = current_heads;
                    baseline_orient_head = refreshed_orient_head;
                    baseline.view = current_view;
                    baseline.orient_state_head = refreshed_orient_head;
                    baseline.next_review_deadline = next_review_deadline;
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
        Command::Poll { peek } => cmd_poll(&cli.pile, cli.persona.as_deref(), peek),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn view(goals_view: impl Into<String>) -> WatchedView {
        WatchedView {
            unread: BTreeSet::new(),
            goals_view: goals_view.into(),
            roster: BTreeSet::new(),
        }
    }

    struct ReviewFixture {
        path: PathBuf,
        repo: Repository<Pile>,
        local_branch: Id,
        compass_branch: Id,
        relations_branch: Id,
        orient_branch: Id,
        persona: Id,
        request: Id,
        initial_head: Option<Id>,
    }

    fn review_fixture(with_malformed_head: bool) -> ReviewFixture {
        use faculties::schemas::compass::{
            review_attestation_fragment, review_request_fragment,
        };
        use faculties::schemas::relations::KIND_PERSON_ID;

        let path = std::env::temp_dir().join(format!("orient-review-{:x}.pile", ufoid().id));
        std::fs::File::create(&path).expect("create temp pile");
        let mut repo = open_repo(&path).expect("open repo");
        let local_branch = repo.ensure_branch("message", None).expect("message branch");
        let compass_branch = repo.ensure_branch("compass", None).expect("compass branch");
        let relations_branch = repo
            .ensure_branch("relations", None)
            .expect("relations branch");
        let orient_branch = repo
            .ensure_branch("orient-state", None)
            .expect("orient branch");
        let persona = ufoid().id;
        let author = ufoid().id;
        let third = ufoid().id;
        let goal = ufoid().id;

        let mut relations_ws = repo.pull(relations_branch).expect("pull relations");
        let mut people = TribleSet::new();
        for person in [persona, author, third] {
            people += entity! { ExclusiveId::force_ref(&person) @
                metadata::tag: &KIND_PERSON_ID,
                rel_attrs::affinity: "zooid",
            };
        }
        relations_ws.commit(people, "test review people");
        repo.push(&mut relations_ws).expect("push relations");

        let mut compass_ws = repo.pull(compass_branch).expect("pull compass");
        let target = compass_ws.put("urn:test:orient-review".to_string());
        let created_at = epoch_interval(now_epoch());
        let request_fragment = review_request_fragment(
            goal,
            author,
            target,
            &[author, persona, third],
            &[],
            &[],
            created_at,
        );
        let request = request_fragment.root().expect("request root");
        let mut board = TribleSet::new();
        board += entity! { ExclusiveId::force_ref(&goal) @ metadata::tag: &KIND_GOAL_ID };
        board += request_fragment;
        let initial_head = with_malformed_head.then(|| {
            let report = compass_ws.put("malformed h1".to_string());
            let attestation = review_attestation_fragment(
                request,
                persona,
                "malformed-h1",
                report,
                &[],
                created_at,
            );
            let id = attestation.root().expect("attestation root");
            board += attestation;
            id
        });
        compass_ws.commit(board, "test pending review");
        repo.push(&mut compass_ws).expect("push compass");

        ReviewFixture {
            path,
            repo,
            local_branch,
            compass_branch,
            relations_branch,
            orient_branch,
            persona,
            request,
            initial_head,
        }
    }

    fn remove_fixture(fixture: ReviewFixture) {
        fixture.repo.close().ok();
        let _ = std::fs::remove_file(fixture.path);
    }

    fn write_test_watermark(
        repo: &mut Repository<Pile>,
        orient_branch: Id,
        persona: Id,
        request: Id,
        deadline: Option<Epoch>,
        review_heads: &[Id],
    ) -> Id {
        let watermark = ufoid();
        let mut orient = repo.pull(orient_branch).expect("pull fixture orient");
        let deadline = deadline.map(epoch_interval);
        let mut change = TribleSet::new();
        change += entity! { &watermark @
            metadata::tag: &KIND_REVIEW_WATERMARK_ID,
            orient_state::persona: &persona,
            orient_state::wm_request: &request,
            orient_state::wm_head*: review_heads.iter(),
            orient_state::wm_deadline?: deadline,
            orient_state::at: epoch_interval(now_epoch()),
        };
        orient.commit(change, "test fixture review watermark");
        repo.push(&mut orient).expect("push fixture watermark");
        watermark.id
    }

    fn write_fixture_snooze(
        fixture: &mut ReviewFixture,
        deadline: Epoch,
        review_heads: &[Id],
    ) -> Id {
        write_test_watermark(
            &mut fixture.repo,
            fixture.orient_branch,
            fixture.persona,
            fixture.request,
            Some(deadline),
            review_heads,
        )
    }

    #[test]
    fn old_four_field_checkpoint_parses_and_new_review_wakes() {
        let me = ufoid().id;
        let other = ufoid().id;
        let goal = ufoid().id;
        let request = ufoid().id;
        let old = view(format!("{goal:x}:review:{other:x}:i"));
        let new = view(format!("{goal:x}:review:{other:x}:ir:{request:x}"));

        let news = view_news(&old, &new, me);
        assert_eq!(news.len(), 1);
        assert!(news[0].contains("REVIEW"));
    }

    #[test]
    fn old_six_field_existing_assignment_upgrades_quietly() {
        let me = ufoid().id;
        let other = ufoid().id;
        let goal = ufoid().id;
        let request = ufoid().id;
        let old = view(format!("{goal:x}:review:{other:x}:r:{request:x}:"));
        let new = view(format!(
            "{goal:x}:review:{other:x}:r:{request:x}::{request:x}@-"
        ));

        assert!(view_news(&old, &new, me).is_empty());
    }

    #[test]
    fn non_required_persona_is_quiet() {
        let me = ufoid().id;
        let other = ufoid().id;
        let goal = ufoid().id;
        let old = view(format!("{goal:x}:doing:{other:x}:"));
        let new = view(format!("{goal:x}:review:{other:x}:"));

        assert!(view_news(&old, &new, me).is_empty());
    }

    #[test]
    fn own_review_open_does_not_wake_author() {
        let me = ufoid().id;
        let goal = ufoid().id;
        let request = ufoid().id;
        let old = view(format!("{goal:x}:doing:{me:x}:i:"));
        let new = view(format!("{goal:x}:review:{me:x}:ir:{request:x}"));

        assert!(view_news(&old, &new, me).is_empty());
    }

    #[test]
    fn unchanged_review_assignment_is_quiet() {
        let me = ufoid().id;
        let other = ufoid().id;
        let goal = ufoid().id;
        let request = ufoid().id;
        let line = format!("{goal:x}:review:{other:x}:r:{request:x}::{request:x}@-");

        assert!(view_news(&view(line.clone()), &view(line), me).is_empty());
    }

    #[test]
    fn malformed_or_forked_attestation_heads_rewake_reviewer() {
        let me = ufoid().id;
        let other = ufoid().id;
        let goal = ufoid().id;
        let request = ufoid().id;
        let malformed = ufoid().id;
        let concurrent = ufoid().id;
        let pending = view(format!(
            "{goal:x}:review:{other:x}:r:{request:x}::{request:x}@-"
        ));
        let one_bad_head = view(format!(
            "{goal:x}:review:{other:x}:r:{request:x}::{request:x}@{malformed:x}"
        ));
        let forked = view(format!(
            "{goal:x}:review:{other:x}:r:{request:x}::{request:x}@{malformed:x}+{concurrent:x}"
        ));

        let news = view_news(&pending, &one_bad_head, me);
        assert_eq!(news.len(), 1);
        assert!(news[0].contains("updated"));

        let news = view_news(&one_bad_head, &forked, me);
        assert_eq!(news.len(), 1);
        assert!(news[0].contains("updated"));
    }

    #[test]
    fn successor_request_re_notifies_reviewer() {
        let me = ufoid().id;
        let other = ufoid().id;
        let goal = ufoid().id;
        let first = Id::from_hex("11111111111111111111111111111111").unwrap();
        let second = Id::from_hex("22222222222222222222222222222222").unwrap();
        let old = view(format!("{goal:x}:review:{other:x}:r:{first:x}"));
        let new = view(format!("{goal:x}:review:{other:x}:r:{second:x}"));

        let news = view_news(&old, &new, me);
        assert_eq!(news.len(), 1);
        assert!(news[0].contains("REVIEW"));
        assert!(news[0].contains(&fmt_id(second)[..8]));
    }

    #[test]
    fn fulfilled_assignment_removal_is_not_news() {
        let me = ufoid().id;
        let other = ufoid().id;
        let goal = ufoid().id;
        let request = ufoid().id;
        let old = view(format!("{goal:x}:review:{other:x}:r:{request:x}"));
        let new = view(format!("{goal:x}:review:{other:x}::"));

        assert!(view_news(&old, &new, me).is_empty());
    }

    #[test]
    fn removing_one_of_two_assignments_does_not_false_wake() {
        let me = ufoid().id;
        let other = ufoid().id;
        let goal = ufoid().id;
        let first = ufoid().id;
        let second = ufoid().id;
        let old = view(format!(
            "{goal:x}:review:{other:x}:r:{first:x},{second:x}:"
        ));
        let new = view(format!("{goal:x}:review:{other:x}:r:{second:x}:"));

        assert!(view_news(&old, &new, me).is_empty());
    }

    #[test]
    fn only_newly_added_assignment_id_wakes() {
        let me = ufoid().id;
        let other = ufoid().id;
        let goal = ufoid().id;
        let first = Id::from_hex("11111111111111111111111111111111").unwrap();
        let second = Id::from_hex("22222222222222222222222222222222").unwrap();
        let old = view(format!("{goal:x}:review:{other:x}:r:{first:x}:"));
        let new = view(format!(
            "{goal:x}:review:{other:x}:r:{first:x},{second:x}:"
        ));

        let news = view_news(&old, &new, me);
        assert_eq!(news.len(), 1);
        assert!(news[0].contains(&fmt_id(second)[..8]));
        assert!(!news[0].contains(&fmt_id(first)[..8]));
    }

    #[test]
    fn multiple_review_edges_render_one_digest_and_capture_exact_heads() {
        let me = ufoid().id;
        let other = ufoid().id;
        let goal_a = ufoid().id;
        let goal_b = ufoid().id;
        let request_a = Id::from_hex("11111111111111111111111111111111").unwrap();
        let request_b = Id::from_hex("22222222222222222222222222222222").unwrap();
        let head_a = ufoid().id;
        let head_b = ufoid().id;
        let old = view(format!(
            "{goal_a:x}:doing:{other:x}:i:\n{goal_b:x}:doing:{other:x}:i:"
        ));
        let new = view(format!(
            "{goal_a:x}:review:{other:x}:ir:{request_a:x}::{request_a:x}@-\n\
             {goal_b:x}:review:{other:x}:ir:{request_b:x}::{request_b:x}@{head_a:x}+{head_b:x}"
        ));

        let report = view_news_report(&old, &new, me);
        let reasons = report.reasons();
        assert_eq!(reasons.len(), 1, "all reviewer work is one digest");
        assert!(reasons[0].starts_with("REVIEWS (2 pending)"));
        assert!(reasons[0].contains(&fmt_id(request_a)[..8]));
        assert!(reasons[0].contains(&fmt_id(request_b)[..8]));

        let deliveries = report.review_deliveries();
        assert_eq!(deliveries.len(), 2);
        assert_eq!(deliveries.get(&request_a), Some(&BTreeSet::new()));
        assert_eq!(
            deliveries.get(&request_b),
            Some(&BTreeSet::from([head_a, head_b]))
        );
    }

    #[test]
    fn review_digest_keeps_direct_and_group_message_edges_prompt() {
        let me = ufoid().id;
        let other = ufoid().id;
        let group = ufoid().id;
        let direct_message = ufoid().id;
        let group_message = ufoid().id;
        let goal = ufoid().id;
        let request = ufoid().id;
        let groups = HashSet::from([group]);
        assert!(is_inbox_message(other, me, me, &groups));
        assert!(is_inbox_message(other, group, me, &groups));

        let old = view("");
        let mut new = view(format!(
            "{goal:x}:review:{other:x}:r:{request:x}::{request:x}@-"
        ));
        new.unread = BTreeSet::from([direct_message, group_message]);
        let reasons = view_news_report(&old, &new, me).reasons();

        assert_eq!(
            reasons
                .iter()
                .filter(|reason| reason.starts_with("new message"))
                .count(),
            2
        );
        assert_eq!(
            reasons
                .iter()
                .filter(|reason| reason.starts_with("REVIEWS"))
                .count(),
            1
        );
    }

    #[test]
    fn delivered_review_is_quiet_until_a_real_head_edge() {
        let me = ufoid().id;
        let other = ufoid().id;
        let goal = ufoid().id;
        let request = ufoid().id;
        let first_head = ufoid().id;
        let second_head = ufoid().id;
        let empty = view("");
        let first = view(format!(
            "{goal:x}:review:{other:x}:r:{request:x}::{request:x}@{first_head:x}"
        ));
        let first_report = view_news_report(&empty, &first, me);
        let first_delivery = first_report.review_deliveries();
        let first_watermark = first_delivery[&request].clone();
        assert!(watermark_quiet(
            &first_watermark,
            None,
            &BTreeSet::from([first_head]),
            0
        ));

        let changed = view(format!(
            "{goal:x}:review:{other:x}:r:{request:x}::{request:x}@{first_head:x}+{second_head:x}"
        ));
        assert!(!watermark_quiet(
            &first_watermark,
            None,
            &BTreeSet::from([first_head, second_head]),
            0
        ));
        let changed_report = view_news_report(&first, &changed, me);
        let reasons = changed_report.reasons();
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("updated"));
        assert_eq!(
            changed_report.review_deliveries().get(&request),
            Some(&BTreeSet::from([first_head, second_head]))
        );
    }

    #[test]
    fn quiet_removal_then_readd_wakes_from_updated_baseline() {
        let me = ufoid().id;
        let other = ufoid().id;
        let goal = ufoid().id;
        let request = ufoid().id;
        let assigned = view(format!("{goal:x}:review:{other:x}:r:{request:x}:"));
        let fulfilled = view(format!("{goal:x}:review:{other:x}:::"));

        assert!(view_news(&assigned, &fulfilled, me).is_empty());
        let news = view_news(&fulfilled, &assigned, me);
        assert_eq!(news.len(), 1);
        assert!(news[0].contains("REVIEW"));
    }

    #[test]
    fn author_state_transition_wakes_even_when_status_author_is_self() {
        let me = ufoid().id;
        let goal = ufoid().id;
        let request = ufoid().id;
        let blocker = ufoid().id;
        let approval = ufoid().id;
        let old = view(format!(
            "{goal:x}:review:{me:x}:ir::REVISE@{request:x}@{blocker:x}"
        ));
        let new = view(format!(
            "{goal:x}:review:{me:x}:ir::SETTLE@{request:x}@{approval:x}"
        ));

        let news = view_news(&old, &new, me);
        assert_eq!(news.len(), 1);
        assert!(news[0].contains("SETTLE updated"));
    }

    #[test]
    fn replacement_blocker_re_notifies_author() {
        let me = ufoid().id;
        let goal = ufoid().id;
        let request = ufoid().id;
        let first = ufoid().id;
        let second = ufoid().id;
        let old = view(format!(
            "{goal:x}:review:{me:x}:ir::REVISE@{request:x}@{first:x}"
        ));
        let new = view(format!(
            "{goal:x}:review:{me:x}:ir::REVISE@{request:x}@{second:x}"
        ));

        let news = view_news(&old, &new, me);
        assert_eq!(news.len(), 1);
        assert!(news[0].contains("REVISE updated"));
    }

    #[test]
    fn fork_repair_action_wakes_its_author() {
        let me = ufoid().id;
        let goal = ufoid().id;
        let first = Id::from_hex("11111111111111111111111111111111").unwrap();
        let second = Id::from_hex("22222222222222222222222222222222").unwrap();
        let old = view(format!("{goal:x}:review:{me:x}:i::"));
        let new = view(format!(
            "{goal:x}:review:{me:x}:ir::REPAIR@{first:x},{second:x}@"
        ));

        let news = view_news(&old, &new, me);
        assert_eq!(news.len(), 1);
        assert!(news[0].contains("REPAIR"));
        assert!(news[0].contains(&fmt_id(first)[..8]));
    }

    #[test]
    fn completed_author_action_removal_is_quiet() {
        let me = ufoid().id;
        let goal = ufoid().id;
        let request = ufoid().id;
        let approval = ufoid().id;
        let old = view(format!(
            "{goal:x}:review:{me:x}:ir::SETTLE@{request:x}@{approval:x}"
        ));
        let new = view(format!("{goal:x}:done:{me:x}:i::"));

        assert!(view_news(&old, &new, me).is_empty());
    }

    // --- Review watermark (ack/snooze) quiet-decision ------------------------

    fn heads(ids: &[Id]) -> BTreeSet<Id> {
        ids.iter().copied().collect()
    }

    #[test]
    fn plain_ack_is_quiet_while_heads_match() {
        let h = heads(&[ufoid().id]);
        // No deadline: quiet regardless of the clock, as long as heads match.
        assert!(watermark_quiet(&h, None, &h, 0));
        assert!(watermark_quiet(&h, None, &h, i128::MAX));
    }

    #[test]
    fn ack_re_surfaces_when_attestation_head_appears() {
        let existing = ufoid().id;
        let acked = heads(&[existing]);
        // A malformed/forked transition adds a head → the acked set no longer
        // matches → not quiet, so the review re-surfaces.
        let now_two = heads(&[existing, ufoid().id]);
        assert!(!watermark_quiet(&acked, None, &now_two, 0));
        // An attestation the reviewer later retracts (head removed) also breaks
        // the match — any change re-surfaces, not just growth.
        assert!(!watermark_quiet(&acked, None, &BTreeSet::new(), 0));
    }

    #[test]
    fn empty_headset_ack_stays_quiet_until_first_attestation() {
        // Pending review with no attestation yet: ack snapshots the empty set,
        // and stays quiet until the reviewer's first attestation head lands.
        assert!(watermark_quiet(
            &BTreeSet::new(),
            None,
            &BTreeSet::new(),
            0
        ));
        let posted = heads(&[ufoid().id]);
        assert!(!watermark_quiet(&BTreeSet::new(), None, &posted, 0));
    }

    #[test]
    fn snooze_is_quiet_before_deadline_and_wakes_after() {
        let h = heads(&[ufoid().id]);
        let deadline = 1_000i128;
        assert!(watermark_quiet(&h, Some(deadline), &h, 500)); // before
        assert!(watermark_quiet(&h, Some(deadline), &h, 1_000)); // at (<=)
        assert!(!watermark_quiet(&h, Some(deadline), &h, 1_001)); // after
    }

    #[test]
    fn head_change_overrides_a_live_snooze() {
        let existing = ufoid().id;
        let acked = heads(&[existing]);
        let changed = heads(&[existing, ufoid().id]);
        // Deadline is still in the future, but the state moved: state wins.
        assert!(!watermark_quiet(&acked, Some(i128::MAX), &changed, 0));
    }

    #[test]
    fn matching_live_snoozes_publish_only_the_earliest_relevant_deadline() {
        let goal = ufoid().id;
        let request_early = ufoid().id;
        let request_late = ufoid().id;
        let request_changed = ufoid().id;
        let head = ufoid().id;
        let changed_head = ufoid().id;
        let mut actions = BTreeMap::from([(
            goal,
            PersonaGoalReview {
                assignments: BTreeMap::from([
                    (request_early, BTreeSet::from([head])),
                    (request_late, BTreeSet::from([head])),
                    (request_changed, BTreeSet::from([changed_head])),
                ]),
                author: None,
            },
        )]);
        let watermarks = BTreeMap::from([
            (
                request_early,
                ReviewWatermark {
                    id: ufoid().id,
                    heads: BTreeSet::from([head]),
                    deadline: Some(100),
                },
            ),
            (
                request_late,
                ReviewWatermark {
                    id: ufoid().id,
                    heads: BTreeSet::from([head]),
                    deadline: Some(200),
                },
            ),
            (
                request_changed,
                ReviewWatermark {
                    id: ufoid().id,
                    heads: BTreeSet::from([head]),
                    deadline: Some(50),
                },
            ),
        ]);

        assert_eq!(apply_review_watermarks(&mut actions, &watermarks, 0), Some(100));
        assert_eq!(
            actions[&goal].assignments,
            BTreeMap::from([(request_changed, BTreeSet::from([changed_head]))]),
            "a stale-head watermark is a visible edge, not a scheduler deadline"
        );
    }

    #[test]
    fn wait_planner_respects_inclusive_deadlines_and_timeout_order() {
        let poll = Duration::from_secs(10);

        let at_equality = plan_wait_step(poll, None, 100, Some(100));
        assert_eq!(
            at_equality.semantic_boundary,
            Some(WaitBoundary::ReviewDeadline)
        );
        assert_eq!(at_equality.delay, Duration::from_nanos(1));
        assert!(!at_equality.delay.is_zero(), "deadline equality must not spin");

        assert_eq!(
            plan_wait_step(poll, None, 101, Some(100)),
            WaitStep {
                delay: Duration::ZERO,
                semantic_boundary: Some(WaitBoundary::ReviewDeadline),
            }
        );
        assert_eq!(
            plan_wait_step(poll, Some(Duration::from_secs(5)), 0, Some(999)),
            WaitStep {
                delay: Duration::from_nanos(1_000),
                semantic_boundary: Some(WaitBoundary::ReviewDeadline),
            },
            "a deadline before both coarse poll and timeout wins"
        );
        assert_eq!(
            plan_wait_step(
                poll,
                Some(Duration::from_nanos(500)),
                0,
                Some(999),
            ),
            WaitStep {
                delay: Duration::from_nanos(500),
                semantic_boundary: Some(WaitBoundary::Timeout),
            },
            "an earlier timeout wins"
        );
        assert_eq!(
            plan_wait_step(
                poll,
                Some(Duration::from_nanos(1_000)),
                0,
                Some(999),
            )
            .semantic_boundary,
            Some(WaitBoundary::Timeout),
            "timeout wins the exact tie because the snooze is quiet through equality"
        );
    }

    #[test]
    fn poll_overshoot_dispatches_the_saved_semantic_order() {
        let poll = Duration::from_nanos(10);

        let timeout_first = plan_wait_step(
            poll,
            Some(Duration::from_nanos(20)),
            0,
            Some(29),
        );
        assert_eq!(timeout_first.delay, poll, "Poll is the immediate edge");
        assert_eq!(
            due_wait_boundary(timeout_first, true, true),
            Some(WaitBoundary::Timeout),
            "a Poll overshoot must not let the later review edge mask timeout"
        );

        let review_first = plan_wait_step(
            poll,
            Some(Duration::from_nanos(30)),
            0,
            Some(19),
        );
        assert_eq!(review_first.delay, poll, "Poll is the immediate edge");
        assert_eq!(
            due_wait_boundary(review_first, true, true),
            Some(WaitBoundary::ReviewDeadline),
            "a Poll overshoot must not let the later timeout mask review"
        );

        let exact_tie = plan_wait_step(
            poll,
            Some(Duration::from_nanos(20)),
            0,
            Some(19),
        );
        assert_eq!(exact_tie.delay, poll, "Poll is the immediate edge");
        assert_eq!(
            due_wait_boundary(exact_tie, true, true),
            Some(WaitBoundary::Timeout),
            "timeout wins an exact semantic tie"
        );
    }

    fn run_post_baseline_snooze_case(initial_snooze: bool) {
        let mut fixture = review_fixture(false);
        let initial_deadline = initial_snooze.then(|| {
            now_epoch() + hifitime::Duration::from_total_nanoseconds(3_000_000_000)
        });
        write_test_watermark(
            &mut fixture.repo,
            fixture.orient_branch,
            fixture.persona,
            fixture.request,
            initial_deadline,
            &[],
        );
        let baseline = load_watched_snapshot(
            &mut fixture.repo,
            fixture.persona,
            fixture.local_branch,
            fixture.compass_branch,
            fixture.relations_branch,
            fixture.orient_branch,
        )
        .expect("load pre-injection baseline");
        assert!(
            !baseline
                .view
                .goals_view
                .contains(&format!("{:x}@", fixture.request)),
            "the matching ack/snooze must suppress the pending assignment"
        );
        match initial_deadline {
            Some(deadline) => assert_eq!(
                baseline.next_review_deadline,
                Some(interval_key(epoch_interval(deadline)))
            ),
            None => assert_eq!(
                baseline.next_review_deadline, None,
                "the key regression starts with no scheduled deadline"
            ),
        }
        let semantic_heads = load_watched_heads(
            &mut fixture.repo,
            fixture.local_branch,
            fixture.compass_branch,
            fixture.relations_branch,
        )
        .expect("pre-injection semantic heads");
        save_checkpoint_heads(
            &mut fixture.repo,
            fixture.orient_branch,
            &semantic_heads,
            Some((fixture.persona, &baseline.view)),
        )
        .expect("save pre-injection baseline");
        fixture.repo.close().expect("close fixture before wait");

        let persona = fmt_id(fixture.persona);
        let mut injected = None;
        let started = Instant::now();
        cmd_wait_inner(
            &fixture.path,
            Some(&persona),
            Some(WaitTarget::For {
                duration: "2s".to_string(),
            }),
            (1, 1, 1),
            20,
            |repo| {
                // This runs after cmd_wait has captured a quiet baseline and
                // its exact orient-state head. No semantic branch moves.
                let deadline =
                    now_epoch() + hifitime::Duration::from_total_nanoseconds(400_000_000);
                injected = Some(write_test_watermark(
                    repo,
                    fixture.orient_branch,
                    fixture.persona,
                    fixture.request,
                    Some(deadline),
                    &[],
                ));
                Ok(())
            },
        )
        .expect("post-baseline snooze wakes at its acquired deadline");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100),
            "a live snooze must not surface immediately: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(1_500),
            "the injected 400ms deadline must beat the 2s timeout: {elapsed:?}"
        );

        fixture.repo = open_repo(&fixture.path).expect("reopen post-baseline fixture");
        assert_eq!(
            load_watched_heads(
                &mut fixture.repo,
                fixture.local_branch,
                fixture.compass_branch,
                fixture.relations_branch,
            )
            .expect("post-wait semantic heads"),
            semantic_heads,
            "only orient-state moved while the wait acquired and expired the snooze"
        );
        let watermark = load_review_watermarks(
            &mut fixture.repo,
            fixture.orient_branch,
            fixture.persona,
        )
        .expect("load post-wake delivery")
        .remove(&fixture.request)
        .expect("request watermark after wake");
        assert_ne!(watermark.id, injected.expect("hook injected a watermark"));
        assert_eq!(watermark.deadline, None, "the request was delivered once");

        remove_fixture(fixture);
    }

    #[test]
    fn snooze_appended_after_deadline_free_baseline_is_acquired_and_wakes() {
        run_post_baseline_snooze_case(false);
    }

    #[test]
    fn shortened_snooze_appended_after_baseline_replaces_the_wait_plan() {
        run_post_baseline_snooze_case(true);
    }

    #[test]
    fn snooze_deadline_wakes_without_branch_movement_then_rearms_quietly() {
        let mut fixture = review_fixture(false);
        let deadline = now_epoch() + hifitime::Duration::from_total_nanoseconds(400_000_000);
        let explicit = write_fixture_snooze(&mut fixture, deadline, &[]);
        let baseline = load_watched_snapshot(
            &mut fixture.repo,
            fixture.persona,
            fixture.local_branch,
            fixture.compass_branch,
            fixture.relations_branch,
            fixture.orient_branch,
        )
        .expect("load snoozed baseline");
        assert!(!baseline
            .view
            .goals_view
            .contains(&format!("{:x}@", fixture.request)));
        assert_eq!(
            baseline.next_review_deadline,
            Some(interval_key(epoch_interval(deadline)))
        );
        let heads = load_watched_heads(
            &mut fixture.repo,
            fixture.local_branch,
            fixture.compass_branch,
            fixture.relations_branch,
        )
        .expect("baseline heads");
        save_checkpoint_heads(
            &mut fixture.repo,
            fixture.orient_branch,
            &heads,
            Some((fixture.persona, &baseline.view)),
        )
        .expect("save snoozed baseline");
        fixture.repo.close().expect("close fixture before wait");

        let persona = fmt_id(fixture.persona);
        let started = Instant::now();
        cmd_wait(
            &fixture.path,
            Some(&persona),
            Some(WaitTarget::For {
                duration: "3s".to_string(),
            }),
            1,
            1,
            1,
            2_000,
        )
        .expect("deadline wakes wait");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100),
            "wait must not surface a still-live 400ms snooze immediately: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(1_800),
            "the 400ms deadline must beat both a 2s poll and a 3s timeout: {elapsed:?}"
        );

        fixture.repo = open_repo(&fixture.path).expect("reopen fixture");
        let watermark = load_review_watermarks(
            &mut fixture.repo,
            fixture.orient_branch,
            fixture.persona,
        )
        .expect("load automatic delivery")
        .remove(&fixture.request)
        .expect("delivered request watermark");
        assert_ne!(watermark.id, explicit);
        assert_eq!(watermark.heads, BTreeSet::new());
        assert_eq!(watermark.deadline, None);

        // The delivered checkpoint still contains the surfaced assignment;
        // first rearm absorbs its watermark-filtered removal, second rearm is
        // fully unchanged. Neither may fire or create another watermark.
        let heads = load_watched_heads(
            &mut fixture.repo,
            fixture.local_branch,
            fixture.compass_branch,
            fixture.relations_branch,
        )
        .expect("rearm heads");
        assert!(matches!(
            check_news_once(
                &mut fixture.repo,
                fixture.persona,
                &heads,
                fixture.local_branch,
                fixture.compass_branch,
                fixture.relations_branch,
                fixture.orient_branch,
                false,
            )
            .expect("first quiet rearm"),
            NewsCheck::Quiet(_)
        ));
        assert!(matches!(
            check_news_once(
                &mut fixture.repo,
                fixture.persona,
                &heads,
                fixture.local_branch,
                fixture.compass_branch,
                fixture.relations_branch,
                fixture.orient_branch,
                false,
            )
            .expect("second quiet rearm"),
            NewsCheck::Quiet(_)
        ));
        assert_eq!(
            load_review_watermarks(
                &mut fixture.repo,
                fixture.orient_branch,
                fixture.persona,
            )
            .expect("watermark after quiet rearm")[&fixture.request]
                .id,
            watermark.id
        );

        remove_fixture(fixture);
    }

    #[test]
    fn checkpoint_and_review_digest_delivery_round_trip_together() {
        let path = std::env::temp_dir().join(format!("orient-delivery-{:x}.pile", ufoid().id));
        std::fs::File::create(&path).expect("create temp pile");
        let mut repo = open_repo(&path).expect("open repo");
        let orient_branch = repo
            .ensure_branch("orient-state", None)
            .expect("ensure orient-state");
        let persona = ufoid().id;
        let request_a = ufoid().id;
        let request_b = ufoid().id;
        let head_a = ufoid().id;
        let head_b = ufoid().id;
        let watched = view("checkpoint view");
        let deliveries = BTreeMap::from([
            (request_a, BTreeSet::new()),
            (request_b, BTreeSet::from([head_a, head_b])),
        ]);
        let watched_heads = WatchedHeads {
            local: None,
            compass: None,
            relations: None,
        };

        save_checkpoint_with_review_deliveries(
            &mut repo,
            orient_branch,
            &watched_heads,
            persona,
            &watched,
            &deliveries,
            &BTreeMap::new(),
        )
        .expect("save checkpoint + delivery");

        assert_eq!(
            load_checkpoint_view(&mut repo, orient_branch, persona)
                .expect("load checkpoint")
                .expect("checkpoint exists"),
            watched
        );
        let watermarks =
            load_review_watermarks(&mut repo, orient_branch, persona).expect("load watermarks");
        assert_eq!(watermarks.len(), 2);
        assert_eq!(watermarks[&request_a].heads, BTreeSet::new());
        assert_eq!(watermarks[&request_a].deadline, None);
        assert_eq!(
            watermarks[&request_b].heads,
            BTreeSet::from([head_a, head_b])
        );
        assert_eq!(watermarks[&request_b].deadline, None);

        repo.close().ok();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrent_explicit_snooze_wins_over_automatic_delivery() {
        let path = std::env::temp_dir().join(format!("orient-snooze-race-{:x}.pile", ufoid().id));
        std::fs::File::create(&path).expect("create temp pile");
        let mut repo = open_repo(&path).expect("open repo");
        let orient_branch = repo
            .ensure_branch("orient-state", None)
            .expect("ensure orient-state");
        let persona = ufoid().id;
        let request = ufoid().id;
        let review_head = ufoid().id;
        let snooze_id = ufoid();
        let deadline = now_epoch() + hifitime::Duration::from_total_nanoseconds(3_600_000_000_000);

        // This explicit snooze lands after the watcher constructed its view;
        // the watcher's observed watermark map is therefore still empty.
        let mut ws = repo.pull(orient_branch).expect("pull orient-state");
        let mut change = TribleSet::new();
        change += entity! { &snooze_id @
            metadata::tag: &KIND_REVIEW_WATERMARK_ID,
            orient_state::persona: &persona,
            orient_state::wm_request: &request,
            orient_state::wm_head: &review_head,
            orient_state::wm_deadline: epoch_interval(deadline),
            orient_state::at: epoch_interval(now_epoch()),
        };
        ws.commit(change, "test concurrent explicit snooze");
        repo.push(&mut ws).expect("push snooze");

        let watched_heads = WatchedHeads {
            local: None,
            compass: None,
            relations: None,
        };
        save_checkpoint_with_review_deliveries(
            &mut repo,
            orient_branch,
            &watched_heads,
            persona,
            &view("review digest view"),
            &BTreeMap::from([(request, BTreeSet::from([review_head]))]),
            &BTreeMap::new(),
        )
        .expect("save checkpoint without overwriting snooze");

        let watermark = load_review_watermarks(&mut repo, orient_branch, persona)
            .expect("load watermarks")
            .remove(&request)
            .expect("snooze remains");
        assert_eq!(watermark.id, snooze_id.id);
        assert_eq!(
            watermark.deadline,
            Some(interval_key(epoch_interval(deadline)))
        );

        repo.close().ok();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn watermark_before_compass_order_preserves_newer_explicit_h2_snooze() {
        use faculties::schemas::compass::review_attestation_fragment;

        let mut fixture = review_fixture(true);
        let h1 = fixture.initial_head.expect("fixture h1");
        let initial = load_watched_snapshot(
            &mut fixture.repo,
            fixture.persona,
            fixture.local_branch,
            fixture.compass_branch,
            fixture.relations_branch,
            fixture.orient_branch,
        )
        .expect("load h1 snapshot");
        assert!(initial
            .view
            .goals_view
            .contains(&format!("{:x}@{:x}", fixture.request, h1)));
        let initial_heads = load_watched_heads(
            &mut fixture.repo,
            fixture.local_branch,
            fixture.compass_branch,
            fixture.relations_branch,
        )
        .expect("initial heads");
        save_checkpoint_heads(
            &mut fixture.repo,
            fixture.orient_branch,
            &initial_heads,
            Some((fixture.persona, &initial.view)),
        )
        .expect("save h1 baseline");

        let explicit_id = ufoid();
        let deadline = now_epoch() + hifitime::Duration::from_total_nanoseconds(3_600_000_000_000);
        let mut h2 = None;
        let loaded = load_watched_snapshot_inner(
            &mut fixture.repo,
            fixture.persona,
            fixture.local_branch,
            fixture.compass_branch,
            fixture.relations_branch,
            fixture.orient_branch,
            |repo| {
                // This seam runs after the watcher read orient-state but before
                // it pulls Compass. The writer advances Compass H1 -> H2 first,
                // then records explicit reader intent for H2.
                let mut compass = repo
                    .pull(fixture.compass_branch)
                    .map_err(|e| anyhow!("pull h2 compass: {e:?}"))?;
                let at = epoch_interval(now_epoch());
                let report = compass.put("malformed h2".to_string());
                let attestation = review_attestation_fragment(
                    fixture.request,
                    fixture.persona,
                    "malformed-h2",
                    report,
                    &[h1],
                    at,
                );
                let h2_id = attestation.root().expect("h2 root");
                let mut change = TribleSet::new();
                change += attestation;
                compass.commit(change, "test advance review to h2");
                repo.push(&mut compass)
                    .map_err(|e| anyhow!("push h2 compass: {e:?}"))?;
                h2 = Some(h2_id);

                let mut orient = repo
                    .pull(fixture.orient_branch)
                    .map_err(|e| anyhow!("pull explicit h2 snooze: {e:?}"))?;
                let mut change = TribleSet::new();
                change += entity! { &explicit_id @
                    metadata::tag: &KIND_REVIEW_WATERMARK_ID,
                    orient_state::persona: &fixture.persona,
                    orient_state::wm_request: &fixture.request,
                    orient_state::wm_head: &h2_id,
                    orient_state::wm_deadline: epoch_interval(deadline),
                    orient_state::at: epoch_interval(now_epoch()),
                };
                orient.commit(change, "test explicit h2 snooze");
                repo.push(&mut orient)
                    .map_err(|e| anyhow!("push explicit h2 snooze: {e:?}"))?;
                Ok(())
            },
        )
        .expect("load causally ordered h2 snapshot");
        let h2 = h2.expect("hook produced h2");
        assert!(loaded
            .view
            .goals_view
            .contains(&format!("{:x}@{:x}", fixture.request, h2)));
        assert_eq!(
            loaded.review_watermark_ids.get(&fixture.request),
            None,
            "the explicit event landed after the watermark snapshot"
        );

        let report = view_news_report(&initial.view, &loaded.view, fixture.persona);
        assert_eq!(report.reasons().len(), 1);
        assert!(report.reasons()[0].contains("updated"));
        let current_heads = load_watched_heads(
            &mut fixture.repo,
            fixture.local_branch,
            fixture.compass_branch,
            fixture.relations_branch,
        )
        .expect("current heads");
        save_checkpoint_with_review_deliveries(
            &mut fixture.repo,
            fixture.orient_branch,
            &current_heads,
            fixture.persona,
            &loaded.view,
            &report.review_deliveries(),
            &loaded.review_watermark_ids,
        )
        .expect("CAS preserves explicit h2 snooze");

        let watermark = load_review_watermarks(
            &mut fixture.repo,
            fixture.orient_branch,
            fixture.persona,
        )
        .expect("load final watermark")
        .remove(&fixture.request)
        .expect("h2 watermark");
        assert_eq!(watermark.id, explicit_id.id);
        assert_eq!(watermark.heads, BTreeSet::from([h2]));
        assert_eq!(
            watermark.deadline,
            Some(interval_key(epoch_interval(deadline)))
        );

        // Once the explicit event is present before acquisition, the later
        // Compass pull sees H2 and the matching snooze filters it quietly.
        let quiet = load_watched_snapshot(
            &mut fixture.repo,
            fixture.persona,
            fixture.local_branch,
            fixture.compass_branch,
            fixture.relations_branch,
            fixture.orient_branch,
        )
        .expect("load quiet h2 snapshot");
        assert!(!quiet.view.goals_view.contains(&format!("{:x}@", fixture.request)));
        assert_eq!(
            quiet.next_review_deadline,
            Some(interval_key(epoch_interval(deadline)))
        );

        remove_fixture(fixture);
    }

    #[test]
    fn explicit_snooze_wins_a_real_checkpoint_try_push_conflict() {
        let path = std::env::temp_dir().join(format!("orient-cas-race-{:x}.pile", ufoid().id));
        std::fs::File::create(&path).expect("create temp pile");
        let mut repo = open_repo(&path).expect("open repo");
        let orient_branch = repo
            .ensure_branch("orient-state", None)
            .expect("ensure orient-state");
        let persona = ufoid().id;
        let request = ufoid().id;
        let review_head = ufoid().id;
        let snooze_id = ufoid();
        let deadline = now_epoch() + hifitime::Duration::from_total_nanoseconds(3_600_000_000_000);
        let watched_heads = WatchedHeads {
            local: None,
            compass: None,
            relations: None,
        };
        let mut injected = false;

        save_checkpoint_inner(
            &mut repo,
            orient_branch,
            &watched_heads,
            Some((persona, &view("review digest view"))),
            &BTreeMap::from([(request, BTreeSet::from([review_head]))]),
            &BTreeMap::new(),
            |repo, attempt| {
                if attempt != 0 {
                    return Ok(());
                }
                injected = true;
                // The checkpoint workspace was pulled before this commit. Its
                // first try_push must conflict; the retry must re-read this
                // explicit event and drop the automatic delivery.
                let mut explicit = repo
                    .pull(orient_branch)
                    .map_err(|e| anyhow!("pull explicit snooze: {e:?}"))?;
                let mut change = TribleSet::new();
                change += entity! { &snooze_id @
                    metadata::tag: &KIND_REVIEW_WATERMARK_ID,
                    orient_state::persona: &persona,
                    orient_state::wm_request: &request,
                    orient_state::wm_head: &review_head,
                    orient_state::wm_deadline: epoch_interval(deadline),
                    orient_state::at: epoch_interval(now_epoch()),
                };
                explicit.commit(change, "test explicit snooze conflict");
                repo.push(&mut explicit)
                    .map_err(|e| anyhow!("push explicit snooze: {e:?}"))?;
                Ok(())
            },
        )
        .expect("checkpoint retry preserves explicit snooze");
        assert!(injected, "the test must force the conflict seam");

        let watermark = load_review_watermarks(&mut repo, orient_branch, persona)
            .expect("load watermarks")
            .remove(&request)
            .expect("explicit snooze remains");
        assert_eq!(watermark.id, snooze_id.id);
        assert_eq!(
            watermark.deadline,
            Some(interval_key(epoch_interval(deadline)))
        );

        repo.close().ok();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn equal_timestamp_explicit_intent_wins_after_offline_merge() {
        fn low_and_high_ids() -> (Id, Id) {
            let a = ufoid().id;
            let b = ufoid().id;
            if a < b { (a, b) } else { (b, a) }
        }

        let persona = ufoid().id;
        let request_ack = ufoid().id;
        let request_snooze = ufoid().id;
        let review_head = ufoid().id;
        let checkpoint = ufoid().id;
        let (explicit_ack, automatic_ack) = low_and_high_ids();
        let (explicit_snooze, automatic_snooze) = low_and_high_ids();
        let at = epoch_interval(now_epoch());
        let deadline = epoch_interval(
            now_epoch() + hifitime::Duration::from_total_nanoseconds(3_600_000_000_000),
        );
        let mut space = TribleSet::new();

        // Give both automatic events the larger id: the old `(at, id)`
        // projection would therefore discard the equal-time explicit intent.
        space += entity! { ExclusiveId::force_ref(&automatic_ack) @
            metadata::tag: &KIND_REVIEW_WATERMARK_ID,
            orient_state::persona: &persona,
            orient_state::wm_request: &request_ack,
            orient_state::wm_head: &review_head,
            orient_state::wm_delivery_checkpoint: &checkpoint,
            orient_state::at: at,
        };
        space += entity! { ExclusiveId::force_ref(&explicit_ack) @
            metadata::tag: &KIND_REVIEW_WATERMARK_ID,
            orient_state::persona: &persona,
            orient_state::wm_request: &request_ack,
            orient_state::wm_head: &review_head,
            orient_state::at: at,
        };
        space += entity! { ExclusiveId::force_ref(&automatic_snooze) @
            metadata::tag: &KIND_REVIEW_WATERMARK_ID,
            orient_state::persona: &persona,
            orient_state::wm_request: &request_snooze,
            orient_state::wm_head: &review_head,
            orient_state::wm_delivery_checkpoint: &checkpoint,
            orient_state::at: at,
        };
        space += entity! { ExclusiveId::force_ref(&explicit_snooze) @
            metadata::tag: &KIND_REVIEW_WATERMARK_ID,
            orient_state::persona: &persona,
            orient_state::wm_request: &request_snooze,
            orient_state::wm_head: &review_head,
            orient_state::wm_deadline: deadline,
            orient_state::at: at,
        };

        let map = review_watermarks_from_space(&space, persona);
        assert_eq!(map[&request_ack].id, explicit_ack);
        assert_eq!(map[&request_ack].deadline, None);
        assert_eq!(map[&request_snooze].id, explicit_snooze);
        assert_eq!(map[&request_snooze].deadline, Some(interval_key(deadline)));
    }

    /// Full round-trip: the watermark entity `compass review ack/snooze` writes
    /// onto the `orient-state` branch reads back through `load_review_watermarks`
    /// exactly — latest-wins per (persona, request), per-persona scoping, the
    /// repeated head-set, and the optional snooze deadline. Uses a fresh
    /// file-backed pile via the production `open_repo` path (no extra dep).
    #[test]
    fn watermarks_round_trip_latest_wins_and_scope_by_persona() {
        let path = std::env::temp_dir().join(format!("orient-wm-{:x}.pile", ufoid().id));
        std::fs::File::create(&path).expect("create temp pile");
        let mut repo = open_repo(&path).expect("open repo");
        let osb = repo
            .ensure_branch("orient-state", None)
            .expect("ensure orient-state");

        let me = ufoid().id;
        let other = ufoid().id;
        let req_ack = ufoid().id;
        let req_snooze = ufoid().id;
        let h1 = ufoid().id;
        let h2 = ufoid().id;

        let early = now_epoch();
        let late = now_epoch() + hifitime::Duration::from_total_nanoseconds(10_000_000_000);
        let deadline_epoch =
            now_epoch() + hifitime::Duration::from_total_nanoseconds(3_600_000_000_000);

        // Append one watermark event, exactly as `write_review_watermark` does.
        fn write_wm(
            repo: &mut Repository<Pile>,
            osb: Id,
            persona: Id,
            request: Id,
            head_ids: &[Id],
            at: Epoch,
            deadline: Option<Epoch>,
        ) {
            let mut ws = repo.pull(osb).expect("pull orient-state");
            let wm_id = ufoid();
            let mut change = TribleSet::new();
            change += entity! { &wm_id @
                metadata::tag: &KIND_REVIEW_WATERMARK_ID,
                orient_state::persona: &persona,
                orient_state::wm_request: &request,
                orient_state::wm_head*: head_ids.iter(),
                orient_state::at: epoch_interval(at),
            };
            if let Some(d) = deadline {
                change += entity! { &wm_id @ orient_state::wm_deadline: epoch_interval(d) };
            }
            ws.commit(change, "test watermark");
            repo.push(&mut ws).expect("push watermark");
        }

        // req_ack: an early {h1} event superseded latest-wins by a later {h1,h2}
        // event (no deadline → plain ack).
        write_wm(&mut repo, osb, me, req_ack, &[h1], early, None);
        write_wm(&mut repo, osb, me, req_ack, &[h1, h2], late, None);
        // req_snooze: a single event carrying a deadline.
        write_wm(&mut repo, osb, me, req_snooze, &[h1], late, Some(deadline_epoch));
        // A different persona's watermark on the same request — must be ignored.
        write_wm(&mut repo, osb, other, req_ack, &[h1], late, None);

        let map = load_review_watermarks(&mut repo, osb, me).expect("load watermarks");

        assert_eq!(map.len(), 2, "only this persona's two requests");

        let ack = map.get(&req_ack).expect("req_ack present");
        assert_eq!(ack.heads, heads(&[h1, h2]), "later event won latest-wins");
        assert!(ack.deadline.is_none(), "plain ack has no deadline");

        let snooze = map.get(&req_snooze).expect("req_snooze present");
        assert_eq!(snooze.heads, heads(&[h1]));
        assert_eq!(
            snooze.deadline,
            Some(interval_key(epoch_interval(deadline_epoch))),
            "snooze deadline round-trips"
        );

        // The reconstructed map drives the same quiet-decision the filter uses.
        let now = interval_key(epoch_interval(now_epoch()));
        assert!(
            watermark_quiet(&ack.heads, ack.deadline, &heads(&[h1, h2]), now),
            "acked review with matching heads is quiet"
        );
        assert!(
            !watermark_quiet(&ack.heads, ack.deadline, &heads(&[h1]), now),
            "a head change re-surfaces it"
        );

        repo.close().ok();
        let _ = std::fs::remove_file(&path);
    }
}
