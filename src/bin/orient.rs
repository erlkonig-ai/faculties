use anyhow::{anyhow, bail, Result};
use chrono::{
    DateTime, Duration as ChronoDuration, Local, LocalResult, NaiveDateTime, NaiveTime, TimeZone,
};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::legacy_hint::open_scope;
use faculties::memory_cover::{render_cover, CoverOpts};
use faculties::schemas::archive::archive;
use faculties::schemas::compass::latest_status_event;
use faculties::schemas::compass::{
    board, DEFAULT_SCOPE_ID as COMPASS_SCOPE_ID, KIND_GOAL_ID, KIND_NOTE_ID, KIND_STATUS_ID,
};
use faculties::schemas::habit::DEFAULT_SCOPE_ID as HABIT_SCOPE_ID;
use faculties::schemas::mail::DEFAULT_SCOPE_ID as MAIL_SCOPE_ID;
use faculties::schemas::memory::DEFAULT_SCOPE_ID as MEMORY_SCOPE_ID;
use faculties::schemas::message::DEFAULT_SCOPE_ID as MESSAGE_SCOPE_ID;
use faculties::schemas::relations::DEFAULT_SCOPE_ID as RELATIONS_SCOPE_ID;
use faculties::schemas::status::DEFAULT_SCOPE_ID as STATUS_SCOPE_ID;
use faculties::schemas::teams::{teams, DEFAULT_SCOPE_ID as TEAMS_SCOPE_ID};
use faculties::schemas::wiki::DEFAULT_SCOPE_ID as WIKI_SCOPE_ID;
use faculties::storage::{load_signer, open_pile_strict};
use faculties::{
    clock, compass, habits, mail as mail_model, memory as memory_model, message,
    orient as orient_model, relations, status, teams as teams_model, wiki as wiki_model,
};
use hifitime::Epoch;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::macros::{find, pattern};
use triblespace::prelude::*;

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
    /// Mid-session overview of the current situation (no memories, no wiki)
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
    /// Wait until the persona-visible semantic view gains news
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
        /// Poll interval for the append-only pile growth gate
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
    /// Establish an explicit seen-note frontier for an observer written by the
    /// earlier checkpoint-only implementation. Run stopped-world: every note
    /// in the coherent Compass snapshot is marked seen, while messages and
    /// other pending news remain untouched.
    MigrateNoteFrontier,
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

#[cfg(test)]
fn epoch_interval(epoch: Epoch) -> Inline<inlineencodings::NsTAIInterval> {
    (epoch, epoch).try_to_inline().unwrap()
}

fn epoch_seconds(epoch: Epoch) -> i64 {
    (epoch.to_tai_duration().total_nanoseconds() / 1_000_000_000) as i64
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
    attention_keys: &HashSet<String>,
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
        let directly_addressed = entity_tags(space, note_id)
            .iter()
            .any(|tag| attention_keys.contains(&tag.to_ascii_lowercase()));
        if directly_addressed || relevant_goals.contains(&goal_id) {
            insert_note_goal(&mut notes, note_id, goal_id);
        }
    }
    notes
}

struct NativeCatalogs {
    messages: TribleSet,
    mail: TribleSet,
    teams: TribleSet,
    compass: TribleSet,
    relations: TribleSet,
    status: TribleSet,
    habits: habits::Catalog,
    checkpoints: TribleSet,
    reader: PileReader,
}

fn materialize_scope(
    pile: &mut Pile,
    signer: &SigningKey,
    scope: Id,
    label: &str,
) -> Result<TribleSet> {
    open_scope(&mut *pile, scope, signer.clone())
        .materialize()
        .map_err(|error| anyhow!("materialize {label} collection: {error}"))
}

/// Read every collection that contributes to Orient from one refreshed Pile.
/// Collection history and record ordering stop at this boundary: callers see
/// only their materialized set values.
fn load_native_catalogs(pile: &mut Pile, signer: &SigningKey) -> Result<NativeCatalogs> {
    let relations_facts = materialize_scope(pile, signer, RELATIONS_SCOPE_ID, "Relations")?;
    let mail_facts = materialize_scope(pile, signer, MAIL_SCOPE_ID, "Mail")?;
    // Teams participates in news but is deliberately not run through
    // `teams::validate_catalog` here: that reads every text payload and every
    // attachment blob, which is far too much work for a path that re-arms
    // after every turn. Orient only reads message identity, state and
    // authorship, all of which are structural.
    let teams_facts = materialize_scope(pile, signer, TEAMS_SCOPE_ID, "Teams")?;
    let message_facts = materialize_scope(pile, signer, MESSAGE_SCOPE_ID, "Message")?;
    let compass_facts = materialize_scope(pile, signer, COMPASS_SCOPE_ID, "Compass")?;
    let status_facts = materialize_scope(pile, signer, STATUS_SCOPE_ID, "Status")?;
    let habit_facts = materialize_scope(pile, signer, HABIT_SCOPE_ID, "Habit")?;
    let checkpoint_facts = materialize_scope(
        pile,
        signer,
        faculties::schemas::orient::DEFAULT_SCOPE_ID,
        "Orient checkpoint",
    )?;
    let reader = pile
        .reader()
        .map_err(|error| anyhow!("open Orient collection reader: {error}"))?;

    relations::validate_catalog(&reader, &relations_facts)
        .map_err(|error| anyhow!("validate Relations collection: {error:#}"))?;
    mail_model::validate_local_catalog(&reader, &mail_facts)
        .map_err(|error| anyhow!("validate Mail collection: {error:#}"))?;
    message::validate_catalog(&reader, &message_facts, &relations_facts)
        .map_err(|error| anyhow!("validate Message collection: {error:#}"))?;
    compass::validate_known_payloads(&reader, &compass_facts)
        .map_err(|error| anyhow!("validate Compass collection: {error:#}"))?;
    status::validate_catalog(&reader, &status_facts)
        .map_err(|error| anyhow!("validate Status collection: {error:#}"))?;
    let habits = habits::load_catalog(&reader, &habit_facts)
        .map_err(|error| anyhow!("validate Habit collection: {error:#}"))?;
    orient_model::validate_catalog(&reader, &checkpoint_facts, &compass_facts)
        .map_err(|error| anyhow!("validate Orient checkpoint collection: {error:#}"))?;

    Ok(NativeCatalogs {
        messages: message_facts,
        mail: mail_facts,
        teams: teams_facts,
        compass: compass_facts,
        relations: relations_facts,
        status: status_facts,
        habits,
        checkpoints: checkpoint_facts,
        reader,
    })
}

fn native_task_title(catalogs: &NativeCatalogs, task: Id) -> String {
    find!(
        handle: compass::TextHandle,
        pattern!(&catalogs.compass, [{ task @ board::title: ?handle }])
    )
    .next()
    .and_then(|handle| compass::read_text(&catalogs.reader, handle).ok())
    .unwrap_or_default()
}

fn render_native_messages(
    catalogs: &NativeCatalogs,
    persona: Option<Id>,
    limit: usize,
) -> Result<String> {
    use std::fmt::Write as _;

    let mut out = String::new();
    let Some(persona) = persona else {
        writeln!(out, "Local messages:").unwrap();
        writeln!(
            out,
            "- Unavailable: no persona (pass --persona <label-or-hex> or set $PERSONA)"
        )
        .unwrap();
        return Ok(out);
    };

    let mut unread = Vec::new();
    if relations::person_anchors(&catalogs.relations).contains(&persona) {
        let identities = relations::IdentityComponents::from_facts(&catalogs.relations)?;
        let reads = message::load_read_rows(&catalogs.messages)?;
        let mut rows = message::load_message_rows(&catalogs.messages)?;
        rows.sort_by_key(|row| std::cmp::Reverse(interval_key(row.created_at)));
        for row in rows {
            if message::is_inbox_message(&row, persona, &catalogs.relations, &identities)?
                && !message::is_read_by(&reads, row.id, persona, &identities)?
            {
                if unread.len() >= limit {
                    break;
                }
                unread.push(row);
            }
        }
    }

    writeln!(
        out,
        "Local messages (unread inbox for {}):",
        native_person_label(catalogs, persona)
    )
    .unwrap();
    if unread.is_empty() {
        writeln!(out, "- None").unwrap();
        return Ok(out);
    }
    let now = interval_key(clock::point_now()?);
    for row in unread {
        writeln!(
            out,
            "- [{}] {} {} -> {} (unread)",
            fmt_id(row.id),
            format_age(now, interval_key(row.created_at)),
            native_person_label(catalogs, row.from),
            native_person_label(catalogs, row.to),
        )
        .unwrap();
        let body = message::read_body(&catalogs.reader, row.body)?;
        if body.is_empty() {
            writeln!(out, "    ").unwrap();
        } else {
            for line in body.lines() {
                writeln!(out, "    {}", line.trim_end_matches('\r')).unwrap();
            }
        }
    }
    Ok(out)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MailSummary {
    claimed_at: Option<i128>,
    from: Option<String>,
    subject: String,
    spam: bool,
}

/// One attention item per unread, non-spam inbound wire message. Re-observing
/// the same wire through another source is idempotent when its presentation
/// agrees; conflicting parser projections are not silently arbitrated.
fn native_unread_mail(catalogs: &NativeCatalogs, persona: Id) -> Result<BTreeMap<Id, MailSummary>> {
    // A raw exact anchor is a valid observer before its Relations profile
    // arrives. Until then it has no identity component and therefore no
    // Relations-dependent Mail inbox projection.
    if !relations::person_anchors(&catalogs.relations).contains(&persona) {
        return Ok(BTreeMap::new());
    }
    let mut by_wire = BTreeMap::new();
    for row in mail_model::inbox_projection(&catalogs.mail, &catalogs.relations, persona)? {
        if !row.unread {
            continue;
        }
        let view = mail_model::projection_view(&catalogs.reader, &catalogs.mail, row.projection)?;
        let summary = MailSummary {
            claimed_at: view.claimed_date.map(interval_key),
            from: view.from,
            subject: view.subject,
            spam: view.spam,
        };
        match by_wire.entry(row.wire) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(summary);
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &summary => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                bail!(
                    "wire message {:x} has conflicting parser projections for Orient",
                    row.wire
                );
            }
        }
    }
    by_wire.retain(|_, summary| !summary.spam);
    Ok(by_wire)
}

/// Logical Teams messages that are attention items for this pile.
///
/// Teams carries no per-reader read state, so the attention set is every
/// present (not deleted) logical message written by somebody other than us;
/// news is growth of that set against the persona's last checkpoint. There is
/// no persona gating: one tenant account serves every window sharing this
/// pile, so a colleague's message is addressed to the pile rather than to one
/// window — the same reading as a peer message sent to a group you are in.
///
/// This reads only what the pile already holds. `orient` never calls Graph:
/// `wait` re-arms after every turn, and a network round trip on that path
/// would both slow the common case and rate-limit the tenant. `teams read`
/// remains the only thing that pulls new messages into the pile.
fn native_teams_messages(catalogs: &NativeCatalogs) -> Result<BTreeSet<Id>> {
    // Author entities for the account this pile posts as. An author's
    // `teams::user_id` and an auth profile's `teams::auth_user_id` are both
    // content-derived UTF8String handles, so equal Graph user ids are equal
    // handle values and the join needs no blob reads.
    let own_authors: BTreeSet<Id> = find!(
        author: Id,
        pattern!(&catalogs.teams, [
            {
                ?author @
                metadata::tag: archive::kind_author,
                teams::source: _?source,
                teams::user_id: _?user,
            },
            {
                _?profile @
                metadata::tag: teams::kind_auth_profile,
                teams::source: _?source,
                teams::auth_user_id: _?user,
            }
        ])
    )
    .collect();

    let mut present = BTreeSet::new();
    let mut deleted = BTreeSet::new();
    for (message, state) in find!(
        (message: Id, state: Inline<inlineencodings::ShortString>),
        pattern!(&catalogs.teams, [{
            _?observation @
            metadata::tag: teams::kind_message_observation,
            teams::message: ?message,
            teams::message_state: ?state,
        }])
    ) {
        let state = String::try_from_inline(&state)
            .map_err(|error| anyhow!("decode Teams observation state: {error:?}"))?;
        match state.as_str() {
            "present" => {
                present.insert(message);
            }
            "deleted" => {
                deleted.insert(message);
            }
            other => bail!("unknown Teams observation state '{other}'"),
        }
    }
    for message in find!(
        message: Id,
        pattern!(&catalogs.teams, [{
            _?tombstone @
            metadata::tag: teams::kind_message_tombstone,
            teams::message: ?message,
        }])
    ) {
        deleted.insert(message);
    }

    // Our own sends come back through the next delta pull. They must not wake
    // anybody, exactly as a persona's own peer sends and goal edits do not
    // wake its watcher. Attribution is also what separates a message from
    // Graph's authorless chat events (`<systemEventMessage/>` for a member
    // added, a chat renamed, ...): news is somebody writing to us, so an
    // unattributed observation is never news, and can never be mistaken for a
    // colleague when we cannot even check it against our own account.
    let mut own = BTreeSet::new();
    let mut from_others = BTreeSet::new();
    for (message, author) in find!(
        (message: Id, author: Id),
        pattern!(&catalogs.teams, [{
            _?observation @
            metadata::tag: teams::kind_message_observation,
            teams::message: ?message,
            archive::author: ?author,
        }])
    ) {
        if own_authors.contains(&author) {
            own.insert(message);
        } else {
            from_others.insert(message);
        }
    }

    present.retain(|message| {
        from_others.contains(message) && !own.contains(message) && !deleted.contains(message)
    });
    Ok(present)
}

/// Newest observation of one logical Teams message, with the display name and
/// body worth printing when it turns up as news.
fn teams_message_detail(catalogs: &NativeCatalogs, message: Id) -> Result<(String, String)> {
    let newest = find!(
        (modified: IntervalValue, observation: Id),
        pattern!(&catalogs.teams, [{
            ?observation @
            metadata::tag: teams::kind_message_observation,
            teams::message: message,
            teams::modified_at: ?modified,
        }])
    )
    .map(|(modified, observation)| (interval_key(modified), observation))
    .max();
    let Some((_, observation)) = newest else {
        return Ok(("(unknown)".to_owned(), "(no observation)".to_owned()));
    };
    let author = find!(
        handle: teams_model::TextHandle,
        pattern!(&catalogs.teams, [{ observation @ teams::author_name: ?handle }])
    )
    .next()
    .map(|handle| teams_model::read_text(&catalogs.reader, handle, "Teams author display name"))
    .transpose()?
    .unwrap_or_else(|| "(unknown)".to_owned());
    let content = find!(
        handle: teams_model::TextHandle,
        pattern!(&catalogs.teams, [{ observation @ archive::content: ?handle }])
    )
    .next()
    .map(|handle| teams_model::read_text(&catalogs.reader, handle, "Teams message content"))
    .transpose()?
    .unwrap_or_else(|| "(no content)".to_owned());
    Ok((author, content))
}

/// Render the same unread native Mail projection that drives `orient wait`.
fn render_native_mail(
    catalogs: &NativeCatalogs,
    persona: Option<Id>,
    limit: usize,
) -> Result<String> {
    use std::fmt::Write as _;

    let mut out = String::new();
    let Some(persona) = persona else {
        writeln!(out, "Mail:").unwrap();
        writeln!(
            out,
            "- Unavailable: no persona (pass --persona <label-or-hex> or set $PERSONA)"
        )
        .unwrap();
        return Ok(out);
    };

    let mut rows = native_unread_mail(catalogs, persona)?
        .into_iter()
        .collect::<Vec<_>>();
    rows.sort_by_key(|(wire, summary)| {
        (
            std::cmp::Reverse(summary.claimed_at),
            std::cmp::Reverse(*wire),
        )
    });

    writeln!(
        out,
        "Mail (unread for {}):",
        native_person_label(catalogs, persona)
    )
    .unwrap();
    if rows.is_empty() {
        writeln!(out, "- None").unwrap();
        return Ok(out);
    }
    let now = interval_key(clock::point_now()?);
    for (wire, summary) in rows.into_iter().take(limit) {
        let age = summary
            .claimed_at
            .map(|at| format_age(now, at))
            .unwrap_or_else(|| "?".to_owned());
        writeln!(
            out,
            "- [{}] {} {} — {}",
            fmt_id(wire),
            age,
            summary.from.unwrap_or_else(|| "(no From)".to_owned()),
            summary.subject,
        )
        .unwrap();
    }
    Ok(out)
}

fn render_native_compass_goals(
    catalogs: &NativeCatalogs,
    doing_limit: usize,
    todo_limit: usize,
) -> String {
    use std::fmt::Write as _;

    let goals = compass::goal_ids(&catalogs.compass);
    let ranks = compass::priority_ranks(
        goals.iter().copied(),
        &compass::goal_priority_edges(&catalogs.compass),
    );
    let mut doing = Vec::<(usize, i128, Id)>::new();
    let mut todo = Vec::<(usize, i128, Id)>::new();
    for task in goals {
        let (status, status_at) = latest_status_event(&catalogs.compass, task)
            .map(|(_, value, at)| (value.to_ascii_lowercase(), Some(interval_key(at))))
            .unwrap_or_else(|| ("todo".to_owned(), None));
        let created = find!(
            at: IntervalValue,
            pattern!(&catalogs.compass, [{ task @ metadata::created_at: ?at }])
        )
        .map(interval_key)
        .min()
        .unwrap_or(0);
        let key = status_at.unwrap_or(created);
        let rank = ranks.get(&task).copied().unwrap_or(usize::MAX);
        match status.as_str() {
            "doing" => doing.push((rank, key, task)),
            "todo" => todo.push((rank, key, task)),
            _ => {}
        }
    }
    let compare = |left: &(usize, i128, Id), right: &(usize, i128, Id)| {
        left.0
            .cmp(&right.0)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| left.2.cmp(&right.2))
    };
    doing.sort_by(compare);
    todo.sort_by(compare);

    let mut out = String::new();
    writeln!(out, "Compass:").unwrap();
    if doing.is_empty() && todo.is_empty() {
        writeln!(out, "- No goals.").unwrap();
        return out;
    }
    writeln!(out, "Doing:").unwrap();
    if doing.is_empty() {
        writeln!(out, "- None").unwrap();
    } else {
        for (_, _, task) in doing.into_iter().take(doing_limit) {
            writeln!(
                out,
                "- [{}] {}{}",
                fmt_id(task),
                native_task_title(catalogs, task),
                render_tags(&entity_tags(&catalogs.compass, task)),
            )
            .unwrap();
        }
    }
    writeln!(out, "Todo:").unwrap();
    if todo.is_empty() {
        writeln!(out, "- None").unwrap();
    } else {
        for (_, _, task) in todo.into_iter().take(todo_limit) {
            writeln!(
                out,
                "- [{}] {}{}",
                fmt_id(task),
                native_task_title(catalogs, task),
                render_tags(&entity_tags(&catalogs.compass, task)),
            )
            .unwrap();
        }
    }
    out
}

fn render_window_status(catalogs: &NativeCatalogs) -> Result<String> {
    use std::fmt::Write as _;

    let latest = status::latest_per_window(status::load_status_rows(&catalogs.status)?)?;
    let mut rows = Vec::new();
    for person in latest.keys() {
        let text = latest
            .get(person)
            .map(|row| status::read_text(&catalogs.reader, row.text))
            .transpose()?;
        rows.push((native_person_label(catalogs, *person), text));
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));

    let mut out = String::new();
    writeln!(out, "Window status:").unwrap();
    if rows.is_empty() {
        writeln!(out, "- (none)").unwrap();
    }
    for (label, text) in rows {
        writeln!(out, "- {label}: {}", text.unwrap_or_else(|| "—".to_owned())).unwrap();
    }
    Ok(out)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DueHabit {
    label: String,
    nudge: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct HabitObservation {
    due: BTreeMap<Id, DueHabit>,
    attention: BTreeMap<Id, String>,
    /// Earliest completion-relative deadline that can change a cooling row.
    next_cooldown_at: Option<i64>,
}

/// Evaluate the shared Habit read model once. The wall clock and evaluation
/// directory are explicit so the wait loop can re-run this without requiring
/// any collection append, and tests can exercise the temporal edge directly.
fn observe_habits(
    catalogs: &NativeCatalogs,
    pile: &Path,
    now_secs: i64,
) -> Result<HabitObservation> {
    let at = habits::evaluation_dir(pile);
    let mut observation = HabitObservation::default();
    for row in catalogs.habits.rows()? {
        let state = habits::evaluate(&row, now_secs, &at);
        match &state {
            habits::State::Due => {
                observation.due.insert(
                    row.id,
                    DueHabit {
                        label: row.label.clone(),
                        nudge: row.nudge.clone(),
                    },
                );
            }
            habits::State::Cooling => {
                if let Some(deadline) = row
                    .next_cooldown_at()
                    .map_err(anyhow::Error::msg)?
                    .filter(|deadline| *deadline > now_secs)
                {
                    observation.next_cooldown_at = Some(
                        observation
                            .next_cooldown_at
                            .map_or(deadline, |seen| seen.min(deadline)),
                    );
                }
            }
            habits::State::Forked(heads) => {
                observation.attention.insert(
                    row.id,
                    format!(
                        "{} [{:x}] has conflicting state heads: {}",
                        row.label,
                        row.id,
                        heads
                            .iter()
                            .map(|(id, state)| format!("{id:x}={}", state.as_str()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );
            }
            habits::State::Unparseable(error) | habits::State::Failed(error) => {
                observation.attention.insert(
                    row.id,
                    format!("{} [{:x}] {}: {error}", row.label, row.id, state.word()),
                );
            }
            habits::State::Waiting | habits::State::Paused => {}
        }
    }
    Ok(observation)
}

fn render_native_habits(observation: &HabitObservation) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    writeln!(out, "Habits due:").unwrap();
    if observation.due.is_empty() {
        writeln!(out, "- None").unwrap();
    } else {
        for (id, habit) in &observation.due {
            writeln!(out, "- [{}] {}: {}", fmt_id(*id), habit.label, habit.nudge).unwrap();
        }
    }
    if !observation.attention.is_empty() {
        writeln!(out, "Habit attention:").unwrap();
        for warning in observation.attention.values() {
            writeln!(out, "- {warning}").unwrap();
        }
    }
    out
}

fn newly_due(previous: &HabitObservation, current: &HabitObservation) -> Vec<(Id, DueHabit)> {
    current
        .due
        .iter()
        .filter(|(id, _)| !previous.due.contains_key(*id))
        .map(|(id, habit)| (*id, habit.clone()))
        .collect()
}

fn newly_needing_attention(
    previous: &HabitObservation,
    current: &HabitObservation,
) -> Vec<(Id, String)> {
    current
        .attention
        .iter()
        .filter(|(id, warning)| previous.attention.get(*id) != Some(*warning))
        .map(|(id, warning)| (*id, warning.clone()))
        .collect()
}

fn print_habit_transitions(previous: &HabitObservation, current: &HabitObservation) -> bool {
    let due = newly_due(previous, current);
    let attention = newly_needing_attention(previous, current);
    if due.is_empty() && attention.is_empty() {
        return false;
    }
    for (id, habit) in &due {
        println!("News: habit [{}] became due ({})", fmt_id(*id), habit.label);
    }
    for (id, _) in &attention {
        println!("News: habit [{}] needs attention", fmt_id(*id));
    }
    if !due.is_empty() {
        println!("\nHabits newly due:");
        for (_, habit) in due {
            println!("- {}: {}", habit.label, habit.nudge);
        }
    }
    if !attention.is_empty() {
        println!("\nHabit attention:");
        for (_, warning) in attention {
            println!("- {warning}");
        }
    }
    true
}

fn resolve_native_persona(catalogs: &NativeCatalogs, input: &str) -> Result<Id> {
    let input = input.trim();
    if let Some(id) = Id::from_hex(input) {
        // Exact anchors remain useful before a profile has arrived.
        return Ok(id);
    }
    relations::resolve_person(&catalogs.reader, &catalogs.relations, input, false)?
        .require_unique("person", input)
}

fn profile_inputs(
    reader: &PileReader,
    facts: &TribleSet,
    person: Id,
) -> Result<Vec<relations::ProfileInput>> {
    let heads = match relations::profile_head(facts, person)? {
        relations::Head::Missing => Vec::new(),
        relations::Head::Unique(id) => vec![id],
        relations::Head::Forked(ids) => ids,
    };
    heads
        .into_iter()
        .map(|id| {
            let snapshot = relations::profile_snapshot(facts, id)?;
            relations::profile_input(reader, &snapshot)
        })
        .collect()
}

fn native_person_label(catalogs: &NativeCatalogs, person: Id) -> String {
    match profile_inputs(&catalogs.reader, &catalogs.relations, person) {
        Ok(inputs) if inputs.len() == 1 => inputs[0].label.clone(),
        _ => fmt_id(person),
    }
}

fn persona_keys(catalogs: &NativeCatalogs, persona: Id) -> Result<HashSet<String>> {
    let mut keys = HashSet::new();
    for profile in profile_inputs(&catalogs.reader, &catalogs.relations, persona)? {
        keys.insert(profile.label.to_ascii_lowercase());
        keys.extend(
            profile
                .aliases
                .into_iter()
                .map(|alias| alias.to_ascii_lowercase()),
        );
    }
    Ok(keys)
}

/// Every textual group selector that may currently address `persona`.
///
/// Attention is a conservative read projection, not a mutation precondition:
/// a legitimate fork in one group must not disable every watcher. We therefore
/// union names and membership over each group's maximal heads. Settled
/// same-person components still participate in membership, while an exact id
/// without a Relations person record simply belongs to no group yet.
fn group_attention_keys(
    reader: &PileReader,
    facts: &TribleSet,
    persona: Id,
) -> Result<HashSet<String>> {
    if !relations::person_anchors(facts).contains(&persona) {
        return Ok(HashSet::new());
    }
    let equivalent = relations::IdentityComponents::from_facts(facts)?.component(persona)?;
    let mut keys = HashSet::new();
    for group in relations::group_anchors(facts) {
        let heads = match relations::group_head(facts, group)? {
            relations::Head::Missing => continue,
            relations::Head::Unique(head) => vec![head],
            relations::Head::Forked(heads) => heads,
        };
        let snapshots: Vec<_> = heads
            .into_iter()
            .map(|head| relations::group_snapshot(facts, head))
            .collect::<Result<_>>()?;
        if snapshots
            .iter()
            .flat_map(|snapshot| snapshot.members.iter())
            .any(|member| equivalent.contains(member))
        {
            for snapshot in snapshots {
                keys.insert(relations::lookup_key(&relations::read_text(
                    reader,
                    snapshot.name,
                )?));
            }
        }
    }
    Ok(keys)
}

fn attention_keys(catalogs: &NativeCatalogs, persona: Id) -> Result<HashSet<String>> {
    let mut keys = persona_keys(catalogs, persona)?;
    keys.extend(group_attention_keys(
        &catalogs.reader,
        &catalogs.relations,
        persona,
    )?);
    Ok(keys)
}

fn status_roster(catalogs: &NativeCatalogs) -> Result<BTreeSet<Id>> {
    Ok(
        status::latest_per_window(status::load_status_rows(&catalogs.status)?)?
            .into_keys()
            .collect(),
    )
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

fn all_note_ids(compass: &TribleSet) -> BTreeSet<Id> {
    find!(
        note_id: Id,
        pattern!(compass, [{
            ?note_id @
            metadata::tag: &KIND_NOTE_ID,
            board::task: _?goal_id,
            board::note: _?body,
        }])
    )
    .collect()
}

fn observed_notes(catalogs: &NativeCatalogs, persona: Id) -> Result<(BTreeSet<Id>, bool)> {
    let initialized = orient_model::has_seen_notes_frontier(&catalogs.checkpoints, persona);
    let mut observed = orient_model::seen_notes(&catalogs.checkpoints, persona);
    if !initialized {
        let events = orient_model::load_checkpoint_events(&catalogs.reader, &catalogs.checkpoints)?;
        observed.extend(
            events
                .into_iter()
                .filter(|event| event.persona == persona)
                .flat_map(|event| event.view.notes.into_keys()),
        );
    }
    Ok((observed, initialized))
}
fn load_watched_view(
    catalogs: &NativeCatalogs,
    persona_id: Id,
) -> Result<orient_model::WatchedView> {
    let mut unread = BTreeSet::new();
    if relations::person_anchors(&catalogs.relations).contains(&persona_id) {
        let identities = relations::IdentityComponents::from_facts(&catalogs.relations)?;
        let reads = message::load_read_rows(&catalogs.messages)?;
        for row in message::load_message_rows(&catalogs.messages)? {
            if message::is_inbox_message(&row, persona_id, &catalogs.relations, &identities)?
                && !message::is_read_by(&reads, row.id, persona_id, &identities)?
            {
                unread.insert(row.id);
            }
        }
    }
    let mail_unread = native_unread_mail(catalogs, persona_id)?
        .into_keys()
        .collect();
    let teams_messages = native_teams_messages(catalogs)?;

    let roster = status_roster(catalogs)?;
    let attention_keys = attention_keys(catalogs, persona_id)?;

    // One line per goal: "id:status:author:flags". Author is the acting
    // persona on the latest status event. Flags are i = this persona has
    // authored a status or note on the goal, and a = addressed through a
    // Relations person or group selector.
    let mut goal_lines = Vec::new();
    let mut relevant_goals = HashSet::new();
    for id in find!(id: Id, pattern!(&catalogs.compass, [{ ?id @ metadata::tag: &KIND_GOAL_ID }])) {
        let authored_status = exists!(pattern!(&catalogs.compass, [{
            _?evt @
            metadata::tag: &KIND_STATUS_ID,
            board::status_of: &id,
            board::by: &persona_id,
        }]));
        let authored_note = exists!(pattern!(&catalogs.compass, [{
            _?evt @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &id,
            board::note: _?body,
            board::by: &persona_id,
        }]));
        let involved = authored_status || authored_note;
        let tags = entity_tags(&catalogs.compass, id);
        let addressed = tags
            .iter()
            .any(|tag| attention_keys.contains(&tag.to_ascii_lowercase()));
        let mut flags = String::new();
        if involved {
            flags.push('i');
        }
        if addressed {
            flags.push('a');
        }
        if involved || addressed {
            relevant_goals.insert(id);
        }

        let line = match latest_status_event(&catalogs.compass, id) {
            Some((event, status, _)) => {
                let by = find!(
                    by: Id,
                    pattern!(&catalogs.compass, [{ event @ board::by: ?by }])
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
    // note itself carries a Relations-resolvable attention tag. Own attributed
    // notes remain quiet; absence of attribution is deliberately not treated
    // as ownership.
    let notes = visible_notes(
        &catalogs.compass,
        persona_id,
        &attention_keys,
        &relevant_goals,
    );

    Ok(orient_model::WatchedView {
        unread,
        mail_unread,
        teams: teams_messages,
        goals_view: goal_lines.join("\n"),
        roster,
        notes,
    })
}

/// What news is in `new` relative to `old`? Returns one line per
/// item, empty = no news. Unread and roster are growth-only. Goal status
/// changes wake only when the goal is relevant to this persona; a new goal
/// wakes only when explicitly addressed by a Relations person or group tag.
fn view_news(
    old: &orient_model::WatchedView,
    new: &orient_model::WatchedView,
    persona_id: Id,
    observed_notes: &BTreeSet<Id>,
) -> Vec<String> {
    let mut reasons = Vec::new();
    for msg in new.unread.difference(&old.unread) {
        reasons.push(format!("new message [{}]", fmt_id(*msg)));
    }
    for mail in new.mail_unread.difference(&old.mail_unread) {
        reasons.push(format!("new mail [{}]", fmt_id(*mail)));
    }
    for message in new.teams.difference(&old.teams) {
        reasons.push(format!("new Teams message [{}]", fmt_id(*message)));
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
        let addressed = flags.contains('a');
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
        if *person != persona_id {
            reasons.push(format!("new status window [{}]", fmt_id(*person)));
        }
    }
    for (note_id, goal_id) in &new.notes {
        if !observed_notes.contains(note_id) {
            reasons.push(format!(
                "new note [{}] on goal [{}]",
                fmt_id(*note_id),
                fmt_id(*goal_id)
            ));
        }
    }
    reasons
}

fn latest_checkpoint_view(
    catalogs: &NativeCatalogs,
    persona: Id,
) -> Result<Option<orient_model::WatchedView>> {
    let events = orient_model::load_checkpoint_events(&catalogs.reader, &catalogs.checkpoints)?;
    Ok(orient_model::latest_checkpoint(events, persona)?.map(|event| event.view))
}

fn save_checkpoint(
    pile: &mut Pile,
    signer: &SigningKey,
    persona: Id,
    view: &orient_model::WatchedView,
    newly_observed: impl IntoIterator<Item = Id>,
) -> Result<()> {
    let (mut fragment, _) = orient_model::checkpoint_fragment(persona, view, clock::point_now()?)?;
    fragment += orient_model::seen_notes_fragment(persona, newly_observed);
    open_scope(
        pile,
        faculties::schemas::orient::DEFAULT_SCOPE_ID,
        signer.clone(),
    )
    .commit(fragment)
    .map_err(|error| anyhow!("commit Orient semantic checkpoint: {error}"))?;
    Ok(())
}

fn require_seen_frontier(
    catalogs: &NativeCatalogs,
    persona: Id,
) -> Result<(BTreeSet<Id>, BTreeSet<Id>)> {
    let universe = all_note_ids(&catalogs.compass);
    let (observed, initialized) = observed_notes(catalogs, persona)?;
    if !initialized {
        bail!(
            "Orient's note frontier is not initialized for this persona: {} current notes exist, {} occur in legacy checkpoints, and {} have no legacy observation record. Stop Compass writers, then run `orient --persona <persona> migrate-note-frontier` once to baseline one coherent current Compass snapshot",
            universe.len(),
            observed.len(),
            universe.difference(&observed).count(),
        );
    }
    Ok((universe, observed))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MigrationOutcome {
    checkpoint: Id,
    observed: usize,
}

fn migrate_note_frontier(
    pile: &mut Pile,
    signer: &SigningKey,
    catalogs: &NativeCatalogs,
    persona: Id,
) -> Result<MigrationOutcome> {
    let (legacy_observed, initialized) = observed_notes(catalogs, persona)?;
    if initialized {
        bail!("note frontier is already initialized for {persona:x}");
    }
    let universe = all_note_ids(&catalogs.compass);
    let stale: Vec<_> = legacy_observed.difference(&universe).copied().collect();
    if !stale.is_empty() {
        bail!(
            "legacy Orient checkpoint for {persona:x} references {} missing Compass note(s), beginning with {}",
            stale.len(),
            fmt_id(stale[0]),
        );
    }
    let events = orient_model::load_checkpoint_events(&catalogs.reader, &catalogs.checkpoints)?;
    let checkpoint = orient_model::latest_checkpoint(events, persona)?.ok_or_else(|| {
        anyhow!("cannot migrate note frontier for {persona:x}: no checkpoint exists")
    })?;
    // `created_at` is authored event time, not publication order: a delayed or
    // backdated note may enter the pile after this checkpoint. A stopped-world
    // migration therefore baselines the one coherent current Compass snapshot
    // rather than pretending timestamps prove historical observation. Notes
    // appended after this commit are absent from Seen and wake normally.
    let selected = universe;
    let fragment = orient_model::seen_notes_fragment(persona, selected.iter().copied());
    open_scope(
        pile,
        faculties::schemas::orient::DEFAULT_SCOPE_ID,
        signer.clone(),
    )
    .commit(fragment)
    .map_err(|error| anyhow!("commit Orient note-frontier migration: {error}"))?;
    Ok(MigrationOutcome {
        checkpoint: checkpoint.event,
        observed: selected.len(),
    })
}

fn cmd_show(
    pile_path: &Path,
    key: Option<&Path>,
    persona: Option<&str>,
    message_limit: usize,
    doing_limit: usize,
    todo_limit: usize,
) -> Result<()> {
    let signer = load_signer(pile_path, key)?;
    let mut pile = open_pile_strict(pile_path)?;
    let mut habits = None;
    let result = (|| {
        let catalogs = load_native_catalogs(&mut pile, &signer)?;
        let persona_id = persona
            .map(|input| resolve_native_persona(&catalogs, input))
            .transpose()?;
        let messages = render_native_messages(&catalogs, persona_id, message_limit)?;
        let mail = render_native_mail(&catalogs, persona_id, message_limit)?;
        habits = Some(render_native_habits(&observe_habits(
            &catalogs,
            pile_path,
            epoch_seconds(clock::now()?),
        )?));
        let goals = render_native_compass_goals(&catalogs, doing_limit, todo_limit);
        let window_status = render_window_status(&catalogs)?;
        if let Some(persona_id) = persona_id {
            let view = load_watched_view(&catalogs, persona_id)?;
            match latest_checkpoint_view(&catalogs, persona_id)? {
                None => save_checkpoint(
                    &mut pile,
                    &signer,
                    persona_id,
                    &view,
                    all_note_ids(&catalogs.compass),
                )?,
                Some(checkpoint) => {
                    let (universe, observed) = require_seen_frontier(&catalogs, persona_id)?;
                    if checkpoint != view || universe != observed {
                        save_checkpoint(
                            &mut pile,
                            &signer,
                            persona_id,
                            &view,
                            universe.difference(&observed).copied(),
                        )?;
                    }
                }
            }
        }
        Ok((messages, mail, goals, window_status))
    })();
    let (messages, mail, goals, window_status) = close_pile(pile, result)?;
    let habits =
        habits.ok_or_else(|| anyhow!("native observation produced no Habits presentation"))?;

    println!("Orient");
    print!("{messages}");
    print!("{mail}");

    println!();
    print!("{habits}");
    print!("{goals}");
    print!("{window_status}");
    Ok(())
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

/// Print only the *novel* content behind the news — new peer messages, Mail
/// and Teams messages, plus newly-arrived roster members — so a woken watcher gets what changed,
/// not a full re-dump of the snapshot. The `News:` reason lines are printed by
/// the caller; this fills in the detail worth reading.
fn print_news_detail(
    catalogs: &NativeCatalogs,
    old: &orient_model::WatchedView,
    new: &orient_model::WatchedView,
    persona_id: Id,
) -> Result<()> {
    let new_msgs: Vec<Id> = new.unread.difference(&old.unread).copied().collect();
    if !new_msgs.is_empty() {
        let rows = message::load_message_rows(&catalogs.messages)?;
        println!("\nNew messages:");
        for id in &new_msgs {
            if let Some(row) = rows.iter().find(|r| r.id == *id) {
                let from = native_person_label(catalogs, row.from);
                let body = message::read_body(&catalogs.reader, row.body)?;
                println!("- {from}: {body}");
            }
        }
    }
    let new_mail: Vec<Id> = new
        .mail_unread
        .difference(&old.mail_unread)
        .copied()
        .collect();
    if !new_mail.is_empty() {
        let summaries = native_unread_mail(catalogs, persona_id)?;
        println!("\nNew mail:");
        for wire in &new_mail {
            let summary = summaries.get(wire).ok_or_else(|| {
                anyhow!("new Mail wire {} vanished from current view", fmt_id(*wire))
            })?;
            println!(
                "- [{}] {} — {}",
                fmt_id(*wire),
                summary.from.as_deref().unwrap_or("(no From)"),
                summary.subject,
            );
        }
    }
    let new_teams: Vec<Id> = new.teams.difference(&old.teams).copied().collect();
    if !new_teams.is_empty() {
        println!("\nNew Teams messages:");
        for message in &new_teams {
            let (author, content) = teams_message_detail(catalogs, *message)?;
            println!("- {author}: {content}");
        }
    }
    let new_people: Vec<Id> = new
        .roster
        .difference(&old.roster)
        .copied()
        .filter(|person| *person != persona_id)
        .collect();
    if !new_people.is_empty() {
        println!("\nNew status window(s):");
        for id in &new_people {
            println!("- {}", native_person_label(catalogs, *id));
        }
    }
    Ok(())
}

/// Outcome of one shot of the wait fire-path (`check_news_once`).
enum NewsCheck {
    /// News was printed tersely and the checkpoint advanced.
    Fired,
    /// A checkpoint exists and nothing is new.
    Quiet,
    /// No checkpoint for this persona yet — the caller decides how to
    /// establish the baseline (`wait` and non-peeking `poll` save it
    /// silently; peeking remains read-only).
    NoCheckpoint(orient_model::WatchedView),
}

/// One shot of the wait fire-path for a persona: load the current
/// watched view, diff it against the persona's last checkpoint, and if
/// there is news print the terse report (`News:` reasons + the novel
/// message bodies / status windows) and advance the checkpoint. Shared by
/// `wait` (pre-loop check) and `poll` (the whole command) — one code
/// path, blocking vs non-blocking only in the caller.
fn check_news_once(
    pile: &mut Pile,
    signer: &SigningKey,
    catalogs: &NativeCatalogs,
    persona_id: Id,
    peek: bool,
) -> Result<NewsCheck> {
    let view = load_watched_view(catalogs, persona_id)?;
    let Some(seen) = latest_checkpoint_view(catalogs, persona_id)? else {
        return Ok(NewsCheck::NoCheckpoint(view));
    };
    let (universe, observed) = require_seen_frontier(catalogs, persona_id)?;
    let reasons = view_news(&seen, &view, persona_id, &observed);
    if reasons.is_empty() {
        if !peek && (view != seen || universe != observed) {
            save_checkpoint(
                pile,
                signer,
                persona_id,
                &view,
                universe.difference(&observed).copied(),
            )?;
        }
        return Ok(NewsCheck::Quiet);
    }
    for reason in &reasons {
        println!("News: {reason}");
    }
    print_news_detail(catalogs, &seen, &view, persona_id)?;
    // Advance the checkpoint — the terse path skips cmd_show, which is
    // what normally saves it. Without this the checkpoint never moves
    // and every re-arm / next poll instantly re-fires on the same news.
    // Peek mode skips the save: report without consuming, for hooks that
    // can't tell whose turn they fire on (root vs subagent).
    if !peek {
        save_checkpoint(
            pile,
            signer,
            persona_id,
            &view,
            universe.difference(&observed).copied(),
        )?;
    }
    Ok(NewsCheck::Fired)
}

/// One-shot, non-blocking `wait`: report news since the persona's
/// checkpoint tersely, or print nothing and exit 0. Meant for per-turn
/// harness hooks (UserPromptSubmit and friends) so busy sessions
/// passively ingest team news at every turn boundary, while `wait`
/// keeps its job of waking idle ones.
fn close_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing pile also failed: {close_error}")))
        }
    }
}

fn cmd_poll(pile_path: &Path, key: Option<&Path>, persona: Option<&str>, peek: bool) -> Result<()> {
    let Some(input) = persona else {
        bail!("poll requires a persona (pass --persona <label-or-hex> or set $PERSONA)");
    };
    let signer = load_signer(pile_path, key)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        let catalogs = load_native_catalogs(&mut pile, &signer)?;
        let persona_id = resolve_native_persona(&catalogs, input)?;
        match check_news_once(&mut pile, &signer, &catalogs, persona_id, peek)? {
            // News printed (+ checkpoint advanced unless peeking).
            NewsCheck::Fired => {}
            // No news: print nothing, write nothing.
            NewsCheck::Quiet => {}
            // First poll for this persona: establish a baseline silently.
            // Dumping "everything currently unread" is a snapshot's job
            // (`orient show`), not a turn-boundary hook's; subsequent
            // polls diff against this checkpoint. Peek writes NOTHING —
            // not even a baseline (a worker turn must not initialize the
            // root persona's checkpoint).
            NewsCheck::NoCheckpoint(view) => {
                if !peek {
                    save_checkpoint(
                        &mut pile,
                        &signer,
                        persona_id,
                        &view,
                        all_note_ids(&catalogs.compass),
                    )?;
                }
            }
        }
        Ok(())
    })();
    close_pile(pile, result)
}

fn cmd_migrate_note_frontier(
    pile_path: &Path,
    key: Option<&Path>,
    persona: Option<&str>,
) -> Result<()> {
    let Some(input) = persona else {
        bail!("migrate-note-frontier requires a persona (pass --persona <label-or-hex> or set $PERSONA)");
    };
    let signer = load_signer(pile_path, key)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        let catalogs = load_native_catalogs(&mut pile, &signer)?;
        let persona_id = resolve_native_persona(&catalogs, input)?;
        let outcome = migrate_note_frontier(&mut pile, &signer, &catalogs, persona_id)?;
        println!(
            "Initialized note frontier for {} from legacy checkpoint {}: {} notes in the coherent Compass snapshot marked observed",
            input,
            fmt_id(outcome.checkpoint),
            outcome.observed,
        );
        Ok(())
    })();
    close_pile(pile, result)
}

fn cmd_wait(
    pile_path: &Path,
    key: Option<&Path>,
    persona: Option<&str>,
    target: Option<WaitTarget>,
    message_limit: usize,
    doing_limit: usize,
    todo_limit: usize,
    poll_ms: u64,
) -> Result<()> {
    let Some(persona_input) = persona else {
        bail!("wait requires a persona (pass --persona <label-or-hex> or set $PERSONA)");
    };
    let timeout = parse_wait_target(target.as_ref())?;
    let signer = load_signer(pile_path, key)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        // This is a processed-prefix watermark, not a last-observed size.
        // Sample before refresh: bytes appended while materializing the
        // baseline then remain beyond the watermark and force another pass.
        let mut observed_length = std::fs::metadata(pile_path)
            .map_err(|error| anyhow!("stat pile {}: {error}", pile_path.display()))?
            .len();
        pile.refresh()
            .map_err(|error| anyhow!("refresh pile {}: {error}", pile_path.display()))?;
        let mut catalogs = load_native_catalogs(&mut pile, &signer)?;
        let persona_id = resolve_native_persona(&catalogs, persona_input)?;
        // Already-due habits establish a quiet, process-local baseline. A
        // rearmed one-shot watcher therefore waits for a transition instead
        // of reporting the same unsatisfied intention forever.
        let mut habit_seen = observe_habits(&catalogs, pile_path, epoch_seconds(clock::now()?))?;
        let mut last_habit_sweep = Instant::now();

        match check_news_once(&mut pile, &signer, &catalogs, persona_id, false)? {
            NewsCheck::Fired => return Ok((true, true)),
            NewsCheck::Quiet => {}
            NewsCheck::NoCheckpoint(view) => {
                save_checkpoint(
                    &mut pile,
                    &signer,
                    persona_id,
                    &view,
                    all_note_ids(&catalogs.compass),
                )?;
            }
        }

        let poll = Duration::from_millis(poll_ms.max(1));
        let start = Instant::now();

        loop {
            if let Some(timeout) = timeout {
                if start.elapsed() >= timeout {
                    return Ok((false, false));
                }
            }
            std::thread::sleep(poll);
            let current_length = std::fs::metadata(pile_path)
                .map_err(|error| anyhow!("stat pile {}: {error}", pile_path.display()))?
                .len();
            let pile_changed = current_length != observed_length;
            let now_secs = epoch_seconds(clock::now()?);
            let cooldown_elapsed = habit_seen
                .next_cooldown_at
                .is_some_and(|deadline| now_secs >= deadline);
            let periodic_condition_check = last_habit_sweep.elapsed() >= Duration::from_secs(60);
            if !pile_changed && !cooldown_elapsed && !periodic_condition_check {
                continue;
            }

            if pile_changed {
                pile.refresh()
                    .map_err(|error| anyhow!("refresh pile {}: {error}", pile_path.display()))?;
                catalogs = load_native_catalogs(&mut pile, &signer)?;
            }

            // This happens before the append-driven news path. If ordinary
            // news and a Habit transition arrive together, both are printed
            // before the one-shot watcher exits; rearming cannot erase either.
            let current_habits = observe_habits(&catalogs, pile_path, now_secs)?;
            let habit_fired = print_habit_transitions(&habit_seen, &current_habits);
            habit_seen = current_habits;
            last_habit_sweep = Instant::now();

            let ordinary_fired = if pile_changed {
                match check_news_once(&mut pile, &signer, &catalogs, persona_id, false)? {
                    NewsCheck::Fired => true,
                    NewsCheck::Quiet => false,
                    NewsCheck::NoCheckpoint(view) => {
                        // This can only happen if an external rewrite removed
                        // the append-only checkpoint collection. Retain total
                        // behavior without inventing a partial baseline.
                        save_checkpoint(
                            &mut pile,
                            &signer,
                            persona_id,
                            &view,
                            all_note_ids(&catalogs.compass),
                        )?;
                        false
                    }
                }
            } else {
                false
            };
            if habit_fired || ordinary_fired {
                return Ok((true, true));
            }
            // Advance only through the exact prefix refreshed above. An
            // external append (or our own checkpoint append) which raced with
            // processing remains beyond this watermark and triggers another
            // refresh instead of being silently swallowed.
            if pile_changed {
                observed_length = current_length;
            }
        }
    })();
    let (changed, news_printed) = close_pile(pile, result)?;
    if news_printed {
        // Terse path: the News: reasons and the novel detail were already
        // printed inside the wait loop — don't re-dump the full snapshot.
        return Ok(());
    }
    if !changed {
        println!("No change detected since wait started; showing current snapshot.");
    }
    cmd_show(
        pile_path,
        key,
        persona,
        message_limit,
        doing_limit,
        todo_limit,
    )
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

/// `orient wake` — assemble the full wake bundle a fresh face reads to come
/// into itself: the memory cover (coarse → fine over ALL memories), then the
/// cover-tagged wiki beliefs (the ambient always-true set), then the compass
/// goals. READ-ONLY: it materializes or checks out, but publishes nothing.
fn cmd_wake(
    pile: &Path,
    key: Option<&Path>,
    chars: usize,
    doing_limit: usize,
    todo_limit: usize,
) -> Result<()> {
    // Memory, Wiki, and Compass all come from one refreshed native snapshot.
    // A plain wake cover never consults rebuildable embeddings, so it
    // deliberately cannot be taken down by a missing or corrupt embedding
    // artifact. Exact preserved legacy rows remain durable evidence without
    // becoming duplicate memories or beliefs in the native projections.
    let signer = load_signer(pile, key)?;
    let mut storage = open_pile_strict(pile)?;
    let result = (|| {
        let memory_facts = materialize_scope(&mut storage, &signer, MEMORY_SCOPE_ID, "Memory")?;
        let wiki_facts = materialize_scope(&mut storage, &signer, WIKI_SCOPE_ID, "Wiki")?;
        let catalogs = load_native_catalogs(&mut storage, &signer)?;

        let memory_catalog = memory_model::validate_catalog(&catalogs.reader, &memory_facts)
            .map_err(|error| anyhow!("validate Memory collection: {error:#}"))?;
        let nodes = memory_catalog.node_ids();
        let mut memory = TribleSet::new();
        for fact in memory_facts.iter().filter(|fact| nodes.contains(fact.e())) {
            memory.insert(fact);
        }
        let cover = render_cover(
            &memory,
            &TribleSet::new(),
            &catalogs.reader,
            &CoverOpts::plain(chars),
        )?;

        let wiki_catalog = wiki_model::validate_catalog(&catalogs.reader, &wiki_facts)
            .map_err(|error| anyhow!("validate Wiki collection: {error:#}"))?;
        let beliefs = wiki_model::cover_fragments(&catalogs.reader, &wiki_catalog)?;
        let goals = render_native_compass_goals(&catalogs, doing_limit, todo_limit);
        Ok((cover, beliefs, goals))
    })();
    let (cover, beliefs, goals) = close_pile(storage, result)?;

    print!("{cover}");
    println!();
    println!("Beliefs (cover):");
    if beliefs.is_empty() {
        println!("- None");
    } else {
        for (title, content) in beliefs {
            println!("- {title}");
            for line in content.lines() {
                println!("    {line}");
            }
        }
    }
    println!();
    print!("{goals}");
    Ok(())
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
            cli.key.as_deref(),
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
            cli.key.as_deref(),
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
        } => cmd_wake(
            &cli.pile,
            cli.key.as_deref(),
            chars,
            doing_limit,
            todo_limit,
        ),
        Command::Poll { peek } => {
            cmd_poll(&cli.pile, cli.key.as_deref(), cli.persona.as_deref(), peek)
        }
        Command::MigrateNoteFrontier => {
            cmd_migrate_note_frontier(&cli.pile, cli.key.as_deref(), cli.persona.as_deref())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEST_PILE: AtomicU64 = AtomicU64::new(0);

    struct TestPile {
        dir: PathBuf,
        path: PathBuf,
        signer: SigningKey,
    }

    impl TestPile {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sequence = NEXT_TEST_PILE.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "faculties-orient-native-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("test.pile");
            fs::File::create(&path).unwrap();
            let signer = SigningKey::generate(&mut rand_core::OsRng);
            let mut pile = open_pile_strict(&path).unwrap();
            faculties::storage::ensure_team_of_one_write_authority(&mut pile, &signer).unwrap();
            pile.close().unwrap();
            Self { dir, path, signer }
        }
    }

    impl Drop for TestPile {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn commit_scope(pile: &mut Pile, signer: &SigningKey, scope: Id, fragment: Fragment) {
        faculties::collection_names::open(pile, scope, signer.clone())
            .commit(fragment)
            .unwrap();
    }

    fn profile(label: &str) -> relations::ProfileInput {
        relations::ProfileInput {
            label: label.to_owned(),
            ..relations::ProfileInput::default()
        }
    }

    fn view(goals_view: impl Into<String>) -> orient_model::WatchedView {
        orient_model::WatchedView {
            unread: BTreeSet::new(),
            mail_unread: BTreeSet::new(),
            teams: BTreeSet::new(),
            goals_view: goals_view.into(),
            roster: BTreeSet::new(),
            notes: BTreeMap::new(),
        }
    }

    #[test]
    fn addressed_new_goal_wakes() {
        let me = ufoid().id;
        let goal = ufoid().id;
        let news = view_news(
            &view(""),
            &view(format!("{goal:x}:todo::a")),
            me,
            &BTreeSet::new(),
        );
        assert_eq!(news, [format!("new goal [{goal:x}] (todo)")]);
    }

    #[test]
    fn unaddressed_new_goal_is_quiet() {
        let me = ufoid().id;
        let goal = ufoid().id;
        assert!(view_news(
            &view(""),
            &view(format!("{goal:x}:todo::")),
            me,
            &BTreeSet::new()
        )
        .is_empty());
    }

    #[test]
    fn own_status_change_is_quiet() {
        let me = ufoid().id;
        let goal = ufoid().id;
        let old = view(format!("{goal:x}:todo:{me:x}:ia"));
        let new = view(format!("{goal:x}:doing:{me:x}:ia"));
        assert!(view_news(&old, &new, me, &BTreeSet::new()).is_empty());
    }

    #[test]
    fn relevant_peer_status_change_wakes() {
        let me = ufoid().id;
        let peer = ufoid().id;
        let goal = ufoid().id;
        let old = view(format!("{goal:x}:todo:{peer:x}:a"));
        let new = view(format!("{goal:x}:doing:{peer:x}:a"));
        assert_eq!(
            view_news(&old, &new, me, &BTreeSet::new()),
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
        let news = view_news(&old, &new, me, &BTreeSet::new());
        assert_eq!(
            news,
            [
                format!("new message [{message:x}]"),
                format!("new status window [{person:x}]"),
            ]
        );
    }

    #[test]
    fn unread_mail_growth_wakes_and_read_removal_is_quiet() {
        let me = ufoid().id;
        let wire = ufoid().id;
        let old = view("");
        let mut unread = old.clone();
        unread.mail_unread.insert(wire);
        assert_eq!(
            view_news(&old, &unread, me, &BTreeSet::new()),
            [format!("new mail [{wire:x}]")]
        );
        assert!(view_news(&unread, &old, me, &BTreeSet::new()).is_empty());
    }

    #[test]
    fn teams_message_growth_wakes_and_disappearance_is_quiet() {
        let me = ufoid().id;
        let message = ufoid().id;
        let old = view("");
        let mut new = old.clone();
        new.teams.insert(message);
        assert_eq!(
            view_news(&old, &new, me, &BTreeSet::new()),
            [format!("new Teams message [{message:x}]")]
        );
        assert!(view_news(&new, &old, me, &BTreeSet::new()).is_empty());
    }

    fn teams_observation(
        source: Id,
        message_id: &str,
        author_user_id: &str,
        author_name: &str,
        content: &str,
        seconds: f64,
    ) -> Fragment {
        let at = epoch_interval(Epoch::from_unix_seconds(seconds));
        teams_model::observation_fragment(
            TEAMS_TENANT,
            source,
            teams_model::MessageObservationInput {
                chat_id: "19:orient-news@thread.v2".to_owned(),
                message_id: message_id.to_owned(),
                raw: BTreeSet::from([format!("{{\"id\":\"{message_id}\"}}")]),
                author_user_id: Some(author_user_id.to_owned()),
                author_name: Some(author_name.to_owned()),
                content: Some(content.to_owned()),
                created_at: Some(at),
                modified_at: at,
                deleted_at: None,
                etag: format!("{message_id}-1"),
                attachments: Vec::new(),
            },
        )
        .unwrap()
        .0
    }

    const TEAMS_TENANT: &str = "orient-news.example";
    const TEAMS_OWN_USER: &str = "own-graph-user-id";

    #[test]
    fn colleague_teams_message_wakes_and_our_own_send_is_quiet() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let persona = ufoid().id;
        let (relations_fragment, _, _) =
            relations::person_fragment(persona, profile("persona")).unwrap();
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        commit_scope(&mut pile, &signer, RELATIONS_SCOPE_ID, relations_fragment);

        let source_fragment = teams_model::source_fragment(TEAMS_TENANT);
        let source = source_fragment.root().unwrap();
        let (auth_fragment, _) = teams_model::auth_profile_fragment(
            source,
            "client-id",
            TEAMS_OWN_USER,
            "Chat.ReadWrite offline_access",
            Some(ufoid().id),
            None,
            Vec::new(),
        )
        .unwrap();
        commit_scope(
            &mut pile,
            &signer,
            TEAMS_SCOPE_ID,
            source_fragment + auth_fragment,
        );

        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let baseline = load_watched_view(&catalogs, persona).unwrap();
        assert!(baseline.teams.is_empty());
        save_checkpoint(&mut pile, &signer, persona, &baseline, std::iter::empty()).unwrap();

        // A colleague's reply is news for every window on this pile.
        commit_scope(
            &mut pile,
            &signer,
            TEAMS_SCOPE_ID,
            teams_observation(
                source,
                "colleague-1",
                "colleague-graph-user-id",
                "Colleague",
                "<p>did the build land?</p>",
                10.0,
            ),
        );
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let incoming = load_watched_view(&catalogs, persona).unwrap();
        assert_eq!(incoming.teams.len(), 1);
        let message = *incoming.teams.iter().next().unwrap();
        assert_eq!(
            view_news(&baseline, &incoming, persona, &BTreeSet::new()),
            [format!("new Teams message [{message:x}]")]
        );
        let (author, content) = teams_message_detail(&catalogs, message).unwrap();
        assert_eq!(author, "Colleague");
        assert!(content.contains("did the build land?"));
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Fired
        ));

        // Our own send comes back through the next delta pull. It is the same
        // shape of record, and it must never wake anyone.
        commit_scope(
            &mut pile,
            &signer,
            TEAMS_SCOPE_ID,
            teams_observation(
                source,
                "own-1",
                TEAMS_OWN_USER,
                "Bulti",
                "<p>it did</p>",
                20.0,
            ),
        );
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let after_own = load_watched_view(&catalogs, persona).unwrap();
        assert_eq!(after_own.teams, BTreeSet::from([message]));
        assert!(view_news(&incoming, &after_own, persona, &BTreeSet::new()).is_empty());
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Quiet
        ));

        // Graph's authorless chat events are not somebody writing to us.
        let at = epoch_interval(Epoch::from_unix_seconds(25.0));
        commit_scope(
            &mut pile,
            &signer,
            TEAMS_SCOPE_ID,
            teams_model::observation_fragment(
                TEAMS_TENANT,
                source,
                teams_model::MessageObservationInput {
                    chat_id: "19:orient-news@thread.v2".to_owned(),
                    message_id: "system-1".to_owned(),
                    raw: BTreeSet::from(["{\"id\":\"system-1\"}".to_owned()]),
                    author_user_id: None,
                    author_name: None,
                    content: Some("<systemEventMessage/>".to_owned()),
                    created_at: Some(at),
                    modified_at: at,
                    deleted_at: None,
                    etag: "system-1-1".to_owned(),
                    attachments: Vec::new(),
                },
            )
            .unwrap()
            .0,
        );
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let after_event = load_watched_view(&catalogs, persona).unwrap();
        assert_eq!(after_event.teams, BTreeSet::from([message]));
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Quiet
        ));

        // Re-observing the same colleague message (an edit) changes storage,
        // not the attention set.
        commit_scope(
            &mut pile,
            &signer,
            TEAMS_SCOPE_ID,
            teams_observation(
                source,
                "colleague-1",
                "colleague-graph-user-id",
                "Colleague",
                "<p>did the build land? (edited)</p>",
                30.0,
            ),
        );
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let after_edit = load_watched_view(&catalogs, persona).unwrap();
        assert_eq!(after_edit.teams, BTreeSet::from([message]));
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Quiet
        ));
        pile.close().unwrap();
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
            view_news(&old, &new, me, &BTreeSet::new()),
            [format!("new note [{note:x}] on goal [{goal:x}]")]
        );
    }

    #[test]
    fn same_view_after_different_collection_history_is_silent() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let persona = ufoid().id;
        let (relations_fragment, _, _) =
            relations::person_fragment(persona, profile("persona")).unwrap();
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        commit_scope(
            &mut pile,
            &signer,
            RELATIONS_SCOPE_ID,
            relations_fragment.clone(),
        );

        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let baseline = load_watched_view(&catalogs, persona).unwrap();
        save_checkpoint(&mut pile, &signer, persona, &baseline, std::iter::empty()).unwrap();

        // A second authored leaf has distinct metadata/history but contributes
        // exactly the same Relations set value.
        let mut replay = relations_fragment;
        *replay.metafacts_mut() += entity! { &ufoid() @ metadata::tag: &ufoid().id };
        commit_scope(&mut pile, &signer, RELATIONS_SCOPE_ID, replay);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        assert_eq!(load_watched_view(&catalogs, persona).unwrap(), baseline);

        let before = fs::metadata(&fixture.path).unwrap().len();
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Quiet
        ));
        let after = fs::metadata(&fixture.path).unwrap().len();
        assert_eq!(before, after, "equal semantic views must not checkpoint");
        pile.close().unwrap();
    }

    #[test]
    fn seen_frontier_blocks_relevance_replay_but_wakes_for_a_later_note() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let persona = ufoid().id;
        let peer = ufoid().id;
        let goal = ufoid().id;
        let old_note = ufoid().id;
        let own_note = ufoid().id;
        let new_note = ufoid().id;
        let mut relations_fragment = relations::person_fragment(persona, profile("persona"))
            .unwrap()
            .0;
        relations_fragment += relations::person_fragment(peer, profile("peer")).unwrap().0;
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        commit_scope(&mut pile, &signer, RELATIONS_SCOPE_ID, relations_fragment);

        let mut history = compass::goal_fragment(
            goal,
            "unrelated history",
            Vec::new(),
            None,
            epoch_interval(Epoch::from_unix_seconds(1.0)),
        )
        .unwrap();
        history += compass::note_fragment(
            old_note,
            goal,
            "old invisible note",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(peer),
            epoch_interval(Epoch::from_unix_seconds(2.0)),
        )
        .unwrap();
        commit_scope(&mut pile, &signer, COMPASS_SCOPE_ID, history);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let baseline = load_watched_view(&catalogs, persona).unwrap();
        assert!(!baseline.notes.contains_key(&old_note));
        save_checkpoint(&mut pile, &signer, persona, &baseline, [old_note]).unwrap();

        let participation = compass::note_fragment(
            own_note,
            goal,
            "joining",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(persona),
            epoch_interval(Epoch::from_unix_seconds(3.0)),
        )
        .unwrap();
        commit_scope(&mut pile, &signer, COMPASS_SCOPE_ID, participation);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Quiet
        ));

        let response = compass::note_fragment(
            new_note,
            goal,
            "new response",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(peer),
            epoch_interval(Epoch::from_unix_seconds(4.0)),
        )
        .unwrap();
        commit_scope(&mut pile, &signer, COMPASS_SCOPE_ID, response);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let current = load_watched_view(&catalogs, persona).unwrap();
        let (_, observed) = require_seen_frontier(&catalogs, persona).unwrap();
        assert_eq!(
            view_news(&baseline, &current, persona, &observed),
            [format!("new note [{new_note:x}] on goal [{goal:x}]")]
        );
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Fired
        ));
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Quiet
        ));
        pile.close().unwrap();
    }

    #[test]
    fn old_checkpoint_requires_explicit_note_baseline() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let persona = ufoid().id;
        let (relations_fragment, _, _) =
            relations::person_fragment(persona, profile("persona")).unwrap();
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        commit_scope(&mut pile, &signer, RELATIONS_SCOPE_ID, relations_fragment);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let baseline = load_watched_view(&catalogs, persona).unwrap();
        let (legacy_checkpoint, _) = orient_model::checkpoint_fragment(
            persona,
            &baseline,
            epoch_interval(Epoch::from_unix_seconds(1.0)),
        )
        .unwrap();
        commit_scope(
            &mut pile,
            &signer,
            faculties::schemas::orient::DEFAULT_SCOPE_ID,
            legacy_checkpoint,
        );
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let error = match check_news_once(&mut pile, &signer, &catalogs, persona, false) {
            Err(error) => error,
            Ok(_) => panic!("legacy checkpoint must require explicit note baseline"),
        };
        assert!(error.to_string().contains("migrate-note-frontier"));

        let frontier = orient_model::seen_notes_fragment(persona, std::iter::empty());
        commit_scope(
            &mut pile,
            &signer,
            faculties::schemas::orient::DEFAULT_SCOPE_ID,
            frontier,
        );
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Quiet
        ));
        pile.close().unwrap();
    }

    #[test]
    fn frontier_migration_rejects_stale_checkpoint_notes_without_appending() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let persona = ufoid().id;
        let missing_note = ufoid().id;
        let missing_goal = ufoid().id;
        let (relations_fragment, _, _) =
            relations::person_fragment(persona, profile("persona")).unwrap();
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        commit_scope(&mut pile, &signer, RELATIONS_SCOPE_ID, relations_fragment);

        let mut stale_view = view("");
        stale_view.notes.insert(missing_note, missing_goal);
        let (checkpoint, _) = orient_model::checkpoint_fragment(
            persona,
            &stale_view,
            epoch_interval(Epoch::from_unix_seconds(10.0)),
        )
        .unwrap();
        commit_scope(
            &mut pile,
            &signer,
            faculties::schemas::orient::DEFAULT_SCOPE_ID,
            checkpoint,
        );

        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let before = fs::metadata(&fixture.path).unwrap().len();
        let error = migrate_note_frontier(&mut pile, &signer, &catalogs, persona).unwrap_err();
        let after = fs::metadata(&fixture.path).unwrap().len();
        assert!(format!("{error:#}").contains("references 1 missing Compass note"));
        assert_eq!(before, after, "a rejected migration must append nothing");
        assert!(!observed_notes(&catalogs, persona).unwrap().1);
        pile.close().unwrap();
    }

    #[test]
    fn first_persona_baseline_is_silent_and_initializes_frontier() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let persona = ufoid().id;
        let (relations_fragment, _, _) =
            relations::person_fragment(persona, profile("persona")).unwrap();
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        commit_scope(&mut pile, &signer, RELATIONS_SCOPE_ID, relations_fragment);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let view = match check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap() {
            NewsCheck::NoCheckpoint(view) => view,
            _ => panic!("first persona must have no checkpoint"),
        };
        save_checkpoint(
            &mut pile,
            &signer,
            persona,
            &view,
            all_note_ids(&catalogs.compass),
        )
        .unwrap();
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        assert!(require_seen_frontier(&catalogs, persona)
            .unwrap()
            .1
            .is_empty());
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Quiet
        ));
        pile.close().unwrap();
    }

    #[test]
    fn raw_persona_first_poll_survives_reload_without_a_relations_profile() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let persona = ufoid().id;
        let input = format!("{persona:x}");
        let mut pile = open_pile_strict(&fixture.path).unwrap();

        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let resolved = resolve_native_persona(&catalogs, &input).unwrap();
        assert_eq!(resolved, persona);
        let baseline =
            match check_news_once(&mut pile, &signer, &catalogs, resolved, false).unwrap() {
                NewsCheck::NoCheckpoint(view) => view,
                _ => panic!("an undeclared raw persona must begin without a checkpoint"),
            };
        save_checkpoint(
            &mut pile,
            &signer,
            resolved,
            &baseline,
            all_note_ids(&catalogs.compass),
        )
        .unwrap();

        // Reloading all catalogs performs the same validation as the next
        // command invocation. The exact raw anchor remains valid even though
        // no Relations profile has arrived yet.
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        assert!(relations::person_anchors(&catalogs.relations).is_empty());
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, resolved, false).unwrap(),
            NewsCheck::Quiet
        ));
        pile.close().unwrap();
    }

    #[test]
    fn frontier_migration_baselines_the_snapshot_but_preserves_pending_messages() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let persona = ufoid().id;
        let sender = ufoid().id;
        let goal = ufoid().id;
        let existing_note = ufoid().id;
        let later_note = ufoid().id;
        let mut relations_fragment = relations::person_fragment(persona, profile("persona"))
            .unwrap()
            .0;
        relations_fragment += relations::person_fragment(sender, profile("sender"))
            .unwrap()
            .0;
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        commit_scope(&mut pile, &signer, RELATIONS_SCOPE_ID, relations_fragment);
        let baseline = view("");
        let (checkpoint, _) = orient_model::checkpoint_fragment(
            persona,
            &baseline,
            epoch_interval(Epoch::from_unix_seconds(10.0)),
        )
        .unwrap();
        commit_scope(
            &mut pile,
            &signer,
            faculties::schemas::orient::DEFAULT_SCOPE_ID,
            checkpoint,
        );
        let mut notes = compass::goal_fragment(
            goal,
            "goal",
            vec!["persona".to_owned()],
            None,
            epoch_interval(Epoch::from_unix_seconds(1.0)),
        )
        .unwrap();
        notes += compass::note_fragment(
            existing_note,
            goal,
            "existing note",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(sender),
            epoch_interval(Epoch::from_unix_seconds(99.0)),
        )
        .unwrap();
        commit_scope(&mut pile, &signer, COMPASS_SCOPE_ID, notes);
        let (message_fragment, message_id) = message::message_fragment(
            sender,
            &message::Recipient::Person(persona),
            "pending",
            epoch_interval(Epoch::from_unix_seconds(13.0)),
        );
        commit_scope(&mut pile, &signer, MESSAGE_SCOPE_ID, message_fragment);

        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let outcome = migrate_note_frontier(&mut pile, &signer, &catalogs, persona).unwrap();
        assert_eq!(outcome.observed, 1);

        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let (_, observed) = require_seen_frontier(&catalogs, persona).unwrap();
        assert!(observed.contains(&existing_note));
        let current = load_watched_view(&catalogs, persona).unwrap();
        let news = view_news(&baseline, &current, persona, &observed);
        assert!(news.contains(&format!("new message [{message_id:x}]")));
        // Publication order—not authored time—defines what was in the
        // migration snapshot. A deliberately backdated note appended now must
        // remain unseen and therefore wake.
        let later = compass::note_fragment(
            later_note,
            goal,
            "later backdated note",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(sender),
            epoch_interval(Epoch::from_unix_seconds(1.0)),
        )
        .unwrap();
        commit_scope(&mut pile, &signer, COMPASS_SCOPE_ID, later);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let (_, observed) = require_seen_frontier(&catalogs, persona).unwrap();
        assert!(!observed.contains(&later_note));
        let current = load_watched_view(&catalogs, persona).unwrap();
        let news = view_news(&baseline, &current, persona, &observed);
        assert!(news.contains(&format!("new note [{later_note:x}] on goal [{goal:x}]")));
        pile.close().unwrap();
    }

    #[test]
    fn publishing_status_is_what_places_a_window_on_the_roster() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let quiet = ufoid().id;
        let active = ufoid().id;
        let mut relations_fragment = relations::person_fragment(quiet, profile("quiet"))
            .unwrap()
            .0;
        relations_fragment += relations::person_fragment(active, profile("active"))
            .unwrap()
            .0;

        let mut pile = open_pile_strict(&fixture.path).unwrap();
        commit_scope(&mut pile, &signer, RELATIONS_SCOPE_ID, relations_fragment);
        let status = status::status_fragment(
            active,
            "building",
            epoch_interval(Epoch::from_unix_seconds(1.0)),
        )
        .unwrap();
        commit_scope(&mut pile, &signer, STATUS_SCOPE_ID, status);

        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        assert_eq!(status_roster(&catalogs).unwrap(), BTreeSet::from([active]));
        let rendered = render_window_status(&catalogs).unwrap();
        assert!(rendered.contains("active: building"));
        assert!(!rendered.contains("quiet"));
        pile.close().unwrap();
    }

    #[test]
    fn own_first_status_is_quiet() {
        let me = ufoid().id;
        let old = view("");
        let mut new = view("");
        new.roster.insert(me);

        assert!(view_news(&old, &new, me, &BTreeSet::new()).is_empty());
    }

    #[test]
    fn group_attention_tolerates_unrelated_and_member_forks() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let me = ufoid().id;
        let peer = ufoid().id;
        let addressed = ufoid().id;
        let unrelated = ufoid().id;

        let mut fragment = relations::person_fragment(me, profile("me")).unwrap().0;
        fragment += relations::person_fragment(peer, profile("peer")).unwrap().0;

        let (addressed_root, addressed_initial) =
            relations::group_create_fragment(addressed, "reviewers").unwrap();
        fragment += addressed_root;
        fragment +=
            relations::group_snapshot_fragment(addressed, "reviewers", &[me], &[addressed_initial])
                .unwrap();
        fragment +=
            relations::group_snapshot_fragment(addressed, "review-team", &[], &[addressed_initial])
                .unwrap();

        let (unrelated_root, unrelated_initial) =
            relations::group_create_fragment(unrelated, "other").unwrap();
        fragment += unrelated_root;
        fragment += relations::group_snapshot_fragment(
            unrelated,
            "other-left",
            &[peer],
            &[unrelated_initial],
        )
        .unwrap();
        fragment +=
            relations::group_snapshot_fragment(unrelated, "other-right", &[], &[unrelated_initial])
                .unwrap();

        let mut pile = open_pile_strict(&fixture.path).unwrap();
        commit_scope(&mut pile, &signer, RELATIONS_SCOPE_ID, fragment);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let keys = group_attention_keys(&catalogs.reader, &catalogs.relations, me).unwrap();

        assert_eq!(
            keys,
            HashSet::from(["reviewers".to_owned(), "review-team".to_owned()]),
            "all maximal names of a containing fork address the member, while an unrelated fork is inert"
        );
        pile.close().unwrap();
    }

    #[test]
    fn habit_cooldown_deadline_wakes_without_pile_growth() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let (definition, habit) =
            habits::habit_fragment("lineage-hygiene", "every 1s", "inspect branches", None, &[])
                .unwrap();
        let completed_at = Epoch::from_unix_seconds(100.0);
        let completed_secs = epoch_seconds(completed_at);
        let (completion, _) =
            habits::completion_fragment(habit, epoch_interval(completed_at)).unwrap();

        let mut pile = open_pile_strict(&fixture.path).unwrap();
        commit_scope(&mut pile, &signer, HABIT_SCOPE_ID, definition);
        commit_scope(&mut pile, &signer, HABIT_SCOPE_ID, completion);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let before = observe_habits(&catalogs, &fixture.path, completed_secs).unwrap();
        assert!(before.due.is_empty());
        assert_eq!(before.next_cooldown_at, Some(completed_secs + 1));
        let pile_length = fs::metadata(&fixture.path).unwrap().len();

        // No refresh and no new collection record: only the explicit wall
        // clock advances across the completion-relative deadline.
        let after = observe_habits(&catalogs, &fixture.path, completed_secs + 1).unwrap();
        assert_eq!(fs::metadata(&fixture.path).unwrap().len(), pile_length);
        assert_eq!(
            newly_due(&before, &after),
            [(
                habit,
                DueHabit {
                    label: "lineage-hygiene".to_owned(),
                    nudge: "inspect branches".to_owned(),
                },
            )]
        );
        assert!(
            newly_due(&after, &after).is_empty(),
            "rearm baseline is quiet"
        );
        assert!(render_native_habits(&after).contains("Habits due:"));
        assert!(render_native_habits(&after).contains("inspect branches"));
        pile.close().unwrap();
    }

    #[test]
    fn habit_attention_transition_wakes_once() {
        let habit = Id::new([0xA5; 16]).unwrap();
        let quiet = HabitObservation::default();
        let mut broken = HabitObservation::default();
        broken.attention.insert(
            habit,
            "lineage-hygiene [a5] ERROR: command not found".to_owned(),
        );

        assert_eq!(
            newly_needing_attention(&quiet, &broken),
            [(
                habit,
                "lineage-hygiene [a5] ERROR: command not found".to_owned()
            )]
        );
        assert!(newly_needing_attention(&broken, &broken).is_empty());
    }

    #[test]
    fn actual_semantic_message_change_is_news() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let persona = ufoid().id;
        let sender = ufoid().id;
        let mut relations_fragment = relations::person_fragment(persona, profile("persona"))
            .unwrap()
            .0;
        relations_fragment += relations::person_fragment(sender, profile("sender"))
            .unwrap()
            .0;
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        commit_scope(&mut pile, &signer, RELATIONS_SCOPE_ID, relations_fragment);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let baseline = load_watched_view(&catalogs, persona).unwrap();
        save_checkpoint(&mut pile, &signer, persona, &baseline, std::iter::empty()).unwrap();

        let (message_fragment, message_id) = message::message_fragment(
            sender,
            &message::Recipient::Person(persona),
            "hello",
            epoch_interval(Epoch::from_unix_seconds(1.0)),
        );
        commit_scope(&mut pile, &signer, MESSAGE_SCOPE_ID, message_fragment);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let current = load_watched_view(&catalogs, persona).unwrap();
        assert_eq!(
            view_news(&baseline, &current, persona, &BTreeSet::new()),
            [format!("new message [{message_id:x}]")]
        );
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Fired
        ));
        pile.close().unwrap();
    }

    #[test]
    fn incoming_native_mail_wakes_once_per_wire_and_reading_is_quiet() {
        let fixture = TestPile::new();
        let signer = fixture.signer.clone();
        let persona = ufoid().id;
        let (relations_fragment, _, _) =
            relations::person_fragment(persona, profile("persona")).unwrap();
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        commit_scope(&mut pile, &signer, RELATIONS_SCOPE_ID, relations_fragment);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let baseline = load_watched_view(&catalogs, persona).unwrap();
        save_checkpoint(&mut pile, &signer, persona, &baseline, std::iter::empty()).unwrap();

        let account = ufoid().id;
        let (account_fragment, config) = mail_model::account_config_fragment(
            account,
            mail_model::AccountConfigInput {
                address: "persona@example.test".to_owned(),
                display_name: "Persona".to_owned(),
                pop_endpoint: "pop.example.test:995".to_owned(),
                smtp_endpoint: "smtp.example.test:465".to_owned(),
                username: "persona@example.test".to_owned(),
                credential: ufoid().id,
                enabled: true,
                predecessors: Vec::new(),
            },
        )
        .unwrap();
        commit_scope(&mut pile, &signer, MAIL_SCOPE_ID, account_fragment);
        let raw = b"From: sender@example.test\r\nTo: persona@example.test\r\nSubject: Native hello\r\nMessage-ID: <native-hello@example.test>\r\nDate: Tue, 11 Aug 2026 06:00:00 +0200\r\n\r\nBody\r\n";
        let publication = mail_model::pop_publication(account, config, "uid-native", raw).unwrap();
        let wire = publication.wire;
        commit_scope(&mut pile, &signer, MAIL_SCOPE_ID, publication.mail);

        let mut catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let incoming = load_watched_view(&catalogs, persona).unwrap();
        assert_eq!(incoming.mail_unread, BTreeSet::from([wire]));
        assert_eq!(
            view_news(&baseline, &incoming, persona, &BTreeSet::new()),
            [format!("new mail [{wire:x}]")]
        );
        let rendered = render_native_mail(&catalogs, Some(persona), 10).unwrap();
        assert!(rendered.contains(&fmt_id(wire)));
        assert!(rendered.contains("sender@example.test"));
        assert!(rendered.contains("Native hello"));

        // Outgoing observations are not inbox rows. Injecting one exact
        // parser publication therefore cannot add its wire to the watched
        // projection (the complete acceptance-chain invariant is exercised
        // by Mail's own catalog tests).
        let outbound = mail_model::outgoing_publication(
            ufoid().id,
            b"From: persona@example.test\r\nTo: other@example.test\r\nSubject: Sent\r\nMessage-ID: <sent@example.test>\r\n\r\nBody\r\n",
        )
        .unwrap();
        let outbound_wire = outbound.wire;
        catalogs.mail += outbound.mail.into_facts();
        let with_outbound = load_watched_view(&catalogs, persona).unwrap();
        assert_eq!(with_outbound.mail_unread, BTreeSet::from([wire]));
        assert!(!with_outbound.mail_unread.contains(&outbound_wire));
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Fired
        ));

        // A second POP source for the same wire is a storage change, not a
        // new attention item.
        let replay = mail_model::pop_publication(account, config, "uid-replay", raw).unwrap();
        assert_eq!(replay.wire, wire);
        commit_scope(&mut pile, &signer, MAIL_SCOPE_ID, replay.mail);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let replayed = load_watched_view(&catalogs, persona).unwrap();
        assert_eq!(replayed, incoming);
        let before = fs::metadata(&fixture.path).unwrap().len();
        assert!(matches!(
            check_news_once(&mut pile, &signer, &catalogs, persona, false).unwrap(),
            NewsCheck::Quiet
        ));
        assert_eq!(fs::metadata(&fixture.path).unwrap().len(), before);

        let (read, _) = mail_model::read_observation_fragment(wire, persona);
        commit_scope(&mut pile, &signer, MAIL_SCOPE_ID, read);
        let catalogs = load_native_catalogs(&mut pile, &signer).unwrap();
        let read = load_watched_view(&catalogs, persona).unwrap();
        assert!(read.mail_unread.is_empty());
        assert!(view_news(&incoming, &read, persona, &BTreeSet::new()).is_empty());
        let rendered = render_native_mail(&catalogs, Some(persona), 10).unwrap();
        assert!(rendered.contains("- None"));
        pile.close().unwrap();
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
