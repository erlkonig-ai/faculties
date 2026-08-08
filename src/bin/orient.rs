use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{
    DateTime, Duration as ChronoDuration, Local, LocalResult, NaiveDateTime, NaiveTime, TimeZone,
};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::collection_access::{
    self, CollectionRevision, CollectionSnapshot, CollectionView, CollectionWriter,
};
use faculties::memory_cover::{render_cover, CoverOpts};
use faculties::schemas::compass::{KIND_GOAL, KIND_NOTE, KIND_STATUS_SNAPSHOT};
use faculties::schemas::mail::KIND_WIRE_MESSAGE;
use faculties::schemas::memory::DEFAULT_MEMORY_BRANCH;
use faculties::schemas::message::KIND_MESSAGE_ID;
use faculties::schemas::orient::DEFAULT_SCOPE_ID as ORIENT_SCOPE_ID;
use faculties::schemas::relations::KIND_PERSON_ID;
use faculties::schemas::status::{status as status_attrs, KIND_STATUS_UPDATE};
use faculties::schemas::wiki::{cover_fragments, WIKI_BRANCH_NAME};
use faculties::{compass, decide, files, mail, message, orient, relations};
use hifitime::Epoch;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::macros::{find, pattern};
use triblespace::prelude::*;

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "orient",
    about = "Orient the agent with recent messages and goals"
)]
struct Cli {
    /// Path to the pile file to use.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Persona identity for collection-native observation state.
    #[arg(long, env = "PERSONA")]
    persona: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show an orientation snapshot and, when a persona is configured, mark
    /// every currently observable item after the complete output is flushed.
    Show {
        #[arg(long, default_value_t = 10)]
        message_limit: usize,
        #[arg(long, default_value_t = 5)]
        doing_limit: usize,
        #[arg(long, default_value_t = 5)]
        todo_limit: usize,
    },
    /// Assemble the full wake bundle: legacy memory/wiki plus current Compass.
    Wake {
        #[arg(long, default_value_t = 800_000)]
        chars: usize,
        #[arg(long, default_value_t = 5)]
        doing_limit: usize,
        #[arg(long, default_value_t = 5)]
        todo_limit: usize,
    },
    /// Wait until current collection state contains persona-relevant news.
    Wait {
        #[command(subcommand)]
        target: Option<WaitTarget>,
        #[arg(long, default_value_t = 10)]
        message_limit: usize,
        #[arg(long, default_value_t = 5)]
        doing_limit: usize,
        #[arg(long, default_value_t = 5)]
        todo_limit: usize,
        #[arg(long, default_value_t = 1000)]
        poll_ms: u64,
    },
    /// Non-blocking persona news check.
    Poll {
        /// Report without publishing Baseline or Seen markers.
        #[arg(long)]
        peek: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum WaitTarget {
    /// Wait for a duration (for example 30s, 15m, or 9h).
    For { duration: String },
    /// Wait until a local time or absolute timestamp.
    Until { when: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Revisions {
    message: CollectionRevision,
    mail: CollectionRevision,
    compass: CollectionRevision,
    relations: CollectionRevision,
    orient: CollectionRevision,
}

/// One coherent seven-scope view. All materializations reuse exactly one
/// immutable `CollectionSnapshot` and one durable signer authority.
struct CurrentCollections {
    message: CollectionView,
    mail: CollectionView,
    compass: CollectionView,
    relations: CollectionView,
    orient: CollectionView,
    orient_catalog: orient::Catalog,
}

impl CurrentCollections {
    fn open(pile: &Path) -> Result<Self> {
        let signer = collection_access::load_signer(pile, None)?;
        let allowed = HashSet::from([signer.verifying_key()]);
        let snapshot = CollectionSnapshot::open(pile)?;

        let relations = snapshot
            .materialize_scope(faculties::schemas::relations::DEFAULT_SCOPE_ID, &allowed)
            .context("materialize Relations collection")?;
        relations::validate_catalog(&relations.reader, &relations.facts)
            .context("validate Relations collection")?;

        let files = snapshot
            .materialize_scope(faculties::schemas::files::DEFAULT_SCOPE_ID, &allowed)
            .context("materialize Files collection")?;
        files::validate_catalog(&files.reader, &files.facts)
            .context("validate Files collection")?;

        let decide = snapshot
            .materialize_scope(faculties::schemas::decide::DEFAULT_SCOPE_ID, &allowed)
            .context("materialize Decide collection")?;
        decide::validate_catalog(&decide.reader, &decide.facts)
            .context("validate Decide collection")?;

        let mail = snapshot
            .materialize_scope(faculties::schemas::mail::DEFAULT_SCOPE_ID, &allowed)
            .context("materialize Mail collection")?;
        mail::validate_catalog(
            &mail.reader,
            &mail.facts,
            &files.facts,
            &decide.facts,
            &relations.facts,
        )
        .context("validate Mail collection")?;

        let message = snapshot
            .materialize_scope(faculties::schemas::message::DEFAULT_SCOPE_ID, &allowed)
            .context("materialize Message collection")?;
        message::validate_catalog(&message.reader, &message.facts, &relations.facts)
            .context("validate Message collection")?;

        let compass = snapshot
            .materialize_scope(faculties::schemas::compass::DEFAULT_SCOPE_ID, &allowed)
            .context("materialize Compass collection")?;
        compass::validate_catalog(&compass.reader, &compass.facts)
            .context("validate Compass collection")?;

        let orient_view = snapshot
            .materialize_scope(ORIENT_SCOPE_ID, &allowed)
            .context("materialize Orient collection")?;
        let orient_catalog = orient::validate_catalog(
            &orient_view.facts,
            &message.facts,
            &mail.facts,
            &compass.facts,
            &relations.facts,
        )
        .context("validate Orient collection")?;

        Ok(Self {
            message,
            mail,
            compass,
            relations,
            orient: orient_view,
            orient_catalog,
        })
    }

    fn revisions(&self) -> Revisions {
        Revisions {
            message: self.message.revision,
            mail: self.mail.revision,
            compass: self.compass.revision,
            relations: self.relations.revision,
            orient: self.orient.revision,
        }
    }
}

fn pile_length(path: &Path) -> Result<u64> {
    std::fs::metadata(path)
        .with_context(|| format!("inspect pile length {}", path.display()))
        .map(|metadata| metadata.len())
}

/// Acquire a collection snapshot bracketed by equal append lengths. An append
/// during discovery forces a retry; an append after this returns is caught by
/// the wait loop's second length check immediately before sleeping.
fn stable_collections(path: &Path) -> Result<(CurrentCollections, u64)> {
    loop {
        let before = pile_length(path)?;
        let collections = CurrentCollections::open(path)?;
        let after = pile_length(path)?;
        if before == after {
            return Ok((collections, after));
        }
    }
}

fn should_rescan_before_sleep(snapshot_length: u64, current_length: u64) -> bool {
    snapshot_length != current_length
}

fn interval_key(interval: IntervalValue) -> Result<i128> {
    let (lower, _): (i128, i128) = interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode time interval: {error:?}"))?;
    Ok(lower)
}

fn now_key() -> Result<i128> {
    let epoch = Epoch::now().map_err(|error| anyhow!("read current epoch: {error:?}"))?;
    let value: IntervalValue = (epoch, epoch)
        .try_to_inline()
        .map_err(|error| anyhow!("encode current epoch: {error:?}"))?;
    interval_key(value)
}

fn format_age(now: i128, past: i128) -> String {
    let seconds = (now.saturating_sub(past) / 1_000_000_000).max(0) as i64;
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86_400 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}d", seconds / 86_400)
    }
}

fn resolve_persona(collections: &CurrentCollections, input: &str) -> Result<Id> {
    relations::resolve_person(
        &collections.relations.reader,
        &collections.relations.facts,
        input,
        false,
    )?
    .require_unique("person", input)
}

fn profile_for(collections: &CurrentCollections, person: Id) -> Result<relations::ProfileInput> {
    let snapshot = relations::current_profile(&collections.relations.facts, person)?;
    relations::profile_input(&collections.relations.reader, &snapshot)
}

fn person_label(collections: &CurrentCollections, person: Id) -> String {
    profile_for(collections, person)
        .map(|profile| profile.label)
        .unwrap_or_else(|_| format!("{person:x}"))
}

fn persona_keys(
    collections: &CurrentCollections,
    component: &BTreeSet<Id>,
) -> Result<HashSet<String>> {
    let mut keys = HashSet::new();
    for &person in component {
        match relations::profile_head(&collections.relations.facts, person)? {
            relations::Head::Unique(id) => {
                let snapshot = relations::profile_snapshot(&collections.relations.facts, id)?;
                let profile = relations::profile_input(&collections.relations.reader, &snapshot)?;
                keys.insert(relations::lookup_key(&profile.label));
                keys.extend(
                    profile
                        .aliases
                        .into_iter()
                        .map(|alias| relations::lookup_key(&alias)),
                );
            }
            relations::Head::Forked(heads) => {
                // A fork stays visible in Relations, but attention tags on
                // either candidate spelling conservatively address the
                // settled identity component.
                for id in heads {
                    let snapshot = relations::profile_snapshot(&collections.relations.facts, id)?;
                    let profile =
                        relations::profile_input(&collections.relations.reader, &snapshot)?;
                    keys.insert(relations::lookup_key(&profile.label));
                    keys.extend(
                        profile
                            .aliases
                            .into_iter()
                            .map(|alias| relations::lookup_key(&alias)),
                    );
                }
            }
            relations::Head::Missing => bail!("person {person:x} has no profile snapshot"),
        }
    }
    Ok(keys)
}

fn is_addressed(tags: &[String], keys: &HashSet<String>) -> bool {
    tags.iter().any(|tag| {
        let key = relations::lookup_key(tag);
        key == "colony" || keys.contains(&key)
    })
}

fn active_zooids(collections: &CurrentCollections) -> Result<Vec<Id>> {
    let mut zooids = Vec::new();
    let identities = relations::IdentityComponents::from_facts(&collections.relations.facts)?;
    for person in relations::person_anchors(&collections.relations.facts) {
        if identities.component(person).is_err() {
            continue;
        }
        let profile_id = match relations::profile_head(&collections.relations.facts, person)? {
            relations::Head::Unique(id) => id,
            relations::Head::Forked(_) | relations::Head::Missing => continue,
        };
        let lifecycle_id = match relations::lifecycle_head(&collections.relations.facts, person)? {
            relations::Head::Unique(id) => id,
            relations::Head::Forked(_) | relations::Head::Missing => continue,
        };
        if relations::lifecycle_snapshot(&collections.relations.facts, lifecycle_id)?.retired {
            continue;
        }
        let profile = relations::profile_input(
            &collections.relations.reader,
            &relations::profile_snapshot(&collections.relations.facts, profile_id)?,
        )?;
        if profile
            .affinities
            .iter()
            .any(|affinity| affinity.eq_ignore_ascii_case("zooid"))
        {
            zooids.push(person);
        }
    }
    zooids.sort_unstable_by_key(|person| (person_label(collections, *person), *person));
    Ok(zooids)
}

#[derive(Clone, Debug)]
struct GoalView {
    id: Id,
    title: String,
    tags: Vec<String>,
    addressed: bool,
    involved: bool,
    created_at: i128,
    status: compass::StatusResolution,
}

impl GoalView {
    fn relevant(&self) -> bool {
        self.addressed || self.involved
    }
}

#[derive(Clone, Debug)]
struct PersonaView {
    persona: Id,
    component: BTreeSet<Id>,
    label: String,
    unread: BTreeMap<Id, message::MessageRow>,
    mail_unread: BTreeMap<Id, Vec<mail::ProjectionView>>,
    goals: BTreeMap<Id, GoalView>,
    notes: BTreeMap<Id, Id>,
    roster: BTreeSet<Id>,
    observations: BTreeSet<orient::Observation>,
}

fn status_observations(status: &compass::StatusResolution) -> BTreeSet<orient::Observation> {
    status
        .head_ids()
        .into_iter()
        .map(|id| orient::Observation::new(KIND_STATUS_SNAPSHOT, id))
        .collect()
}

fn current_persona_view(collections: &CurrentCollections, persona: Id) -> Result<PersonaView> {
    let identities = relations::IdentityComponents::from_facts(&collections.relations.facts)?;
    let component = identities.component(persona)?;
    let keys = persona_keys(collections, &component)?;

    let reads = message::load_read_rows(&collections.message.facts)?;
    let mut unread = BTreeMap::new();
    for row in message::load_message_rows(&collections.message.facts)? {
        if message::is_inbox_message(&row, persona, &collections.relations.facts, &identities)?
            && !message::is_read_by(&reads, row.id, persona, &identities)?
        {
            unread.insert(row.id, row);
        }
    }

    let mut mail_unread = BTreeMap::<Id, Vec<mail::ProjectionView>>::new();
    for row in mail::inbox_projection(
        &collections.mail.facts,
        &collections.relations.facts,
        persona,
    )? {
        if !row.unread {
            continue;
        }
        let projection = mail::projection_view(
            &collections.mail.reader,
            &collections.mail.facts,
            row.projection,
        )?;
        // Spam is durable parser evidence rather than a mutable mailbox
        // folder.  Orient keeps it out of the attention stream while `mail
        // list --spam` remains the explicit view.
        if !projection.spam {
            mail_unread.entry(row.wire).or_default().push(projection);
        }
    }
    for projections in mail_unread.values_mut() {
        projections.sort_unstable_by_key(|projection| (projection.source, projection.id));
    }

    let mut goals = BTreeMap::new();
    for goal_id in compass::goal_anchors(&collections.compass.facts) {
        let genesis = compass::genesis_for_goal(&collections.compass.facts, goal_id)?
            .ok_or_else(|| anyhow!("validated goal {goal_id:x} has no genesis"))?;
        let title = compass::read_text(&collections.compass.reader, genesis.title)?;
        let tags = compass::tag_labels(
            &collections.compass.reader,
            &collections.compass.facts,
            &genesis.tags,
        )?;
        let addressed = is_addressed(&tags, &keys);
        let authored_status = find!(
            id: Id,
            pattern!(&collections.compass.facts, [{ ?id @
                metadata::tag: &KIND_STATUS_SNAPSHOT,
                faculties::schemas::compass::status::of: &goal_id,
            }])
        )
        .any(|id| {
            compass::status_snapshot(&collections.compass.facts, id)
                .ok()
                .and_then(|snapshot| snapshot.by)
                .is_some_and(|by| component.contains(&by))
        });
        let authored_note = compass::notes_for_goal(&collections.compass.facts, goal_id)?
            .iter()
            .any(|note| note.by.is_some_and(|by| component.contains(&by)));
        let status = compass::status_resolution(&collections.compass.facts, goal_id);
        goals.insert(
            goal_id,
            GoalView {
                id: goal_id,
                title,
                tags,
                addressed,
                involved: authored_status || authored_note,
                created_at: interval_key(genesis.created_at)?,
                status,
            },
        );
    }

    let mut notes = BTreeMap::new();
    for goal in goals.values() {
        for note in compass::notes_for_goal(&collections.compass.facts, goal.id)? {
            if note.by.is_some_and(|by| component.contains(&by)) {
                continue;
            }
            let tags = compass::tag_labels(
                &collections.compass.reader,
                &collections.compass.facts,
                &note.tags,
            )?;
            if goal.relevant() || is_addressed(&tags, &keys) {
                notes.insert(note.id, goal.id);
            }
        }
    }

    let roster: BTreeSet<Id> = active_zooids(collections)?.into_iter().collect();
    let mut observations = BTreeSet::new();
    observations.extend(
        unread
            .keys()
            .copied()
            .map(|id| orient::Observation::new(KIND_MESSAGE_ID, id)),
    );
    observations.extend(
        mail_unread
            .keys()
            .copied()
            .map(|id| orient::Observation::new(KIND_WIRE_MESSAGE, id)),
    );
    for goal in goals.values() {
        // Goal anchors and every current status head are observed even when
        // irrelevant or self-authored. If relevance expands later, old state
        // cannot replay as stale news.
        observations.insert(orient::Observation::new(KIND_GOAL, goal.id));
        observations.extend(status_observations(&goal.status));
    }
    observations.extend(
        notes
            .keys()
            .copied()
            .map(|id| orient::Observation::new(KIND_NOTE, id)),
    );
    observations.extend(
        roster
            .iter()
            .copied()
            .map(|id| orient::Observation::new(KIND_PERSON_ID, id)),
    );

    Ok(PersonaView {
        persona,
        component,
        label: person_label(collections, persona),
        unread,
        mail_unread,
        goals,
        notes,
        roster,
        observations,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StatusMeaning {
    Missing,
    Settled(String),
    Forked(BTreeSet<String>),
    Invalid(String),
}

fn status_meaning(status: &compass::StatusResolution) -> StatusMeaning {
    match status {
        compass::StatusResolution::Missing => StatusMeaning::Missing,
        compass::StatusResolution::Unique(snapshot) => {
            StatusMeaning::Settled(snapshot.value.clone())
        }
        compass::StatusResolution::Agreed(snapshots) => StatusMeaning::Settled(
            snapshots
                .first()
                .expect("agreed status has at least two heads")
                .value
                .clone(),
        ),
        compass::StatusResolution::Forked(snapshots) => StatusMeaning::Forked(
            snapshots
                .iter()
                .map(|snapshot| snapshot.value.clone())
                .collect(),
        ),
        compass::StatusResolution::Invalid(reason) => StatusMeaning::Invalid(reason.clone()),
    }
}

fn status_graph(facts: &TribleSet, goal: Id) -> Result<BTreeMap<Id, compass::StatusSnapshot>> {
    let mut graph = BTreeMap::new();
    for id in find!(
        id: Id,
        pattern!(facts, [{ ?id @
            metadata::tag: &KIND_STATUS_SNAPSHOT,
            faculties::schemas::compass::status::of: &goal,
        }])
    ) {
        graph.insert(id, compass::status_snapshot(facts, id)?);
    }
    Ok(graph)
}

fn reaches_status(
    graph: &BTreeMap<Id, compass::StatusSnapshot>,
    descendant: Id,
    ancestor: Id,
) -> bool {
    let mut pending = vec![descendant];
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let Some(snapshot) = graph.get(&id) else {
            continue;
        };
        for predecessor in &snapshot.predecessors {
            if *predecessor == ancestor {
                return true;
            }
            pending.push(*predecessor);
        }
    }
    false
}

/// Reconstruct the semantic frontier represented by all Seen status ids for a
/// goal. Only maximal Seen nodes matter; a later marker semantically replaces
/// every Seen ancestor even when an unobserved transient node lies between.
fn seen_status_frontier(
    facts: &TribleSet,
    goal: Id,
    seen: &BTreeSet<orient::Observation>,
) -> Result<compass::StatusResolution> {
    let graph = status_graph(facts, goal)?;
    let seen_ids: BTreeSet<Id> = seen
        .iter()
        .filter(|marker| marker.source_kind == KIND_STATUS_SNAPSHOT)
        .map(|marker| marker.source_item)
        .filter(|id| graph.contains_key(id))
        .collect();
    let heads: Vec<Id> = seen_ids
        .iter()
        .copied()
        .filter(|candidate| {
            !seen_ids
                .iter()
                .copied()
                .any(|other| other != *candidate && reaches_status(&graph, other, *candidate))
        })
        .collect();
    let snapshots: Vec<_> = heads
        .into_iter()
        .filter_map(|id| graph.get(&id).cloned())
        .collect();
    Ok(match snapshots.as_slice() {
        [] => compass::StatusResolution::Missing,
        [snapshot] => compass::StatusResolution::Unique(snapshot.clone()),
        _ if snapshots
            .iter()
            .all(|snapshot| snapshot.value == snapshots[0].value) =>
        {
            compass::StatusResolution::Agreed(snapshots)
        }
        _ => compass::StatusResolution::Forked(snapshots),
    })
}

fn render_status(status: &compass::StatusResolution) -> String {
    match status {
        compass::StatusResolution::Missing => "todo (no status snapshot)".to_owned(),
        compass::StatusResolution::Unique(snapshot) => snapshot.value.clone(),
        compass::StatusResolution::Agreed(snapshots) => format!(
            "{} (agreed heads: {})",
            snapshots[0].value,
            snapshots
                .iter()
                .map(|snapshot| format!("{:x}", snapshot.id))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        compass::StatusResolution::Forked(snapshots) => format!(
            "forked [{}]",
            snapshots
                .iter()
                .map(|snapshot| format!("{:x}={}", snapshot.id, snapshot.value))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        compass::StatusResolution::Invalid(reason) => format!("invalid ({reason})"),
    }
}

fn status_change_reason(
    facts: &TribleSet,
    goal: &GoalView,
    component: &BTreeSet<Id>,
    seen: &BTreeSet<orient::Observation>,
) -> Result<Option<String>> {
    if !goal.relevant() {
        return Ok(None);
    }
    let previous = seen_status_frontier(facts, goal.id, seen)?;
    if status_meaning(&previous) == status_meaning(&goal.status) {
        return Ok(None);
    }
    let unseen_heads: Vec<_> = goal
        .status
        .head_ids()
        .into_iter()
        .filter(|id| !seen.contains(&orient::Observation::new(KIND_STATUS_SNAPSHOT, *id)))
        .collect();
    if unseen_heads.is_empty() {
        return Ok(None);
    }
    let own_only = unseen_heads.iter().all(|id| {
        compass::status_snapshot(facts, *id)
            .ok()
            .and_then(|snapshot| snapshot.by)
            .is_some_and(|by| component.contains(&by))
    });
    if own_only {
        return Ok(None);
    }
    Ok(Some(format!(
        "goal [{:x}]: {} → {}",
        goal.id,
        render_status(&previous),
        render_status(&goal.status)
    )))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NewsReport {
    reasons: Vec<String>,
    messages: Vec<Id>,
    mail: Vec<Id>,
    people: Vec<Id>,
}

fn news_report(
    collections: &CurrentCollections,
    view: &PersonaView,
    seen: &BTreeSet<orient::Observation>,
) -> Result<NewsReport> {
    let mut report = NewsReport::default();
    for id in view.unread.keys() {
        let marker = orient::Observation::new(KIND_MESSAGE_ID, *id);
        if !seen.contains(&marker) {
            report.reasons.push(format!("new message [{id:x}]"));
            report.messages.push(*id);
        }
    }
    for id in view.mail_unread.keys() {
        let marker = orient::Observation::new(KIND_WIRE_MESSAGE, *id);
        if !seen.contains(&marker) {
            report.reasons.push(format!("new mail [{id:x}]"));
            report.mail.push(*id);
        }
    }
    for goal in view.goals.values() {
        let goal_marker = orient::Observation::new(KIND_GOAL, goal.id);
        if !seen.contains(&goal_marker) && goal.relevant() {
            report.reasons.push(format!(
                "new goal [{:x}] ({})",
                goal.id,
                render_status(&goal.status)
            ));
        } else if let Some(reason) =
            status_change_reason(&collections.compass.facts, goal, &view.component, seen)?
        {
            report.reasons.push(reason);
        }
    }
    for (note, goal) in &view.notes {
        if !seen.contains(&orient::Observation::new(KIND_NOTE, *note)) {
            report
                .reasons
                .push(format!("new note [{note:x}] on goal [{goal:x}]"));
        }
    }
    for person in &view.roster {
        if !seen.contains(&orient::Observation::new(KIND_PERSON_ID, *person)) {
            report.reasons.push(format!("new person [{person:x}]"));
            report.people.push(*person);
        }
    }
    Ok(report)
}

struct PersonaEvaluation {
    view: PersonaView,
    has_baseline: bool,
    markers_to_publish: BTreeSet<orient::Observation>,
    news: NewsReport,
}

fn evaluate_persona(collections: &CurrentCollections, persona: Id) -> Result<PersonaEvaluation> {
    let view = current_persona_view(collections, persona)?;
    let has_baseline = collections
        .orient_catalog
        .has_baseline(view.component.iter());
    let seen = collections.orient_catalog.seen(view.component.iter());
    let markers_to_publish = if has_baseline {
        view.observations.difference(&seen).copied().collect()
    } else {
        // Initial consumption establishes a complete quiet baseline even if a
        // malformed older workflow happened to publish Seen without Baseline.
        view.observations.clone()
    };
    let news = if has_baseline {
        news_report(collections, &view, &seen)?
    } else {
        NewsReport::default()
    };
    Ok(PersonaEvaluation {
        view,
        has_baseline,
        markers_to_publish,
        news,
    })
}

fn publish_evaluation(
    pile: &Path,
    collections: &CurrentCollections,
    evaluation: &PersonaEvaluation,
) -> Result<bool> {
    let include_baseline = !evaluation.has_baseline;
    if !include_baseline && evaluation.markers_to_publish.is_empty() {
        return Ok(false);
    }
    let fragment = orient::marker_fragment(
        evaluation.view.persona,
        include_baseline,
        evaluation.markers_to_publish.iter().copied(),
    );
    orient::validate_catalog_union(
        &collections.orient.facts,
        &fragment,
        &collections.message.facts,
        &collections.mail.facts,
        &collections.compass.facts,
        &collections.relations.facts,
    )
    .context("preflight Orient marker union")?;
    let mut writer = CollectionWriter::open(pile, None, ORIENT_SCOPE_ID)?;
    let result = writer
        .publish_fragment(fragment, Fragment::empty())
        .context("publish Orient markers")
        .map(|_| ());
    writer.finish(result)?;
    Ok(true)
}

fn emit(output: &str) -> Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    stdout
        .write_all(output.as_bytes())
        .context("write Orient output")?;
    stdout.flush().context("flush Orient output")
}

fn render_tags(tags: &[String]) -> String {
    if tags.is_empty() {
        String::new()
    } else {
        format!(
            " {}",
            tags.iter()
                .map(|tag| format!("#{}", tag.trim_start_matches('#')))
                .collect::<Vec<_>>()
                .join(" ")
        )
    }
}

fn status_sort_key(goal: &GoalView) -> Result<i128> {
    Ok(match &goal.status {
        compass::StatusResolution::Unique(snapshot) => interval_key(snapshot.created_at)?,
        compass::StatusResolution::Agreed(snapshots)
        | compass::StatusResolution::Forked(snapshots) => {
            let keys = snapshots
                .iter()
                .map(|snapshot| interval_key(snapshot.created_at))
                .collect::<Result<Vec<_>>>()?;
            keys.into_iter().max().unwrap_or(goal.created_at)
        }
        compass::StatusResolution::Missing | compass::StatusResolution::Invalid(_) => {
            goal.created_at
        }
    })
}

fn settled_status(status: &compass::StatusResolution) -> Option<&str> {
    match status {
        compass::StatusResolution::Missing => Some("todo"),
        compass::StatusResolution::Unique(snapshot) => Some(&snapshot.value),
        compass::StatusResolution::Agreed(snapshots) => snapshots.first().map(|s| s.value.as_str()),
        compass::StatusResolution::Forked(_) | compass::StatusResolution::Invalid(_) => None,
    }
}

fn render_goal_line(out: &mut String, goal: &GoalView) {
    let status_detail = match &goal.status {
        compass::StatusResolution::Missing | compass::StatusResolution::Unique(_) => String::new(),
        _ => format!(" [status: {}]", render_status(&goal.status)),
    };
    writeln!(
        out,
        "- [{:x}] {}{}{}",
        goal.id,
        goal.title,
        render_tags(&goal.tags),
        status_detail
    )
    .unwrap();
}

fn render_compass_goals(
    collections: &CurrentCollections,
    doing_limit: usize,
    todo_limit: usize,
) -> Result<String> {
    // Goal rendering is persona-independent; use the validated catalog
    // directly so show without a persona remains fully useful and read-only.
    let mut goals = Vec::new();
    for goal_id in compass::goal_anchors(&collections.compass.facts) {
        let genesis = compass::genesis_for_goal(&collections.compass.facts, goal_id)?
            .ok_or_else(|| anyhow!("validated goal {goal_id:x} has no genesis"))?;
        goals.push(GoalView {
            id: goal_id,
            title: compass::read_text(&collections.compass.reader, genesis.title)?,
            tags: compass::tag_labels(
                &collections.compass.reader,
                &collections.compass.facts,
                &genesis.tags,
            )?,
            addressed: false,
            involved: false,
            created_at: interval_key(genesis.created_at)?,
            status: compass::status_resolution(&collections.compass.facts, goal_id),
        });
    }
    let mut goals = goals
        .into_iter()
        .map(|goal| Ok((status_sort_key(&goal)?, goal)))
        .collect::<Result<Vec<_>>>()?;
    goals.sort_by_key(|(key, goal)| std::cmp::Reverse((*key, goal.id)));
    let goals: Vec<_> = goals.into_iter().map(|(_, goal)| goal).collect();
    let doing: Vec<_> = goals
        .iter()
        .filter(|goal| settled_status(&goal.status).is_some_and(|value| value == "doing"))
        .take(doing_limit)
        .collect();
    let todo: Vec<_> = goals
        .iter()
        .filter(|goal| settled_status(&goal.status).is_some_and(|value| value == "todo"))
        .take(todo_limit)
        .collect();
    let unsettled: Vec<_> = goals
        .iter()
        .filter(|goal| settled_status(&goal.status).is_none())
        .collect();

    let mut out = String::new();
    writeln!(out, "Compass:").unwrap();
    if goals.is_empty() {
        writeln!(out, "- No goals.").unwrap();
        return Ok(out);
    }
    writeln!(out, "Doing:").unwrap();
    if doing.is_empty() {
        writeln!(out, "- None").unwrap();
    } else {
        for goal in doing {
            render_goal_line(&mut out, goal);
        }
    }
    writeln!(out, "Todo:").unwrap();
    if todo.is_empty() {
        writeln!(out, "- None").unwrap();
    } else {
        for goal in todo {
            render_goal_line(&mut out, goal);
        }
    }
    if !unsettled.is_empty() {
        writeln!(out, "Unsettled:").unwrap();
        for goal in unsettled {
            render_goal_line(&mut out, goal);
        }
    }
    Ok(out)
}

fn read_legacy_text(reader: &PileReader, handle: TextHandle) -> Result<String> {
    let value: anybytes::View<str> = reader
        .get(handle)
        .map_err(|error| anyhow!("read legacy text: {error:?}"))?;
    Ok(value.to_string())
}

/// Render the same validated collection-native inbox projection that drives
/// Orient observations.  One WireMessage is one attention item even when the
/// same raw message was observed by several POP transactions.
fn render_mail(
    evaluation: Option<&PersonaEvaluation>,
    message_limit: usize,
    now: i128,
) -> Result<String> {
    let mut out = String::new();
    let Some(evaluation) = evaluation else {
        writeln!(out, "Mail:").unwrap();
        writeln!(
            out,
            "- Unavailable: no persona (pass --persona <label-or-hex> or set $PERSONA)"
        )
        .unwrap();
        return Ok(out);
    };

    let mut rows = Vec::new();
    for (&wire, projections) in &evaluation.view.mail_unread {
        let primary = projections
            .first()
            .expect("mail_unread never stores an empty projection group");
        let claimed_at = primary
            .claimed_date
            .map(interval_key)
            .transpose()?
            .unwrap_or(i128::MIN);
        rows.push((claimed_at, wire, primary, projections.len()));
    }
    rows.sort_by_key(|row| std::cmp::Reverse((row.0, row.1)));
    writeln!(out, "Mail (unread for {}):", evaluation.view.label).unwrap();
    if rows.is_empty() {
        writeln!(out, "- None").unwrap();
    } else {
        for (claimed_at, wire, projection, sources) in rows.into_iter().take(message_limit) {
            let age = if claimed_at == i128::MIN {
                "unknown-date".to_owned()
            } else {
                format_age(now, claimed_at)
            };
            let source_note = (sources > 1)
                .then(|| format!(" ({sources} source observations)"))
                .unwrap_or_default();
            writeln!(
                out,
                "- [{wire:x}] {age} {} — {}{source_note}",
                projection.from.as_deref().unwrap_or("(no From)"),
                projection.subject,
            )
            .unwrap();
        }
    }
    Ok(out)
}

/// Isolated legacy Status read. Relations identity and roster always come from
/// the validated collection snapshot.
fn render_legacy_colony(pile: &Path, collections: &CurrentCollections) -> Result<String> {
    let status = collection_access::materialize_named_legacy_branch(pile, "status")?;
    let mut latest = HashMap::<Id, (TextHandle, i128)>::new();
    if let Some(status) = &status {
        for (window, text, at) in find!(
            (window: Id, text: TextHandle, at: IntervalValue),
            pattern!(&status.facts, [{ _?event @
                metadata::tag: &KIND_STATUS_UPDATE,
                status_attrs::window: ?window,
                status_attrs::text: ?text,
                metadata::created_at: ?at,
            }])
        ) {
            let at = interval_key(at)?;
            latest
                .entry(window)
                .and_modify(|current| {
                    if at > current.1 {
                        *current = (text, at);
                    }
                })
                .or_insert((text, at));
        }
    }
    let mut out = String::new();
    writeln!(out, "Colony:").unwrap();
    let zooids = active_zooids(collections)?;
    if zooids.is_empty() {
        writeln!(out, "- (no zooids)").unwrap();
    }
    for person in zooids {
        let text = match (&status, latest.get(&person)) {
            (Some(status), Some((handle, _))) => {
                read_legacy_text(&status.reader, *handle).unwrap_or_else(|_| "—".to_owned())
            }
            _ => "—".to_owned(),
        };
        writeln!(out, "- {}: {text}", person_label(collections, person)).unwrap();
    }
    Ok(out)
}

fn render_show(
    pile: &Path,
    collections: &CurrentCollections,
    persona: Option<Id>,
    message_limit: usize,
    doing_limit: usize,
    todo_limit: usize,
) -> Result<(String, Option<PersonaEvaluation>)> {
    let now = now_key()?;
    let evaluation = persona
        .map(|persona| evaluate_persona(collections, persona))
        .transpose()?;
    let mut out = String::new();
    writeln!(out, "Orient").unwrap();
    if let Some(evaluation) = &evaluation {
        writeln!(
            out,
            "Local messages (unread inbox for {}):",
            evaluation.view.label
        )
        .unwrap();
        let mut rows = evaluation
            .view
            .unread
            .values()
            .map(|row| Ok((interval_key(row.created_at)?, row)))
            .collect::<Result<Vec<_>>>()?;
        rows.sort_by_key(|(created_at, row)| std::cmp::Reverse((*created_at, row.id)));
        if rows.is_empty() {
            writeln!(out, "- None").unwrap();
        } else {
            for (created_at, row) in rows.into_iter().take(message_limit) {
                writeln!(
                    out,
                    "- [{:x}] {} {} -> {} (unread)",
                    row.id,
                    format_age(now, created_at),
                    person_label(collections, row.from),
                    person_label(collections, row.to),
                )
                .unwrap();
                let body = message::read_body(&collections.message.reader, row.body)?;
                if body.is_empty() {
                    writeln!(out, "    ").unwrap();
                } else {
                    for line in body.lines() {
                        writeln!(out, "    {}", line.trim_end_matches('\r')).unwrap();
                    }
                }
            }
        }
    } else {
        writeln!(out, "Local messages:").unwrap();
        writeln!(
            out,
            "- Unavailable: no persona (pass --persona <label-or-hex> or set $PERSONA)"
        )
        .unwrap();
    }
    out.push_str(&render_mail(evaluation.as_ref(), message_limit, now)?);
    writeln!(out).unwrap();
    out.push_str(&render_compass_goals(collections, doing_limit, todo_limit)?);
    out.push_str(&render_legacy_colony(pile, collections)?);
    Ok((out, evaluation))
}

fn render_news(collections: &CurrentCollections, evaluation: &PersonaEvaluation) -> Result<String> {
    let mut out = String::new();
    for reason in &evaluation.news.reasons {
        writeln!(out, "News: {reason}").unwrap();
    }
    if !evaluation.news.messages.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "New messages:").unwrap();
        for id in &evaluation.news.messages {
            if let Some(row) = evaluation.view.unread.get(id) {
                let body = message::read_body(&collections.message.reader, row.body)?;
                writeln!(out, "- {}: {body}", person_label(collections, row.from)).unwrap();
            }
        }
    }
    if !evaluation.news.mail.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "New mail:").unwrap();
        for wire in &evaluation.news.mail {
            let Some(projections) = evaluation.view.mail_unread.get(wire) else {
                continue;
            };
            let projection = projections
                .first()
                .expect("mail_unread never stores an empty projection group");
            writeln!(
                out,
                "- [{wire:x}] {} — {}",
                projection.from.as_deref().unwrap_or("(no From)"),
                projection.subject,
            )
            .unwrap();
            for line in projection.body.lines() {
                writeln!(out, "    {}", line.trim_end_matches('\r')).unwrap();
            }
            if projections.len() > 1 {
                writeln!(out, "    ({} source observations)", projections.len()).unwrap();
            }
        }
    }
    if !evaluation.news.people.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "New zooid(s):").unwrap();
        for person in &evaluation.news.people {
            writeln!(out, "- {}", person_label(collections, *person)).unwrap();
        }
    }
    Ok(out)
}

fn cmd_show(
    pile: &Path,
    persona: Option<&str>,
    message_limit: usize,
    doing_limit: usize,
    todo_limit: usize,
) -> Result<()> {
    let (collections, _) = stable_collections(pile)?;
    let persona = persona
        .map(|input| resolve_persona(&collections, input))
        .transpose()?;
    let (output, evaluation) = render_show(
        pile,
        &collections,
        persona,
        message_limit,
        doing_limit,
        todo_limit,
    )?;
    emit(&output)?;
    if let Some(evaluation) = &evaluation {
        publish_evaluation(pile, &collections, evaluation)?;
    }
    Ok(())
}

fn cmd_poll(pile: &Path, persona: Option<&str>, peek: bool) -> Result<()> {
    let input = persona.ok_or_else(|| {
        anyhow!("poll requires a persona (pass --persona <label-or-hex> or set $PERSONA)")
    })?;
    let (collections, _) = stable_collections(pile)?;
    let persona = resolve_persona(&collections, input)?;
    let evaluation = evaluate_persona(&collections, persona)?;
    let output = render_news(&collections, &evaluation)?;
    emit(&output)?;
    if !peek {
        publish_evaluation(pile, &collections, &evaluation)?;
    }
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
                .map_err(|error| anyhow!("invalid wait duration '{duration}': {error}"))?;
            if parsed.is_zero() {
                bail!("wait duration must be greater than zero");
            }
            Ok(Some(parsed))
        }
        WaitTarget::Until { when } => parse_until_spec(when).map(|(duration, _)| Some(duration)),
    }
}

fn parse_until_spec(raw: &str) -> Result<(Duration, DateTime<Local>)> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("wait until requires a time (e.g. 09:00, 9am, or an RFC3339 timestamp)");
    }
    let now = Local::now();
    let target = if let Ok(parsed) = DateTime::parse_from_rfc3339(raw) {
        parsed.with_timezone(&Local)
    } else if let Some(parsed) = parse_local_datetime_spec(raw)? {
        parsed
    } else if let Some(time) = parse_local_time_spec(raw) {
        let today = now.date_naive().and_time(time);
        let today = localize_naive_datetime(today)?;
        if today > now {
            today
        } else {
            localize_naive_datetime((now.date_naive() + ChronoDuration::days(1)).and_time(time))?
        }
    } else {
        bail!("invalid wait-until time '{raw}' (use HH:MM, 9am/9pm, YYYY-MM-DD HH:MM, or RFC3339)");
    };
    let duration = chrono_duration_to_std(target.signed_duration_since(now));
    if duration.is_zero() {
        bail!("wait-until target is not in the future: {target}");
    }
    Ok((duration, target))
}

fn parse_local_datetime_spec(raw: &str) -> Result<Option<DateTime<Local>>> {
    for format in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(value) = NaiveDateTime::parse_from_str(raw, format) {
            return localize_naive_datetime(value).map(Some);
        }
    }
    Ok(None)
}

fn parse_local_time_spec(raw: &str) -> Option<NaiveTime> {
    let normalized = raw.trim().to_ascii_lowercase().replace(' ', "");
    for format in ["%H:%M:%S", "%H:%M", "%I:%M%P", "%I%P"] {
        if let Ok(value) = NaiveTime::parse_from_str(&normalized, format) {
            return Some(value);
        }
    }
    None
}

fn localize_naive_datetime(value: NaiveDateTime) -> Result<DateTime<Local>> {
    match Local.from_local_datetime(&value) {
        LocalResult::Single(value) => Ok(value),
        LocalResult::Ambiguous(first, _) => Ok(first),
        LocalResult::None => {
            bail!("local time does not exist because of a daylight-saving transition")
        }
    }
}

fn chrono_duration_to_std(duration: ChronoDuration) -> Duration {
    if duration <= ChronoDuration::zero() {
        Duration::ZERO
    } else {
        duration.to_std().unwrap_or(Duration::MAX)
    }
}

#[allow(clippy::too_many_arguments)]
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
    let start = Instant::now();
    let (mut collections, mut observed_length) = stable_collections(pile)?;
    let persona = persona
        .map(|input| resolve_persona(&collections, input))
        .transpose()?;

    // A consuming persona wait absorbs an existing quiet baseline before it
    // can sleep. Existing news fires immediately. No-persona wait keeps only
    // an in-memory revision baseline and remains read-only.
    if let Some(persona) = persona {
        let evaluation = evaluate_persona(&collections, persona)?;
        let output = render_news(&collections, &evaluation)?;
        emit(&output)?;
        let fired = !evaluation.news.reasons.is_empty();
        let wrote = publish_evaluation(pile, &collections, &evaluation)?;
        if fired {
            return Ok(());
        }
        if wrote {
            (collections, observed_length) = stable_collections(pile)?;
        }
    }
    let mut revisions = collections.revisions();
    let poll = Duration::from_millis(poll_ms.max(1));

    loop {
        let before_sleep = pile_length(pile)?;
        if should_rescan_before_sleep(observed_length, before_sleep) {
            let loaded = stable_collections(pile)?;
            collections = loaded.0;
            observed_length = loaded.1;
        } else {
            let sleep_for = timeout
                .map(|limit| limit.saturating_sub(start.elapsed()).min(poll))
                .unwrap_or(poll);
            if !sleep_for.is_zero() {
                std::thread::sleep(sleep_for);
            }
            let after_sleep = pile_length(pile)?;
            if after_sleep != observed_length {
                let loaded = stable_collections(pile)?;
                collections = loaded.0;
                observed_length = loaded.1;
            } else if timeout.is_none_or(|limit| start.elapsed() < limit) {
                continue;
            }
        }

        let current_revisions = collections.revisions();
        if current_revisions != revisions {
            if let Some(persona) = persona {
                // Orient is part of the revision tuple, so any concurrent Seen
                // publication invalidates suppression state before this read.
                let evaluation = evaluate_persona(&collections, persona)?;
                let output = render_news(&collections, &evaluation)?;
                emit(&output)?;
                let fired = !evaluation.news.reasons.is_empty();
                let wrote = publish_evaluation(pile, &collections, &evaluation)?;
                if fired {
                    return Ok(());
                }
                if wrote {
                    let loaded = stable_collections(pile)?;
                    collections = loaded.0;
                    observed_length = loaded.1;
                }
            } else {
                let (snapshot, _) = render_show(
                    pile,
                    &collections,
                    None,
                    message_limit,
                    doing_limit,
                    todo_limit,
                )?;
                emit(&snapshot)?;
                return Ok(());
            }
            revisions = collections.revisions();
        }

        if timeout.is_some_and(|limit| start.elapsed() >= limit) {
            let (snapshot, evaluation) = render_show(
                pile,
                &collections,
                persona,
                message_limit,
                doing_limit,
                todo_limit,
            )?;
            let output = format!(
                "No change detected since wait started; showing current snapshot.\n{snapshot}"
            );
            emit(&output)?;
            if let Some(evaluation) = &evaluation {
                publish_evaluation(pile, &collections, evaluation)?;
            }
            return Ok(());
        }
    }
}

/// Legacy Memory and Wiki remain sharply isolated reads. They never supply a
/// fallback for collection-native Compass, Message, Relations, or Orient.
fn render_legacy_wake(pile: &Path, chars: usize) -> Result<String> {
    let mut out = String::new();
    match collection_access::materialize_named_legacy_branch(pile, DEFAULT_MEMORY_BRANCH)? {
        Some(view) => {
            out.push_str(&render_cover(
                &view.facts,
                &view.reader,
                &CoverOpts::plain(chars),
            )?);
        }
        None => writeln!(out, "no memory chunks").unwrap(),
    }
    writeln!(out).unwrap();
    writeln!(out, "Beliefs (cover):").unwrap();
    match collection_access::materialize_named_legacy_branch(pile, WIKI_BRANCH_NAME)? {
        Some(view) => {
            let beliefs = cover_fragments(&view.facts, &view.reader);
            if beliefs.is_empty() {
                writeln!(out, "- None").unwrap();
            } else {
                for (title, content) in beliefs {
                    writeln!(out, "- {title}").unwrap();
                    for line in content.lines() {
                        writeln!(out, "    {line}").unwrap();
                    }
                }
            }
        }
        None => writeln!(out, "- None").unwrap(),
    }
    Ok(out)
}

fn cmd_wake(pile: &Path, chars: usize, doing_limit: usize, todo_limit: usize) -> Result<()> {
    let (collections, _) = stable_collections(pile)?;
    let mut output = render_legacy_wake(pile, chars)?;
    writeln!(output).unwrap();
    output.push_str(&render_compass_goals(
        &collections,
        doing_limit,
        todo_limit,
    )?);
    emit(&output)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    match command {
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
        Command::Wake {
            chars,
            doing_limit,
            todo_limit,
        } => cmd_wake(&cli.pile, chars, doing_limit, todo_limit),
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
    use std::fs::File;

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("orient-test.pile");
            File::create(&pile).unwrap();
            collection_access::initialize_signer(&pile, None).unwrap();
            Self {
                _directory: directory,
                pile,
            }
        }

        fn publish(&self, scope: Id, fragment: Fragment) {
            collection_access::publish_fragment(
                &self.pile,
                None,
                scope,
                fragment,
                Fragment::empty(),
            )
            .unwrap();
        }

        fn person(&self, id: Id, label: &str, zooid: bool) {
            let fragment = relations::person_fragment(
                id,
                relations::ProfileInput {
                    label: label.to_owned(),
                    affinities: if zooid {
                        vec!["zooid".to_owned()]
                    } else {
                        Vec::new()
                    },
                    ..relations::ProfileInput::default()
                },
            )
            .unwrap()
            .0;
            self.publish(faculties::schemas::relations::DEFAULT_SCOPE_ID, fragment);
        }
    }

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at(seconds: f64) -> IntervalValue {
        let epoch = Epoch::from_unix_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn status_id(fragment: &Fragment) -> Id {
        fragment.root().expect("status fragment has one root")
    }

    fn goal_view(goal: Id, status: compass::StatusResolution) -> GoalView {
        GoalView {
            id: goal,
            title: "goal".to_owned(),
            tags: vec!["colony".to_owned()],
            addressed: true,
            involved: false,
            created_at: 0,
            status,
        }
    }

    #[test]
    fn append_between_snapshot_and_sleep_forces_rescan() {
        assert!(!should_rescan_before_sleep(64, 64));
        assert!(should_rescan_before_sleep(64, 128));
    }

    #[test]
    fn first_peek_is_quiet_and_read_only_then_consumption_sweeps_baseline() {
        let fixture = Fixture::new();
        let persona = test_id(20);
        fixture.person(persona, "me", true);

        let before_peek = pile_length(&fixture.pile).unwrap();
        cmd_poll(&fixture.pile, Some(&format!("{persona:x}")), true).unwrap();
        assert_eq!(pile_length(&fixture.pile).unwrap(), before_peek);
        let (before, _) = stable_collections(&fixture.pile).unwrap();
        let evaluation = evaluate_persona(&before, persona).unwrap();
        assert!(!evaluation.has_baseline);
        assert!(evaluation.news.reasons.is_empty());

        cmd_poll(&fixture.pile, Some(&format!("{persona:x}")), false).unwrap();
        assert!(pile_length(&fixture.pile).unwrap() > before_peek);
        let (after, _) = stable_collections(&fixture.pile).unwrap();
        let evaluation = evaluate_persona(&after, persona).unwrap();
        assert!(evaluation.has_baseline);
        assert!(evaluation.markers_to_publish.is_empty());
        assert!(evaluation.news.reasons.is_empty());
        assert!(after
            .orient_catalog
            .seen([&persona])
            .contains(&orient::Observation::new(KIND_PERSON_ID, persona)));
    }

    #[test]
    fn no_persona_show_render_is_read_only() {
        let fixture = Fixture::new();
        let persona = test_id(21);
        fixture.person(persona, "me", true);
        let (collections, _) = stable_collections(&fixture.pile).unwrap();
        let before = pile_length(&fixture.pile).unwrap();
        let (output, evaluation) =
            render_show(&fixture.pile, &collections, None, 10, 5, 5).unwrap();
        assert!(output.starts_with("Orient\n"));
        assert!(evaluation.is_none());
        assert_eq!(pile_length(&fixture.pile).unwrap(), before);
    }

    #[test]
    fn inbound_mail_wakes_once_per_wire_and_read_evidence_removes_it() {
        let fixture = Fixture::new();
        let persona = test_id(40);
        let account = test_id(41);
        let credential = test_id(42);
        fixture.person(persona, "me", true);
        cmd_poll(&fixture.pile, Some(&format!("{persona:x}")), false).unwrap();

        let mut account_fragment =
            mail::credential_fragment(credential, b"orient-test", "secret").unwrap();
        let (config_fragment, config) = mail::account_config_fragment(
            account,
            mail::AccountConfigInput {
                address: "me@example.com".to_owned(),
                display_name: "Me".to_owned(),
                pop_endpoint: "pop.example.com:995".to_owned(),
                smtp_endpoint: "smtp.example.com:465".to_owned(),
                username: "me@example.com".to_owned(),
                credential,
                enabled: true,
                predecessors: Vec::new(),
            },
        )
        .unwrap();
        account_fragment += config_fragment;
        fixture.publish(faculties::schemas::mail::DEFAULT_SCOPE_ID, account_fragment);

        let publication = mail::pop_publication(
            account,
            config,
            "uid-1",
            b"From: Sender <sender@example.com>\r\nTo: me@example.com\r\nMessage-ID: <orient-test@example.com>\r\nDate: Thu, 01 Jan 1970 00:00:01 +0000\r\nSubject: Hello\r\n\r\nbody\r\n",
        )
        .unwrap();
        let wire = publication.wire;
        if !publication.files.facts().is_empty() {
            fixture.publish(
                faculties::schemas::files::DEFAULT_SCOPE_ID,
                publication.files,
            );
        }
        fixture.publish(faculties::schemas::mail::DEFAULT_SCOPE_ID, publication.mail);

        let (collections, _) = stable_collections(&fixture.pile).unwrap();
        let evaluation = evaluate_persona(&collections, persona).unwrap();
        assert!(evaluation.view.mail_unread.contains_key(&wire));
        assert_eq!(evaluation.news.mail, vec![wire]);
        assert!(render_news(&collections, &evaluation)
            .unwrap()
            .contains("New mail:"));

        cmd_poll(&fixture.pile, Some(&format!("{persona:x}")), false).unwrap();
        let (read, _) = mail::read_observation_fragment(wire, persona);
        fixture.publish(faculties::schemas::mail::DEFAULT_SCOPE_ID, read);
        let (collections, _) = stable_collections(&fixture.pile).unwrap();
        let evaluation = evaluate_persona(&collections, persona).unwrap();
        assert!(!evaluation.view.mail_unread.contains_key(&wire));
        assert!(evaluation.news.mail.is_empty());
    }

    #[test]
    fn isolated_legacy_wake_reads_are_read_only() {
        let fixture = Fixture::new();
        let before = pile_length(&fixture.pile).unwrap();
        let output = render_legacy_wake(&fixture.pile, 1_000).unwrap();
        assert!(output.contains("no memory chunks"));
        assert!(output.contains("Beliefs (cover):"));
        assert_eq!(pile_length(&fixture.pile).unwrap(), before);
    }

    #[test]
    fn foreign_and_unattributed_notes_wake_but_own_note_is_quiet() {
        let fixture = Fixture::new();
        let me = test_id(22);
        let peer = test_id(23);
        fixture.person(me, "me", true);
        fixture.person(peer, "peer", true);
        let goal = test_id(24);
        let (mut goal_fragment, _, _) = compass::goal_fragment(
            goal,
            "shared goal",
            vec!["colony".to_owned()],
            None,
            "todo",
            Some(me),
            at(1.0),
        )
        .unwrap();
        goal_fragment += compass::priority_snapshot_fragment([], &[]).unwrap().0;
        fixture.publish(faculties::schemas::compass::DEFAULT_SCOPE_ID, goal_fragment);
        cmd_poll(&fixture.pile, Some(&format!("{me:x}")), false).unwrap();

        let (own, own_id) = compass::note_fragment(
            test_id(25),
            goal,
            "mine",
            Vec::new(),
            Vec::new(),
            &[],
            Some(me),
            at(2.0),
        )
        .unwrap();
        let (foreign, foreign_id) = compass::note_fragment(
            test_id(26),
            goal,
            "theirs",
            Vec::new(),
            Vec::new(),
            &[],
            Some(peer),
            at(3.0),
        )
        .unwrap();
        let (unattributed, unattributed_id) = compass::note_fragment(
            test_id(27),
            goal,
            "ledger",
            Vec::new(),
            Vec::new(),
            &[],
            None,
            at(4.0),
        )
        .unwrap();
        fixture.publish(faculties::schemas::compass::DEFAULT_SCOPE_ID, own);
        fixture.publish(faculties::schemas::compass::DEFAULT_SCOPE_ID, foreign);
        fixture.publish(faculties::schemas::compass::DEFAULT_SCOPE_ID, unattributed);

        let (collections, _) = stable_collections(&fixture.pile).unwrap();
        let evaluation = evaluate_persona(&collections, me).unwrap();
        assert!(!evaluation.view.notes.contains_key(&own_id));
        assert!(evaluation.view.notes.contains_key(&foreign_id));
        assert!(evaluation.view.notes.contains_key(&unattributed_id));
        assert_eq!(
            evaluation
                .news
                .reasons
                .iter()
                .filter(|reason| reason.starts_with("new note"))
                .count(),
            2
        );
    }

    #[test]
    fn same_value_concurrent_head_is_quiet_but_observable() {
        let goal = test_id(1);
        let peer = test_id(2);
        let first = compass::status_fragment(goal, "todo", &[], Some(peer), at(1.0)).unwrap();
        let first_id = status_id(&first);
        let concurrent = compass::status_fragment(goal, "todo", &[], Some(peer), at(2.0)).unwrap();
        let concurrent_id = status_id(&concurrent);
        let mut facts = first.into_facts();
        facts += concurrent.into_facts();
        let current = compass::status_resolution(&facts, goal);
        assert!(matches!(current, compass::StatusResolution::Agreed(_)));
        let seen = BTreeSet::from([orient::Observation::new(KIND_STATUS_SNAPSHOT, first_id)]);
        assert_eq!(
            status_change_reason(
                &facts,
                &goal_view(goal, current.clone()),
                &BTreeSet::new(),
                &seen,
            )
            .unwrap(),
            None
        );
        assert_eq!(
            status_observations(&current),
            BTreeSet::from([
                orient::Observation::new(KIND_STATUS_SNAPSHOT, first_id),
                orient::Observation::new(KIND_STATUS_SNAPSHOT, concurrent_id),
            ])
        );
    }

    #[test]
    fn divergent_fork_and_foreign_reconciliation_wake() {
        let goal = test_id(3);
        let peer = test_id(4);
        let first = compass::status_fragment(goal, "todo", &[], Some(peer), at(1.0)).unwrap();
        let first_id = status_id(&first);
        let second = compass::status_fragment(goal, "doing", &[], Some(peer), at(2.0)).unwrap();
        let second_id = status_id(&second);
        let mut fork = first.into_facts();
        fork += second.into_facts();
        let seen_first = BTreeSet::from([orient::Observation::new(KIND_STATUS_SNAPSHOT, first_id)]);
        let current_fork = compass::status_resolution(&fork, goal);
        assert!(status_change_reason(
            &fork,
            &goal_view(goal, current_fork),
            &BTreeSet::new(),
            &seen_first,
        )
        .unwrap()
        .is_some());

        let resolved =
            compass::status_fragment(goal, "done", &[first_id, second_id], Some(peer), at(3.0))
                .unwrap();
        let mut settled = fork;
        settled += resolved.into_facts();
        let seen_fork = BTreeSet::from([
            orient::Observation::new(KIND_STATUS_SNAPSHOT, first_id),
            orient::Observation::new(KIND_STATUS_SNAPSHOT, second_id),
        ]);
        let current = compass::status_resolution(&settled, goal);
        assert!(status_change_reason(
            &settled,
            &goal_view(goal, current),
            &BTreeSet::new(),
            &seen_fork,
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn own_transition_and_resolved_unseen_transient_fork_are_quiet() {
        let goal = test_id(5);
        let me = test_id(6);
        let peer = test_id(7);
        let first = compass::status_fragment(goal, "todo", &[], Some(peer), at(1.0)).unwrap();
        let first_id = status_id(&first);
        let own = compass::status_fragment(goal, "doing", &[first_id], Some(me), at(2.0)).unwrap();
        let mut own_facts = first.clone().into_facts();
        own_facts += own.into_facts();
        let seen = BTreeSet::from([orient::Observation::new(KIND_STATUS_SNAPSHOT, first_id)]);
        let current = compass::status_resolution(&own_facts, goal);
        assert_eq!(
            status_change_reason(
                &own_facts,
                &goal_view(goal, current),
                &BTreeSet::from([me]),
                &seen,
            )
            .unwrap(),
            None
        );

        let transient = compass::status_fragment(goal, "doing", &[], Some(peer), at(2.0)).unwrap();
        let transient_id = status_id(&transient);
        let reconciliation =
            compass::status_fragment(goal, "todo", &[first_id, transient_id], Some(peer), at(3.0))
                .unwrap();
        let mut resolved = first.into_facts();
        resolved += transient.into_facts();
        resolved += reconciliation.into_facts();
        let current = compass::status_resolution(&resolved, goal);
        assert_eq!(
            status_change_reason(
                &resolved,
                &goal_view(goal, current),
                &BTreeSet::new(),
                &seen,
            )
            .unwrap(),
            None
        );
    }
}
