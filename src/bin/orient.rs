use anybytes::{Bytes, View};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{
    DateTime, Duration as ChronoDuration, Local, LocalResult, NaiveDateTime, NaiveTime, TimeZone,
};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::collection_names::open_configured;
use faculties::memory_cover::{render_cover, CoverOpts};
use faculties::schemas::archive::archive;
use faculties::schemas::compass::DEFAULT_SCOPE_ID as COMPASS_SCOPE_ID;
use faculties::schemas::compass::{board, KIND_GOAL_ID, KIND_NOTE_ID, KIND_STATUS_ID};
use faculties::schemas::habit::DEFAULT_SCOPE_ID as HABIT_SCOPE_ID;
use faculties::schemas::habit::{
    attrs as habit_attrs, KIND_DONE_ID as KIND_HABIT_DONE_ID, KIND_HABIT_ID,
    KIND_STATE_ID as KIND_HABIT_STATE_ID, STATE_ACTIVE, STATE_PAUSED,
};
use faculties::schemas::mail::DEFAULT_SCOPE_ID as MAIL_SCOPE_ID;
use faculties::schemas::mail::{
    imported as imported_mail, observation as mail_observation, projection as mail_projection,
    read as mail_read, IMPORT_RECEIVED, KIND_IMPORTED_OBSERVATION, KIND_PARSED_PROJECTION,
    KIND_POP_OBSERVATION, KIND_READ_OBSERVATION, RECIPE_RFC5322_V1,
};
use faculties::schemas::memory::DEFAULT_SCOPE_ID as MEMORY_SCOPE_ID;
use faculties::schemas::message::{
    local as local_message, DEFAULT_SCOPE_ID as MESSAGE_SCOPE_ID, KIND_MESSAGE_ID, KIND_READ_ID,
};
use faculties::schemas::orient::{presentation, KIND_PRESENTED};
use faculties::schemas::relations::{
    group as relation_group, identity as relation_identity, lifecycle as relation_lifecycle,
    profile as relation_profile, DEFAULT_SCOPE_ID as RELATIONS_SCOPE_ID, KIND_GROUP,
    KIND_GROUP_SNAPSHOT, KIND_IDENTITY_VERDICT, KIND_PERSON_ID, KIND_PERSON_LIFECYCLE,
    KIND_PERSON_PROFILE,
};
use faculties::schemas::status::DEFAULT_SCOPE_ID as STATUS_SCOPE_ID;
use faculties::schemas::status::{status as window_status, KIND_STATUS_UPDATE};
use faculties::schemas::teams::{teams, DEFAULT_SCOPE_ID as TEAMS_SCOPE_ID};
use faculties::schemas::wiki::DEFAULT_SCOPE_ID as WIKI_SCOPE_ID;
use faculties::storage::{load_signer, open_pile_strict, FactArchive, FactCollection};
use faculties::{
    clock, compass, habits, mail as mail_model, message, orient as orient_model, relations, status,
    teams as teams_model, wiki as wiki_model,
};
use hifitime::Epoch;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use triblespace::core::blob::encodings::succinctarchive::Rank9AcceleratedSuccinctArchiveBlob;
use triblespace::core::collection::lww_register::{LwwIndex, LwwRegisterBlob};
use triblespace::core::collection::{
    next_authorization_change, Collection, CollectionSnapshot, CollectionSnapshotExt,
    CollectionStoreExt, Support,
};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::{BlobStoreGet, BlobStoreList, StoreSnapshot};
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

fn entity_tags<P: TriblePattern>(space: &P, entity_id: Id) -> Vec<String> {
    let mut tags: Vec<String> =
        find!(tag: String, pattern!(space, [{ entity_id @ board::tag: ?tag }])).collect();
    tags.sort();
    tags.dedup();
    tags
}

fn visible_notes<P: TriblePattern>(
    space: &P,
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

/// One authored fact collection and its maintained Succinct projection.
struct OrientSource {
    facts: FactCollection,
    label: &'static str,
}

impl OrientSource {
    fn open(pile: &mut Pile, signer: &SigningKey, scope: Id, label: &'static str) -> Result<Self> {
        let authority = signer.verifying_key();
        let collection = open_configured(pile, scope, authority)?;
        let facts = FactCollection::new(pile, collection)
            .with_context(|| format!("register {label} maintained fact collection"))?;
        Ok(Self { facts, label })
    }

    async fn maintain(&self, pile: &mut Pile, snapshot: &PileSnapshot) -> Result<Support> {
        let support = snapshot
            .collection(self.facts.source())
            .map_err(|error| anyhow!("observe admitted {} support: {error}", self.label))?
            .support()
            .clone();
        drop(
            self.facts
                .maintain_exact(pile, &support)
                .await
                .with_context(|| format!("maintain {} fact collection", self.label))?,
        );
        Ok(support)
    }

    fn attach_exact(&self, snapshot: &PileSnapshot, support: &Support) -> Result<OrientFact> {
        let collection = snapshot
            .collection_exact(self.facts.rank9(), support)
            .with_context(|| format!("observe exact {} Rank9 projection", self.label))?;
        let view = collection
            .view::<FactArchive>()
            .with_context(|| format!("read exact {} Rank9 projection", self.label))?;
        Ok(OrientFact { collection, view })
    }
}

struct OrientSources {
    messages: OrientSource,
    mail: OrientSource,
    teams: OrientSource,
    compass: OrientSource,
    relations: OrientSource,
    status: OrientSource,
    habits: Option<OrientSource>,
    presentations: OrientSource,
    compass_status: Collection<LwwRegisterBlob>,
}

impl OrientSources {
    /// Fetch direct source dependencies before choosing a common observation.
    async fn ensure(&self, pile: &mut Pile) -> Result<()> {
        for source in [
            Some(&self.messages),
            Some(&self.mail),
            Some(&self.teams),
            Some(&self.compass),
            Some(&self.relations),
            Some(&self.status),
            self.habits.as_ref(),
            Some(&self.presentations),
        ]
        .into_iter()
        .flatten()
        {
            drop(
                pile.ensure(source.facts.source())
                    .await
                    .with_context(|| format!("ensure {} source collection", source.label))?,
            );
        }
        Ok(())
    }

    fn open(pile: &mut Pile, signer: &SigningKey, include_habits: bool) -> Result<Self> {
        let authority = signer.verifying_key();
        Ok(Self {
            messages: OrientSource::open(pile, signer, MESSAGE_SCOPE_ID, "Message")?,
            mail: OrientSource::open(pile, signer, MAIL_SCOPE_ID, "Mail")?,
            teams: OrientSource::open(pile, signer, TEAMS_SCOPE_ID, "Teams")?,
            compass: OrientSource::open(pile, signer, COMPASS_SCOPE_ID, "Compass")?,
            relations: OrientSource::open(pile, signer, RELATIONS_SCOPE_ID, "Relations")?,
            status: OrientSource::open(pile, signer, STATUS_SCOPE_ID, "Status")?,
            habits: include_habits
                .then(|| OrientSource::open(pile, signer, HABIT_SCOPE_ID, "Habit"))
                .transpose()?,
            presentations: OrientSource::open(
                pile,
                signer,
                faculties::schemas::orient::DEFAULT_SCOPE_ID,
                "Orient",
            )?,
            compass_status: compass::status_register_collection(pile, authority)?,
        })
    }
}

struct OrientFact {
    collection: CollectionSnapshot<PileSnapshot, Rank9AcceleratedSuccinctArchiveBlob>,
    view: FactArchive,
}

impl OrientFact {
    fn support(&self) -> &Support {
        self.collection.support()
    }

    fn view(&self) -> &FactArchive {
        &self.view
    }
}

struct OrientFacts {
    messages: OrientFact,
    mail: OrientFact,
    teams: OrientFact,
    compass: OrientFact,
    relations: OrientFact,
    status: OrientFact,
    habits: Option<OrientFact>,
    presentations: OrientFact,
}

/// Foundational supports selected at one immutable source watermark.
///
/// These coordinates are the denotational boundary of an Orient observation.
/// A later store snapshot may contain more authored commits or independently
/// maintained target nodes, but attachment must remain exact to this vector.
struct OrientSupports {
    messages: Support,
    mail: Support,
    teams: Support,
    compass: Support,
    relations: Support,
    status: Support,
    habits: Option<Support>,
    presentations: Support,
}

/// One coherent semantic observation. Each source stays in its own resident
/// target collection and Rank9 query view; shared vocabulary never turns those
/// authority boundaries into an accidental global fact union.
struct OrientObservation {
    /// Exact immutable store boundary from which every collection view and
    /// selected payload is read.
    snapshot: PileSnapshot,
    facts: OrientFacts,
    compass_status: LwwIndex,
    next_authorization_change: Option<Epoch>,
}

impl OrientObservation {
    fn query(&self) -> OrientQuery<'_> {
        OrientQuery {
            messages: self.facts.messages.view(),
            mail: self.facts.mail.view(),
            teams: self.facts.teams.view(),
            compass: self.facts.compass.view(),
            relations: self.facts.relations.view(),
            status: self.facts.status.view(),
            habits: self.facts.habits.as_ref().map(OrientFact::view),
            presentations: self.facts.presentations.view(),
            compass_status: &self.compass_status,
            snapshot: &self.snapshot,
        }
    }
}

/// Maintain the resident support admitted by one immutable control snapshot.
///
/// Source acquisition precedes this observation. Later records, proofs, and
/// blobs cannot enter any support selected by this batch.
async fn maintain_sources(
    pile: &mut Pile,
    snapshot: &PileSnapshot,
    sources: &OrientSources,
) -> Result<OrientSupports> {
    let messages = sources.messages.maintain(pile, snapshot).await?;
    let mail = sources.mail.maintain(pile, snapshot).await?;
    let teams = sources.teams.maintain(pile, snapshot).await?;
    let compass = sources.compass.maintain(pile, snapshot).await?;
    let relations = sources.relations.maintain(pile, snapshot).await?;
    let status = sources.status.maintain(pile, snapshot).await?;
    let habits = match sources.habits.as_ref() {
        Some(source) => Some(source.maintain(pile, snapshot).await?),
        None => None,
    };
    let presentations = sources.presentations.maintain(pile, snapshot).await?;
    drop(
        pile.maintain_exact(sources.compass_status, &compass)
            .await
            .map_err(|error| anyhow!("maintain Compass status register: {error}"))?,
    );
    Ok(OrientSupports {
        messages,
        mail,
        teams,
        compass,
        relations,
        status,
        habits,
        presentations,
    })
}

/// Read every target collection as it actually exists at one immutable store
/// boundary and one authorization instant. This function performs no writes.
fn observe_sources(
    snapshot: PileSnapshot,
    sources: &OrientSources,
    supports: &OrientSupports,
) -> Result<OrientObservation> {
    let next_authorization_change = next_authorization_change(&snapshot)
        .map_err(|error| anyhow!("inspect next collection authorization change: {error}"))?;
    let messages = sources
        .messages
        .attach_exact(&snapshot, &supports.messages)?;
    let mail = sources.mail.attach_exact(&snapshot, &supports.mail)?;
    let teams = sources.teams.attach_exact(&snapshot, &supports.teams)?;
    // Compass facts and their maintained LWW index are one logical query
    // substrate. Pin both to the same resident foundational support so a
    // concurrent maintainer cannot expose one half of a newer support here.
    let compass = sources.compass.attach_exact(&snapshot, &supports.compass)?;
    let relations = sources
        .relations
        .attach_exact(&snapshot, &supports.relations)?;
    let status = sources.status.attach_exact(&snapshot, &supports.status)?;
    let habits = sources
        .habits
        .as_ref()
        .zip(supports.habits.as_ref())
        .map(|(source, support)| source.attach_exact(&snapshot, support))
        .transpose()?;
    let presentations = sources
        .presentations
        .attach_exact(&snapshot, &supports.presentations)?;
    let compass_status = snapshot
        .collection_exact(sources.compass_status, &supports.compass)
        .map_err(|error| anyhow!("observe Compass status register: {error}"))?
        .view::<LwwIndex>()
        .map_err(|error| anyhow!("read Compass status register: {error}"))?;
    Ok(OrientObservation {
        snapshot,
        facts: OrientFacts {
            messages,
            mail,
            teams,
            compass,
            relations,
            status,
            habits,
            presentations,
        },
        compass_status,
        next_authorization_change,
    })
}

/// Maintain from one frozen source boundary, then observe only the target
/// state resident in the later boundary. `source_snapshot` remains the
/// caller's polling watermark; it is not part of the semantic observation.
/// Preserve its authorization instant too: if maintenance crosses a validity
/// boundary, the next poll must still see that boundary and refresh admission.
async fn maintain_and_observe_snapshot(
    pile: &mut Pile,
    source_snapshot: &PileSnapshot,
    sources: &OrientSources,
) -> Result<OrientObservation> {
    let supports = maintain_sources(pile, source_snapshot, sources).await?;
    let snapshot = pile
        .snapshot_at(source_snapshot.instant())
        .map_err(|error| anyhow!("freeze maintained Orient snapshot: {error}"))?;
    observe_sources(snapshot, sources, &supports)
}

async fn maintain_and_observe_sources(
    pile: &mut Pile,
    sources: &OrientSources,
) -> Result<OrientObservation> {
    sources.ensure(pile).await?;
    let source_snapshot = pile
        .snapshot()
        .map_err(|error| anyhow!("freeze shared Orient native store snapshot: {error}"))?;
    maintain_and_observe_snapshot(pile, &source_snapshot, sources).await
}

/// Borrowed inputs for one declarative Orient query.
///
/// Every source remains a separately admitted, maintained Succinct relation.
/// Cross-source joins are explicit at the query site.
struct OrientQuery<'a> {
    messages: &'a FactArchive,
    mail: &'a FactArchive,
    teams: &'a FactArchive,
    compass: &'a FactArchive,
    relations: &'a FactArchive,
    status: &'a FactArchive,
    habits: Option<&'a FactArchive>,
    presentations: &'a FactArchive,
    compass_status: &'a LwwIndex,
    snapshot: &'a PileSnapshot,
}

#[derive(Debug)]
struct PayloadPending(&'static str);

impl std::fmt::Display for PayloadPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "selected {} payload is not resident", self.0)
    }
}

impl std::error::Error for PayloadPending {}

fn is_payload_pending(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|source| source.downcast_ref::<PayloadPending>().is_some())
}

fn read_utf8(
    snapshot: &PileSnapshot,
    handle: Inline<inlineencodings::Handle<blobencodings::UTF8String>>,
    label: &str,
) -> Result<String> {
    let unknown = Inline::<inlineencodings::Handle<blobencodings::UnknownBlob>>::new(handle.raw);
    if !snapshot
        .contains_blob(unknown)
        .map_err(|error| anyhow!("inspect {label} residency: {error}"))?
    {
        return Err(PayloadPending("UTF-8").into());
    }
    let value: View<str> = snapshot
        .get(handle)
        .with_context(|| format!("read {label} payload {}", hex::encode(handle.raw)))?;
    Ok(value.to_string())
}

fn read_bytes(
    snapshot: &PileSnapshot,
    handle: Inline<inlineencodings::Handle<blobencodings::RawBytes>>,
    label: &str,
) -> Result<Vec<u8>> {
    let unknown = Inline::<inlineencodings::Handle<blobencodings::UnknownBlob>>::new(handle.raw);
    if !snapshot
        .contains_blob(unknown)
        .map_err(|error| anyhow!("inspect {label} residency: {error}"))?
    {
        return Err(PayloadPending("raw bytes").into());
    }
    let value: Bytes = snapshot
        .get(handle)
        .with_context(|| format!("read {label} payload {}", hex::encode(handle.raw)))?;
    Ok(value.to_vec())
}

fn ids_of_kind<P: TriblePattern>(space: &P, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &kind }])).collect()
}

fn track_heads<P: TriblePattern>(
    space: &P,
    kind: Id,
    owner_attribute: &Attribute<inlineencodings::GenId>,
    owner: Id,
) -> Vec<Id> {
    let members: BTreeSet<Id> = find!(
        id: Id,
        pattern!(space, [{ ?id @
            metadata::tag: &kind,
            owner_attribute: &owner,
        }])
    )
    .collect();
    let superseded: BTreeSet<Id> = find!(
        old: Id,
        pattern!(space, [{ _?new @
            metadata::tag: &kind,
            owner_attribute: &owner,
            metadata::supersedes: ?old,
        }])
    )
    .collect();
    members.difference(&superseded).copied().collect()
}

fn person_anchors<P: TriblePattern>(space: &P) -> BTreeSet<Id> {
    ids_of_kind(space, KIND_PERSON_ID)
}

fn group_anchors<P: TriblePattern>(space: &P) -> BTreeSet<Id> {
    ids_of_kind(space, KIND_GROUP)
}

fn profile_heads<P: TriblePattern>(space: &P, person: Id) -> Vec<Id> {
    track_heads(space, KIND_PERSON_PROFILE, &relation_profile::of, person)
}

fn profile_lookup_handles<P: TriblePattern>(space: &P, person: Id) -> Vec<relations::TextHandle> {
    let mut handles = BTreeSet::new();
    for head in profile_heads(space, person) {
        handles.extend(find!(
            value: relations::TextHandle,
            pattern!(space, [{ head @ metadata::name: ?value }])
        ));
        handles.extend(find!(
            value: relations::TextHandle,
            pattern!(space, [{ head @ relation_profile::alias: ?value }])
        ));
    }
    handles.into_iter().collect()
}

#[derive(Default)]
struct IdentityIndex {
    parent: HashMap<Id, Id>,
    contradictory: BTreeSet<Id>,
    unsettled: BTreeSet<(Id, Id)>,
}

fn identity_root(parent: &HashMap<Id, Id>, mut id: Id) -> Id {
    while let Some(next) = parent.get(&id).copied() {
        if next == id {
            break;
        }
        id = next;
    }
    id
}

fn union_identity(parent: &mut HashMap<Id, Id>, left: Id, right: Id) {
    let left = identity_root(parent, left);
    let right = identity_root(parent, right);
    if left == right {
        return;
    }
    let (low, high) = if left < right {
        (left, right)
    } else {
        (right, left)
    };
    parent.insert(low, low);
    parent.insert(high, low);
}

impl IdentityIndex {
    fn from_relations<P: TriblePattern>(space: &P) -> Self {
        let mut index = Self::default();
        for person in person_anchors(space) {
            index.parent.insert(person, person);
        }

        let rows: Vec<(Id, Id, Id, bool)> = find!(
            (event: Id, low: Id, high: Id, same: bool),
            pattern!(space, [{ ?event @
                metadata::tag: &KIND_IDENTITY_VERDICT,
                relation_identity::low: ?low,
                relation_identity::high: ?high,
                relation_identity::same: ?same,
            }])
        )
        .collect();
        let superseded: BTreeSet<Id> = find!(
            old: Id,
            pattern!(space, [{ _?event @
                metadata::tag: &KIND_IDENTITY_VERDICT,
                metadata::supersedes: ?old,
            }])
        )
        .collect();
        let mut pairs = BTreeMap::<(Id, Id), BTreeSet<bool>>::new();
        for (event, left, right, same) in rows {
            let (low, high) = if left < right {
                (left, right)
            } else {
                (right, left)
            };
            index.parent.entry(low).or_insert(low);
            index.parent.entry(high).or_insert(high);
            if !superseded.contains(&event) {
                pairs.entry((low, high)).or_default().insert(same);
            }
        }

        for (&(low, high), values) in &pairs {
            if values.len() == 1 && values.contains(&true) {
                union_identity(&mut index.parent, low, high);
            } else if values.len() > 1 {
                index.unsettled.insert((low, high));
            }
        }
        for (&(low, high), values) in &pairs {
            if values.len() == 1 && values.contains(&false) {
                let low = identity_root(&index.parent, low);
                let high = identity_root(&index.parent, high);
                if low == high {
                    index.contradictory.insert(low);
                }
            }
        }
        index
    }

    fn equivalent(&self, left: Id, right: Id) -> Result<bool> {
        if left == right {
            return Ok(true);
        }
        let left = identity_root(&self.parent, left);
        let right = identity_root(&self.parent, right);
        if self.contradictory.contains(&left) || self.contradictory.contains(&right) {
            bail!("identity comparison touches a contradictory component");
        }
        let roots = if left < right {
            (left, right)
        } else {
            (right, left)
        };
        if self.unsettled.iter().any(|(low, high)| {
            let low = identity_root(&self.parent, *low);
            let high = identity_root(&self.parent, *high);
            (low.min(high), low.max(high)) == roots
        }) {
            bail!("identity comparison is unsettled by a forked verdict");
        }
        Ok(left == right)
    }

    fn component(&self, person: Id) -> Result<BTreeSet<Id>> {
        let root = identity_root(&self.parent, person);
        if self.contradictory.contains(&root) {
            bail!("identity component containing {person:x} is contradictory");
        }
        let mut component: BTreeSet<Id> = self
            .parent
            .keys()
            .copied()
            .filter(|candidate| identity_root(&self.parent, *candidate) == root)
            .collect();
        component.insert(person);
        Ok(component)
    }
}

fn lifecycle_retired<P: TriblePattern>(space: &P, person: Id) -> Result<Option<bool>> {
    let heads = track_heads(
        space,
        KIND_PERSON_LIFECYCLE,
        &relation_lifecycle::of,
        person,
    );
    if heads.is_empty() {
        return Ok(Some(false));
    }
    let values: BTreeSet<bool> = heads
        .into_iter()
        .flat_map(|head| {
            find!(
                value: bool,
                pattern!(space, [{ head @ relation_lifecycle::retired: ?value }])
            )
        })
        .collect();
    Ok((values.len() == 1).then(|| *values.first().expect("one lifecycle value")))
}

fn group_head_ids<P: TriblePattern>(space: &P, group: Id) -> Vec<Id> {
    track_heads(
        space,
        KIND_GROUP_SNAPSHOT,
        &relation_group::snapshot_of,
        group,
    )
}

fn group_members<P: TriblePattern>(space: &P, snapshot: Id) -> BTreeSet<Id> {
    find!(
        member: Id,
        pattern!(space, [{ snapshot @ relation_group::member: ?member }])
    )
    .collect()
}

fn presented_events<P: TriblePattern>(space: &P, persona: Id) -> BTreeSet<Id> {
    find!(
        event: Id,
        pattern!(space, [{ _?presentation @
            metadata::tag: &KIND_PRESENTED,
            presentation::persona: &persona,
            presentation::event: ?event,
        }])
    )
    .collect()
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NativeMessage {
    id: Id,
    from: Id,
    to: Id,
    body: message::TextHandle,
    created_at: IntervalValue,
}

fn native_message_rows(query: &OrientQuery<'_>) -> Vec<NativeMessage> {
    find!(
        (id: Id, from: Id, to: Id, body: message::TextHandle, created_at: IntervalValue),
        pattern!(query.messages, [{ ?id @
            metadata::tag: &KIND_MESSAGE_ID,
            local_message::from: ?from,
            local_message::to: ?to,
            local_message::body: ?body,
            metadata::created_at: ?created_at,
        }])
    )
    .map(|(id, from, to, body, created_at)| NativeMessage {
        id,
        from,
        to,
        body,
        created_at,
    })
    .collect()
}

fn message_is_inbox(
    query: &OrientQuery<'_>,
    identities: &IdentityIndex,
    row: &NativeMessage,
    persona: Id,
) -> Result<bool> {
    if identities.equivalent(row.from, persona)? {
        return Ok(false);
    }
    let snapshots: Vec<Id> = find!(
        snapshot: Id,
        pattern!(query.messages, [{ row.id @ local_message::group_snapshot: ?snapshot }])
    )
    .collect();
    if snapshots.is_empty() {
        return identities.equivalent(row.to, persona);
    }
    for snapshot in snapshots {
        for member in group_members(query.relations, snapshot) {
            if identities.equivalent(member, persona)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn message_is_read(
    query: &OrientQuery<'_>,
    identities: &IdentityIndex,
    message: Id,
    persona: Id,
) -> Result<bool> {
    for reader in find!(
        reader: Id,
        pattern!(query.messages, [{ _?read @
            metadata::tag: &KIND_READ_ID,
            local_message::about_message: &message,
            local_message::reader: ?reader,
        }])
    ) {
        if identities.equivalent(reader, persona)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn unread_messages(query: &OrientQuery<'_>, persona: Id) -> Result<Vec<NativeMessage>> {
    if !person_anchors(query.relations).contains(&persona) {
        return Ok(Vec::new());
    }
    let identities = IdentityIndex::from_relations(query.relations);
    let mut rows = Vec::new();
    for row in native_message_rows(query) {
        if message_is_inbox(query, &identities, &row, persona)?
            && !message_is_read(query, &identities, row.id, persona)?
        {
            rows.push(row);
        }
    }
    rows.sort_by_key(|row| (std::cmp::Reverse(interval_key(row.created_at)), row.id));
    rows.dedup_by_key(|row| row.id);
    Ok(rows)
}

fn native_task_title(query: &OrientQuery<'_>, task: Id) -> Result<String> {
    find!(
        handle: compass::TextHandle,
        pattern!(query.compass, [{ task @ board::title: ?handle }])
    )
    .next()
    .map(|handle| read_utf8(query.snapshot, handle, "Compass title"))
    .transpose()
    .map(|title| title.unwrap_or_default())
}

fn render_native_messages(
    query: &OrientQuery<'_>,
    persona: Option<Id>,
    limit: usize,
) -> Result<(String, BTreeSet<Id>)> {
    use std::fmt::Write as _;

    let mut out = String::new();
    let Some(persona) = persona else {
        writeln!(out, "Local messages:").unwrap();
        writeln!(
            out,
            "- Unavailable: no persona (pass --persona <label-or-hex> or set $PERSONA)"
        )
        .unwrap();
        return Ok((out, BTreeSet::new()));
    };

    let unread = unread_messages(query, persona)?;

    writeln!(
        out,
        "Local messages (unread inbox for {}):",
        read_native_person_label(query, persona)?
    )
    .unwrap();
    if unread.is_empty() {
        writeln!(out, "- None").unwrap();
        return Ok((out, BTreeSet::new()));
    }
    let now = interval_key(clock::point_now()?);
    let mut shown = BTreeSet::new();
    for row in unread.into_iter().take(limit) {
        shown.insert(row.id);
        writeln!(
            out,
            "- [{}] {} {} -> {} (unread)",
            fmt_id(row.id),
            format_age(now, interval_key(row.created_at)),
            read_native_person_label(query, row.from)?,
            read_native_person_label(query, row.to)?,
        )
        .unwrap();
        let body = read_utf8(query.snapshot, row.body, "Message body")?;
        if body.is_empty() {
            writeln!(out, "    ").unwrap();
        } else {
            for line in body.lines() {
                writeln!(out, "    {}", line.trim_end_matches('\r')).unwrap();
            }
        }
    }
    Ok((out, shown))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MailSummary {
    claimed_at: Option<i128>,
    from: Option<mail_model::TextHandle>,
    subject: mail_model::TextHandle,
}

/// One attention item per unread, non-spam inbound wire message. Re-observing
/// the same wire through another source is idempotent when its presentation
/// agrees; conflicting parser projections are not silently arbitrated.
fn native_unread_mail(query: &OrientQuery<'_>, persona: Id) -> Result<BTreeMap<Id, MailSummary>> {
    // A raw exact anchor is a valid observer before its Relations profile
    // arrives. Until then it has no identity component and therefore no
    // Relations-dependent Mail inbox projection.
    if !person_anchors(query.relations).contains(&persona) {
        return Ok(BTreeMap::new());
    }
    let component = IdentityIndex::from_relations(query.relations).component(persona)?;
    let read_wires: BTreeSet<Id> = find!(
        (wire: Id, reader: Id),
        pattern!(query.mail, [{ _?read @
            metadata::tag: &KIND_READ_OBSERVATION,
            mail_read::wire: ?wire,
            mail_read::reader: ?reader,
        }])
    )
    .filter_map(|(wire, reader)| component.contains(&reader).then_some(wire))
    .collect();

    let mut sources: BTreeSet<(Id, Id)> = find!(
        (source: Id, wire: Id),
        pattern!(query.mail, [{ ?source @
            metadata::tag: &KIND_POP_OBSERVATION,
            mail_observation::wire: ?wire,
        }])
    )
    .collect();
    sources.extend(find!(
        (source: Id, wire: Id),
        pattern!(query.mail, [{ ?source @
            metadata::tag: &KIND_IMPORTED_OBSERVATION,
            imported_mail::direction: &IMPORT_RECEIVED,
            mail_observation::wire: ?wire,
        }])
    ));

    let mut by_wire = BTreeMap::new();
    for (source, wire) in sources {
        if read_wires.contains(&wire) {
            continue;
        }
        let projections: BTreeSet<Id> = find!(
            projection: Id,
            pattern!(query.mail, [{ ?projection @
                metadata::tag: &KIND_PARSED_PROJECTION,
                mail_projection::source: &source,
                mail_projection::recipe: &RECIPE_RFC5322_V1,
            }])
        )
        .collect();
        for projection in projections {
            for (subject, spam) in find!(
                (subject: mail_model::TextHandle, spam: bool),
                pattern!(query.mail, [{ projection @
                    mail_projection::subject: ?subject,
                    mail_projection::spam: ?spam,
                }])
            ) {
                if spam {
                    continue;
                }
                let from = find!(
                    value: mail_model::TextHandle,
                    pattern!(query.mail, [{ projection @ mail_projection::from: ?value }])
                )
                .min_by_key(|value| value.raw);
                let claimed_at = find!(
                    value: IntervalValue,
                    pattern!(query.mail, [{ projection @ mail_projection::claimed_date: ?value }])
                )
                .map(interval_key)
                .min();
                by_wire.entry(wire).or_insert(MailSummary {
                    claimed_at,
                    from,
                    subject,
                });
            }
        }
    }
    Ok(by_wire)
}

/// Logical Teams messages that are attention items for this pile.
///
/// Teams carries no per-reader read state, so the attention set is every
/// present (not deleted) logical message written by somebody other than us;
/// news is that set minus the persona's relational `Presented` ledger. There is
/// no persona gating: one tenant account serves every window sharing this
/// pile, so a colleague's message is addressed to the pile rather than to one
/// window — the same reading as a peer message sent to a group you are in.
///
/// This reads only what the pile already holds. `orient` never calls Graph:
/// `wait` re-arms after every turn, and a network round trip on that path
/// would both slow the common case and rate-limit the tenant. `teams read`
/// remains the only thing that pulls new messages into the pile.
fn native_teams_messages(query: &OrientQuery<'_>) -> Result<BTreeSet<Id>> {
    // Author entities for the account this pile posts as. An author's
    // `teams::user_id` and an auth profile's `teams::auth_user_id` are both
    // content-derived UTF8String handles, so equal Graph user ids are equal
    // handle values and the join needs no blob reads.
    let own_authors: BTreeSet<Id> = find!(
        author: Id,
        pattern!(query.teams, [
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

    let present_state: Inline<inlineencodings::ShortString> = "present"
        .try_to_inline()
        .expect("Teams present state fits ShortString");
    let deleted_state: Inline<inlineencodings::ShortString> = "deleted"
        .try_to_inline()
        .expect("Teams deleted state fits ShortString");
    let mut present: BTreeSet<Id> = find!(
        message: Id,
        pattern!(query.teams, [{
            _?observation @
            metadata::tag: teams::kind_message_observation,
            teams::message: ?message,
            teams::message_state: &present_state,
        }])
    )
    .collect();
    let mut deleted: BTreeSet<Id> = find!(
        message: Id,
        pattern!(query.teams, [{
            _?observation @
            metadata::tag: teams::kind_message_observation,
            teams::message: ?message,
            teams::message_state: &deleted_state,
        }])
    )
    .collect();
    for message in find!(
        message: Id,
        pattern!(query.teams, [{
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
        pattern!(query.teams, [{
            _?observation @
            metadata::tag: teams::kind_message_observation,
            teams::message: ?message,
            archive::author: ?author,
            teams::message_state: &present_state,
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
#[derive(Clone, Copy)]
struct TeamsMessageDetailHandles {
    author: Option<teams_model::TextHandle>,
    content: Option<teams_model::TextHandle>,
}

fn teams_message_detail_handles(
    query: &OrientQuery<'_>,
    message: Id,
) -> Result<TeamsMessageDetailHandles> {
    let present_state: Inline<inlineencodings::ShortString> = "present"
        .try_to_inline()
        .expect("Teams present state fits ShortString");
    let newest = find!(
        (modified: IntervalValue, observation: Id),
        pattern!(query.teams, [{
            ?observation @
            metadata::tag: teams::kind_message_observation,
            teams::message: message,
            teams::modified_at: ?modified,
            teams::message_state: &present_state,
        }])
    )
    .map(|(modified, observation)| (interval_key(modified), observation))
    .max();
    let Some((_, observation)) = newest else {
        return Ok(TeamsMessageDetailHandles {
            author: None,
            content: None,
        });
    };
    let author = find!(
        handle: teams_model::TextHandle,
        pattern!(query.teams, [{ observation @ teams::author_name: ?handle }])
    )
    .next();
    let content = find!(
        handle: teams_model::TextHandle,
        pattern!(query.teams, [{ observation @ archive::content: ?handle }])
    )
    .next();
    Ok(TeamsMessageDetailHandles { author, content })
}

fn teams_message_detail(query: &OrientQuery<'_>, message: Id) -> Result<(String, String)> {
    let handles = teams_message_detail_handles(query, message)?;
    let author = handles
        .author
        .map(|handle| read_utf8(query.snapshot, handle, "Teams author display name"))
        .transpose()?
        .unwrap_or_else(|| "(unknown)".to_owned());
    let content = handles
        .content
        .map(|handle| read_utf8(query.snapshot, handle, "Teams message content"))
        .transpose()?
        .unwrap_or_else(|| "(no content)".to_owned());
    Ok((author, content))
}

/// Render the same unread native Mail projection that drives `orient wait`.
fn render_native_mail(
    query: &OrientQuery<'_>,
    persona: Option<Id>,
    limit: usize,
) -> Result<(String, BTreeSet<Id>)> {
    use std::fmt::Write as _;

    let mut out = String::new();
    let Some(persona) = persona else {
        writeln!(out, "Mail:").unwrap();
        writeln!(
            out,
            "- Unavailable: no persona (pass --persona <label-or-hex> or set $PERSONA)"
        )
        .unwrap();
        return Ok((out, BTreeSet::new()));
    };

    let mut rows = native_unread_mail(query, persona)?
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
        read_native_person_label(query, persona)?
    )
    .unwrap();
    if rows.is_empty() {
        writeln!(out, "- None").unwrap();
        return Ok((out, BTreeSet::new()));
    }
    let now = interval_key(clock::point_now()?);
    let mut shown = BTreeSet::new();
    for (wire, summary) in rows.into_iter().take(limit) {
        shown.insert(wire);
        let age = summary
            .claimed_at
            .map(|at| format_age(now, at))
            .unwrap_or_else(|| "?".to_owned());
        let from = summary
            .from
            .map(|handle| read_utf8(query.snapshot, handle, "Mail From"))
            .transpose()?
            .unwrap_or_else(|| "(no From)".to_owned());
        let subject = read_utf8(query.snapshot, summary.subject, "Mail subject")?;
        writeln!(out, "- [{}] {} {} — {}", fmt_id(wire), age, from, subject,).unwrap();
    }
    Ok((out, shown))
}

fn latest_goal_status(query: &OrientQuery<'_>, goal: Id) -> Option<(Id, String, IntervalValue)> {
    find!(
        (event: Id, status: String, at: IntervalValue),
        and!(
            pattern!(query.compass, [{ ?event @
                metadata::tag: &KIND_STATUS_ID,
                board::status_of: &goal,
                board::status: ?status,
                metadata::created_at: ?at,
            }]),
            maximal(event, query.compass_status),
        )
    )
    .next()
}

fn goal_priority_edges(query: &OrientQuery<'_>, goals: &BTreeSet<Id>) -> BTreeSet<(Id, Id)> {
    let mut latest = BTreeMap::<(Id, Id), ((i128, Id), bool)>::new();
    let mut absorb = |event: Id, higher: Id, lower: Id, at: IntervalValue, active: bool| {
        let order = (interval_key(at), event);
        let entry = latest.entry((higher, lower)).or_insert((order, active));
        if order > entry.0 {
            *entry = (order, active);
        }
    };
    for (event, higher, lower, at) in find!(
        (event: Id, higher: Id, lower: Id, at: IntervalValue),
        pattern!(query.compass, [{ ?event @
            metadata::tag: &faculties::schemas::compass::KIND_PRIORITIZE_ID,
            board::higher: ?higher,
            board::lower: ?lower,
            metadata::created_at: ?at,
        }])
    ) {
        absorb(event, higher, lower, at, true);
    }
    for (event, higher, lower, at) in find!(
        (event: Id, higher: Id, lower: Id, at: IntervalValue),
        pattern!(query.compass, [{ ?event @
            metadata::tag: &faculties::schemas::compass::KIND_DEPRIORITIZE_ID,
            board::higher: ?higher,
            board::lower: ?lower,
            metadata::created_at: ?at,
        }])
    ) {
        absorb(event, higher, lower, at, false);
    }
    let mut edges: BTreeSet<(Id, Id)> = latest
        .into_iter()
        .filter_map(|(edge, (_, active))| active.then_some(edge))
        .collect();
    for (child, parent) in find!(
        (child: Id, parent: Id),
        pattern!(query.compass, [{ ?child @
            metadata::tag: &KIND_GOAL_ID,
            board::parent: ?parent,
        }])
    ) {
        if goals.contains(&parent) {
            edges.insert((child, parent));
        }
    }
    edges
}

fn render_native_compass_goals(
    query: &OrientQuery<'_>,
    doing_limit: usize,
    todo_limit: usize,
) -> Result<(String, BTreeSet<Id>)> {
    use std::fmt::Write as _;

    let goals = ids_of_kind(query.compass, KIND_GOAL_ID);
    let ranks = compass::priority_ranks(goals.iter().copied(), &goal_priority_edges(query, &goals));
    let mut doing = Vec::<(usize, i128, Id, Option<Id>)>::new();
    let mut todo = Vec::<(usize, i128, Id, Option<Id>)>::new();
    for task in goals {
        let (status_event, status, status_at) = latest_goal_status(query, task)
            .map(|(event, value, at)| {
                (
                    Some(event),
                    value.to_ascii_lowercase(),
                    Some(interval_key(at)),
                )
            })
            .unwrap_or_else(|| (None, "todo".to_owned(), None));
        let created = find!(
            at: IntervalValue,
            pattern!(query.compass, [{ task @ metadata::created_at: ?at }])
        )
        .map(interval_key)
        .min()
        .unwrap_or(0);
        let key = status_at.unwrap_or(created);
        let rank = ranks.get(&task).copied().unwrap_or(usize::MAX);
        match status.as_str() {
            "doing" => doing.push((rank, key, task, status_event)),
            "todo" => todo.push((rank, key, task, status_event)),
            _ => {}
        }
    }
    let compare = |left: &(usize, i128, Id, Option<Id>), right: &(usize, i128, Id, Option<Id>)| {
        left.0
            .cmp(&right.0)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| left.2.cmp(&right.2))
    };
    doing.sort_by(compare);
    todo.sort_by(compare);

    let mut out = String::new();
    let mut shown = BTreeSet::new();
    writeln!(out, "Compass:").unwrap();
    if doing.is_empty() && todo.is_empty() {
        writeln!(out, "- No goals.").unwrap();
        return Ok((out, shown));
    }
    writeln!(out, "Doing:").unwrap();
    if doing.is_empty() {
        writeln!(out, "- None").unwrap();
    } else {
        for (_, _, task, status_event) in doing.into_iter().take(doing_limit) {
            shown.insert(task);
            shown.extend(status_event);
            writeln!(
                out,
                "- [{}] {}{}",
                fmt_id(task),
                native_task_title(query, task)?,
                render_tags(&entity_tags(query.compass, task)),
            )
            .unwrap();
        }
    }
    writeln!(out, "Todo:").unwrap();
    if todo.is_empty() {
        writeln!(out, "- None").unwrap();
    } else {
        for (_, _, task, status_event) in todo.into_iter().take(todo_limit) {
            shown.insert(task);
            shown.extend(status_event);
            writeln!(
                out,
                "- [{}] {}{}",
                fmt_id(task),
                native_task_title(query, task)?,
                render_tags(&entity_tags(query.compass, task)),
            )
            .unwrap();
        }
    }
    Ok((out, shown))
}

fn render_window_status(query: &OrientQuery<'_>) -> Result<(String, BTreeSet<Id>)> {
    use std::fmt::Write as _;

    let mut latest = BTreeMap::<Id, ((i128, Id), status::TextHandle)>::new();
    for (event, window, text, at) in find!(
        (event: Id, window: Id, text: status::TextHandle, at: IntervalValue),
        pattern!(query.status, [{ ?event @
            metadata::tag: &KIND_STATUS_UPDATE,
            window_status::window: ?window,
            window_status::text: ?text,
            metadata::created_at: ?at,
        }])
    ) {
        let key = (interval_key(at), event);
        let entry = latest.entry(window).or_insert((key, text));
        if key > entry.0 {
            *entry = (key, text);
        }
    }
    let mut rows = Vec::new();
    for (person, (_, handle)) in &latest {
        let text = Some(read_utf8(query.snapshot, *handle, "Status text")?);
        rows.push((read_native_person_label(query, *person)?, text));
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));

    let mut out = String::new();
    let shown = latest.keys().copied().collect();
    writeln!(out, "Window status:").unwrap();
    if rows.is_empty() {
        writeln!(out, "- (none)").unwrap();
    }
    for (label, text) in rows {
        writeln!(out, "- {label}: {}", text.unwrap_or_else(|| "—".to_owned())).unwrap();
    }
    Ok((out, shown))
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
    snapshot: &PileSnapshot,
    facts: &FactArchive,
    pile: &Path,
    now_secs: i64,
) -> Result<HabitObservation> {
    let at = habits::evaluation_dir(pile);
    let mut observation = HabitObservation::default();
    let definitions: Vec<(Id, String, habits::TextHandle, habits::TextHandle)> = find!(
        (habit: Id, label: String, condition: habits::TextHandle, nudge: habits::TextHandle),
        pattern!(facts, [{ ?habit @
            metadata::tag: &KIND_HABIT_ID,
            habit_attrs::label: ?label,
            habit_attrs::condition: ?condition,
            habit_attrs::nudge: ?nudge,
        }])
    )
    .collect();
    let superseded: BTreeSet<Id> = find!(
        old: Id,
        pattern!(facts, [{ _?new @
            metadata::tag: &KIND_HABIT_ID,
            metadata::supersedes: ?old,
        }])
    )
    .collect();

    for (habit, label, condition_handle, nudge_handle) in definitions {
        if superseded.contains(&habit) {
            continue;
        }
        let condition = read_utf8(snapshot, condition_handle, "Habit condition")?;
        let nudge = read_utf8(snapshot, nudge_handle, "Habit nudge")?;
        let script_handle = find!(
            handle: habits::ScriptHandle,
            pattern!(facts, [{ habit @ habit_attrs::script: ?handle }])
        )
        .min_by_key(|handle| handle.raw);
        let script = match script_handle {
            Some(handle) => Some(habits::Script {
                handle,
                bytes: read_bytes(snapshot, handle, "Habit script")?,
            }),
            None => None,
        };

        let mut completed_at: Vec<i64> = find!(
            at: IntervalValue,
            pattern!(facts, [{ _?done @
                metadata::tag: &KIND_HABIT_DONE_ID,
                habit_attrs::of: &habit,
                metadata::created_at: ?at,
            }])
        )
        .map(|at| (interval_key(at) / 1_000_000_000) as i64)
        .collect();
        completed_at.sort_unstable();
        completed_at.dedup();

        let state_rows: Vec<(Id, String, IntervalValue)> = find!(
            (id: Id, state: String, at: IntervalValue),
            pattern!(facts, [{ ?id @
                metadata::tag: &KIND_HABIT_STATE_ID,
                habit_attrs::of: &habit,
                habit_attrs::state: ?state,
                metadata::created_at: ?at,
            }])
        )
        .collect();
        let state_superseded: BTreeSet<Id> = find!(
            old: Id,
            pattern!(facts, [{ _?new @
                metadata::tag: &KIND_HABIT_STATE_ID,
                habit_attrs::of: &habit,
                metadata::supersedes: ?old,
            }])
        )
        .collect();
        let mut heads = Vec::new();
        for (id, state, asserted_at) in state_rows {
            if state_superseded.contains(&id) {
                continue;
            }
            let state = match state.as_str() {
                STATE_ACTIVE => habits::DeclaredState::Active,
                STATE_PAUSED => habits::DeclaredState::Paused,
                other => {
                    observation.attention.insert(
                        habit,
                        format!("{label} [{habit:x}] has unknown state {other:?}"),
                    );
                    continue;
                }
            };
            heads.push(habits::StateAssertion {
                id,
                habit,
                state,
                predecessors: find!(
                    predecessor: Id,
                    pattern!(facts, [{ id @ metadata::supersedes: ?predecessor }])
                )
                .collect(),
                asserted_at,
            });
        }
        let activation = if heads.is_empty()
            || heads
                .iter()
                .all(|head| head.state == habits::DeclaredState::Active)
        {
            habits::Activation::Active(heads)
        } else if heads
            .iter()
            .all(|head| head.state == habits::DeclaredState::Paused)
        {
            habits::Activation::Paused(heads)
        } else {
            habits::Activation::Forked(heads)
        };
        let row = habits::HabitRow {
            id: habit,
            label,
            condition,
            nudge,
            script,
            activation,
            completed_at,
        };
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

fn render_habit_transitions(
    previous: &HabitObservation,
    current: &HabitObservation,
) -> Option<String> {
    use std::fmt::Write as _;

    let due = newly_due(previous, current);
    let attention = newly_needing_attention(previous, current);
    if due.is_empty() && attention.is_empty() {
        return None;
    }
    let mut out = String::new();
    for (id, habit) in &due {
        writeln!(
            out,
            "News: habit [{}] became due ({})",
            fmt_id(*id),
            habit.label
        )
        .unwrap();
    }
    for (id, _) in &attention {
        writeln!(out, "News: habit [{}] needs attention", fmt_id(*id)).unwrap();
    }
    if !due.is_empty() {
        writeln!(out, "\nHabits newly due:").unwrap();
        for (_, habit) in due {
            writeln!(out, "- {}: {}", habit.label, habit.nudge).unwrap();
        }
    }
    if !attention.is_empty() {
        writeln!(out, "\nHabit attention:").unwrap();
        for (_, warning) in attention {
            writeln!(out, "- {warning}").unwrap();
        }
    }
    Some(out)
}

#[derive(Debug)]
struct PersonaNotFound(String);

impl std::fmt::Display for PersonaNotFound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "no person matches '{}'", self.0)
    }
}

impl std::error::Error for PersonaNotFound {}

fn is_persona_not_found(error: &anyhow::Error) -> bool {
    error.downcast_ref::<PersonaNotFound>().is_some()
}

fn resolve_native_persona(query: &OrientQuery<'_>, input: &str) -> Result<Id> {
    let input = input.trim();
    if let Some(id) = Id::from_hex(input) {
        // Exact anchors remain useful before a profile has arrived.
        return Ok(id);
    }
    if input.is_empty() {
        bail!("empty person selector");
    }
    let wanted = relations::lookup_key(input);
    let mut settled = Vec::new();
    let mut forked = Vec::new();
    for person in person_anchors(query.relations) {
        let heads = profile_heads(query.relations, person);
        let mut matched = false;
        for handle in profile_lookup_handles(query.relations, person) {
            let value = read_utf8(query.snapshot, handle, "Relations profile selector")?;
            if relations::lookup_key(&value) == wanted {
                matched = true;
                break;
            }
        }
        if !matched || lifecycle_retired(query.relations, person)? == Some(true) {
            continue;
        }
        if heads.len() == 1 && lifecycle_retired(query.relations, person)?.is_some() {
            settled.push(person);
        } else {
            forked.push(person);
        }
    }
    if !forked.is_empty() {
        bail!(
            "cannot resolve person '{input}': unreconciled Relations state on {}",
            forked
                .iter()
                .map(|id| fmt_id(*id))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    match settled.as_slice() {
        [person] => Ok(*person),
        [] => Err(PersonaNotFound(input.to_owned()).into()),
        _ => bail!(
            "multiple people match '{input}': {}",
            settled
                .iter()
                .map(|id| fmt_id(*id))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn native_person_label_handle(
    query: &OrientQuery<'_>,
    person: Id,
) -> Result<Option<relations::TextHandle>> {
    let heads = profile_heads(query.relations, person);
    let [head] = heads.as_slice() else {
        return Ok(None);
    };
    let head = *head;
    Ok(find!(
        handle: relations::TextHandle,
        pattern!(query.relations, [{ head @ metadata::name: ?handle }])
    )
    .min_by_key(|handle| handle.raw))
}

fn read_native_person_label(query: &OrientQuery<'_>, person: Id) -> Result<String> {
    native_person_label_handle(query, person)?
        .map(|handle| read_utf8(query.snapshot, handle, "Relations person label"))
        .transpose()
        .map(|label| label.unwrap_or_else(|| fmt_id(person)))
}

fn persona_keys(query: &OrientQuery<'_>, persona: Id) -> Result<HashSet<String>> {
    profile_lookup_handles(query.relations, persona)
        .into_iter()
        .map(|handle| {
            read_utf8(query.snapshot, handle, "Relations persona selector")
                .map(|value| value.to_ascii_lowercase())
        })
        .collect()
}

/// Every textual group selector that may currently address `persona`.
///
/// Attention is a conservative read projection, not a mutation precondition:
/// a legitimate fork in one group must not disable every watcher. We therefore
/// inspect each maximal snapshot independently. A fork head names an
/// attention group only when that same snapshot contains the persona; names
/// from a sibling head cannot borrow another head's membership. Settled
/// same-person components still participate in membership, while an exact id
/// without a Relations person record simply belongs to no group yet.
fn group_attention_name_handles<P: TriblePattern>(
    facts: &P,
    persona: Id,
) -> Result<Vec<relations::TextHandle>> {
    if !person_anchors(facts).contains(&persona) {
        return Ok(Vec::new());
    }
    let equivalent = IdentityIndex::from_relations(facts).component(persona)?;
    let mut handles = BTreeSet::new();
    for group in group_anchors(facts) {
        for head in group_head_ids(facts, group) {
            if group_members(facts, head)
                .iter()
                .any(|member| equivalent.contains(member))
            {
                handles.extend(find!(
                    handle: relations::TextHandle,
                    pattern!(facts, [{ head @ metadata::name: ?handle }])
                ));
            }
        }
    }
    Ok(handles.into_iter().collect())
}

fn group_attention_keys<P: TriblePattern>(
    reader: &PileSnapshot,
    facts: &P,
    persona: Id,
) -> Result<HashSet<String>> {
    group_attention_name_handles(facts, persona)?
        .into_iter()
        .map(|handle| {
            read_utf8(reader, handle, "Relations group name")
                .map(|value| relations::lookup_key(&value))
        })
        .collect()
}

fn attention_keys(query: &OrientQuery<'_>, persona: Id) -> Result<HashSet<String>> {
    let mut keys = persona_keys(query, persona)?;
    keys.extend(group_attention_keys(
        query.snapshot,
        query.relations,
        persona,
    )?);
    Ok(keys)
}

fn status_roster(query: &OrientQuery<'_>) -> Result<BTreeSet<Id>> {
    Ok(find!(
        window: Id,
        pattern!(query.status, [{ _?event @
            metadata::tag: &KIND_STATUS_UPDATE,
            window_status::window: ?window,
        }])
    )
    .collect())
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

#[derive(Clone, Debug, Eq, PartialEq)]
enum AttentionEvent {
    Message(Id),
    Mail(Id),
    Teams(Id),
    Goal { event: Id, goal: Id, status: String },
    Note { note: Id, goal: Id },
    StatusWindow(Id),
}

impl AttentionEvent {
    fn id(&self) -> Id {
        match self {
            Self::Message(id) | Self::Mail(id) | Self::Teams(id) | Self::StatusWindow(id) => *id,
            Self::Goal { event, .. } => *event,
            Self::Note { note, .. } => *note,
        }
    }

    fn reason(&self) -> String {
        match self {
            Self::Message(id) => format!("new message [{}]", fmt_id(*id)),
            Self::Mail(id) => format!("new mail [{}]", fmt_id(*id)),
            Self::Teams(id) => format!("new Teams message [{}]", fmt_id(*id)),
            Self::Goal {
                event,
                goal,
                status,
            } if event == goal => format!("new goal [{}] ({status})", fmt_id(*goal)),
            Self::Goal { goal, status, .. } => {
                format!("goal [{}] is now {status}", fmt_id(*goal))
            }
            Self::Note { note, goal } => {
                format!("new note [{}] on goal [{}]", fmt_id(*note), fmt_id(*goal))
            }
            Self::StatusWindow(window) => {
                format!("new status window [{}]", fmt_id(*window))
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct AttentionView {
    events: BTreeMap<Id, AttentionEvent>,
}

impl AttentionView {
    fn insert(&mut self, event: AttentionEvent) {
        self.events.entry(event.id()).or_insert(event);
    }

    fn ids(&self) -> impl ExactSizeIterator<Item = Id> + '_ {
        self.events.keys().copied()
    }

    fn pending(&self, presented: &BTreeSet<Id>) -> Self {
        Self {
            events: self
                .events
                .iter()
                .filter(|(event, _)| !presented.contains(*event))
                .map(|(event, detail)| (*event, detail.clone()))
                .collect(),
        }
    }

    fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// Derive the exact attention-event set visible to one persona from the
/// current source collections. This is deliberately an ephemeral query view;
/// durable state consists only of `Presented(persona, event)` atoms.
fn load_attention_view(query: &OrientQuery<'_>, persona_id: Id) -> Result<AttentionView> {
    let mut view = AttentionView::default();
    for row in unread_messages(query, persona_id)? {
        view.insert(AttentionEvent::Message(row.id));
    }
    for wire in native_unread_mail(query, persona_id)?.into_keys() {
        view.insert(AttentionEvent::Mail(wire));
    }
    for message in native_teams_messages(query)? {
        view.insert(AttentionEvent::Teams(message));
    }

    let attention_keys = attention_keys(query, persona_id)?;

    let mut relevant_goals = HashSet::new();
    for id in find!(id: Id, pattern!(query.compass, [{ ?id @ metadata::tag: &KIND_GOAL_ID }])) {
        let authored_status = exists!(pattern!(query.compass, [{
            _?evt @
            metadata::tag: &KIND_STATUS_ID,
            board::status_of: &id,
            board::by: &persona_id,
        }]));
        let authored_note = exists!(pattern!(query.compass, [{
            _?evt @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &id,
            board::note: _?body,
            board::by: &persona_id,
        }]));
        let involved = authored_status || authored_note;
        let tags = entity_tags(query.compass, id);
        let addressed = tags
            .iter()
            .any(|tag| attention_keys.contains(&tag.to_ascii_lowercase()));
        if involved || addressed {
            relevant_goals.insert(id);
            match latest_goal_status(query, id) {
                Some((event, status, _)) => {
                    let by = find!(
                        by: Id,
                        pattern!(query.compass, [{ event @ board::by: ?by }])
                    )
                    .next();
                    if by != Some(persona_id) {
                        view.insert(AttentionEvent::Goal {
                            event,
                            goal: id,
                            status,
                        });
                    }
                }
                None if addressed => view.insert(AttentionEvent::Goal {
                    event: id,
                    goal: id,
                    status: "todo".to_owned(),
                }),
                None => {}
            }
        }
    }

    for (note, goal) in visible_notes(query.compass, persona_id, &attention_keys, &relevant_goals) {
        view.insert(AttentionEvent::Note { note, goal });
    }

    for window in status_roster(query)? {
        if window != persona_id {
            view.insert(AttentionEvent::StatusWindow(window));
        }
    }

    Ok(view)
}

fn save_presentations(
    pile: &mut Pile,
    signer: &SigningKey,
    persona: Id,
    events: impl IntoIterator<Item = Id>,
) -> Result<()> {
    let fragment = orient_model::presented_fragment(persona, events);
    if fragment.facts().is_empty() {
        return Ok(());
    }
    let collection = open_configured(
        pile,
        faculties::schemas::orient::DEFAULT_SCOPE_ID,
        signer.verifying_key(),
    )?;
    pile.commit(collection, signer, fragment)
        .map_err(|error| anyhow!("commit Orient presentation facts: {error}"))?;
    Ok(())
}

async fn cmd_baseline(pile_path: &Path, key: Option<&Path>, persona: Option<&str>) -> Result<()> {
    let Some(input) = persona else {
        bail!("baseline requires a persona (pass --persona <label-or-hex> or set $PERSONA)");
    };
    let signer = load_signer(pile_path, key)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = async {
        let sources = OrientSources::open(&mut pile, &signer, false)?;
        let observation = maintain_and_observe_sources(&mut pile, &sources).await?;
        let query = observation.query();
        let persona = resolve_native_persona(&query, input)?;
        let view = load_attention_view(&query, persona)?;
        let events = view.ids().collect::<Vec<_>>();
        save_presentations(&mut pile, &signer, persona, events.iter().copied())?;
        Ok(events.len())
    }
    .await;
    let count = close_pile(pile, result)?;
    println!("Baselined {count} current attention event(s) for {input}.");
    Ok(())
}

async fn cmd_show(
    pile_path: &Path,
    key: Option<&Path>,
    persona: Option<&str>,
    message_limit: usize,
    doing_limit: usize,
    todo_limit: usize,
) -> Result<()> {
    use std::fmt::Write as _;

    let signer = load_signer(pile_path, key)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = async {
        let sources = OrientSources::open(&mut pile, &signer, true)?;
        let observation = maintain_and_observe_sources(&mut pile, &sources).await?;
        let instant = observation.snapshot.instant();
        let query = observation.query();
        let persona_id = persona
            .map(|input| resolve_native_persona(&query, input))
            .transpose()?;
        let (messages, message_events) = render_native_messages(&query, persona_id, message_limit)?;
        let (mail, mail_events) = render_native_mail(&query, persona_id, message_limit)?;
        let habits = render_native_habits(&observe_habits(
            query.snapshot,
            query
                .habits
                .expect("Show opens the Habit source collection"),
            pile_path,
            epoch_seconds(instant),
        )?);
        let (goals, goal_events) = render_native_compass_goals(&query, doing_limit, todo_limit)?;
        let (window_status, status_events) = render_window_status(&query)?;

        let mut report = String::new();
        writeln!(report, "Orient").unwrap();
        report.push_str(&messages);
        report.push_str(&mail);
        report.push('\n');
        report.push_str(&habits);
        report.push_str(&goals);
        report.push_str(&window_status);

        let stdout = io::stdout();
        let mut output = stdout.lock();
        write_complete_report(&mut output, &report, "Orient overview")?;

        if let Some(persona_id) = persona_id {
            let candidates: BTreeSet<_> = load_attention_view(&query, persona_id)?.ids().collect();
            let shown = message_events
                .into_iter()
                .chain(mail_events)
                .chain(goal_events)
                .chain(status_events)
                .filter(|event| candidates.contains(event));
            save_presentations(&mut pile, &signer, persona_id, shown)?;
        }
        Ok(())
    }
    .await;
    close_pile(pile, result)
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

/// Render only the *novel* content behind the news — new peer messages, Mail
/// and Teams messages, plus newly-arrived roster members — so a woken watcher gets what changed,
/// not a full re-dump of the snapshot. The `News:` reason lines are rendered by
/// the caller; this fills in the detail worth reading.
fn render_news_detail(
    query: &OrientQuery<'_>,
    pending: &AttentionView,
    persona_id: Id,
) -> Result<String> {
    use std::fmt::Write as _;

    let mut out = String::new();
    let new_msgs: Vec<Id> = pending
        .events
        .values()
        .filter_map(|event| match event {
            AttentionEvent::Message(id) => Some(*id),
            _ => None,
        })
        .collect();
    if !new_msgs.is_empty() {
        let rows = native_message_rows(query);
        writeln!(out, "\nNew messages:").unwrap();
        for id in &new_msgs {
            if let Some(row) = rows.iter().find(|r| r.id == *id) {
                let from = read_native_person_label(query, row.from)?;
                let body = read_utf8(query.snapshot, row.body, "Message body")?;
                writeln!(out, "- {from}: {body}").unwrap();
            }
        }
    }
    let new_mail: Vec<Id> = pending
        .events
        .values()
        .filter_map(|event| match event {
            AttentionEvent::Mail(id) => Some(*id),
            _ => None,
        })
        .collect();
    if !new_mail.is_empty() {
        let summaries = native_unread_mail(query, persona_id)?;
        writeln!(out, "\nNew mail:").unwrap();
        for wire in &new_mail {
            let summary = summaries.get(wire).ok_or_else(|| {
                anyhow!("new Mail wire {} vanished from current view", fmt_id(*wire))
            })?;
            let from = summary
                .from
                .map(|handle| read_utf8(query.snapshot, handle, "Mail From"))
                .transpose()?
                .unwrap_or_else(|| "(no From)".to_owned());
            let subject = read_utf8(query.snapshot, summary.subject, "Mail subject")?;
            writeln!(out, "- [{}] {} — {}", fmt_id(*wire), from, subject,).unwrap();
        }
    }
    let new_teams: Vec<Id> = pending
        .events
        .values()
        .filter_map(|event| match event {
            AttentionEvent::Teams(id) => Some(*id),
            _ => None,
        })
        .collect();
    if !new_teams.is_empty() {
        writeln!(out, "\nNew Teams messages:").unwrap();
        for message in &new_teams {
            let (author, content) = teams_message_detail(query, *message)?;
            writeln!(out, "- {author}: {content}").unwrap();
        }
    }
    let new_people: Vec<Id> = pending
        .events
        .values()
        .filter_map(|event| match event {
            AttentionEvent::StatusWindow(id) if *id != persona_id => Some(*id),
            _ => None,
        })
        .collect();
    if !new_people.is_empty() {
        writeln!(out, "\nNew status window(s):").unwrap();
        for id in &new_people {
            writeln!(out, "- {}", read_native_person_label(query, *id)?).unwrap();
        }
    }
    Ok(out)
}

enum News {
    Pending,
    Quiet,
    Report { text: String, events: Vec<Id> },
}

fn write_complete_report(output: &mut impl Write, report: &str, description: &str) -> Result<()> {
    output
        .write_all(report.as_bytes())
        .with_context(|| format!("write complete {description}"))?;
    output
        .flush()
        .with_context(|| format!("flush complete {description}"))
}

fn prepare_news_once(query: &OrientQuery<'_>, persona_id: Id) -> Result<News> {
    let prepared = (|| {
        let candidates = load_attention_view(query, persona_id)?;
        let presented = presented_events(query.presentations, persona_id);
        let pending = candidates.pending(&presented);
        if pending.is_empty() {
            return Ok(News::Quiet);
        }
        use std::fmt::Write as _;

        let mut text = String::new();
        for event in pending.events.values() {
            writeln!(text, "News: {}", event.reason()).unwrap();
        }
        text.push_str(&render_news_detail(query, &pending, persona_id)?);
        Ok(News::Report {
            text,
            events: pending.ids().collect(),
        })
    })();
    match prepared {
        Err(error) if is_payload_pending(&error) => Ok(News::Pending),
        other => other,
    }
}

fn apply_prepared_news(
    pile: &mut Pile,
    signer: &SigningKey,
    persona_id: Id,
    peek: bool,
    prepared: &News,
    prefix: &str,
    output: &mut impl Write,
) -> Result<()> {
    match prepared {
        News::Report { text, events } => {
            let mut complete = String::with_capacity(prefix.len() + text.len());
            complete.push_str(prefix);
            complete.push_str(text);
            write_complete_report(output, &complete, "Orient news report")?;
            if !peek {
                save_presentations(pile, signer, persona_id, events.iter().copied())?;
            }
        }
        News::Quiet => {
            if !prefix.is_empty() {
                write_complete_report(output, prefix, "Orient habit report")?;
            }
        }
        News::Pending => {}
    }
    Ok(())
}

/// One shot of the wait fire-path for a persona: load the current
/// attention-event set, subtract the persona's presentation ledger, and if
/// anything remains print the terse report (`News:` reasons + the novel
/// message bodies / status windows) before recording those events. Shared by
/// `wait` (pre-loop check) and `poll` (the whole command) — one code
/// path, blocking vs non-blocking only in the caller.
fn check_news_once(
    pile: &mut Pile,
    signer: &SigningKey,
    query: &OrientQuery<'_>,
    persona_id: Id,
    peek: bool,
) -> Result<News> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    check_news_once_to(pile, signer, query, persona_id, peek, &mut output)
}

fn check_news_once_to(
    pile: &mut Pile,
    signer: &SigningKey,
    query: &OrientQuery<'_>,
    persona_id: Id,
    peek: bool,
    output: &mut impl Write,
) -> Result<News> {
    let news = prepare_news_once(query, persona_id)?;
    apply_prepared_news(pile, signer, persona_id, peek, &news, "", output)?;
    Ok(news)
}

/// One-shot, non-blocking `wait`: report pending attention tersely, or print
/// nothing and exit 0. Meant for per-turn
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

async fn cmd_poll(
    pile_path: &Path,
    key: Option<&Path>,
    persona: Option<&str>,
    peek: bool,
) -> Result<()> {
    let Some(input) = persona else {
        bail!("poll requires a persona (pass --persona <label-or-hex> or set $PERSONA)");
    };
    let signer = load_signer(pile_path, key)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = async {
        let sources = OrientSources::open(&mut pile, &signer, false)?;
        let observation = maintain_and_observe_sources(&mut pile, &sources).await?;
        let query = observation.query();
        let persona_id = match resolve_native_persona(&query, input) {
            Ok(persona) => persona,
            Err(error) if is_payload_pending(&error) || is_persona_not_found(&error) => {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        check_news_once(&mut pile, &signer, &query, persona_id, peek)?;
        Ok(())
    }
    .await;
    close_pile(pile, result)
}

struct WaitOutcome {
    news_printed: bool,
    view_pending: bool,
    had_ready_frame: bool,
}

struct WaitFrame {
    watermark: PileSnapshot,
    observation: OrientObservation,
    persona: Id,
    habits: HabitObservation,
    news: News,
}

struct PendingWaitFrame {
    watermark: PileSnapshot,
    next_authorization_change: Option<Epoch>,
    reason: PendingWaitReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingWaitReason {
    /// The persona selector cannot yet be resolved in this observation.
    PersonaSelection,
    /// The persona is settled, but another selected payload is unavailable.
    Payload,
}

impl PendingWaitFrame {
    fn awaiting_view(
        watermark: PileSnapshot,
        observation: &OrientObservation,
        reason: PendingWaitReason,
    ) -> Self {
        Self {
            watermark,
            next_authorization_change: observation.next_authorization_change,
            reason,
        }
    }
}

enum WaitFrameLoad {
    Pending(PendingWaitFrame),
    Ready(WaitFrame),
}

impl WaitFrameLoad {
    fn watermark_snapshot(&self) -> &PileSnapshot {
        match self {
            Self::Pending(pending) => &pending.watermark,
            Self::Ready(frame) => &frame.watermark,
        }
    }

    fn next_authorization_change(&self) -> Option<Epoch> {
        match self {
            Self::Pending(pending) => pending.next_authorization_change,
            Self::Ready(frame) => frame.observation.next_authorization_change,
        }
    }
}

async fn load_wait_frame(
    pile: &mut Pile,
    sources: &OrientSources,
    snapshot: PileSnapshot,
    pile_path: &Path,
    persona_input: &str,
) -> Result<WaitFrameLoad> {
    // Fetching may change residency, but this attempt keeps its caller's
    // watermark. The next poll observes those additions (and any concurrent
    // records); maintenance never consumes an unobserved source frontier.
    sources.ensure(pile).await?;
    let instant = snapshot.instant();
    let observation = maintain_and_observe_snapshot(pile, &snapshot, sources).await?;
    let query = observation.query();
    let persona = match resolve_native_persona(&query, persona_input) {
        Ok(persona) => persona,
        Err(error) if is_payload_pending(&error) || is_persona_not_found(&error) => {
            return Ok(WaitFrameLoad::Pending(PendingWaitFrame::awaiting_view(
                snapshot,
                &observation,
                PendingWaitReason::PersonaSelection,
            )));
        }
        Err(error) => return Err(error),
    };
    let habits = match observe_habits(
        query.snapshot,
        query
            .habits
            .expect("Wait opens the Habit source collection"),
        pile_path,
        epoch_seconds(instant),
    ) {
        Ok(habits) => habits,
        Err(error) if is_payload_pending(&error) => {
            return Ok(WaitFrameLoad::Pending(PendingWaitFrame::awaiting_view(
                snapshot,
                &observation,
                PendingWaitReason::Payload,
            )));
        }
        Err(error) => return Err(error),
    };
    let news = prepare_news_once(&query, persona)?;
    if matches!(news, News::Pending) {
        return Ok(WaitFrameLoad::Pending(PendingWaitFrame::awaiting_view(
            snapshot,
            &observation,
            PendingWaitReason::Payload,
        )));
    }
    Ok(WaitFrameLoad::Ready(WaitFrame {
        watermark: snapshot,
        observation,
        persona,
        habits,
        news,
    }))
}

fn retained_habit_support_is_admitted(
    observation: &OrientObservation,
    sources: &OrientSources,
    snapshot: &PileSnapshot,
) -> Result<bool> {
    let (Some(source), Some(facts)) = (sources.habits.as_ref(), observation.facts.habits.as_ref())
    else {
        return Ok(true);
    };
    let admitted = source
        .facts
        .source()
        .admitted(snapshot)
        .map_err(|error| anyhow!("recheck retained Habit authorization: {error}"))?;
    facts
        .support()
        .is_subset(&admitted)
        .map_err(|error| anyhow!("compare retained Habit authorization: {error}"))
}

fn observe_habits_in_observation(
    observation: &OrientObservation,
    pile_path: &Path,
    now_secs: i64,
) -> Result<HabitObservation> {
    let facts = observation
        .facts
        .habits
        .as_ref()
        .expect("a wait observation includes Habit");
    observe_habits(&observation.snapshot, facts.view(), pile_path, now_secs)
}

fn authorization_change_elapsed(boundary: Option<Epoch>, now: Epoch) -> bool {
    boundary.is_some_and(|boundary| now >= boundary)
}

async fn cmd_wait(
    pile_path: &Path,
    key: Option<&Path>,
    persona: Option<&str>,
    target: Option<WaitTarget>,
    poll_ms: u64,
) -> Result<()> {
    let Some(persona_input) = persona else {
        bail!("wait requires a persona (pass --persona <label-or-hex> or set $PERSONA)");
    };
    let timeout = parse_wait_target(target.as_ref())?;
    let signer = load_signer(pile_path, key)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = async {
        let sources = OrientSources::open(&mut pile, &signer, true)?;
        let poll = Duration::from_millis(poll_ms.max(1));
        let start = Instant::now();
        let mut view_pending;

        // `observed_snapshot` is the pre-maintenance prefix we attempted. It
        // deliberately remains the polling watermark after derived writes so
        // a concurrent source append cannot be swallowed by those writes.
        let first_snapshot = pile
            .snapshot()
            .map_err(|error| anyhow!("freeze initial Orient wait snapshot: {error}"))?;
        let mut attempt = load_wait_frame(
            &mut pile,
            &sources,
            first_snapshot,
            pile_path,
            persona_input,
        )
        .await?;
        let mut observed_snapshot = attempt.watermark_snapshot().clone();
        let mut next_authorization_change = attempt.next_authorization_change();

        let initial = loop {
            if matches!(attempt, WaitFrameLoad::Ready(_)) {
                let WaitFrameLoad::Ready(frame) = attempt else {
                    unreachable!()
                };
                view_pending = false;
                break frame;
            }
            let WaitFrameLoad::Pending(_) = &attempt else {
                unreachable!()
            };
            view_pending = true;

            if timeout.is_some_and(|timeout| start.elapsed() >= timeout) {
                return Ok(WaitOutcome {
                    news_printed: false,
                    view_pending,
                    had_ready_frame: false,
                });
            }
            std::thread::sleep(poll);
            let sampled = pile
                .snapshot()
                .map_err(|error| anyhow!("refresh Orient wait snapshot: {error}"))?;
            let changed = !sampled.changes_since(&observed_snapshot).is_empty();
            let instant = sampled.instant();
            if !changed
                && instant >= observed_snapshot.instant()
                && !authorization_change_elapsed(next_authorization_change, instant)
            {
                continue;
            }
            attempt =
                load_wait_frame(&mut pile, &sources, sampled, pile_path, persona_input).await?;
            observed_snapshot = attempt.watermark_snapshot().clone();
            next_authorization_change = attempt.next_authorization_change();
        };

        let WaitFrame {
            watermark: _,
            observation: mut current,
            persona: persona_id,
            habits: mut habit_seen,
            news,
        } = initial;
        // Already-due habits establish a quiet, process-local baseline. A
        // rearmed one-shot watcher therefore waits for a transition instead
        // of reporting the same unsatisfied intention forever.
        let mut last_habit_sweep = Instant::now();
        let mut current_habit_context_valid = true;

        let stdout = io::stdout();
        let mut output = stdout.lock();
        let initial_report = matches!(news, News::Report { .. });
        apply_prepared_news(
            &mut pile,
            &signer,
            persona_id,
            false,
            &news,
            "",
            &mut output,
        )?;
        if initial_report {
            return Ok(WaitOutcome {
                news_printed: true,
                view_pending: false,
                had_ready_frame: true,
            });
        }

        loop {
            if let Some(timeout) = timeout {
                if start.elapsed() >= timeout {
                    return Ok(WaitOutcome {
                        news_printed: false,
                        view_pending,
                        had_ready_frame: true,
                    });
                }
            }
            std::thread::sleep(poll);
            let sampled = pile
                .snapshot()
                .map_err(|error| anyhow!("refresh Orient wait snapshot: {error}"))?;
            let storage_changed = !sampled.changes_since(&observed_snapshot).is_empty();
            let now = sampled.instant();
            let now_secs = epoch_seconds(now);
            let authorization_changed = now < observed_snapshot.instant()
                || authorization_change_elapsed(next_authorization_change, now);
            let cooldown_elapsed = habit_seen
                .next_cooldown_at
                .is_some_and(|deadline| now_secs >= deadline);
            let periodic_condition_check = last_habit_sweep.elapsed() >= Duration::from_secs(60);
            if !storage_changed
                && !authorization_changed
                && !cooldown_elapsed
                && !periodic_condition_check
            {
                continue;
            }

            if storage_changed || authorization_changed {
                let attempt =
                    load_wait_frame(&mut pile, &sources, sampled, pile_path, persona_input).await?;
                observed_snapshot = attempt.watermark_snapshot().clone();
                next_authorization_change = attempt.next_authorization_change();
                match attempt {
                    WaitFrameLoad::Ready(candidate) => {
                        view_pending = false;
                        current_habit_context_valid = true;
                        let habit_report = render_habit_transitions(&habit_seen, &candidate.habits)
                            .unwrap_or_default();
                        let habit_fired = !habit_report.is_empty();
                        let ordinary_fired = matches!(candidate.news, News::Report { .. });
                        apply_prepared_news(
                            &mut pile,
                            &signer,
                            candidate.persona,
                            false,
                            &candidate.news,
                            &habit_report,
                            &mut output,
                        )?;
                        if habit_fired || ordinary_fired {
                            return Ok(WaitOutcome {
                                news_printed: true,
                                view_pending: false,
                                had_ready_frame: true,
                            });
                        }
                        current = candidate.observation;
                        habit_seen = candidate.habits;
                        last_habit_sweep = Instant::now();
                        continue;
                    }
                    WaitFrameLoad::Pending(pending) => {
                        view_pending = true;
                        if pending.reason == PendingWaitReason::PersonaSelection {
                            // Once a formerly resolved selector is absent or
                            // undecidable, the old persona context cannot emit
                            // new time-driven reports.
                            current_habit_context_valid = false;
                        } else if authorization_changed {
                            // A global capability boundary is only a reload
                            // trigger. It invalidates the retained Habit view
                            // only when that view's own support lost admission.
                            current_habit_context_valid &= retained_habit_support_is_admitted(
                                &current,
                                &sources,
                                &pending.watermark,
                            )?;
                        }
                    }
                }
            }

            // A frame whose persona selection is unresolved or whose Habit
            // support actually lost admission remains only a presentation
            // baseline until a readable replacement arrives.
            if !current_habit_context_valid {
                last_habit_sweep = Instant::now();
                continue;
            }

            // A newer observation awaiting required view input never replaces
            // `current`. Time-driven Habit transitions therefore remain
            // observable from the last fully readable frame.
            let current_habits = observe_habits_in_observation(&current, pile_path, now_secs)?;
            let habit_report =
                render_habit_transitions(&habit_seen, &current_habits).unwrap_or_default();
            let habit_fired = !habit_report.is_empty();
            if habit_fired {
                write_complete_report(&mut output, &habit_report, "Orient habit report")?;
            }
            habit_seen = current_habits;
            last_habit_sweep = Instant::now();
            if habit_fired {
                return Ok(WaitOutcome {
                    news_printed: true,
                    view_pending,
                    had_ready_frame: true,
                });
            }
        }
    }
    .await;
    let outcome = close_pile(pile, result)?;
    if outcome.news_printed {
        // Terse path: the News: reasons and the novel detail were already
        // printed inside the wait loop — don't re-dump the full snapshot.
        return Ok(());
    }
    if outcome.view_pending {
        if outcome.had_ready_frame {
            println!(
                "The latest pile prefix does not yet provide a readable attention view; the watcher retained its last readable snapshot."
            );
        } else {
            println!("No fully readable attention view became available before wait ended.");
        }
        return Ok(());
    }
    println!("No change detected since wait started.");
    Ok(())
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
/// goals. Semantically read-only: it publishes no authoritative collection
/// commits, though exact derived indexes may be maintained as cache exhaust.
async fn cmd_wake(
    pile_path: &Path,
    key: Option<&Path>,
    persona: Option<&str>,
    chars: usize,
    doing_limit: usize,
    todo_limit: usize,
) -> Result<()> {
    use std::fmt::Write as _;

    let signer = load_signer(pile_path, key)?;
    let mut storage = open_pile_strict(pile_path)?;
    let result = async {
        // Register every descriptor before freezing the one source watermark.
        // Maintenance may append derived lattice nodes; all reads attach only
        // after that work, from one later immutable pile snapshot.
        let sources = OrientSources::open(&mut storage, &signer, false)?;
        let memory_source = open_configured(&mut storage, MEMORY_SCOPE_ID, signer.verifying_key())?;
        let memory_collection = FactCollection::new(&mut storage, memory_source)
            .context("register maintained Memory collection")?;
        let wiki_source = open_configured(&mut storage, WIKI_SCOPE_ID, signer.verifying_key())?;
        let wiki_collection = FactCollection::new(&mut storage, wiki_source)
            .context("register maintained Wiki collection")?;
        let wiki_observed = wiki_model::observed_collection(&mut storage, signer.verifying_key())
            .context("register maintained Wiki supersession index")?;
        sources.ensure(&mut storage).await?;
        drop(storage.ensure(memory_source).await?);
        drop(storage.ensure(wiki_source).await?);
        let source_snapshot = storage
            .snapshot()
            .map_err(|error| anyhow!("freeze shared wake source snapshot: {error}"))?;
        let memory_support = source_snapshot.collection(memory_source)?.support().clone();
        let wiki_support = source_snapshot.collection(wiki_source)?.support().clone();
        drop(
            memory_collection
                .maintain_exact(&mut storage, &memory_support)
                .await
                .context("maintain Memory collection")?,
        );
        drop(
            wiki_collection
                .maintain_exact(&mut storage, &wiki_support)
                .await
                .context("maintain Wiki collection")?,
        );
        drop(
            storage
                .maintain_exact(wiki_observed, &wiki_support)
                .await
                .context("maintain Wiki supersession index")?,
        );
        let observation =
            maintain_and_observe_snapshot(&mut storage, &source_snapshot, &sources).await?;
        drop(source_snapshot);
        let memory_facts = observation
            .snapshot
            .collection_exact(memory_collection.rank9(), &memory_support)
            .context("observe maintained Memory collection")?
            .view::<FactArchive>()
            .context("attach maintained Memory collection")?;
        let wiki_facts = observation
            .snapshot
            .collection_exact(wiki_collection.rank9(), &wiki_support)
            .context("observe maintained Wiki collection")?
            .view::<FactArchive>()
            .context("attach maintained Wiki collection")?;
        let wiki_order = observation
            .snapshot
            .collection_exact(wiki_observed, &wiki_support)
            .context("observe maintained Wiki supersession index")?
            .view::<triblespace::core::collection::observed_union::ObservedIndex>()
            .context("attach maintained Wiki supersession index")?;
        let query = observation.query();
        let persona_id = persona
            .map(|input| resolve_native_persona(&query, input))
            .transpose()?;

        // Plain wake never consults Embeddings. The maintained Memory archive
        // remains shard-backed and is queried directly; opaque historical ids
        // are ordinary additive journal members.
        let cover = render_cover(
            &memory_facts,
            &TribleSet::new(),
            &observation.snapshot,
            &CoverOpts::plain(chars),
        )?;

        let beliefs = wiki_model::cover_fragments(&observation.snapshot, &wiki_facts, &wiki_order)?;
        let (goals, shown) = render_native_compass_goals(&query, doing_limit, todo_limit)?;

        let mut report = String::new();
        report.push_str(&cover);
        report.push('\n');
        writeln!(report, "Beliefs (cover):").unwrap();
        if beliefs.is_empty() {
            writeln!(report, "- None").unwrap();
        } else {
            for (title, content) in beliefs {
                writeln!(report, "- {title}").unwrap();
                for line in content.lines() {
                    writeln!(report, "    {line}").unwrap();
                }
            }
        }
        report.push('\n');
        report.push_str(&goals);

        let stdout = io::stdout();
        let mut output = stdout.lock();
        write_complete_report(&mut output, &report, "Orient wake report")?;

        if let Some(persona_id) = persona_id {
            let candidates: BTreeSet<_> = load_attention_view(&query, persona_id)?.ids().collect();
            save_presentations(
                &mut storage,
                &signer,
                persona_id,
                shown.into_iter().filter(|event| candidates.contains(event)),
            )?;
        }
        Ok(())
    }
    .await;
    close_pile(storage, result)
}

fn main() -> Result<()> {
    pollster::block_on(async_main())
}

async fn async_main() -> Result<()> {
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
        } => {
            cmd_show(
                &cli.pile,
                cli.key.as_deref(),
                cli.persona.as_deref(),
                message_limit,
                doing_limit,
                todo_limit,
            )
            .await
        }
        Command::Wait { target, poll_ms } => {
            cmd_wait(
                &cli.pile,
                cli.key.as_deref(),
                cli.persona.as_deref(),
                target,
                poll_ms,
            )
            .await
        }
        Command::Wake {
            chars,
            doing_limit,
            todo_limit,
        } => {
            cmd_wake(
                &cli.pile,
                cli.key.as_deref(),
                cli.persona.as_deref(),
                chars,
                doing_limit,
                todo_limit,
            )
            .await
        }
        Command::Poll { peek } => {
            cmd_poll(&cli.pile, cli.key.as_deref(), cli.persona.as_deref(), peek).await
        }
        Command::Baseline => {
            cmd_baseline(&cli.pile, cli.key.as_deref(), cli.persona.as_deref()).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use triblespace::core::blob::encodings::succinctarchive::{
        OrderedUniverse, SuccinctArchive, UnionArchive,
    };

    static NEXT_TEST_PILE: AtomicU64 = AtomicU64::new(0);

    struct TestPile {
        dir: PathBuf,
        path: PathBuf,
        signer: SigningKey,
    }

    impl TestPile {
        fn new() -> Self {
            // Developer shells deliberately export exact live descriptors;
            // an isolated pile must construct all of its own source
            // collections.
            for scope in [
                MESSAGE_SCOPE_ID,
                MAIL_SCOPE_ID,
                TEAMS_SCOPE_ID,
                COMPASS_SCOPE_ID,
                RELATIONS_SCOPE_ID,
                STATUS_SCOPE_ID,
                HABIT_SCOPE_ID,
                faculties::schemas::orient::DEFAULT_SCOPE_ID,
            ] {
                std::env::remove_var(faculties::collection_names::override_env_name(scope));
            }
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let sequence = NEXT_TEST_PILE.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "faculties-orient-succinct-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("test.pile");
            fs::File::create(&path).unwrap();
            let signer = SigningKey::from_bytes(&[7; 32]);
            Self { dir, path, signer }
        }
    }

    impl Drop for TestPile {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn archive(facts: &TribleSet) -> FactArchive {
        UnionArchive::new(vec![SuccinctArchive::<OrderedUniverse>::from(facts)])
    }

    fn stored_presentations(pile: &mut Pile, signer: &SigningKey, persona: Id) -> BTreeSet<Id> {
        let collection = open_configured(
            pile,
            faculties::schemas::orient::DEFAULT_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        let snapshot = pile.snapshot().unwrap();
        let (facts, _) = faculties::storage::read_fact_collection(collection, &snapshot).unwrap();
        presented_events(&facts, persona)
    }

    #[test]
    fn facts_do_not_cross_source_boundaries() {
        let person = entity! { metadata::tag: &KIND_PERSON_ID };
        let person_id = person.root().unwrap();
        let message_source = archive(person.facts());
        let relations_source = archive(&TribleSet::new());

        assert_eq!(person_anchors(&message_source), BTreeSet::from([person_id]));
        assert!(person_anchors(&relations_source).is_empty());
    }

    #[test]
    fn wait_maintenance_is_bounded_by_and_preserves_its_input_watermark() {
        pollster::block_on(wait_maintenance_is_bounded_by_and_preserves_its_input_watermark_async())
    }

    async fn wait_maintenance_is_bounded_by_and_preserves_its_input_watermark_async() {
        let fixture = TestPile::new();
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        let sources = OrientSources::open(&mut pile, &fixture.signer, true).unwrap();
        let persona = id(42);
        let profile = faculties::relations::ProfileInput {
            label: "test-persona".to_owned(),
            ..Default::default()
        };
        let (person, _, _) = relations::person_fragment(persona, profile).unwrap();
        pile.commit(sources.relations.facts.source(), &fixture.signer, person)
            .unwrap();
        let watermark = pile.snapshot_at(Epoch::from_tai_seconds(42.0)).unwrap();
        let expected_support = watermark
            .collection(sources.messages.facts.source())
            .unwrap()
            .support()
            .clone();

        // This commit arrives after the wait watermark was frozen. Another
        // maintainer also realizes that newer support before this reader runs.
        // The observation must still attach the exact support selected at its
        // own source watermark, rather than re-selecting from the later target.
        let message_collection = sources.messages.facts.source();
        pile.commit(
            message_collection,
            &fixture.signer,
            entity! { metadata::tag: &KIND_MESSAGE_ID },
        )
        .unwrap();
        drop(sources.messages.facts.maintain(&mut pile).await.unwrap());
        let attempt = load_wait_frame(
            &mut pile,
            &sources,
            watermark.clone(),
            &fixture.path,
            "test-persona",
        )
        .await
        .unwrap();
        let WaitFrameLoad::Ready(frame) = attempt else {
            panic!("resident persona payload unexpectedly pending")
        };

        let resident_after = frame
            .observation
            .snapshot
            .collection(message_collection)
            .unwrap();
        assert_eq!(frame.observation.snapshot.instant(), watermark.instant());
        assert_eq!(
            frame.observation.facts.messages.support(),
            &expected_support,
            "maintenance must derive only the source support resident at its input watermark",
        );
        assert_ne!(
            resident_after.support(), &expected_support,
            "the later observation must contain the racing source commit without pretending its target was already derived",
        );
        assert_eq!(frame.observation.facts.messages.view().iter().count(), 0);
        assert!(
            frame.watermark.changes_since(&watermark).is_empty()
                && watermark.changes_since(&frame.watermark).is_empty(),
            "the production wait frame must retain the exact input watermark",
        );
        assert!(
            !frame
                .observation
                .snapshot
                .changes_since(&frame.watermark)
                .is_empty(),
            "the post-maintenance observation must not replace its polling watermark",
        );
        pile.close().unwrap();
    }

    #[test]
    fn tags_are_normalized_for_display() {
        assert_eq!(
            render_tags(&[
                "review".to_owned(),
                "#urgent".to_owned(),
                "review".to_owned(),
            ]),
            " #urgent #review"
        );
    }

    #[test]
    fn presented_events_are_subtracted_relationally() {
        let first = id(1);
        let second = id(2);
        let mut view = AttentionView::default();
        view.insert(AttentionEvent::Message(first));
        view.insert(AttentionEvent::Mail(second));

        assert_eq!(
            view.pending(&BTreeSet::from([first]))
                .ids()
                .collect::<Vec<_>>(),
            vec![second]
        );
    }

    #[test]
    fn duration_wait_target_is_parsed_without_wall_clock_state() {
        let duration = parse_wait_target(Some(&WaitTarget::For {
            duration: "1500ms".to_owned(),
        }))
        .unwrap();
        assert_eq!(duration, Some(Duration::from_millis(1500)));
    }

    #[test]
    fn a_missing_selected_payload_is_pending() {
        let fixture = TestPile::new();
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let handle = Inline::<inlineencodings::Handle<blobencodings::UTF8String>>::new([42; 32]);

        let error = read_utf8(&snapshot, handle, "selected test body").unwrap_err();
        assert!(is_payload_pending(&error));
        pile.close().unwrap();
    }

    #[test]
    fn a_missing_persona_preserves_the_wait_watermark() {
        pollster::block_on(a_missing_persona_preserves_the_wait_watermark_async())
    }

    async fn a_missing_persona_preserves_the_wait_watermark_async() {
        let fixture = TestPile::new();
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        let sources = OrientSources::open(&mut pile, &fixture.signer, true).unwrap();
        let watermark = pile.snapshot().unwrap();

        let attempt = load_wait_frame(
            &mut pile,
            &sources,
            watermark.clone(),
            &fixture.path,
            "not-yet-resident",
        )
        .await
        .unwrap();
        let WaitFrameLoad::Pending(pending) = attempt else {
            panic!("an absent persona unexpectedly produced a readable wait frame")
        };
        assert_eq!(pending.reason, PendingWaitReason::PersonaSelection);
        assert!(
            pending.watermark.changes_since(&watermark).is_empty()
                && watermark.changes_since(&pending.watermark).is_empty(),
            "a pending production frame must preserve its input watermark",
        );
        pile.close().unwrap();
    }

    #[test]
    fn report_is_written_before_its_flush_barrier() {
        #[derive(Default)]
        struct Writer {
            bytes: Vec<u8>,
            flushed: bool,
        }

        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                assert!(!self.flushed);
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                assert_eq!(self.bytes, b"complete");
                self.flushed = true;
                Ok(())
            }
        }

        let mut writer = Writer::default();
        write_complete_report(&mut writer, "complete", "test report").unwrap();
        assert!(writer.flushed);
    }

    #[test]
    fn failed_flush_is_retryable_and_cannot_present() {
        struct FailingFlush(Vec<u8>);

        impl Write for FailingFlush {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("injected flush failure"))
            }
        }

        let fixture = TestPile::new();
        let persona = id(3);
        let event = id(4);
        let news = News::Report {
            text: "News: retry me\n".to_owned(),
            events: vec![event],
        };
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        let error = apply_prepared_news(
            &mut pile,
            &fixture.signer,
            persona,
            false,
            &news,
            "",
            &mut FailingFlush(Vec::new()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("injected flush failure"));
        assert!(stored_presentations(&mut pile, &fixture.signer, persona).is_empty());

        let mut output = Vec::new();
        apply_prepared_news(
            &mut pile,
            &fixture.signer,
            persona,
            false,
            &news,
            "",
            &mut output,
        )
        .unwrap();
        assert_eq!(output, b"News: retry me\n");
        assert_eq!(
            stored_presentations(&mut pile, &fixture.signer, persona),
            BTreeSet::from([event])
        );
        pile.close().unwrap();
    }

    #[test]
    fn peek_reports_without_presenting() {
        let fixture = TestPile::new();
        let persona = id(5);
        let event = id(6);
        let news = News::Report {
            text: "News: peek\n".to_owned(),
            events: vec![event],
        };
        let mut pile = open_pile_strict(&fixture.path).unwrap();
        let mut output = Vec::new();
        apply_prepared_news(
            &mut pile,
            &fixture.signer,
            persona,
            true,
            &news,
            "",
            &mut output,
        )
        .unwrap();

        assert_eq!(output, b"News: peek\n");
        assert!(stored_presentations(&mut pile, &fixture.signer, persona).is_empty());
        pile.close().unwrap();
    }

    #[test]
    fn baseline_is_exactly_the_current_attention_set() {
        let fixture = TestPile::new();
        let persona = id(7);
        let first = id(8);
        let second = id(9);
        let mut view = AttentionView::default();
        view.insert(AttentionEvent::Message(first));
        view.insert(AttentionEvent::Mail(second));
        let mut pile = open_pile_strict(&fixture.path).unwrap();

        save_presentations(&mut pile, &fixture.signer, persona, view.ids()).unwrap();
        let presented = stored_presentations(&mut pile, &fixture.signer, persona);
        assert_eq!(presented, BTreeSet::from([first, second]));
        assert!(view.pending(&presented).is_empty());
        pile.close().unwrap();
    }

    #[test]
    fn becoming_relevant_late_does_not_retroactively_present_an_event() {
        let event = id(10);
        let initial = AttentionView::default();
        let presented: BTreeSet<Id> = initial.ids().collect();

        let mut later = AttentionView::default();
        later.insert(AttentionEvent::Note {
            note: event,
            goal: id(11),
        });
        assert_eq!(
            later.pending(&presented).ids().collect::<Vec<_>>(),
            vec![event]
        );
    }
}
