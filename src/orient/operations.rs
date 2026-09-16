//! Reusable Orient observations and one-shot waiting, independent of argv and stdout.
//!
//! Facts, query instants and selected event IDs remain frozen while
//! exact payloads are acquired. Condition scripts run only after acquisition,
//! once per evaluation. Presentation follows successful output acceptance.

#[path = "health.rs"]
mod health;
use health::HealthSources;
#[path = "receipt_import.rs"]
mod receipt_import;

#[derive(Clone, Debug)]
pub struct Orient {
    storage: Storage,
    health_max_age: Duration,
}

#[derive(Clone, Debug)]
pub struct ShowOptions {
    pub message_limit: usize,
    pub doing_limit: usize,
    pub todo_limit: usize,
    pub evaluate_habits: bool,
}
impl Default for ShowOptions {
    fn default() -> Self {
        Self {
            message_limit: 10,
            doing_limit: 5,
            todo_limit: 5,
            evaluate_habits: true,
        }
    }
}
#[derive(Clone, Debug)]
pub struct WakeOptions {
    pub chars: usize,
    pub doing_limit: usize,
    pub todo_limit: usize,
}
impl Default for WakeOptions {
    fn default() -> Self {
        Self {
            chars: 800_000,
            doing_limit: 5,
            todo_limit: 5,
        }
    }
}
#[derive(Clone, Debug)]
pub struct WaitOptions {
    pub timeout: Option<Duration>,
    pub poll_interval: Duration,
}
impl Default for WaitOptions {
    fn default() -> Self {
        Self {
            timeout: None,
            poll_interval: Duration::from_secs(1),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaselineReceipt {
    pub persona: Id,
    pub events: usize,
}

impl Orient {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(Storage::new(pile, key))
    }
    pub fn with_storage(storage: Storage) -> Self {
        Self {
            storage,
            health_max_age: crate::schemas::swarm_health::DEFAULT_MAX_AGE,
        }
    }
    /// Choose how long this reader treats the latest health observation as current.
    /// This does not change the report facts or the reporting daemon.
    pub fn with_health_max_age(mut self, max_age: Duration) -> Self {
        self.health_max_age = max_age;
        self
    }
    /// Situational overview. Evaluates stored Habit conditions: trusted local execution.
    pub fn show(
        &self,
        persona: Option<&str>,
        options: &ShowOptions,
        out: &mut Out<'_>,
    ) -> Result<()> {
        self.storage.with_store(|pile, signer, runtime| {
            runtime.block_on(cmd_show(
                pile,
                signer,
                self.storage.path(),
                persona,
                options.message_limit,
                options.doing_limit,
                options.todo_limit,
                options.evaluate_habits,
                self.health_max_age,
                out,
            ))
        })
    }
    pub fn wake(
        &self,
        persona: Option<&str>,
        options: &WakeOptions,
        out: &mut Out<'_>,
    ) -> Result<()> {
        self.storage.with_store(|pile, signer, runtime| {
            runtime.block_on(cmd_wake(
                pile,
                signer,
                persona,
                options.chars,
                options.doing_limit,
                options.todo_limit,
                out,
            ))
        })
    }
    pub fn poll(&self, persona: &str, peek: bool, out: &mut Out<'_>) -> Result<()> {
        self.storage.with_store(|pile, signer, runtime| {
            runtime.block_on(cmd_poll(
                pile,
                signer,
                Some(persona),
                peek,
                self.health_max_age,
                out,
            ))
        })
    }
    pub fn baseline(&self, persona: &str) -> Result<BaselineReceipt> {
        self.storage.with_store(|pile, signer, runtime| {
            runtime.block_on(cmd_baseline(
                pile,
                signer,
                Some(persona),
                self.health_max_age,
            ))
        })
    }
    /// Explicit additive import of one legacy persona's resident receipts into
    /// this signing zooid's private source. It never baselines unseen events.
    pub fn import_receipts(&self, legacy_persona: &str) -> Result<usize> {
        self.storage.with_store(|pile, signer, runtime| {
            runtime.block_on(receipt_import::import(pile, signer, legacy_persona))
        })
    }
    /// One-shot wait. It returns after the first complete news report or timeout.
    /// No permanent process or competing observer is started by constructing Orient.
    pub fn wait(&self, persona: &str, options: &WaitOptions, out: &mut Out<'_>) -> Result<()> {
        self.storage.with_store(|pile, signer, runtime| {
            runtime.block_on(cmd_wait(
                pile,
                signer,
                self.storage.path(),
                Some(persona),
                options,
                self.health_max_age,
                out,
            ))
        })
    }
}

use crate::collection_names::{configured_handle, open_configured, open_exact_in};
use crate::memory_cover::{render_cover_report, CoverOpts};
use crate::out::Out;
use crate::schemas::archive::archive;
use crate::schemas::compass::DEFAULT_SCOPE_ID as COMPASS_SCOPE_ID;
use crate::schemas::compass::{board, KIND_GOAL_ID, KIND_NOTE_ID, KIND_STATUS_ID};
use crate::schemas::habit::DEFAULT_SCOPE_ID as HABIT_SCOPE_ID;
use crate::schemas::habit::{
    attrs as habit_attrs, KIND_DONE_ID as KIND_HABIT_DONE_ID, KIND_HABIT_ID,
    KIND_STATE_ID as KIND_HABIT_STATE_ID, STATE_ACTIVE, STATE_PAUSED,
};
use crate::schemas::mail::DEFAULT_SCOPE_ID as MAIL_SCOPE_ID;
use crate::schemas::mail::{
    imported as imported_mail, observation as mail_observation, projection as mail_projection,
    read as mail_read, IMPORT_RECEIVED, KIND_IMPORTED_OBSERVATION, KIND_PARSED_PROJECTION,
    KIND_POP_OBSERVATION, KIND_READ_OBSERVATION, RECIPE_RFC5322_V1,
};
use crate::schemas::memory::DEFAULT_SCOPE_ID as MEMORY_SCOPE_ID;
use crate::schemas::message::{
    local as local_message, DEFAULT_SCOPE_ID as MESSAGE_SCOPE_ID, KIND_MESSAGE_ID, KIND_READ_ID,
};
use crate::schemas::orient::{presentation, KIND_PRESENTED};
use crate::schemas::relations::{
    group as relation_group, identity as relation_identity, lifecycle as relation_lifecycle,
    profile as relation_profile, DEFAULT_SCOPE_ID as RELATIONS_SCOPE_ID, KIND_GROUP,
    KIND_GROUP_SNAPSHOT, KIND_IDENTITY_VERDICT, KIND_PERSON_ID, KIND_PERSON_LIFECYCLE,
    KIND_PERSON_PROFILE,
};
use crate::schemas::status::DEFAULT_SCOPE_ID as STATUS_SCOPE_ID;
use crate::schemas::status::{status as window_status, KIND_STATUS_UPDATE};
use crate::schemas::teams::{teams, DEFAULT_SCOPE_ID as TEAMS_SCOPE_ID};
use crate::schemas::wiki::DEFAULT_SCOPE_ID as WIKI_SCOPE_ID;
use crate::storage::FacultySnapshot;
#[cfg(test)]
use crate::storage::{open_store, runtime};
use crate::storage::{read, FactArchive, FacultyStore, Storage};
use crate::{
    clock, compass, habits, mail as mail_model, message, orient as orient_model, relations, status,
    teams as teams_model, wiki as wiki_model,
};
use anybytes::{Bytes, View};
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use triblespace::core::blob::encodings::entity_id_set::{EntityIdSet, EntityIdSetBlob};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::lww_register::{LwwIndex, LwwQuery, LwwRegisterBlob};
#[cfg(test)]
use triblespace::core::collection::Support;
use triblespace::core::collection::{
    Collection, CollectionEncoding, CollectionRealizationError, CollectionSnapshot,
    CollectionSnapshotExt, CollectionStoreExt, Cover,
};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::{
    BlobStoreGet, BlobStoreList, CapabilityProofRead, MissingBlob, StoreChanges, StoreSnapshot,
};
use triblespace::macros::{find, pattern};
use triblespace::prelude::*;

type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

// Temporary, opt-in diagnostics. These retain only existing cover roots and
// report to stderr; they never choose a view or change a retry decision.
fn trace_refresh_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("ORIENT_TRACE_REFRESH").is_some_and(|v| v == "1"))
}

fn trace_refresh_line(fields: std::fmt::Arguments<'_>) {
    use std::io::Write;
    // A closed diagnostic pipe must not turn a successful observation into a
    // failed command (or interrupt receipt publication).
    let _ = writeln!(std::io::stderr().lock(), "ORIENT_TRACE_REFRESH {fields}");
}

fn trace_refresh_call<T, E>(
    target: &'static str,
    stage: &'static str,
    operation: impl FnOnce() -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    if !trace_refresh_enabled() {
        return operation();
    }
    let started = Instant::now();
    let result = operation();
    // Attachment/view/query stages are synchronous. In one `wait` command
    // they occur in order inside the enclosing refresh begin/end pair, before
    // ordinary payload acquisition can yield to another health poll.
    trace_refresh_line(format_args!(
        "event=stage target={target:?} stage={stage} elapsed_us={} ok={}",
        started.elapsed().as_micros(),
        result.is_ok(),
    ));
    result
}

struct RefreshProbe {
    id: u64,
    scope: &'static str,
    started: Instant,
}

impl RefreshProbe {
    fn begin(
        scope: &'static str,
        sampled: &FacultySnapshot,
        previous: Option<&FacultySnapshot>,
        pending: Option<&PendingWaitFrame>,
    ) -> Option<Self> {
        if !trace_refresh_enabled() {
            return None;
        }
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let probe = Self {
            id: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            scope,
            started: Instant::now(),
        };
        let changes = previous.map(|previous| sampled.changes_since(previous));
        trace_refresh_line(format_args!(
            "event=begin refresh={} scope={} initial={} blobs={:?} records={:?} proofs={:?} wants={:?} pending={:?} exact_missing={}",
            probe.id,
            scope,
            previous.is_none(),
            changes.map(|c| c.contains(StoreChanges::BLOBS)),
            changes.map(|c| c.contains(StoreChanges::COLLECTION_RECORDS)),
            changes.map(|c| c.contains(StoreChanges::CAPABILITY_PROOFS)),
            changes.map(|c| c.contains(StoreChanges::WANTS)),
            pending.map(|p| p.reason),
            pending.is_some_and(|p| p.missing.is_some()),
        ));
        Some(probe)
    }

    fn finish(&self, outcome: &'static str) {
        trace_refresh_line(format_args!(
            "event=end refresh={} scope={} outcome={} elapsed_us={}",
            self.id,
            self.scope,
            outcome,
            self.started.elapsed().as_micros(),
        ));
    }

    fn cover<E: CollectionEncoding>(
        &self,
        target: &'static str,
        previous: Option<&Cover<E>>,
        cover: &Cover<E>,
    ) {
        trace_refresh_line(format_args!(
            "event=target refresh={} scope={} target={target:?} cover_equal={:?} cover_before={:?} cover_after={}",
            self.id,
            self.scope,
            previous.map(|old| old == cover),
            previous.map(|old| old.len()),
            cover.len(),
        ));
    }

    fn fact(&self, target: &'static str, previous: Option<&OrientFact>, current: &OrientFact) {
        self.cover(
            target,
            previous.map(|old| old.collection.cover()),
            current.collection.cover(),
        );
    }

    fn ordinary(&self, previous: Option<&OrientObservation>, current: &OrientObservation) {
        for (target, old, new) in [
            (
                "Message",
                previous.map(|p| &p.facts.messages),
                &current.facts.messages,
            ),
            ("Mail", previous.map(|p| &p.facts.mail), &current.facts.mail),
            (
                "Teams",
                previous.map(|p| &p.facts.teams),
                &current.facts.teams,
            ),
            (
                "Compass",
                previous.map(|p| &p.facts.compass),
                &current.facts.compass,
            ),
            (
                "Relations",
                previous.map(|p| &p.facts.relations),
                &current.facts.relations,
            ),
            (
                "Status",
                previous.map(|p| &p.facts.status),
                &current.facts.status,
            ),
        ] {
            self.fact(target, old, new);
        }
        if let Some(habits) = &current.facts.habits {
            self.fact(
                "Habit",
                previous.and_then(|p| p.facts.habits.as_ref()),
                habits,
            );
        }
        self.cover(
            "Orient receipts",
            previous.map(|p| p.facts.presentations.collection.cover()),
            current.facts.presentations.collection.cover(),
        );
        self.cover(
            "Compass status",
            previous.map(|p| p.compass_status_collection.cover()),
            current.compass_status_collection.cover(),
        );
    }

    fn frame(&self, previous: Option<&OrientObservation>, result: &Result<Option<WaitFrameLoad>>) {
        // Initial pending attempts have no comparison baseline. Later pending
        // frames compare to the last ready observation, not to one another;
        // never clone their prepared queries just for this diagnostic.
        trace_refresh_line(format_args!(
            "event=baseline refresh={} scope={} baseline={}",
            self.id,
            self.scope,
            if previous.is_some() {
                "last_ready"
            } else {
                "absent"
            },
        ));
        let outcome = match result {
            Ok(Some(WaitFrameLoad::Ready(frame))) => {
                self.ordinary(previous, &frame.observation);
                "ready"
            }
            Ok(Some(WaitFrameLoad::Pending(pending))) => {
                if let Some(observation) = &pending.observation {
                    self.ordinary(previous, observation);
                }
                trace_refresh_line(format_args!(
                    "event=pending refresh={} scope={} reason={:?} observation={} exact_missing={}",
                    self.id,
                    self.scope,
                    pending.reason,
                    pending.observation.is_some(),
                    pending.missing.is_some(),
                ));
                "pending"
            }
            Ok(None) => "health_deadline",
            Err(_) => "error",
        };
        self.finish(outcome);
    }
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval.try_from_inline().unwrap();
    lower
}

fn epoch_seconds(epoch: Epoch) -> i64 {
    (epoch.to_tai_duration().total_nanoseconds() / 1_000_000_000) as i64
}

/// The earlier of two optional deadlines.
fn earliest(left: Option<Epoch>, right: Option<Epoch>) -> Option<Epoch> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left <= right { left } else { right }),
        (left, right) => left.or(right),
    }
}

/// The wall-clock second at which a cooling habit in `seen` can next fall due.
fn habit_deadline(seen: &Option<HabitObservation>) -> Option<Epoch> {
    seen.as_ref()
        .and_then(|seen| seen.next_cooldown_at)
        .map(|secs| Epoch::from_tai_seconds(secs as f64))
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

/// One Orient input's authored collection and explicit query projections.
struct OrientSource {
    source: Collection<SimpleArchive>,
    #[cfg(test)]
    succinct: Collection<SuccinctArchiveBlob>,
    rank9: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
    label: &'static str,
}

impl OrientSource {
    async fn open(
        pile: &mut FacultyStore,
        signer: &SigningKey,
        scope: Id,
        label: &'static str,
    ) -> Result<Self> {
        let authority = signer.verifying_key();
        let source = if let Some(handle) = configured_handle(scope)? {
            let snapshot = pile.snapshot()?;
            read(pile, &snapshot, |reader| {
                open_exact_in(reader, scope, handle)
            })
            .await?
        } else {
            open_configured(pile, scope, authority)?
        };
        Self::register(pile, source, label)
    }

    fn register<S>(
        pile: &mut S,
        source: Collection<SimpleArchive>,
        label: &'static str,
    ) -> Result<Self>
    where
        S: CollectionStoreExt + SnapshotSource,
        S::Snapshot: BlobStoreGet + CapabilityProofRead,
    {
        let descriptors = pile
            .snapshot()
            .with_context(|| format!("freeze {label} source policy snapshot"))?;
        let policy = source
            .policy(&descriptors)
            .with_context(|| format!("read {label} source policy"))?;
        drop(descriptors);
        let succinct = pile
            .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
            .with_context(|| format!("register {label} Succinct collection"))?;
        let rank9 = pile
            .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
            .with_context(|| format!("register {label} Rank9 collection"))?;
        Ok(Self {
            source,
            #[cfg(test)]
            succinct,
            rank9,
            label,
        })
    }

    #[cfg(test)]
    fn can_maintain<S>(&self, snapshot: &S, signer: &SigningKey) -> Result<bool>
    where
        S: StoreSnapshot + BlobStoreGet + CapabilityProofRead,
    {
        let subject = signer.verifying_key();
        Ok(self
            .succinct
            .writer_is_admitted(snapshot, subject)
            .with_context(|| format!("check {} Succinct WRITE admission", self.label))?
            && self
                .rank9
                .writer_is_admitted(snapshot, subject)
                .with_context(|| format!("check {} Rank9 WRITE admission", self.label))?)
    }

    /// Test fixtures explicitly model an authorized background producer.
    #[cfg(test)]
    async fn maintain(&self, pile: &mut FacultyStore, signer: &SigningKey) -> Result<()> {
        if !self.can_maintain(&pile.snapshot()?, signer)? {
            return Ok(());
        }
        self.maintain_local(pile, signer).await
    }

    #[cfg(test)]
    async fn maintain_local(&self, pile: &mut FacultyStore, signer: &SigningKey) -> Result<()> {
        drop(
            pile.maintain(self.succinct, signer)
                .await
                .with_context(|| format!("maintain {} Succinct collection", self.label))?,
        );
        drop(
            pile.maintain(self.rank9, signer)
                .await
                .with_context(|| format!("maintain {} Rank9 collection", self.label))?,
        );
        Ok(())
    }

    fn observe(&self, snapshot: &FacultySnapshot) -> Result<OrientFact> {
        let collection =
            trace_refresh_call(self.label, "attach", || snapshot.collection(self.rank9))
                .with_context(|| format!("observe resident {} Rank9 projection", self.label))?;
        let view = trace_refresh_call(self.label, "view", || collection.view::<FactArchive>())
            .with_context(|| format!("read resident {} Rank9 projection", self.label))?;
        Ok(OrientFact { collection, view })
    }
}

/// Rich receipt facts and their compact, ordinary derived membership set.
/// The signing key is the zooid identity; routing aliases are not authority.
struct ReceiptSource {
    source: Collection<SimpleArchive>,
    ids: Collection<EntityIdSetBlob>,
}

impl ReceiptSource {
    fn register<S: CollectionStoreExt>(pile: &mut S, signer: &SigningKey) -> Result<Self> {
        let policy = crate::collection_names::private_policy(signer.verifying_key());
        let source = pile.collection(
            crate::schemas::orient::RECEIPT_COLLECTION_NAME,
            policy.clone(),
        )?;
        let ids = pile.derive::<EntityIdSetBlob>(source, presentation::event.id(), policy)?;
        Ok(Self { source, ids })
    }

    fn observe(&self, snapshot: &FacultySnapshot) -> Result<ReceiptObservation> {
        let collection = trace_refresh_call("Orient receipts", "attach", || {
            snapshot.collection(self.ids)
        })?;
        let view = trace_refresh_call("Orient receipts", "view", || {
            collection.view::<EntityIdSet>()
        })?;
        Ok(ReceiptObservation { collection, view })
    }

    #[cfg(test)]
    async fn maintain(&self, pile: &mut FacultyStore, signer: &SigningKey) -> Result<()> {
        drop(pile.maintain(self.ids, signer).await?);
        Ok(())
    }
}

struct ReceiptObservation {
    collection: CollectionSnapshot<FacultySnapshot, EntityIdSetBlob>,
    view: EntityIdSet,
}

impl ReceiptObservation {
    fn view(&self) -> &EntityIdSet {
        &self.view
    }

    fn is_current(&self, snapshot: &FacultySnapshot) -> bool {
        self.collection.is_current(snapshot)
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
    presentations: ReceiptSource,
    compass_status: Collection<LwwRegisterBlob>,
    #[cfg(test)]
    observations: std::sync::atomic::AtomicUsize,
}

impl OrientSources {
    async fn open(
        pile: &mut FacultyStore,
        signer: &SigningKey,
        include_habits: bool,
    ) -> Result<Self> {
        let authority = signer.verifying_key();
        let messages = OrientSource::open(pile, signer, MESSAGE_SCOPE_ID, "Message").await?;
        let mail = OrientSource::open(pile, signer, MAIL_SCOPE_ID, "Mail").await?;
        let teams = OrientSource::open(pile, signer, TEAMS_SCOPE_ID, "Teams").await?;
        let compass = OrientSource::open(pile, signer, COMPASS_SCOPE_ID, "Compass").await?;
        let relations = OrientSource::open(pile, signer, RELATIONS_SCOPE_ID, "Relations").await?;
        let status = OrientSource::open(pile, signer, STATUS_SCOPE_ID, "Status").await?;
        let habits = if include_habits {
            Some(OrientSource::open(pile, signer, HABIT_SCOPE_ID, "Habit").await?)
        } else {
            None
        };
        let presentations = ReceiptSource::register(pile, signer)?;
        let compass_status = compass::status_register_collection(pile, authority)?;
        Ok(Self {
            messages,
            mail,
            teams,
            compass,
            relations,
            status,
            habits,
            presentations,
            compass_status,
            #[cfg(test)]
            observations: std::sync::atomic::AtomicUsize::new(0),
        })
    }
}

struct OrientFact {
    collection: CollectionSnapshot<FacultySnapshot, Rank9AcceleratedSuccinctArchiveBlob>,
    view: FactArchive,
}

impl OrientFact {
    #[cfg(test)]
    fn support(&self) -> &Support {
        self.collection.support().expect("explicit fixture support")
    }

    fn is_current(&self, snapshot: &FacultySnapshot) -> bool {
        self.collection.is_current(snapshot)
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
    presentations: ReceiptObservation,
}

/// One coherent semantic observation. Each source stays in its own resident
/// target collection and Rank9 query view; shared vocabulary never turns those
/// authority boundaries into an accidental global fact union.
struct OrientObservation {
    /// Resident payload reader at the observation's frozen authorization
    /// instant. Exact acquisition may advance its blob residency without
    /// changing any selected fact view, support, or authorization boundary.
    snapshot: FacultySnapshot,
    facts: OrientFacts,
    compass_status: LwwQuery,
    compass_status_collection: CollectionSnapshot<FacultySnapshot, LwwRegisterBlob>,
}

impl OrientObservation {
    fn is_current(&self, snapshot: &FacultySnapshot) -> bool {
        [
            &self.facts.messages,
            &self.facts.mail,
            &self.facts.teams,
            &self.facts.compass,
            &self.facts.relations,
            &self.facts.status,
        ]
        .into_iter()
        .all(|fact| fact.is_current(snapshot))
            && self
                .facts
                .habits
                .as_ref()
                .is_none_or(|fact| fact.is_current(snapshot))
            && self.facts.presentations.is_current(snapshot)
            && self.compass_status_collection.is_current(snapshot)
    }

    fn query<'a>(&'a self, snapshot: &'a FacultySnapshot) -> OrientQuery<'a> {
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
            snapshot,
        }
    }
}

/// Explicit fixture upkeep, separate from every production reader.
#[cfg(test)]
async fn maintain_sources(
    pile: &mut FacultyStore,
    signer: &SigningKey,
    sources: &OrientSources,
) -> Result<()> {
    for source in [
        Some(&sources.messages),
        Some(&sources.mail),
        Some(&sources.teams),
        Some(&sources.compass),
        Some(&sources.relations),
        Some(&sources.status),
        sources.habits.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        source.maintain(pile, signer).await?;
    }
    sources.presentations.maintain(pile, signer).await?;
    if sources
        .compass_status
        .writer_is_admitted(&pile.snapshot()?, signer.verifying_key())
        .context("check Compass status WRITE admission")?
    {
        drop(
            pile.maintain(sources.compass_status, signer)
                .await
                .map_err(|error| anyhow!("maintain Compass status register: {error}"))?,
        );
    }
    Ok(())
}

/// Read every target collection as it actually exists at one immutable store
/// boundary and one query instant. This function performs no writes.
fn observe_sources(
    snapshot: FacultySnapshot,
    sources: &OrientSources,
) -> Result<OrientObservation> {
    let messages = sources.messages.observe(&snapshot)?;
    let mail = sources.mail.observe(&snapshot)?;
    let teams = sources.teams.observe(&snapshot)?;
    let compass = sources.compass.observe(&snapshot)?;
    let relations = sources.relations.observe(&snapshot)?;
    let status = sources.status.observe(&snapshot)?;
    let habits = sources
        .habits
        .as_ref()
        .map(|source| source.observe(&snapshot))
        .transpose()?;
    let presentations = sources.presentations.observe(&snapshot)?;
    // Positive known-winner membership is an ordinary relation: it does not
    // require the fact and register collections to have identical support.
    let status_collection = trace_refresh_call("Compass status", "attach", || {
        snapshot.collection(sources.compass_status)
    })
    .map_err(|error| anyhow!("observe Compass status register: {error}"))?;
    let status_index = trace_refresh_call("Compass status", "view", || {
        status_collection.view::<LwwIndex>()
    })
    .map_err(|error| anyhow!("read Compass status register: {error}"))?;
    let compass_status = trace_refresh_call("Compass status", "query", || status_index.query())
        .map_err(|error| anyhow!("prepare Compass status register query: {error}"))?;
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
        compass_status_collection: status_collection,
    })
}

/// Observe the resident targets at the caller's exact immutable boundary.
/// Receipt projection lag may repeat an event; it never blocks an observation.
fn observe_snapshot(
    snapshot: FacultySnapshot,
    sources: &OrientSources,
) -> Result<OrientObservation> {
    #[cfg(test)]
    sources
        .observations
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    observe_sources(snapshot, sources)
}

fn observe_current_sources(
    pile: &mut FacultyStore,
    sources: &OrientSources,
) -> Result<OrientObservation> {
    let snapshot = pile
        .snapshot()
        .map_err(|error| anyhow!("freeze shared Orient native store snapshot: {error}"))?;
    observe_snapshot(snapshot, sources)
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
    presentations: &'a EntityIdSet,
    compass_status: &'a LwwQuery,
    snapshot: &'a FacultySnapshot,
}

fn is_payload_pending(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|source| source.downcast_ref::<MissingBlob>().is_some())
}

/// An unavailable observation may be retried; authority, malformed descriptors,
/// contradictory equations, and other storage failures are not availability.
fn is_preparation_pending(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source.downcast_ref::<MissingBlob>().is_some()
            || matches!(
                source.downcast_ref::<CollectionRealizationError>(),
                Some(CollectionRealizationError::IncompleteCover { .. })
            )
    })
}

fn read_utf8(
    snapshot: &FacultySnapshot,
    handle: Inline<inlineencodings::Handle<blobencodings::UTF8String>>,
    label: &str,
) -> Result<String> {
    let unknown = Inline::<inlineencodings::Handle<blobencodings::UnknownBlob>>::new(handle.raw);
    if !snapshot
        .contains_blob(unknown)
        .map_err(|error| anyhow!("inspect {label} residency: {error}"))?
    {
        return Err(MissingBlob { handle: unknown }.into());
    }
    let value: View<str> = BlobStoreGet::get(snapshot, handle)
        .with_context(|| format!("read {label} payload {}", hex::encode(handle.raw)))?;
    Ok(value.to_string())
}

fn read_bytes(
    snapshot: &FacultySnapshot,
    handle: Inline<inlineencodings::Handle<blobencodings::RawBytes>>,
    label: &str,
) -> Result<Vec<u8>> {
    let unknown = Inline::<inlineencodings::Handle<blobencodings::UnknownBlob>>::new(handle.raw);
    if !snapshot
        .contains_blob(unknown)
        .map_err(|error| anyhow!("inspect {label} residency: {error}"))?
    {
        return Err(MissingBlob { handle: unknown }.into());
    }
    let value: Bytes = BlobStoreGet::get(snapshot, handle)
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
            query.compass_status.has(event),
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
            metadata::tag: &crate::schemas::compass::KIND_PRIORITIZE_ID,
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
            metadata::tag: &crate::schemas::compass::KIND_DEPRIORITIZE_ID,
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
    /// The second this due began: the last completion plus the cooldown, or 0
    /// for an intention never completed. It is the identity of one due event,
    /// so a fresh completion and the due that follows it are a new event.
    since: i64,
    /// Addressed to the observing persona.
    targeted: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct HabitObservation {
    due: BTreeMap<Id, DueHabit>,
    attention: BTreeMap<Id, String>,
    /// Intentions addressed to the observing persona.
    targeted: BTreeSet<Id>,
    /// Earliest completion-relative deadline that can change a cooling row.
    next_cooldown_at: Option<i64>,
}

/// Prepare only the selected Habit evaluation inputs. No scripts run here:
/// a missing payload can safely retry this read against the same frozen facts.
fn prepare_habits(
    snapshot: &FacultySnapshot,
    facts: &FactArchive,
    persona: Option<Id>,
) -> Result<(Vec<habits::HabitRow>, HabitObservation)> {
    let mut rows = Vec::new();
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
        // Attention routing is a fact on the intention, not its author. Check
        // before fetching payloads or executing any predicate. Without an
        // observer, only global intentions apply.
        let targeted = exists!(pattern!(facts, [{ habit @ habit_attrs::persona: _?target }]));
        if targeted
            && !persona.is_some_and(|persona| {
                exists!(pattern!(facts, [{ habit @ habit_attrs::persona: &persona }]))
            })
        {
            continue;
        }
        if targeted {
            observation.targeted.insert(habit);
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
        rows.push(habits::HabitRow {
            id: habit,
            label,
            condition,
            nudge,
            script,
            activation,
            completed_at,
        });
    }
    Ok((rows, observation))
}

/// Evaluate once after payload preparation succeeds. The wall clock and
/// directory stay explicit so a wait can observe temporal edges without an
/// append, and an acquisition retry cannot repeat a condition script.
fn observe_habits(
    (rows, mut observation): (Vec<habits::HabitRow>, HabitObservation),
    pile: &Path,
    now_secs: i64,
) -> Result<HabitObservation> {
    let at = habits::evaluation_dir(pile);
    for row in rows {
        let state = habits::evaluate(&row, now_secs, &at);
        match &state {
            habits::State::Due => {
                let since = row
                    .next_cooldown_at()
                    .map_err(anyhow::Error::msg)?
                    .unwrap_or(0);
                observation.due.insert(
                    row.id,
                    DueHabit {
                        label: row.label.clone(),
                        nudge: row.nudge.clone(),
                        since,
                        targeted: observation.targeted.contains(&row.id),
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

fn render_passive_habits(facts: &FactArchive, persona: Option<Id>) -> String {
    use std::fmt::Write as _;
    let superseded: BTreeSet<Id> = find!(old: Id, pattern!(facts, [{ _?new @ metadata::tag: &KIND_HABIT_ID, metadata::supersedes: ?old }])).collect();
    let mut text = String::from("Habits (passive; conditions not evaluated):\n");
    let mut count = 0;
    for (habit, label) in find!((habit: Id, label: String), pattern!(facts, [{ ?habit @ metadata::tag: &KIND_HABIT_ID, habit_attrs::label: ?label }]))
    {
        let targeted = exists!(pattern!(facts, [{ habit @ habit_attrs::persona: _?target }]));
        if targeted
            && !persona.is_some_and(|persona| {
                exists!(pattern!(facts, [{ habit @ habit_attrs::persona: &persona }]))
            })
        {
            continue;
        }
        if !superseded.contains(&habit) {
            writeln!(text, "- [{}] {label} (not evaluated)", fmt_id(habit)).unwrap();
            count += 1;
        }
    }
    if count == 0 {
        text.push_str("- None\n");
    }
    text
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
        .filter(|(id, habit)| {
            previous
                .due
                .get(*id)
                .is_none_or(|seen| seen.since != habit.since)
        })
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

fn push_due_news(out: &mut String, due: &[(Id, DueHabit)]) {
    use std::fmt::Write as _;
    for (id, habit) in due {
        writeln!(
            out,
            "News: habit [{}] became due ({})",
            fmt_id(*id),
            habit.label
        )
        .unwrap();
    }
}

fn push_due_detail(out: &mut String, due: &[(Id, DueHabit)]) {
    use std::fmt::Write as _;
    if due.is_empty() {
        return;
    }
    writeln!(out, "\nHabits newly due:").unwrap();
    for (_, habit) in due {
        writeln!(out, "- {}: {}", habit.label, habit.nudge).unwrap();
    }
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
    push_due_news(&mut out, &due);
    for (id, _) in &attention {
        writeln!(out, "News: habit [{}] needs attention", fmt_id(*id)).unwrap();
    }
    push_due_detail(&mut out, &due);
    if !attention.is_empty() {
        writeln!(out, "\nHabit attention:").unwrap();
        for (_, warning) in attention {
            writeln!(out, "- {warning}").unwrap();
        }
    }
    Some(out)
}

/// Intentions addressed to the observing persona that are already due when a
/// watcher arms. Their due instant can fall between one wait's exit and the
/// next arm, and nobody else will complete them, so they are reported at once
/// instead of joining the quiet baseline that keeps a rearmed watcher from
/// repeating every unsatisfied shared intention.
fn render_habits_due_at_arm(current: &HabitObservation) -> Option<String> {
    let owned: Vec<(Id, DueHabit)> = current
        .due
        .iter()
        .filter(|(_, habit)| habit.targeted)
        .map(|(id, habit)| (*id, habit.clone()))
        .collect();
    if owned.is_empty() {
        return None;
    }
    let mut out = String::new();
    push_due_news(&mut out, &owned);
    push_due_detail(&mut out, &owned);
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
    resolve_resident_persona(query.relations, query.snapshot, input)
}

fn resolve_resident_persona(
    facts: &FactArchive,
    snapshot: &FacultySnapshot,
    input: &str,
) -> Result<Id> {
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
    for person in person_anchors(facts) {
        let heads = profile_heads(facts, person);
        let mut matched = false;
        for handle in profile_lookup_handles(facts, person) {
            let value = read_utf8(snapshot, handle, "Relations profile selector")?;
            if relations::lookup_key(&value) == wanted {
                matched = true;
                break;
            }
        }
        if !matched || lifecycle_retired(facts, person)? == Some(true) {
            continue;
        }
        if heads.len() == 1 && lifecycle_retired(facts, person)?.is_some() {
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
    reader: &FacultySnapshot,
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CollectionSyncIssue {
    ComparisonUnavailable,
    DivergenceStalled,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CollectionSyncGroup {
    observer: String,
    peer_scope: String,
    issue: CollectionSyncIssue,
}

impl CollectionSyncGroup {
    fn reason(&self, collections: usize) -> String {
        let issue = match self.issue {
            CollectionSyncIssue::ComparisonUnavailable => {
                "collection comparisons unavailable beyond progress grace"
            }
            CollectionSyncIssue::DivergenceStalled => {
                "collections remain divergent without observed progress beyond grace"
            }
        };
        format!(
            "swarm health: observer [{}] collection sync{}: {collections} {issue}",
            self.observer, self.peer_scope
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AttentionEvent {
    Message(Id),
    Mail(Id),
    Teams(Id),
    Goal {
        event: Id,
        goal: Id,
        status: String,
    },
    Note {
        note: Id,
        goal: Id,
    },
    StatusWindow(Id),
    Health {
        event: Id,
        detail: String,
        collection_group: Option<CollectionSyncGroup>,
    },
}

impl AttentionEvent {
    fn id(&self) -> Id {
        match self {
            Self::Message(id) | Self::Mail(id) | Self::Teams(id) | Self::StatusWindow(id) => *id,
            Self::Goal { event, .. } => *event,
            Self::Note { note, .. } => *note,
            Self::Health { event, .. } => *event,
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
            Self::Health { detail, .. } => format!("swarm health: {detail}"),
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

    fn pending(&self, presented: &EntityIdSet) -> Self {
        Self {
            events: self
                .events
                .iter()
                .filter(|(event, _)| !presented.contains(**event))
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
/// durable state consists only of receipt facts in the zooid's collection.
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

fn presentation_collection_for_write(
    pile: &mut FacultyStore,
    signer: &SigningKey,
) -> Result<Collection<SimpleArchive>> {
    let collection = ReceiptSource::register(pile, signer)?.source;
    require_presentation_write(&pile.snapshot()?, collection, signer)?;
    Ok(collection)
}

fn require_presentation_write(
    snapshot: &FacultySnapshot,
    collection: Collection<SimpleArchive>,
    signer: &SigningKey,
) -> Result<()> {
    if !collection
        .writer_is_admitted(snapshot, signer.verifying_key())
        .context("check Orient presentation WRITE admission")?
    {
        bail!("Orient presentation collection requires WRITE to record Presented receipts");
    }
    Ok(())
}

fn save_presentations(
    pile: &mut FacultyStore,
    signer: &SigningKey,
    events: impl IntoIterator<Item = Id>,
) -> Result<()> {
    let fragment = orient_model::receipt_fragment(events, clock::point_now()?);
    if fragment.facts().is_empty() {
        return Ok(());
    }
    let collection = presentation_collection_for_write(pile, signer)?;
    pile.commit(collection, signer, fragment)
        .map_err(|error| anyhow!("commit Orient presentation facts: {error}"))?;
    Ok(())
}

async fn cmd_baseline(
    pile: &mut FacultyStore,
    signer: &SigningKey,
    persona: Option<&str>,
    health_max_age: Duration,
) -> Result<BaselineReceipt> {
    let Some(input) = persona else {
        bail!("baseline requires a persona (pass --persona <label-or-hex> or set $PERSONA)");
    };
    async {
        let health = HealthSources::open(pile, signer, health_max_age)?.observe(pile)?;
        let health_events = health.report().attention;
        let sources = OrientSources::open(pile, signer, false).await?;
        let observation = observe_current_sources(pile, &sources)?;
        let (persona, events) = read(pile, &observation.snapshot, |reader| {
            let query = observation.query(reader);
            let persona = resolve_native_persona(&query, input)?;
            let view = load_attention_view(&query, persona)?;
            Ok((
                persona,
                view.ids()
                    .chain(health_events.ids())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>(),
            ))
        })
        .await?;
        save_presentations(pile, signer, events.iter().copied())?;
        Ok(BaselineReceipt {
            persona,
            events: events.len(),
        })
    }
    .await
}

async fn cmd_show(
    pile: &mut FacultyStore,
    signer: &SigningKey,
    pile_path: &Path,
    persona: Option<&str>,
    message_limit: usize,
    doing_limit: usize,
    todo_limit: usize,
    evaluate_habits: bool,
    health_max_age: Duration,
    output: &mut Out<'_>,
) -> Result<()> {
    use std::fmt::Write as _;

    async {
        let health_sources = HealthSources::open(pile, signer, health_max_age)?;
        let health = health_sources.observe(pile)?;
        let health_report = health.report();
        write_complete_report(output, &health_report.text, "local swarm health overview")?;
        if let Some(input) = persona {
            match health.persona(input) {
                Ok(_) => save_presentations(pile, signer, health_report.attention.ids())?,
                Err(error) if is_payload_pending(&error) || is_persona_not_found(&error) => {}
                Err(error) => return Err(error),
            }
        }
        let sources = OrientSources::open(pile, signer, true).await?;
        let observation = observe_current_sources(pile, &sources)?;
        let instant = observation.snapshot.instant();
        let (persona_id, messages, mail, habits, goals, window_status, shown) =
            read(pile, &observation.snapshot, |reader| {
                let query = observation.query(reader);
                let persona_id = persona
                    .map(|input| resolve_native_persona(&query, input))
                    .transpose()?;
                let (messages, message_events) =
                    render_native_messages(&query, persona_id, message_limit)?;
                let (mail, mail_events) = render_native_mail(&query, persona_id, message_limit)?;
                let habits = if evaluate_habits {
                    Some(prepare_habits(
                        reader,
                        query
                            .habits
                            .expect("Show opens the Habit source collection"),
                        persona_id,
                    )?)
                } else {
                    None
                };
                let (goals, goal_events) =
                    render_native_compass_goals(&query, doing_limit, todo_limit)?;
                let (window_status, status_events) = render_window_status(&query)?;
                let shown = match persona_id {
                    Some(persona) => {
                        let candidates: BTreeSet<_> =
                            load_attention_view(&query, persona)?.ids().collect();
                        message_events
                            .into_iter()
                            .chain(mail_events)
                            .chain(goal_events)
                            .chain(status_events)
                            .filter(|event| candidates.contains(event))
                            .collect::<Vec<_>>()
                    }
                    None => Vec::new(),
                };
                Ok((
                    persona_id,
                    messages,
                    mail,
                    habits,
                    goals,
                    window_status,
                    shown,
                ))
            })
            .await?;
        let habits = match habits {
            Some(habits) => {
                render_native_habits(&observe_habits(habits, pile_path, epoch_seconds(instant))?)
            }
            None => render_passive_habits(
                observation
                    .facts
                    .habits
                    .as_ref()
                    .expect("Show opens Habits")
                    .view(),
                persona_id,
            ),
        };

        let mut report = String::new();
        writeln!(report, "Orient").unwrap();
        report.push_str(&messages);
        report.push_str(&mail);
        report.push('\n');
        report.push_str(&habits);
        report.push_str(&goals);
        report.push_str(&window_status);

        write_complete_report(output, &report, "Orient overview")?;

        if persona_id.is_some() {
            save_presentations(pile, signer, shown)?;
        }
        Ok(())
    }
    .await
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
    Quiet,
    Report { text: String, events: Vec<Id> },
}

fn write_complete_report(output: &mut Out<'_>, report: &str, description: &str) -> Result<()> {
    // An accepted complete native Part is the delivery boundary. The CLI sink
    // flushes it before returning. A collecting frontend accepts it into its
    // response; this is deliberately not a remote receipt or processing ack.
    output
        .text(report)
        .with_context(|| format!("deliver complete {description}"))
}

fn prepare_news_once(query: &OrientQuery<'_>, persona_id: Id) -> Result<News> {
    let candidates = load_attention_view(query, persona_id)?;
    let pending = candidates.pending(query.presentations);
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
}

fn apply_prepared_news(
    pile: &mut FacultyStore,
    signer: &SigningKey,
    peek: bool,
    prepared: &News,
    prefix: &str,
    output: &mut Out<'_>,
) -> Result<()> {
    match prepared {
        News::Report { text, events } => {
            // Do not deliver consuming news that this principal cannot record.
            // Target production authority is independent and may be remote.
            let receipt = if !peek && !events.is_empty() {
                Some((
                    presentation_collection_for_write(pile, signer)?,
                    orient_model::receipt_fragment(events.iter().copied(), clock::point_now()?),
                ))
            } else {
                None
            };
            let mut complete = String::with_capacity(prefix.len() + text.len());
            complete.push_str(prefix);
            complete.push_str(text);
            write_complete_report(output, &complete, "Orient news report")?;
            if let Some((collection, fragment)) = receipt {
                pile.commit(collection, signer, fragment)
                    .map_err(|error| anyhow!("commit Orient presentation facts: {error}"))?;
            }
        }
        News::Quiet => {
            if !prefix.is_empty() {
                write_complete_report(output, prefix, "Orient habit report")?;
            }
        }
    }
    Ok(())
}

/// One-shot `wait`: acquire selected payloads, report pending attention
/// tersely, and only then record presentation. No provider means quiet pending,
/// not acknowledgment of a body the recipient never saw.
async fn cmd_poll(
    pile: &mut FacultyStore,
    signer: &SigningKey,
    persona: Option<&str>,
    peek: bool,
    health_max_age: Duration,
    output: &mut Out<'_>,
) -> Result<()> {
    let Some(input) = persona else {
        bail!("poll requires a persona (pass --persona <label-or-hex> or set $PERSONA)");
    };
    async {
        let mut health = HealthSources::open(pile, signer, health_max_age)?;
        if health.poll(pile, signer, input, peek, output)?.0 {
            return Ok(());
        }
        let sources = OrientSources::open(pile, signer, false).await?;
        let observation = match observe_current_sources(pile, &sources) {
            Ok(observation) => observation,
            Err(error) if is_preparation_pending(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        let prepared = read(pile, &observation.snapshot, |reader| {
            let query = observation.query(reader);
            let persona = resolve_native_persona(&query, input)?;
            prepare_news_once(&query, persona)
        })
        .await;
        let news = match prepared {
            Ok(prepared) => prepared,
            Err(error) if is_payload_pending(&error) || is_persona_not_found(&error) => {
                return Ok(())
            }
            Err(error) => return Err(error),
        };
        apply_prepared_news(pile, signer, peek, &news, "", output)?;
        Ok(())
    }
    .await
}

struct WaitOutcome {
    news_printed: bool,
    view_pending: bool,
    had_ready_frame: bool,
}

struct WaitFrame {
    watermark: FacultySnapshot,
    observation: OrientObservation,
    persona: Id,
    habits: HabitObservation,
    news: News,
}

struct PendingWaitFrame {
    watermark: FacultySnapshot,
    reason: PendingWaitReason,
    /// An exact failed read can make progress when a provider appears even
    /// though the pile prefix is unchanged. Projection absence cannot.
    missing: Option<MissingBlob>,
    /// Keep the actual immutable targets selected before payload acquisition.
    /// Retrying a body or persona label must not replace these target views.
    observation: Option<OrientObservation>,
    /// The persona this observation resolved, once it did.
    persona: Option<Id>,
    /// Habit readiness depends on the Habit source alone: the observation
    /// evaluated at this watermark once persona and Habit payloads were
    /// readable, kept across pure body retries so no condition script reruns,
    /// and cleared whenever persona or preparation is pending again.
    habits: Option<HabitObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingWaitReason {
    /// A required descriptor or selected input cannot yet be read.
    Preparation,
    /// The persona selector cannot yet be resolved in this observation.
    PersonaSelection,
    /// The persona is settled, but another selected payload is unavailable.
    Payload,
}

impl PendingWaitFrame {
    fn awaiting_view(watermark: FacultySnapshot, reason: PendingWaitReason) -> Self {
        Self {
            watermark,
            reason,
            missing: None,
            observation: None,
            persona: None,
            habits: None,
        }
    }
}

fn wait_storage_changed(sampled: &FacultySnapshot, previous: &FacultySnapshot) -> bool {
    let changes = sampled.changes_since(previous);
    // Blob changes stay conservative: a new fallback occurrence can repair a
    // previously unusable member even when no new content hash was added.
    // Generic authority has no clock expiry, and WANT is not a query input.
    changes.contains(StoreChanges::BLOBS)
        || changes.contains(StoreChanges::COLLECTION_RECORDS)
        || changes.contains(StoreChanges::CAPABILITY_PROOFS)
}

fn pending_blob(error: &anyhow::Error) -> Option<MissingBlob> {
    error
        .chain()
        .find_map(|source| source.downcast_ref::<MissingBlob>().copied())
}

enum WaitFrameLoad {
    Pending(PendingWaitFrame),
    Ready(WaitFrame),
}

impl WaitFrameLoad {
    fn watermark_snapshot(&self) -> &FacultySnapshot {
        match self {
            Self::Pending(pending) => &pending.watermark,
            Self::Ready(frame) => &frame.watermark,
        }
    }
}

async fn load_wait_frame(
    pile: &mut FacultyStore,
    sources: &OrientSources,
    snapshot: FacultySnapshot,
    pending: &mut Option<PendingWaitFrame>,
    pile_path: &Path,
    persona_input: &str,
) -> Result<WaitFrameLoad> {
    // The observation and polling baseline are the same immutable prefix.
    // Later selected-payload acquisition cannot swallow a concurrent append.
    let instant = snapshot.instant();
    let observation = match observe_snapshot(snapshot.clone(), sources) {
        Ok(observation) => observation,
        Err(error) if is_preparation_pending(&error) => {
            let mut fresh =
                PendingWaitFrame::awaiting_view(snapshot, PendingWaitReason::Preparation);
            fresh.missing = pending_blob(&error);
            return Ok(WaitFrameLoad::Pending(fresh));
        }
        Err(error) => return Err(error),
    };
    // The fresh frame lives in the caller's slot while its payloads are read,
    // so a boundary that cancels the read keeps what the read had already
    // resolved: the persona and the habit observation.
    let mut fresh = PendingWaitFrame::awaiting_view(snapshot, PendingWaitReason::Payload);
    fresh.observation = Some(observation);
    let slot = pending.insert(fresh);
    match resume_wait_payloads(pile, slot, pile_path, persona_input, instant).await? {
        Some(frame) => {
            pending.take();
            Ok(WaitFrameLoad::Ready(frame))
        }
        None => Ok(WaitFrameLoad::Pending(
            pending.take().expect("pending payload frame"),
        )),
    }
}

/// Retry only the selected immutable inputs. This borrows the cached view so a
/// health deadline can cancel the network read without losing that selection.
async fn resume_wait_payloads<S>(
    pile: &mut S,
    pending: &mut PendingWaitFrame,
    pile_path: &Path,
    persona_input: &str,
    instant: Epoch,
) -> Result<Option<WaitFrame>>
where
    S: SnapshotSource<Snapshot = FacultySnapshot>
        + triblespace::core::repo::async_store::AsyncBlobStoreAcquire,
{
    let observation = pending
        .observation
        .as_mut()
        .expect("payload continuation retains its selected views");
    let (persona, reader) = match read(pile, &observation.snapshot, |reader| {
        let persona = resolve_native_persona(&observation.query(reader), persona_input)?;
        Ok((persona, reader.clone()))
    })
    .await
    {
        Ok(persona) => persona,
        Err(error) if is_payload_pending(&error) || is_persona_not_found(&error) => {
            pending.reason = PendingWaitReason::PersonaSelection;
            pending.missing = pending_blob(&error);
            // A different persona would select different intentions.
            pending.persona = None;
            pending.habits = None;
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    observation.snapshot = reader;
    pending.persona = Some(persona);
    // Habit readiness comes first and depends on the Habit source alone.
    // Evaluate it once at this watermark; a pure body retry reuses it and
    // reruns no condition script.
    if pending.habits.is_none() {
        let prepared = read(pile, &observation.snapshot, |reader| {
            let query = observation.query(reader);
            let habits = prepare_habits(
                reader,
                query
                    .habits
                    .expect("Wait opens the Habit source collection"),
                Some(persona),
            )?;
            Ok((reader.clone(), habits))
        })
        .await;
        let (reader, habits) = match prepared {
            Ok(prepared) => prepared,
            Err(error) if is_payload_pending(&error) => {
                pending.reason = PendingWaitReason::Payload;
                pending.missing = pending_blob(&error);
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        // Retain acquired bytes for later timer-driven Habit evaluation. The
        // selected target views and polling watermark remain untouched.
        observation.snapshot = reader;
        pending.habits = Some(observe_habits(habits, pile_path, epoch_seconds(instant))?);
    }
    // News readiness depends on the directed-news bodies. A missing body
    // keeps the frame pending without discarding the habit observation.
    let prepared = read(pile, &observation.snapshot, |reader| {
        let query = observation.query(reader);
        let news = prepare_news_once(&query, persona)?;
        Ok((reader.clone(), news))
    })
    .await;
    let (reader, news) = match prepared {
        Ok(prepared) => prepared,
        Err(error) if is_payload_pending(&error) => {
            pending.reason = PendingWaitReason::Payload;
            pending.missing = pending_blob(&error);
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    observation.snapshot = reader;
    let habits = pending
        .habits
        .take()
        .expect("habit readiness precedes news readiness");
    Ok(Some(WaitFrame {
        watermark: pending.watermark.clone(),
        observation: pending
            .observation
            .take()
            .expect("selected payloads are ready"),
        persona,
        habits,
        news,
    }))
}

fn observe_habits_in_observation(
    observation: &OrientObservation,
    pile_path: &Path,
    now_secs: i64,
    persona: Id,
) -> Result<HabitObservation> {
    let facts = observation
        .facts
        .habits
        .as_ref()
        .expect("a wait observation includes Habit");
    observe_habits(
        prepare_habits(&observation.snapshot, facts.view(), Some(persona))?,
        pile_path,
        now_secs,
    )
}

/// Selected payload acquisition yields at a local health
/// validity boundary. Completed cache work remains reusable when the caller
/// re-observes health before resuming this attention view.
async fn load_wait_frame_before_health_deadline(
    pile: &mut FacultyStore,
    sources: &OrientSources,
    mut snapshot: FacultySnapshot,
    pending: &mut Option<PendingWaitFrame>,
    pile_path: &Path,
    persona_input: &str,
    next_health_change: Option<Epoch>,
) -> Result<Option<WaitFrameLoad>> {
    let unchanged = pending.as_ref().is_some_and(|pending| {
        pending.observation.as_ref().map_or_else(
            || !wait_storage_changed(&snapshot, &pending.watermark),
            |observation| observation.is_current(&snapshot),
        )
    });
    if unchanged {
        let cached = pending.as_mut().expect("unchanged pending frame exists");
        if cached.observation.is_some() {
            // A selected observation whose payload read failed or was cut at
            // a boundary is retried; the persona and habits it already
            // resolved are reused.
            let ready = tokio::select! {
                boundary = health::deadline(next_health_change) => {
                    boundary?;
                    return Ok(None);
                }
                frame = resume_wait_payloads(
                    pile, cached, pile_path, persona_input, snapshot.instant(),
                ) => frame?,
            };
            return Ok(Some(match ready {
                Some(frame) => WaitFrameLoad::Ready(frame),
                None => WaitFrameLoad::Pending(pending.take().expect("pending payload")),
            }));
        }
        if let Some(missing) = cached.missing {
            // An exact preparation dependency can also become available from
            // a new provider. Retry that handle, not the entire preparation.
            let acquired = tokio::select! {
                boundary = health::deadline(next_health_change) => {
                    boundary?;
                    return Ok(None);
                }
                bytes = pile.acquire(missing.handle) => bytes?,
            };
            if acquired.is_none() {
                return Ok(Some(WaitFrameLoad::Pending(
                    pending.take().expect("pending preparation dependency"),
                )));
            }
            // No observation was selected yet. Retry preparation at the
            // prefix containing the acquired dependency, not the old snapshot
            // which necessarily still lacks it.
            snapshot = pile.snapshot()?;
        } else {
            // Nothing in this outcome performs I/O: absent projection records
            // or an absent persona require a different store observation.
            return Ok(Some(WaitFrameLoad::Pending(
                pending.take().expect("unchanged pending observation"),
            )));
        }
    }
    tokio::select! {
        boundary = health::deadline(next_health_change) => {
            boundary?;
            Ok(None)
        }
        frame = load_wait_frame(pile, sources, snapshot, pending, pile_path, persona_input) => frame.map(Some),
    }
}

async fn cmd_wait(
    pile: &mut FacultyStore,
    signer: &SigningKey,
    pile_path: &Path,
    persona: Option<&str>,
    options: &WaitOptions,
    health_max_age: Duration,
    output: &mut Out<'_>,
) -> Result<()> {
    let Some(persona_input) = persona else {
        bail!("wait requires a persona (pass --persona <label-or-hex> or set $PERSONA)");
    };
    let timeout = options.timeout;
    let result: Result<WaitOutcome> = async {
        let mut health = HealthSources::open(pile, signer, health_max_age)?;
        let poll = options.poll_interval.max(Duration::from_millis(1));
        let start = Instant::now();
        let mut view_pending;
        let mut next_health_change;
        let mut pending_frame: Option<PendingWaitFrame> = None;
        // While directed news is still pending, the persona's own clocks keep
        // running against the pending observation. Their baseline and sweep
        // cadence mirror the ready frame's.
        let mut pending_habits_seen: Option<HabitObservation> = None;
        let mut last_pending_sweep = Instant::now();

        let sources = loop {
            let (fired, deadline) = health.poll(pile, signer, persona_input, false, output)?;
            next_health_change = deadline;
            if fired {
                return Ok(WaitOutcome {
                    news_printed: true,
                    view_pending: false,
                    had_ready_frame: true,
                });
            }
            tokio::select! {
                boundary = health::deadline(next_health_change) => { boundary?; }
                sources = OrientSources::open(pile, signer, true) => break sources?,
            }
        };

        // Keep the prefix which selected these target views as the polling
        // watermark, including while their lazy payload reads are pending.
        let initial = loop {
            let (fired, deadline) = health.poll(pile, signer, persona_input, false, output)?;
            next_health_change = deadline;
            if fired {
                return Ok(WaitOutcome {
                    news_printed: true,
                    view_pending: false,
                    had_ready_frame: true,
                });
            }
            let sampled = pile.snapshot()?;
            let probe = RefreshProbe::begin(
                "ordinary",
                &sampled,
                pending_frame.as_ref().map(|pending| &pending.watermark),
                pending_frame.as_ref(),
            );
            // A pending body fetch yields at the next habit deadline as well
            // as at the health boundary, so the clock gets its turn. Before a
            // habit baseline exists, a selected observation's first payload
            // read gets one poll interval, so a stalled body cannot keep the
            // persona's clocks unobserved; a pending preparation keeps the
            // health boundary alone.
            let boundary = match habit_deadline(&pending_habits_seen) {
                Some(deadline) => earliest(next_health_change, Some(deadline)),
                None if pending_frame
                    .as_ref()
                    .is_none_or(|pending| pending.observation.is_some()) =>
                {
                    let first_read = Epoch::from_tai_seconds(
                        clock::now()?.to_tai_seconds() + poll.as_secs_f64(),
                    );
                    earliest(next_health_change, Some(first_read))
                }
                None => next_health_change,
            };
            let attempt = load_wait_frame_before_health_deadline(
                pile,
                &sources,
                sampled,
                &mut pending_frame,
                pile_path,
                persona_input,
                boundary,
            )
            .await;
            if let Some(probe) = &probe {
                probe.frame(None, &attempt);
            }
            if let Some(attempt) = attempt? {
                match attempt {
                    WaitFrameLoad::Ready(frame) => {
                        pending_frame = None;
                        view_pending = false;
                        break frame;
                    }
                    WaitFrameLoad::Pending(pending) => {
                        if matches!(
                            pending.reason,
                            PendingWaitReason::PersonaSelection | PendingWaitReason::Preparation
                        ) {
                            // A different persona or observation would select
                            // different intentions: no habit context to keep.
                            pending_habits_seen = None;
                        }
                        pending_frame = Some(pending);
                    }
                }
            }
            // Whether the read returned pending or was cut at the boundary,
            // the retained frame is what the persona's clocks run against.
            if let Some(pending) = pending_frame.as_ref() {
                if let (Some(persona), Some(habits), Some(observation)) = (
                    pending.persona,
                    pending.habits.as_ref(),
                    pending.observation.as_ref(),
                ) {
                    match &pending_habits_seen {
                        None => {
                            // An owned intention already due when the watcher
                            // arms is reported at once, even while a news body
                            // is still pending.
                            let owned_due = render_habits_due_at_arm(habits).unwrap_or_default();
                            pending_habits_seen = Some(habits.clone());
                            last_pending_sweep = Instant::now();
                            if !owned_due.is_empty() {
                                write_complete_report(output, &owned_due, "Orient habit report")?;
                                return Ok(WaitOutcome {
                                    news_printed: true,
                                    view_pending: true,
                                    had_ready_frame: false,
                                });
                            }
                        }
                        Some(seen) => {
                            let now_secs = epoch_seconds(clock::now()?);
                            let cooldown_elapsed = seen
                                .next_cooldown_at
                                .is_some_and(|deadline| now_secs >= deadline);
                            let periodic_condition_check =
                                last_pending_sweep.elapsed() >= Duration::from_secs(60);
                            if cooldown_elapsed || periodic_condition_check {
                                let current_habits = observe_habits_in_observation(
                                    observation,
                                    pile_path,
                                    now_secs,
                                    persona,
                                )?;
                                let habit_report = render_habit_transitions(seen, &current_habits)
                                    .unwrap_or_default();
                                pending_habits_seen = Some(current_habits);
                                last_pending_sweep = Instant::now();
                                if !habit_report.is_empty() {
                                    // A habit-only report acknowledges no news.
                                    write_complete_report(
                                        output,
                                        &habit_report,
                                        "Orient habit report",
                                    )?;
                                    return Ok(WaitOutcome {
                                        news_printed: true,
                                        view_pending: true,
                                        had_ready_frame: false,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            view_pending = true;

            if timeout.is_some_and(|timeout| start.elapsed() >= timeout) {
                return Ok(WaitOutcome {
                    news_printed: false,
                    view_pending,
                    had_ready_frame: false,
                });
            }
            let boundary = earliest(next_health_change, habit_deadline(&pending_habits_seen));
            let sleep =
                health::until(boundary, clock::now()?).map_or(poll, |delay| delay.min(poll));
            let sleep = timeout.map_or(sleep, |timeout| {
                sleep.min(timeout.saturating_sub(start.elapsed()))
            });
            tokio::time::sleep(sleep).await;
            // The next poll only retries an exact failed payload read unless
            // storage changed. Provider appearance does not require rebuilding
            // an otherwise identical collection observation.
        };

        let mut observed_snapshot = initial.watermark.clone();

        let WaitFrame {
            watermark: _,
            observation: mut current,
            persona: mut persona_id,
            habits: mut habit_seen,
            news,
        } = initial;
        // Already-due habits establish a quiet, process-local baseline. A
        // rearmed one-shot watcher therefore waits for a transition instead
        // of reporting the same unsatisfied intention forever. An intention
        // addressed to this persona is the exception: its due instant can
        // fall between one wait's exit and the next arm, and nobody else will
        // complete it, so it is reported at once.
        let mut last_habit_sweep = Instant::now();
        let mut current_habit_context_valid = true;

        let initial_report = matches!(news, News::Report { .. });
        // With a baseline taken while news was pending, what fell due since is
        // news at this frame and the fresh observation is kept; without one,
        // an owned intention already due is reported at arm.
        let arm_report = match pending_habits_seen.take() {
            Some(seen) => render_habit_transitions(&seen, &habit_seen),
            None => render_habits_due_at_arm(&habit_seen),
        }
        .unwrap_or_default();
        let arm_fired = !arm_report.is_empty();
        apply_prepared_news(pile, signer, false, &news, &arm_report, output)?;
        if initial_report || arm_fired {
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
            let sleep = health::until(next_health_change, clock::now()?)
                .map_or(poll, |delay| delay.min(poll));
            let sleep = timeout.map_or(sleep, |timeout| {
                sleep.min(timeout.saturating_sub(start.elapsed()))
            });
            tokio::time::sleep(sleep).await;
            let (fired, deadline) = health.poll(pile, signer, persona_input, false, output)?;
            next_health_change = deadline;
            if fired {
                return Ok(WaitOutcome {
                    news_printed: true,
                    view_pending: false,
                    had_ready_frame: true,
                });
            }
            let sampled = pile
                .snapshot()
                .map_err(|error| anyhow!("refresh Orient wait snapshot: {error}"))?;
            let storage_changed = !current.is_current(&sampled);
            let probe = RefreshProbe::begin(
                "ordinary",
                &sampled,
                Some(&observed_snapshot),
                pending_frame.as_ref(),
            );
            let now = sampled.instant();
            let now_secs = epoch_seconds(now);
            let cooldown_elapsed = habit_seen
                .next_cooldown_at
                .is_some_and(|deadline| now_secs >= deadline);
            let periodic_condition_check = last_habit_sweep.elapsed() >= Duration::from_secs(60);
            if !storage_changed && !view_pending && !cooldown_elapsed && !periodic_condition_check {
                if let Some(probe) = &probe {
                    probe.finish("unchanged");
                }
                continue;
            }

            if storage_changed || view_pending {
                let attempt = load_wait_frame_before_health_deadline(
                    pile,
                    &sources,
                    sampled,
                    &mut pending_frame,
                    pile_path,
                    persona_input,
                    next_health_change,
                )
                .await;
                if let Some(probe) = &probe {
                    probe.frame(Some(&current), &attempt);
                }
                let Some(attempt) = attempt? else {
                    view_pending = true;
                    continue;
                };
                observed_snapshot = attempt.watermark_snapshot().clone();
                match attempt {
                    WaitFrameLoad::Ready(candidate) => {
                        pending_frame = None;
                        view_pending = false;
                        current_habit_context_valid = true;
                        let habit_report = render_habit_transitions(&habit_seen, &candidate.habits)
                            .unwrap_or_default();
                        let habit_fired = !habit_report.is_empty();
                        let ordinary_fired = matches!(candidate.news, News::Report { .. });
                        apply_prepared_news(
                            pile,
                            signer,
                            false,
                            &candidate.news,
                            &habit_report,
                            output,
                        )?;
                        if habit_fired || ordinary_fired {
                            return Ok(WaitOutcome {
                                news_printed: true,
                                view_pending: false,
                                had_ready_frame: true,
                            });
                        }
                        current = candidate.observation;
                        persona_id = candidate.persona;
                        habit_seen = candidate.habits;
                        last_habit_sweep = Instant::now();
                        continue;
                    }
                    WaitFrameLoad::Pending(pending) => {
                        view_pending = true;
                        if matches!(
                            pending.reason,
                            PendingWaitReason::PersonaSelection | PendingWaitReason::Preparation
                        ) {
                            // Once a formerly resolved selector is absent or
                            // undecidable, the old persona context cannot emit
                            // new time-driven reports.
                            current_habit_context_valid = false;
                        }
                        pending_frame = Some(pending);
                    }
                }
            } else if let Some(probe) = &probe {
                probe.finish("clock_only");
            }

            // A frame whose persona selection is unresolved remains only a
            // presentation baseline until a readable replacement arrives.
            if !current_habit_context_valid {
                last_habit_sweep = Instant::now();
                continue;
            }
            if !cooldown_elapsed && !periodic_condition_check {
                continue;
            }

            // A newer observation awaiting required view input never replaces
            // `current`. Time-driven Habit transitions therefore remain
            // observable from the last fully readable frame.
            let current_habits =
                observe_habits_in_observation(&current, pile_path, now_secs, persona_id)?;
            let habit_report =
                render_habit_transitions(&habit_seen, &current_habits).unwrap_or_default();
            let habit_fired = !habit_report.is_empty();
            if habit_fired {
                write_complete_report(output, &habit_report, "Orient habit report")?;
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
    let outcome = result?;
    if outcome.news_printed {
        // Terse path: the News: reasons and the novel detail were already
        // printed inside the wait loop — don't re-dump the full snapshot.
        return Ok(());
    }
    if outcome.view_pending {
        if outcome.had_ready_frame {
            output.line(format!(
                "The latest pile prefix does not yet provide a readable attention view; the watcher retained its last readable snapshot."
            ))?;
        } else {
            output.line(format!(
                "No fully readable attention view became available before wait ended."
            ))?;
        }
        return Ok(());
    }
    output.line(format!("No change detected since wait started."))?;
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
/// goals. A supplied persona records shown attention events after output
/// acceptance; previous presentation history does not filter this overview.
async fn cmd_wake(
    storage: &mut FacultyStore,
    signer: &SigningKey,
    persona: Option<&str>,
    chars: usize,
    doing_limit: usize,
    todo_limit: usize,
    output: &mut Out<'_>,
) -> Result<()> {
    use std::fmt::Write as _;

    async {
        // Register descriptors before freezing one resident query boundary.
        // Background workers alone produce the projections selected here.
        let sources = OrientSources::open(storage, signer, false).await?;
        let memory_collection =
            OrientSource::open(storage, signer, MEMORY_SCOPE_ID, "Memory").await?;
        let wiki_collection = OrientSource::open(storage, signer, WIKI_SCOPE_ID, "Wiki").await?;
        let wiki_latest = wiki_model::latest_collection(storage, signer.verifying_key())
            .context("register Wiki supersession index")?;
        let snapshot = storage
            .snapshot()
            .map_err(|error| anyhow!("freeze shared wake query instant: {error}"))?;
        // Wake renders the requested overview, not unseen news. Its output
        // does not depend on prior Presented facts; recording what this wake
        // shows afterward must not impose a historical receipt-read barrier.
        let observation = observe_snapshot(snapshot, &sources)?;
        let memory_facts = observation
            .snapshot
            .collection(memory_collection.rank9)
            .context("observe resident Memory collection")?
            .view::<FactArchive>()
            .context("attach resident Memory collection")?;
        let wiki_facts = observation
            .snapshot
            .collection(wiki_collection.rank9)
            .context("observe resident Wiki collection")?
            .view::<FactArchive>()
            .context("attach resident Wiki collection")?;
        let wiki_order = observation
            .snapshot
            .collection(wiki_latest)
            .context("observe resident Wiki supersession index")?
            .view::<triblespace::core::collection::latest::LatestIndex>()
            .context("attach resident Wiki supersession index")?;
        let persona_id = read(storage, &observation.snapshot, |reader| {
            let query = observation.query(reader);
            persona
                .map(|input| resolve_native_persona(&query, input))
                .transpose()
        })
        .await?;
        // Prepare each independent section separately. A missing Wiki or
        // Compass attachment must not repeat memory-cover planning/diagnostics.
        // Plain wake never consults Embeddings; these facts stay shard-backed.
        let cover = read(storage, &observation.snapshot, |reader| {
            render_cover_report(
                &memory_facts,
                &TribleSet::new(),
                reader,
                &CoverOpts::plain(chars),
            )
        })
        .await?;
        let beliefs = read(storage, &observation.snapshot, |reader| {
            wiki_model::cover_fragments(reader, &wiki_facts, &wiki_order)
        })
        .await?;
        let (goals, shown) = read(storage, &observation.snapshot, |reader| {
            let query = observation.query(reader);
            let (goals, shown) = render_native_compass_goals(&query, doing_limit, todo_limit)?;
            let shown = match persona_id {
                Some(persona) => {
                    let candidates: BTreeSet<_> =
                        load_attention_view(&query, persona)?.ids().collect();
                    shown
                        .into_iter()
                        .filter(|event| candidates.contains(event))
                        .collect::<Vec<_>>()
                }
                None => Vec::new(),
            };

            Ok((goals, shown))
        })
        .await?;

        let mut report = cover.text;
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

        write_complete_report(output, &report, "Orient wake report")?;
        if !cover.diagnostics.is_empty() {
            output.line(format!(
                "Memory diagnostics (outside the charged cover text):\n{}",
                cover.diagnostics.join("\n")
            ))?;
        }

        if persona_id.is_some() {
            save_presentations(storage, signer, shown)?;
        }
        Ok(())
    }
    .await
}

#[cfg(test)]
mod tests {
    fn due_habit(label: &str, since: i64, targeted: bool) -> DueHabit {
        DueHabit {
            label: label.to_owned(),
            nudge: "do it".to_owned(),
            since,
            targeted,
        }
    }

    #[test]
    fn a_fresh_completion_makes_the_next_due_a_new_event() {
        let habit = Id::new([7; 16]).unwrap();
        let mut previous = HabitObservation::default();
        previous.due.insert(habit, due_habit("tick", 100, true));
        let mut current = HabitObservation::default();
        current.due.insert(habit, due_habit("tick", 100, true));
        assert!(
            newly_due(&previous, &current).is_empty(),
            "the same due event is not news twice"
        );
        current.due.insert(habit, due_habit("tick", 1300, true));
        assert_eq!(
            newly_due(&previous, &current).len(),
            1,
            "the due after a fresh completion is a new event"
        );
    }

    #[test]
    fn only_owned_due_habits_are_reported_when_the_watcher_arms() {
        let owned = Id::new([8; 16]).unwrap();
        let shared = Id::new([9; 16]).unwrap();
        let mut armed = HabitObservation::default();
        armed
            .due
            .insert(shared, due_habit("stranded-work", 0, false));
        assert!(
            render_habits_due_at_arm(&armed).is_none(),
            "an untargeted due intention stays a quiet baseline"
        );
        armed.due.insert(owned, due_habit("cc-tick", 1300, true));
        let report = render_habits_due_at_arm(&armed).expect("an owned clock is reported at arm");
        assert!(report.contains(&format!(
            "News: habit [{}] became due (cc-tick)",
            fmt_id(owned)
        )));
        assert!(!report.contains("stranded-work"));
    }

    use super::super::cli::{parse_wait_target, WaitTarget};
    use super::*;
    use std::fs;
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use triblespace::core::blob::encodings::entity_id_set;
    use triblespace::core::blob::encodings::succinctarchive::{
        OrderedUniverse, SuccinctArchive, UnionArchive,
    };
    use triblespace::core::blob::{Blob, IntoBlob, TryFromBlob};
    use triblespace::core::collection::{
        records::empty_metadata_handle, CollectionCommit, CollectionRecord, CollectionStore,
    };
    use triblespace::core::repo::{StorageClose, WantRead};

    fn write_report_to_writer(
        writer: &mut impl Write,
        report: &str,
        description: &str,
    ) -> Result<()> {
        let mut emit = |part| {
            let crate::out::Part::Text { text } = part else {
                bail!("expected report text")
            };
            writer.write_all(text.as_bytes())?;
            writer.flush()?;
            Ok(())
        };
        write_complete_report(&mut Out::new(&mut emit), report, description)
    }
    fn apply_news_to_writer(
        pile: &mut FacultyStore,
        signer: &SigningKey,
        _persona: Id,
        peek: bool,
        news: &News,
        prefix: &str,
        writer: &mut impl Write,
    ) -> Result<()> {
        let mut emit = |part| {
            let crate::out::Part::Text { text } = part else {
                bail!("expected report text")
            };
            writer.write_all(text.as_bytes())?;
            writer.flush()?;
            Ok(())
        };
        apply_prepared_news(pile, signer, peek, news, prefix, &mut Out::new(&mut emit))
    }

    static NEXT_TEST_PILE: AtomicU64 = AtomicU64::new(0);

    struct TestPile {
        dir: PathBuf,
        path: PathBuf,
        signer: SigningKey,
    }

    impl TestPile {
        fn new() -> Self {
            // Run isolated tests with collection override environment cleared by the runner.
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

    #[test]
    fn nonwriter_observes_lagging_external_input_and_retains_own_receipts() {
        pollster::block_on(async {
            let fixture = TestPile::new();
            let reader_key = SigningKey::from_bytes(&[73; 32]);
            let mut pile = open_store(&fixture.path).unwrap();
            // External Relations are owned elsewhere; notification receipts
            // remain this local writer's collection.
            let mut sources = OrientSources::open(&mut pile, &reader_key, false)
                .await
                .unwrap();
            sources.relations =
                OrientSource::open(&mut pile, &fixture.signer, RELATIONS_SCOPE_ID, "Relations")
                    .await
                    .unwrap();
            let known = id(71);
            let pending = id(72);
            let person = |person, label: &str| {
                relations::person_fragment(
                    person,
                    crate::relations::ProfileInput {
                        label: label.to_owned(),
                        ..Default::default()
                    },
                )
                .unwrap()
                .0
            };
            pile.commit(
                sources.relations.source,
                &fixture.signer,
                person(known, "resident-reader"),
            )
            .unwrap();
            sources
                .relations
                .maintain(&mut pile, &fixture.signer)
                .await
                .unwrap();
            pile.commit(
                sources.relations.source,
                &fixture.signer,
                person(pending, "pending-reader"),
            )
            .unwrap();
            let before = pile.snapshot().unwrap();
            let records: Vec<_> = before.records().unwrap().map(Result::unwrap).collect();
            let observation = observe_current_sources(&mut pile, &sources).unwrap();
            assert_eq!(
                person_anchors(observation.facts.relations.view()),
                BTreeSet::from([known]),
            );
            assert_eq!(
                pile.snapshot()
                    .unwrap()
                    .records()
                    .unwrap()
                    .map(Result::unwrap)
                    .collect::<Vec<_>>(),
                records,
                "a nonwriter read must not publish equations for lagging external input",
            );

            let event = id(74);
            save_presentations(&mut pile, &reader_key, [event]).unwrap();
            sources
                .presentations
                .maintain(&mut pile, &reader_key)
                .await
                .unwrap();
            let next = observe_current_sources(&mut pile, &sources).unwrap();
            assert!(next.facts.presentations.view().contains(event));
            assert_eq!(
                person_anchors(next.facts.relations.view()),
                BTreeSet::from([known])
            );

            // External upkeep makes the new input visible to the next read.
            sources
                .relations
                .maintain(&mut pile, &fixture.signer)
                .await
                .unwrap();
            let caught_up = observe_current_sources(&mut pile, &sources).unwrap();
            assert_eq!(
                person_anchors(caught_up.facts.relations.view()),
                BTreeSet::from([known, pending]),
            );
            pile.close().unwrap();
        });
    }

    #[test]
    fn unprojected_receipts_do_not_block_passive_observation() {
        pollster::block_on(async {
            let fixture = TestPile::new();
            let reader_key = SigningKey::from_bytes(&[73; 32]);
            let mut pile = open_store(&fixture.path).unwrap();
            let mut sources = OrientSources::open(&mut pile, &reader_key, false)
                .await
                .unwrap();
            sources.presentations = ReceiptSource::register(&mut pile, &fixture.signer).unwrap();
            pile.commit(
                sources.presentations.source,
                &fixture.signer,
                orient_model::receipt_fragment([id(76)], clock::point_now().unwrap()),
            )
            .unwrap();
            let before = pile.snapshot().unwrap();
            let records: Vec<_> = before.records().unwrap().map(Result::unwrap).collect();
            let observation = observe_current_sources(&mut pile, &sources).unwrap();
            assert!(observation.facts.presentations.view().is_empty());
            assert_eq!(
                pile.snapshot()
                    .unwrap()
                    .records()
                    .unwrap()
                    .map(Result::unwrap)
                    .collect::<Vec<_>>(),
                records,
                "reading an unprojected receipt never performs upkeep or blocks",
            );
            assert!(observation.snapshot.wants().unwrap().next().is_none());
            sources
                .presentations
                .maintain(&mut pile, &fixture.signer)
                .await
                .unwrap();
            let ready = observe_current_sources(&mut pile, &sources).unwrap();
            assert!(ready.facts.presentations.view().contains(id(76)));
            assert!(observation.facts.presentations.view().is_empty());
            pile.close().unwrap();
        });
    }

    #[test]
    fn one_shot_receipt_projection_lag_allows_repeats_until_maintenance() {
        pollster::block_on(async {
            let fixture = TestPile::new();
            let reader = SigningKey::from_bytes(&[73; 32]);
            let mut pile = open_store(&fixture.path).unwrap();
            let sources = OrientSources::open(&mut pile, &reader, false)
                .await
                .unwrap();
            let persona = id(77);
            let event = id(78);
            let news = News::Report {
                text: "News: one delivery\n".to_owned(),
                events: vec![event],
            };
            let mut output = Vec::new();
            apply_news_to_writer(&mut pile, &reader, persona, false, &news, "", &mut output)
                .unwrap();
            assert_eq!(output, b"News: one delivery\n");

            // A fresh one-shot sees the same signer-owned receipt descriptors.
            // Its passive view may repeat an event until background upkeep
            // publishes the projection; there is no whole-ledger barrier.
            let restarted = OrientSources::open(&mut pile, &reader, false)
                .await
                .unwrap();
            assert_eq!(restarted.presentations.source, sources.presentations.source);
            assert_eq!(restarted.presentations.ids, sources.presentations.ids);
            assert!(restarted
                .presentations
                .ids
                .writer_is_admitted(&pile.snapshot().unwrap(), reader.verifying_key())
                .unwrap());
            let before = pile.snapshot().unwrap();
            let records: Vec<_> = before.records().unwrap().map(Result::unwrap).collect();
            let lagging = observe_current_sources(&mut pile, &restarted).unwrap();
            let mut attention = AttentionView::default();
            attention.insert(AttentionEvent::Message(event));
            assert_eq!(
                attention
                    .pending(lagging.facts.presentations.view())
                    .ids()
                    .collect::<Vec<_>>(),
                vec![event],
                "a repeat is accepted while the receipt projection is behind",
            );
            assert_eq!(
                pile.snapshot()
                    .unwrap()
                    .records()
                    .unwrap()
                    .map(Result::unwrap)
                    .collect::<Vec<_>>(),
                records,
                "observation cannot publish the missing projection",
            );

            restarted
                .presentations
                .maintain(&mut pile, &reader)
                .await
                .unwrap();
            let ready = observe_current_sources(&mut pile, &restarted).unwrap();
            assert!(attention
                .pending(ready.facts.presentations.view())
                .is_empty());
            assert!(!attention
                .pending(lagging.facts.presentations.view())
                .is_empty());

            // Routing aliases do not split one zooid's receipt authority.
            save_presentations(&mut pile, &reader, [id(80)]).unwrap();
            let aliases = ReceiptSource::register(&mut pile, &reader).unwrap();
            assert_eq!(aliases.source, restarted.presentations.source);
            assert_eq!(aliases.ids, restarted.presentations.ids);
            assert!(!observe_current_sources(&mut pile, &restarted)
                .unwrap()
                .facts
                .presentations
                .view()
                .contains(id(80)));
            aliases.maintain(&mut pile, &reader).await.unwrap();
            let refreshed = observe_current_sources(&mut pile, &restarted).unwrap();
            assert_eq!(
                refreshed
                    .facts
                    .presentations
                    .view()
                    .iter()
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([event, id(80)]),
            );
            pile.close().unwrap();
        });
    }

    #[test]
    fn persona_wake_ignores_unrelated_historical_receipt_projection_lag() {
        runtime().unwrap().block_on(async {
            let fixture = TestPile::new();
            let mut pile = open_store(&fixture.path).unwrap();
            let sources = OrientSources::open(&mut pile, &fixture.signer, false)
                .await
                .unwrap();
            let persona = id(86);
            let prior_event = id(87);
            let (person, _, _) = relations::person_fragment(
                persona,
                relations::ProfileInput {
                    label: "wake-reader".to_owned(),
                    ..Default::default()
                },
            )
            .unwrap();
            pile.commit(sources.relations.source, &fixture.signer, person)
                .unwrap();
            let (goal, goal_id) = compass::goal_fragment(
                "a resident goal for this wake",
                vec!["wake-reader".to_owned()],
                None,
                clock::point_now().unwrap(),
            )
            .unwrap();
            pile.commit(sources.compass.source, &fixture.signer, goal)
                .unwrap();
            pile.commit(
                sources.presentations.source,
                &fixture.signer,
                orient_model::receipt_fragment([prior_event], clock::point_now().unwrap()),
            )
            .unwrap();
            maintain_sources(&mut pile, &fixture.signer, &sources)
                .await
                .unwrap();

            // An unrelated historical receipt record arrives without its
            // archive. Its absence cannot hide the existing projection.
            let cold = orient_model::receipt_fragment([id(89)], clock::point_now().unwrap());
            let cold = IntoBlob::<SimpleArchive>::to_blob(cold.facts().clone());
            let arriving = CollectionCommit::sign(
                &fixture.signer,
                sources.presentations.source.handle(),
                inlineencodings::Handle::<SimpleArchive>::to_hash(cold.get_handle()),
                empty_metadata_handle(),
            );
            pile.insert(CollectionRecord::Commit(arriving)).unwrap();
            let sources = OrientSources::open(&mut pile, &fixture.signer, false)
                .await
                .unwrap();
            let before = sources
                .presentations
                .observe(&pile.snapshot().unwrap())
                .unwrap();
            assert_eq!(
                before.view().iter().collect::<BTreeSet<_>>(),
                BTreeSet::from([prior_event]),
            );
            assert!(!before.view().contains(id(89)));
            assert!(!pile
                .snapshot()
                .unwrap()
                .contains_blob(cold.get_handle())
                .unwrap());

            let mut report = String::new();
            cmd_wake(
                &mut pile,
                &fixture.signer,
                Some("wake-reader"),
                0,
                5,
                5,
                &mut Out::new(&mut |part| {
                    let crate::out::Part::Text { text } = part else {
                        bail!("expected wake text")
                    };
                    report.push_str(&text);
                    Ok(())
                }),
            )
            .await
            .unwrap();
            assert!(report.contains("Beliefs (cover):"));
            assert!(report.contains("a resident goal for this wake"));

            // The accepted overview still publishes its shown goal receipt.
            // Making that new receipt visible does not fetch the historical
            // gap; all ordinary receipt readers accept the resident set.
            sources
                .presentations
                .maintain(&mut pile, &fixture.signer)
                .await
                .unwrap();
            let snapshot = pile.snapshot().unwrap();
            let after = sources.presentations.observe(&snapshot).unwrap();
            assert_eq!(
                after.view().iter().collect::<BTreeSet<_>>(),
                BTreeSet::from([prior_event, goal_id]),
            );
            assert!(observe_current_sources(&mut pile, &sources)
                .unwrap()
                .facts
                .presentations
                .view()
                .contains(goal_id));
            assert!(!snapshot.contains_blob(cold.get_handle()).unwrap());
            assert!(snapshot.wants().unwrap().next().is_none());
            assert!(pile.health().started_at.is_none());
            pile.close().unwrap();
        });
    }

    #[test]
    fn compact_receipt_targets_do_not_need_original_payloads_or_metadata() {
        pollster::block_on(async {
            let fixture = TestPile::new();
            let copy = TestPile::new();
            let mut pile = open_store(&fixture.path).unwrap();
            let sources = OrientSources::open(&mut pile, &fixture.signer, false)
                .await
                .unwrap();
            let mut omitted = BTreeSet::new();
            for event in [id(82), id(83)] {
                let commit = pile
                    .commit(
                        sources.presentations.source,
                        &fixture.signer,
                        orient_model::receipt_fragment([event], clock::point_now().unwrap()),
                    )
                    .unwrap();
                omitted.insert(commit.data().raw);
                omitted.insert(commit.metadata().raw);
            }
            sources
                .presentations
                .maintain(&mut pile, &fixture.signer)
                .await
                .unwrap();
            let before = pile.snapshot().unwrap();
            let mut copied = open_store(&copy.path).unwrap();
            for info in before.blobs() {
                let info = info.unwrap();
                if !omitted.contains(&info.handle.raw) {
                    let blob: Blob<blobencodings::UnknownBlob> =
                        BlobStoreGet::get(&before, info.handle).unwrap();
                    copied.put::<blobencodings::UnknownBlob, _>(blob).unwrap();
                }
            }
            for record in before.records().unwrap() {
                copied.insert(record.unwrap()).unwrap();
            }
            let snapshot = copied.snapshot().unwrap();
            for handle in omitted {
                assert!(!snapshot
                    .contains_blob(
                        Inline::<inlineencodings::Handle<blobencodings::UnknownBlob>>::new(handle)
                    )
                    .unwrap());
            }
            let records: Vec<_> = snapshot.records().unwrap().map(Result::unwrap).collect();
            let observation = observe_current_sources(&mut copied, &sources).unwrap();
            let observed = &observation.facts.presentations;
            assert_eq!(
                observed.view().iter().collect::<BTreeSet<_>>(),
                BTreeSet::from([id(82), id(83)])
            );
            assert!(observation.snapshot.wants().unwrap().next().is_none());
            assert_eq!(
                observation
                    .snapshot
                    .records()
                    .unwrap()
                    .map(Result::unwrap)
                    .collect::<Vec<_>>(),
                records,
                "warm target reads do not reconstruct historical source records",
            );
            copied.close().unwrap();
            pile.close().unwrap();
        });
    }

    #[test]
    fn receipt_write_denial_is_not_pending_availability() {
        let fixture = TestPile::new();
        let stranger = SigningKey::from_bytes(&[73; 32]);
        let mut pile = open_store(&fixture.path).unwrap();
        let source = ReceiptSource::register(&mut pile, &fixture.signer)
            .unwrap()
            .source;
        let snapshot = pile.snapshot().unwrap();
        let error = require_presentation_write(&snapshot, source, &stranger).unwrap_err();
        assert!(format!("{error:#}").contains("requires WRITE"));
        assert!(!is_preparation_pending(&error));
        assert!(snapshot.records().unwrap().next().is_none());
        pile.close().unwrap();
    }

    #[test]
    fn cold_receipts_do_not_fetch_history_while_persona_is_pending() {
        let fixture = TestPile::new();
        let mut pile = open_store(&fixture.path).unwrap();
        let source = ReceiptSource::register(&mut pile, &fixture.signer)
            .unwrap()
            .source;
        let fragment = orient_model::receipt_fragment([id(85)], clock::point_now().unwrap());
        let blob = IntoBlob::<SimpleArchive>::to_blob(fragment.facts().clone());
        let commit = CollectionCommit::sign(
            &fixture.signer,
            source.handle(),
            inlineencodings::Handle::<SimpleArchive>::to_hash(blob.get_handle()),
            empty_metadata_handle(),
        );
        pile.insert(CollectionRecord::Commit(commit)).unwrap();
        let options = WaitOptions {
            timeout: Some(Duration::from_millis(25)),
            poll_interval: Duration::from_secs(1),
        };
        let mut text = String::new();
        let mut emit = |part| {
            let crate::out::Part::Text { text: part } = part else {
                bail!("expected text")
            };
            text.push_str(&part);
            Ok(())
        };
        let started = Instant::now();
        runtime().unwrap().block_on(async {
            tokio::time::timeout(
                Duration::from_secs(2),
                cmd_wait(
                    &mut pile,
                    &fixture.signer,
                    &fixture.path,
                    Some("waiting-reader"),
                    &options,
                    Duration::from_secs(180),
                    &mut Out::new(&mut emit),
                ),
            )
            .await
            .expect("pending persona selection must honor its timeout without fetching history")
            .unwrap();
        });
        assert!(started.elapsed() >= options.timeout.unwrap());
        assert!(text.contains("No fully readable attention view"));
        let snapshot = pile.snapshot().unwrap();
        assert!(!snapshot.contains_blob(blob.get_handle()).unwrap());
        assert!(snapshot.wants().unwrap().next().is_none());
        assert_eq!(
            snapshot
                .records()
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>(),
            vec![CollectionRecord::Commit(commit)],
        );
        pile.close().unwrap();
    }

    #[test]
    fn receipt_refresh_is_scoped_to_target_progress() {
        pollster::block_on(async {
            let fixture = TestPile::new();
            let mut pile = open_store(&fixture.path).unwrap();
            let sources = OrientSources::open(&mut pile, &fixture.signer, true)
                .await
                .unwrap();
            let observation = observe_current_sources(&mut pile, &sources).unwrap();
            let receipt = orient_model::receipt_fragment([id(87)], clock::point_now().unwrap());
            let bytes = IntoBlob::<SimpleArchive>::to_blob(receipt.facts().clone());
            let commit = CollectionCommit::sign(
                &fixture.signer,
                sources.presentations.source.handle(),
                inlineencodings::Handle::<SimpleArchive>::to_hash(bytes.get_handle()),
                empty_metadata_handle(),
            );
            pile.insert(CollectionRecord::Commit(commit)).unwrap();
            let cold = pile.snapshot().unwrap();
            assert!(!cold.contains_blob(bytes.get_handle()).unwrap());
            assert!(
                observation.is_current(&cold),
                "an unprojected source record does not change the selected receipt set"
            );

            let unrelated = pile
                .collection(
                    "unrelated-refresh-fixture",
                    crate::collection_names::private_policy(fixture.signer.verifying_key()),
                )
                .unwrap();
            pile.commit(
                unrelated,
                &fixture.signer,
                entity! { metadata::name: "elsewhere" },
            )
            .unwrap();
            assert!(
                observation.is_current(&pile.snapshot().unwrap()),
                "unrelated records do not invalidate the selected attention inputs"
            );

            // Explicit fixture arrival/upkeep changes only the receipt target.
            pile.put::<SimpleArchive, _>(bytes).unwrap();
            sources
                .presentations
                .maintain(&mut pile, &fixture.signer)
                .await
                .unwrap();
            let advanced = pile.snapshot().unwrap();
            assert!(!observation.is_current(&advanced));
            assert!(!observation.facts.presentations.is_current(&advanced));
            for fact in [
                &observation.facts.messages,
                &observation.facts.mail,
                &observation.facts.teams,
                &observation.facts.compass,
                &observation.facts.relations,
                &observation.facts.status,
                observation.facts.habits.as_ref().unwrap(),
            ] {
                assert!(fact.is_current(&advanced));
            }
            let refreshed = observe_snapshot(advanced, &sources).unwrap();
            assert!(refreshed.facts.presentations.view().contains(id(87)));
            assert!(observation.facts.presentations.view().is_empty());
            assert!(refreshed.snapshot.wants().unwrap().next().is_none());
            assert!(pile.health().started_at.is_none());
            pile.close().unwrap();
        });
    }

    #[test]
    fn acquired_preparation_descriptor_is_used_by_the_same_retry() {
        runtime().unwrap().block_on(async {
            let fixture = TestPile::new();
            let mut pile = open_store(&fixture.path).unwrap();
            // A preparation boundary can predate the descriptor's arrival.
            // Register the real sources afterward; no network mock is needed
            // because exact acquisition also handles newly resident bytes.
            let watermark = pile.snapshot().unwrap();
            let sources = OrientSources::open(&mut pile, &fixture.signer, true)
                .await
                .unwrap();
            let descriptor = Inline::<inlineencodings::Handle<blobencodings::UnknownBlob>>::new(
                sources.messages.rank9.handle().raw,
            );
            let resident = pile.snapshot().unwrap();
            assert!(!watermark.contains_blob(descriptor).unwrap());
            assert!(resident.contains_blob(descriptor).unwrap());
            assert!(sources.messages.observe(&watermark).is_err());
            assert_eq!(sources.observations.load(Ordering::Relaxed), 0);

            let mut preparation =
                PendingWaitFrame::awaiting_view(watermark.clone(), PendingWaitReason::Preparation);
            preparation.missing = Some(MissingBlob { handle: descriptor });
            let mut pending = Some(preparation);
            let persona = id(89);
            let attempt = load_wait_frame_before_health_deadline(
                &mut pile,
                &sources,
                watermark.clone(),
                &mut pending,
                &fixture.path,
                &fmt_id(persona),
                None,
            )
            .await
            .unwrap()
            .expect("no health deadline interrupts the preparation retry");
            let WaitFrameLoad::Ready(frame) = attempt else {
                panic!("successful descriptor acquisition must prepare from its resident prefix")
            };
            assert_eq!(frame.persona, persona);
            assert!(matches!(frame.news, News::Quiet));
            assert_eq!(sources.observations.load(Ordering::Relaxed), 1);
            assert!(frame.watermark.contains_blob(descriptor).unwrap());
            assert!(frame
                .observation
                .snapshot
                .contains_blob(descriptor)
                .unwrap());
            assert!(!watermark.contains_blob(descriptor).unwrap());
            assert!(frame.watermark.changes_since(&resident).is_empty());
            let after = pile.snapshot().unwrap();
            assert!(after.changes_since(&resident).is_empty());
            assert!(after.wants().unwrap().next().is_none());
            assert!(pile.health().started_at.is_none());
            pile.close().unwrap();
        });
    }

    #[test]
    fn unchanged_pending_persona_reuses_the_scoped_observation() {
        runtime().unwrap().block_on(async {
            let fixture = TestPile::new();
            let mut pile = open_store(&fixture.path).unwrap();
            let sources = OrientSources::open(&mut pile, &fixture.signer, true)
                .await
                .unwrap();
            let unrelated = pile
                .collection(
                    "unrelated-pending-fixture",
                    crate::collection_names::private_policy(fixture.signer.verifying_key()),
                )
                .unwrap();
            let mut pending = None;
            for iteration in 0..6 {
                if iteration == 1 {
                    pile.commit(
                        unrelated,
                        &fixture.signer,
                        entity! { metadata::name: "elsewhere" },
                    )
                    .unwrap();
                }
                let sampled = pile.snapshot().unwrap();
                let attempt = load_wait_frame_before_health_deadline(
                    &mut pile,
                    &sources,
                    sampled,
                    &mut pending,
                    &fixture.path,
                    "waiting-reader",
                    None,
                )
                .await
                .unwrap()
                .unwrap();
                let WaitFrameLoad::Pending(frame) = attempt else {
                    panic!("an absent persona must remain pending")
                };
                assert_eq!(frame.reason, PendingWaitReason::PersonaSelection);
                assert!(frame.missing.is_none());
                assert!(
                    frame.observation.is_some(),
                    "retain the exact selected views"
                );
                pending = Some(frame);
            }
            assert_eq!(sources.observations.load(Ordering::Relaxed), 1);

            let persona = id(86);
            let (person, _, _) = relations::person_fragment(
                persona,
                relations::ProfileInput {
                    label: "waiting-reader".to_owned(),
                    ..Default::default()
                },
            )
            .unwrap();
            pile.commit(sources.relations.source, &fixture.signer, person)
                .unwrap();
            sources
                .relations
                .maintain(&mut pile, &fixture.signer)
                .await
                .unwrap();
            let sampled = pile.snapshot().unwrap();
            let attempt = load_wait_frame_before_health_deadline(
                &mut pile,
                &sources,
                sampled,
                &mut pending,
                &fixture.path,
                "waiting-reader",
                None,
            )
            .await
            .unwrap()
            .unwrap();
            let WaitFrameLoad::Ready(frame) = attempt else {
                panic!("newly maintained persona must complete the pending selection")
            };
            assert_eq!(frame.persona, persona);
            assert_eq!(sources.observations.load(Ordering::Relaxed), 2);
            assert!(pile.health().started_at.is_none());
            pile.close().unwrap();
        });
    }

    #[test]
    fn only_incomplete_realization_is_preparation_pending() {
        assert!(is_preparation_pending(
            &CollectionRealizationError::IncompleteCover {
                missing: Vec::new(),
                unsupported_members: Vec::new(),
            }
            .into()
        ));
        for error in [
            CollectionRealizationError::InvalidCover("bad support".to_owned()),
            CollectionRealizationError::Resolution("conflicting equations".to_owned()),
            CollectionRealizationError::Stalled { cover: Vec::new() },
        ] {
            assert!(!is_preparation_pending(&error.into()));
        }
    }

    #[test]
    fn habit_targets_select_before_loading_payloads() {
        let fixture = TestPile::new();
        let mut pile = open_store(&fixture.path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let habit = id(11); // An opaque, not intrinsically derived entity id.
        let owner = id(12);
        let other = id(13);
        let absent = habits::TextHandle::new([14; 32]);
        let absent_script = habits::ScriptHandle::new([15; 32]);
        let fragment = entity! { ExclusiveId::force_ref(&habit) @
            metadata::tag: &KIND_HABIT_ID,
            habit_attrs::label: "other-persona-clock",
            habit_attrs::condition: absent,
            habit_attrs::nudge: absent,
            habit_attrs::script: absent_script,
            habit_attrs::persona: &owner,
        };
        let facts = archive(fragment.facts());
        for observer in [None, Some(other)] {
            let (rows, attention) = prepare_habits(&snapshot, &facts, observer).unwrap();
            assert!(rows.is_empty());
            assert!(attention.attention.is_empty());
            assert!(!render_passive_habits(&facts, observer).contains("other-persona-clock"));
        }
        assert!(prepare_habits(&snapshot, &facts, Some(owner)).is_err());
        assert!(render_passive_habits(&facts, Some(owner)).contains("other-persona-clock"));
        pile.close().unwrap();
    }

    #[test]
    fn habit_targets_are_exact_sets_and_omission_is_global() {
        let fixture = TestPile::new();
        let mut pile = open_store(&fixture.path).unwrap();
        let collection = open_configured(
            &mut pile,
            crate::schemas::habit::DEFAULT_SCOPE_ID,
            fixture.signer.verifying_key(),
        )
        .unwrap();
        let gpt = id(16);
        let cc = id(17);
        let mut fragment = Fragment::empty();
        let mut ids = Vec::new();
        for (label, targets) in [
            ("global", vec![]),
            ("gpt", vec![gpt]),
            ("cc", vec![cc]),
            ("both", vec![cc, gpt]),
        ] {
            let (definition, id) =
                habits::habit_fragment(label, "every 1h", "do it", None, &[], &targets).unwrap();
            fragment += definition;
            ids.push(id);
        }
        let facts = archive(fragment.facts());
        pile.commit(collection, &fixture.signer, fragment).unwrap();
        let snapshot = pile.snapshot().unwrap();
        for (observer, expected) in [
            (None, BTreeSet::from([ids[0]])),
            (Some(gpt), BTreeSet::from([ids[0], ids[1], ids[3]])),
            (Some(cc), BTreeSet::from([ids[0], ids[2], ids[3]])),
            (Some(id(18)), BTreeSet::from([ids[0]])),
        ] {
            let prepared = prepare_habits(&snapshot, &facts, observer).unwrap();
            let observed = observe_habits(prepared, &fixture.path, 100).unwrap();
            assert_eq!(
                observed.due.keys().copied().collect::<BTreeSet<_>>(),
                expected
            );
        }
        pile.close().unwrap();
    }

    #[test]
    fn wait_initial_and_timer_paths_do_not_execute_other_personas_predicates() {
        pollster::block_on(async {
            let fixture = TestPile::new();
            let mut pile = open_store(&fixture.path).unwrap();
            let sources = OrientSources::open(&mut pile, &fixture.signer, true)
                .await
                .unwrap();
            let gpt = id(19);
            let cc = id(20);
            for (persona, label) in [(gpt, "gpt"), (cc, "cc")] {
                let (person, _, _) = relations::person_fragment(
                    persona,
                    crate::relations::ProfileInput {
                        label: label.to_owned(),
                        ..Default::default()
                    },
                )
                .unwrap();
                pile.commit(sources.relations.source, &fixture.signer, person)
                    .unwrap();
            }
            let (clock, global) =
                habits::habit_fragment("global-clock", "every 1h", "global due", None, &[], &[])
                    .unwrap();
            let (done, _) = habits::completion_fragment(
                global,
                clock::point(Epoch::from_tai_seconds(99.0)).unwrap(),
            )
            .unwrap();
            let (other, cc_habit) = habits::habit_fragment(
                "cc-clock",
                "when printf x >> other-invocations",
                "cc due",
                None,
                &[],
                &[cc],
            )
            .unwrap();
            pile.commit(
                sources.habits.as_ref().unwrap().source,
                &fixture.signer,
                clock + done + other,
            )
            .unwrap();
            maintain_sources(&mut pile, &fixture.signer, &sources)
                .await
                .unwrap();
            let watermark = pile.snapshot_at(Epoch::from_tai_seconds(100.0)).unwrap();
            let WaitFrameLoad::Ready(frame) = load_wait_frame(
                &mut pile,
                &sources,
                watermark,
                &mut None,
                &fixture.path,
                "gpt",
            )
            .await
            .unwrap() else {
                panic!("complete local inputs must be ready")
            };
            assert_eq!(frame.persona, gpt);
            assert!(frame.habits.due.is_empty());
            let marker = fixture.dir.join("other-invocations");
            assert!(!marker.exists());
            let later = observe_habits_in_observation(&frame.observation, &fixture.path, 3700, gpt)
                .unwrap();
            assert_eq!(later.due.keys().copied().collect::<Vec<_>>(), vec![global]);
            assert!(!marker.exists(), "the timer must retain persona selection");
            let cc_observation =
                observe_habits_in_observation(&frame.observation, &fixture.path, 3700, cc).unwrap();
            assert!(cc_observation.due.contains_key(&cc_habit));
            assert_eq!(fs::read(marker).unwrap(), b"x");
            pile.close().unwrap();
        });
    }

    fn run_wait_for(
        pile: &mut FacultyStore,
        fixture: &TestPile,
        persona: &str,
        timeout: Duration,
        poll: Duration,
    ) -> String {
        let options = WaitOptions {
            timeout: Some(timeout),
            poll_interval: poll,
        };
        let mut text = String::new();
        let mut emit = |part| {
            let crate::out::Part::Text { text: part } = part else {
                bail!("expected text")
            };
            text.push_str(&part);
            Ok(())
        };
        runtime().unwrap().block_on(async {
            tokio::time::timeout(
                timeout + Duration::from_secs(5),
                cmd_wait(
                    pile,
                    &fixture.signer,
                    &fixture.path,
                    Some(persona),
                    &options,
                    Duration::from_secs(180),
                    &mut Out::new(&mut emit),
                ),
            )
            .await
            .expect("wait honors its timeout")
            .unwrap();
        });
        text
    }

    #[test]
    fn an_owned_clock_falls_due_while_a_message_body_is_still_missing() {
        let fixture = TestPile::new();
        let mut pile = open_store(&fixture.path).unwrap();
        let sources =
            pollster::block_on(OrientSources::open(&mut pile, &fixture.signer, true)).unwrap();
        let cc = id(22);
        let sender = id(23);
        let (person, _, _) = relations::person_fragment(
            cc,
            crate::relations::ProfileInput {
                label: "cc".to_owned(),
                ..Default::default()
            },
        )
        .unwrap();
        pile.commit(sources.relations.source, &fixture.signer, person)
            .unwrap();
        // A message addressed to cc whose body has not arrived: directed news
        // stays pending for the whole wait.
        let mut remote = MemoryRepo::default();
        let body = remote
            .put::<blobencodings::UTF8String, _>("still on its way".to_owned())
            .unwrap();
        pile.commit(
            sources.messages.source,
            &fixture.signer,
            message::envelope_fragment(
                sender,
                cc,
                body,
                clock::point(Epoch::from_tai_seconds(42.0)).unwrap(),
                None,
                None,
            ),
        )
        .unwrap();
        // An owned clock that falls due about three seconds into the wait.
        let now = clock::now().unwrap();
        let done = clock::point(Epoch::from_tai_seconds(now.to_tai_seconds() - 1197.0)).unwrap();
        let (owned, owned_id) =
            habits::habit_fragment("cc-clock", "every 20m", "mark it", None, &[], &[cc]).unwrap();
        let (owned_done, _) = habits::completion_fragment(owned_id, done).unwrap();
        let habit_source = sources.habits.as_ref().unwrap().source;
        pile.commit(habit_source, &fixture.signer, owned + owned_done)
            .unwrap();
        pollster::block_on(maintain_sources(&mut pile, &fixture.signer, &sources)).unwrap();

        let started = Instant::now();
        let text = run_wait_for(
            &mut pile,
            &fixture,
            "cc",
            Duration::from_secs(8),
            Duration::from_millis(200),
        );
        assert!(
            text.contains(&format!(
                "News: habit [{}] became due (cc-clock)",
                fmt_id(owned_id)
            )),
            "the clock must be reported while the body is still missing: {text}"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "fixture setup ate the due margin: the clock was already due at arm"
        );
        assert!(!text.contains("News: new message"), "{text}");
        assert!(
            stored_presentations(&mut pile, &fixture.signer, cc).is_empty(),
            "a habit-only report acknowledges no news"
        );

        // Its owner completes the clock, then the body arrives: a rearmed wait
        // reports the message and records it.
        let (fresh, _) = habits::completion_fragment(owned_id, clock::point(now).unwrap()).unwrap();
        pile.commit(habit_source, &fixture.signer, fresh).unwrap();
        pile.put::<blobencodings::UTF8String, _>("still on its way".to_owned())
            .unwrap();
        pollster::block_on(maintain_sources(&mut pile, &fixture.signer, &sources)).unwrap();
        let delivered = run_wait_for(
            &mut pile,
            &fixture,
            "cc",
            Duration::from_millis(25),
            Duration::from_secs(1),
        );
        assert!(delivered.contains("News: new message"), "{delivered}");
        assert_eq!(
            stored_presentations(&mut pile, &fixture.signer, cc).len(),
            1
        );

        // Nothing new once the worker has carried that receipt: a further
        // rearm is quiet.
        pollster::block_on(maintain_sources(&mut pile, &fixture.signer, &sources)).unwrap();
        let quiet = run_wait_for(
            &mut pile,
            &fixture,
            "cc",
            Duration::from_millis(25),
            Duration::from_secs(1),
        );
        assert!(!quiet.contains("News:"), "{quiet}");
        assert!(quiet.contains("No change detected"), "{quiet}");
        pile.close().unwrap();
    }

    #[test]
    fn a_persona_clock_already_due_at_arm_is_reported_once_per_due() {
        let fixture = TestPile::new();
        let mut pile = open_store(&fixture.path).unwrap();
        let sources =
            pollster::block_on(OrientSources::open(&mut pile, &fixture.signer, true)).unwrap();
        let cc = id(21);
        let (person, _, _) = relations::person_fragment(
            cc,
            crate::relations::ProfileInput {
                label: "cc".to_owned(),
                ..Default::default()
            },
        )
        .unwrap();
        pile.commit(sources.relations.source, &fixture.signer, person)
            .unwrap();
        let now = clock::now().unwrap();
        let an_hour_ago =
            clock::point(Epoch::from_tai_seconds(now.to_tai_seconds() - 3600.0)).unwrap();
        let (owned, owned_id) =
            habits::habit_fragment("cc-clock", "every 20m", "mark it", None, &[], &[cc]).unwrap();
        let (owned_done, _) = habits::completion_fragment(owned_id, an_hour_ago).unwrap();
        let (shared, shared_id) =
            habits::habit_fragment("shared-clock", "every 20m", "anyone", None, &[], &[]).unwrap();
        let (shared_done, _) = habits::completion_fragment(shared_id, an_hour_ago).unwrap();
        let habit_source = sources.habits.as_ref().unwrap().source;
        pile.commit(
            habit_source,
            &fixture.signer,
            owned + owned_done + shared + shared_done,
        )
        .unwrap();
        pollster::block_on(maintain_sources(&mut pile, &fixture.signer, &sources)).unwrap();

        // Both fell due before the watcher armed. The clock addressed to this
        // persona is reported at once; the shared intention is a quiet baseline.
        let armed = run_wait_for(
            &mut pile,
            &fixture,
            "cc",
            Duration::from_millis(25),
            Duration::from_secs(1),
        );
        assert!(
            armed.contains(&format!(
                "News: habit [{}] became due (cc-clock)",
                fmt_id(owned_id)
            )),
            "{armed}"
        );
        assert!(!armed.contains("shared-clock"), "{armed}");

        // Completed now: the rearmed watcher is quiet until the next due.
        let (fresh, _) = habits::completion_fragment(owned_id, clock::point(now).unwrap()).unwrap();
        pile.commit(habit_source, &fixture.signer, fresh).unwrap();
        pollster::block_on(maintain_sources(&mut pile, &fixture.signer, &sources)).unwrap();
        let rearmed = run_wait_for(
            &mut pile,
            &fixture,
            "cc",
            Duration::from_millis(25),
            Duration::from_secs(1),
        );
        assert!(!rearmed.contains("became due"), "{rearmed}");
        assert!(!rearmed.contains("shared-clock"), "{rearmed}");
        assert!(rearmed.contains("No change detected"), "{rearmed}");
        pile.close().unwrap();
    }

    #[test]
    fn an_owned_clock_already_due_is_reported_while_a_message_body_is_still_missing() {
        let fixture = TestPile::new();
        let mut pile = open_store(&fixture.path).unwrap();
        let sources =
            pollster::block_on(OrientSources::open(&mut pile, &fixture.signer, true)).unwrap();
        let cc = id(24);
        let sender = id(25);
        let (person, _, _) = relations::person_fragment(
            cc,
            crate::relations::ProfileInput {
                label: "cc".to_owned(),
                ..Default::default()
            },
        )
        .unwrap();
        pile.commit(sources.relations.source, &fixture.signer, person)
            .unwrap();
        let mut remote = MemoryRepo::default();
        let body = remote
            .put::<blobencodings::UTF8String, _>("still on its way".to_owned())
            .unwrap();
        pile.commit(
            sources.messages.source,
            &fixture.signer,
            message::envelope_fragment(
                sender,
                cc,
                body,
                clock::point(Epoch::from_tai_seconds(42.0)).unwrap(),
                None,
                None,
            ),
        )
        .unwrap();
        let now = clock::now().unwrap();
        let an_hour_ago =
            clock::point(Epoch::from_tai_seconds(now.to_tai_seconds() - 3600.0)).unwrap();
        let (owned, owned_id) =
            habits::habit_fragment("cc-clock", "every 20m", "mark it", None, &[], &[cc]).unwrap();
        let (owned_done, _) = habits::completion_fragment(owned_id, an_hour_ago).unwrap();
        pile.commit(
            sources.habits.as_ref().unwrap().source,
            &fixture.signer,
            owned + owned_done,
        )
        .unwrap();
        pollster::block_on(maintain_sources(&mut pile, &fixture.signer, &sources)).unwrap();

        // Already due when the watcher arms, body still missing: reported at
        // once, nothing acknowledged.
        let armed = run_wait_for(
            &mut pile,
            &fixture,
            "cc",
            Duration::from_millis(500),
            Duration::from_millis(100),
        );
        assert!(
            armed.contains(&format!(
                "News: habit [{}] became due (cc-clock)",
                fmt_id(owned_id)
            )),
            "{armed}"
        );
        assert!(!armed.contains("News: new message"), "{armed}");
        assert!(stored_presentations(&mut pile, &fixture.signer, cc).is_empty());
        pile.close().unwrap();
    }

    #[test]
    fn an_owned_clock_gets_its_turn_while_a_body_fetch_stalls() {
        use triblespace_net::peer::{Peer, ReconcileDirection, ReconcileQos};
        let fixture = TestPile::new();
        // A peer wired with no network capability: every body fetch stalls
        // for its whole budget instead of failing fast. The wiring must stay
        // alive, or the fetch would fail at once.
        let (sender, receiver, wiring) =
            triblespace_net::host::wire(iroh_base::SecretKey::from_bytes(&[7; 32]).public());
        let mut pile: FacultyStore = Peer::with_wiring(
            crate::storage::open_pile_strict(&fixture.path).unwrap(),
            ReconcileQos {
                direction: ReconcileDirection::ReadOnly,
            },
            sender,
            receiver,
        );
        let sources =
            pollster::block_on(OrientSources::open(&mut pile, &fixture.signer, true)).unwrap();
        let cc = id(26);
        let sender_id = id(27);
        let (person, _, _) = relations::person_fragment(
            cc,
            crate::relations::ProfileInput {
                label: "cc".to_owned(),
                ..Default::default()
            },
        )
        .unwrap();
        pile.commit(sources.relations.source, &fixture.signer, person)
            .unwrap();
        let mut remote = MemoryRepo::default();
        let body = remote
            .put::<blobencodings::UTF8String, _>("stalled on the wire".to_owned())
            .unwrap();
        pile.commit(
            sources.messages.source,
            &fixture.signer,
            message::envelope_fragment(
                sender_id,
                cc,
                body,
                clock::point(Epoch::from_tai_seconds(42.0)).unwrap(),
                None,
                None,
            ),
        )
        .unwrap();
        let now = clock::now().unwrap();
        let done = clock::point(Epoch::from_tai_seconds(now.to_tai_seconds() - 1197.0)).unwrap();
        let (owned, owned_id) =
            habits::habit_fragment("cc-clock", "every 20m", "mark it", None, &[], &[cc]).unwrap();
        let (owned_done, _) = habits::completion_fragment(owned_id, done).unwrap();
        // A shared script intention counts its evaluations: once at the first
        // preparation and once per timer sweep, never per cancelled retry.
        let (probe, _) = habits::habit_fragment(
            "evaluation-probe",
            "when printf x >> evaluation-probe-invocations",
            "probe",
            None,
            &[],
            &[],
        )
        .unwrap();
        pile.commit(
            sources.habits.as_ref().unwrap().source,
            &fixture.signer,
            owned + owned_done + probe,
        )
        .unwrap();
        pollster::block_on(maintain_sources(&mut pile, &fixture.signer, &sources)).unwrap();

        let started = Instant::now();
        let text = run_wait_for(
            &mut pile,
            &fixture,
            "cc",
            Duration::from_secs(8),
            Duration::from_millis(200),
        );
        assert!(
            text.contains(&format!(
                "News: habit [{}] became due (cc-clock)",
                fmt_id(owned_id)
            )),
            "the clock must get its turn while the fetch stalls: {text}"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "fixture setup ate the due margin: the clock was already due at arm"
        );
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "the clock must not wait for the stalled fetch budget"
        );
        assert!(!text.contains("evaluation-probe"), "{text}");
        let evaluations = fs::read(fixture.dir.join("evaluation-probe-invocations"))
            .unwrap()
            .len();
        assert!(
            evaluations <= 2,
            "condition scripts reran under cancelled body retries: {evaluations} evaluations"
        );
        assert!(stored_presentations(&mut pile, &fixture.signer, cc).is_empty());
        pile.close().unwrap();
        drop(wiring);
    }

    fn stored_presentations(
        pile: &mut FacultyStore,
        signer: &SigningKey,
        _persona: Id,
    ) -> BTreeSet<Id> {
        // Inspect committed receipt facts, not the asynchronously maintained
        // projection. Routing aliases share the signing zooid's source.
        let collection = ReceiptSource::register(pile, signer).unwrap().source;
        let snapshot = pile.snapshot().unwrap();
        let facts = snapshot
            .collection(collection)
            .unwrap()
            .view::<TribleSet>()
            .unwrap();
        find!(event: Id, pattern!(&facts, [{ presentation::event: ?event }])).collect()
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
    fn resident_fact_and_status_views_do_not_require_equal_support() {
        pollster::block_on(async {
            let fixture = TestPile::new();
            let mut pile = open_store(&fixture.path).unwrap();
            let sources = OrientSources::open(&mut pile, &fixture.signer, false)
                .await
                .unwrap();
            let goal = id(46);
            let unseen_goal = id(47);
            let initial = compass::status_fragment(
                goal,
                "todo",
                None,
                clock::point(Epoch::from_tai_seconds(1.0)).unwrap(),
            )
            .unwrap();
            let initial_id = initial.root().unwrap();
            pile.commit(sources.compass.source, &fixture.signer, initial)
                .unwrap();
            maintain_sources(&mut pile, &fixture.signer, &sources)
                .await
                .unwrap();
            let watermark = pile.snapshot().unwrap();
            let observation = observe_snapshot(watermark, &sources).unwrap();

            let next = compass::status_fragment(
                goal,
                "done",
                None,
                clock::point(Epoch::from_tai_seconds(2.0)).unwrap(),
            )
            .unwrap();
            let next_id = next.root().unwrap();
            let unseen = compass::status_fragment(
                unseen_goal,
                "doing",
                None,
                clock::point(Epoch::from_tai_seconds(3.0)).unwrap(),
            )
            .unwrap();
            let unseen_id = unseen.root().unwrap();
            pile.commit(sources.compass.source, &fixture.signer, next + unseen)
                .unwrap();
            drop(
                pile.maintain(sources.compass.succinct, &fixture.signer)
                    .await
                    .unwrap(),
            );
            let snapshot = pile
                .maintain(sources.compass.rank9, &fixture.signer)
                .await
                .unwrap();
            let lagging = observe_sources(snapshot, &sources).unwrap();
            let status_support = lagging.snapshot.collection(sources.compass_status).unwrap();
            assert_ne!(
                lagging.facts.compass.support(),
                status_support.support().unwrap()
            );
            let query = lagging.query(&lagging.snapshot);
            assert_eq!(latest_goal_status(&query, goal).unwrap().0, initial_id);
            assert_eq!(latest_goal_status(&query, unseen_goal), None);

            let ready = pile
                .maintain(sources.compass_status, &fixture.signer)
                .await
                .unwrap();
            let advanced = observe_sources(ready, &sources).unwrap();
            let query = advanced.query(&advanced.snapshot);
            assert_eq!(latest_goal_status(&query, goal).unwrap().0, next_id);
            assert_eq!(
                latest_goal_status(&query, unseen_goal).unwrap().0,
                unseen_id
            );
            let frozen = lagging.query(&lagging.snapshot);
            assert_eq!(latest_goal_status(&frozen, goal).unwrap().0, initial_id);
            assert_eq!(latest_goal_status(&frozen, unseen_goal), None);
            assert_eq!(
                latest_goal_status(&observation.query(&observation.snapshot), goal)
                    .unwrap()
                    .0,
                initial_id,
            );
            pile.close().unwrap();
        });
    }

    #[test]
    fn wait_selects_resident_targets_and_preserves_polling_watermark() {
        pollster::block_on(wait_selects_resident_targets_and_preserves_polling_watermark_async())
    }

    async fn wait_selects_resident_targets_and_preserves_polling_watermark_async() {
        use triblespace::core::repo::WantRead;

        let fixture = TestPile::new();
        let mut pile = open_store(&fixture.path).unwrap();
        let sources = OrientSources::open(&mut pile, &fixture.signer, true)
            .await
            .unwrap();
        let persona = id(42);
        let profile = crate::relations::ProfileInput {
            label: "test-persona".to_owned(),
            ..Default::default()
        };
        let (person, _, _) = relations::person_fragment(persona, profile).unwrap();
        pile.commit(sources.relations.source, &fixture.signer, person)
            .unwrap();
        sources
            .relations
            .maintain(&mut pile, &fixture.signer)
            .await
            .unwrap();
        let watermark = pile.snapshot_at(Epoch::from_tai_seconds(42.0)).unwrap();
        let expected_support = watermark
            .collection(sources.messages.source)
            .unwrap()
            .support()
            .unwrap()
            .clone();

        // This commit arrives after the wait watermark was frozen. Another
        // maintainer also realizes that newer support before this reader runs.
        // The selected view must still belong to the supplied snapshot. A new
        // polling sample will see the externally produced target progress.
        let message_collection = sources.messages.source;
        pile.commit(
            message_collection,
            &fixture.signer,
            entity! { metadata::tag: &KIND_MESSAGE_ID },
        )
        .unwrap();
        drop(
            pile.maintain(sources.messages.succinct, &fixture.signer)
                .await
                .unwrap(),
        );
        drop(
            pile.maintain(sources.messages.rank9, &fixture.signer)
                .await
                .unwrap(),
        );
        let attempt = load_wait_frame(
            &mut pile,
            &sources,
            watermark.clone(),
            &mut None,
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
            .collection(sources.messages.rank9)
            .unwrap();
        assert_eq!(frame.observation.snapshot.instant(), watermark.instant());
        assert_eq!(
            frame.observation.facts.messages.support(),
            &expected_support,
            "later target progress cannot alter the selected immutable snapshot",
        );
        assert_eq!(
            frame.observation.facts.messages.support(),
            resident_after.support().unwrap(),
            "the selected view must be the resident target at the observation snapshot",
        );
        assert_eq!(frame.observation.facts.messages.view().iter().count(), 0);
        assert!(frame.observation.snapshot.wants().unwrap().next().is_none());
        assert!(
            frame.watermark.changes_since(&watermark).is_empty()
                && watermark.changes_since(&frame.watermark).is_empty(),
            "the production wait frame must retain the exact input watermark",
        );
        assert!(
            frame
                .observation
                .snapshot
                .changes_since(&frame.watermark)
                .is_empty(),
            "passive attachment must use the exact polling snapshot",
        );
        let sampled = pile.snapshot_at(watermark.instant()).unwrap();
        assert!(wait_storage_changed(&sampled, &frame.watermark));
        let WaitFrameLoad::Ready(next) = load_wait_frame(
            &mut pile,
            &sources,
            sampled,
            &mut None,
            &fixture.path,
            "test-persona",
        )
        .await
        .unwrap() else {
            panic!("externally maintained target must be readable")
        };
        assert_eq!(next.observation.facts.messages.view().iter().count(), 1);
        assert_ne!(next.observation.facts.messages.support(), &expected_support);
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
    fn projected_receipt_ids_are_subtracted_from_attention() {
        let first = id(1);
        let second = id(2);
        let mut view = AttentionView::default();
        view.insert(AttentionEvent::Message(first));
        view.insert(AttentionEvent::Mail(second));

        let presented = EntityIdSet::try_from_blob(entity_id_set::encode([first])).unwrap();
        assert_eq!(
            view.pending(&presented).ids().collect::<Vec<_>>(),
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
        let mut pile = open_store(&fixture.path).unwrap();
        let snapshot = pile.snapshot().unwrap();
        let handle = Inline::<inlineencodings::Handle<blobencodings::UTF8String>>::new([42; 32]);

        let error = read_utf8(&snapshot, handle, "selected test body").unwrap_err();
        assert!(is_payload_pending(&error));
        assert_eq!(
            error.downcast_ref::<MissingBlob>().unwrap().handle.raw,
            handle.raw,
        );
        assert!(!pile.snapshot().unwrap().contains_blob(handle).unwrap());
        pile.close().unwrap();
    }

    #[test]
    fn news_acquires_only_its_selected_body_before_presenting_frozen_events() {
        use triblespace::core::repo::async_store::AsyncBlobStoreAcquire;
        use triblespace::core::repo::WantRead;

        struct Supply {
            store: FacultyStore,
            source: Collection<blobencodings::SimpleArchive>,
            succinct: Collection<SuccinctArchiveBlob>,
            rank9: Collection<Rank9AcceleratedSuccinctArchiveBlob>,
            signer: SigningKey,
            handle: Inline<inlineencodings::Handle<blobencodings::UnknownBlob>>,
            bytes: Bytes,
            available: bool,
            requested: Vec<Inline<inlineencodings::Handle<blobencodings::UnknownBlob>>>,
        }

        impl SnapshotSource for Supply {
            type Snapshot = FacultySnapshot;
            type SnapshotError = <FacultyStore as SnapshotSource>::SnapshotError;

            fn snapshot_at(
                &mut self,
                instant: Epoch,
            ) -> std::result::Result<Self::Snapshot, Self::SnapshotError> {
                self.store.snapshot_at(instant)
            }
        }

        impl AsyncBlobStoreAcquire for Supply {
            type AcquireError = io::Error;

            async fn acquire(
                &mut self,
                handle: Inline<inlineencodings::Handle<blobencodings::UnknownBlob>>,
            ) -> std::result::Result<Option<Bytes>, Self::AcquireError> {
                self.requested.push(handle);
                assert_eq!(handle, self.handle, "an unrelated body must stay cold");
                if !self.available {
                    return Ok(None);
                }
                let cached = self
                    .store
                    .put::<blobencodings::UnknownBlob, _>(self.bytes.clone())
                    .unwrap();
                assert_eq!(cached, handle);
                // Acquiring bytes races with an unrelated authoritative append
                // and its maintenance. The render must retain its chosen view
                // even though a newer target is now resident in the reader.
                self.store
                    .commit(
                        self.source,
                        &self.signer,
                        entity! { metadata::tag: &KIND_MESSAGE_ID },
                    )
                    .unwrap();
                drop(
                    self.store
                        .maintain(self.succinct, &self.signer)
                        .await
                        .unwrap(),
                );
                drop(self.store.maintain(self.rank9, &self.signer).await.unwrap());
                Ok(Some(self.bytes.clone()))
            }
        }

        pollster::block_on(async {
            let fixture = TestPile::new();
            let mut pile = open_store(&fixture.path).unwrap();
            let sources = OrientSources::open(&mut pile, &fixture.signer, true)
                .await
                .unwrap();
            let persona = id(43);
            let sender = id(44);
            let (person, _, _) = relations::person_fragment(
                persona,
                relations::ProfileInput {
                    label: "lazy-reader".to_owned(),
                    ..Default::default()
                },
            )
            .unwrap();
            pile.commit(sources.relations.source, &fixture.signer, person)
                .unwrap();

            let mut remote = MemoryRepo::default();
            let bytes: Bytes = Vec::from("newly synced message body").into();
            let body = remote
                .put::<blobencodings::UTF8String, _>("newly synced message body".to_owned())
                .unwrap();
            let unrelated = remote
                .put::<blobencodings::UTF8String, _>("not addressed to this reader".to_owned())
                .unwrap();
            let instant = Epoch::from_tai_seconds(42.0);
            let envelope = message::envelope_fragment(
                sender,
                persona,
                body,
                clock::point(instant).unwrap(),
                None,
                None,
            );
            let event = envelope.root().unwrap();
            pile.commit(sources.messages.source, &fixture.signer, envelope)
                .unwrap();
            pile.commit(
                sources.messages.source,
                &fixture.signer,
                message::envelope_fragment(
                    sender,
                    id(45),
                    unrelated,
                    clock::point(instant).unwrap(),
                    None,
                    None,
                ),
            )
            .unwrap();
            maintain_sources(&mut pile, &fixture.signer, &sources)
                .await
                .unwrap();
            let watermark = pile.snapshot_at(instant).unwrap();
            let observation = observe_snapshot(watermark.clone(), &sources).unwrap();
            let support = observation.facts.messages.support().clone();
            let handle = Inline::new(body.raw);
            let mut supply = Supply {
                store: pile,
                source: sources.messages.source,
                succinct: sources.messages.succinct,
                rank9: sources.messages.rank9,
                signer: fixture.signer.clone(),
                handle,
                bytes,
                available: false,
                requested: Vec::new(),
            };

            let frozen = observation.snapshot.clone();
            let mut pending =
                PendingWaitFrame::awaiting_view(watermark.clone(), PendingWaitReason::Payload);
            pending.observation = Some(observation);
            assert!(resume_wait_payloads(
                &mut supply,
                &mut pending,
                &fixture.path,
                "lazy-reader",
                instant,
            )
            .await
            .unwrap()
            .is_none());
            assert_eq!(pending.reason, PendingWaitReason::Payload);
            assert_eq!(pending.missing.unwrap().handle, handle);
            assert!(stored_presentations(&mut supply.store, &fixture.signer, persona).is_empty());

            let before_provider = supply.snapshot_at(instant).unwrap();
            assert!(!wait_storage_changed(&before_provider, &pending.watermark));
            supply.available = true;
            assert!(!wait_storage_changed(
                &supply.snapshot_at(instant).unwrap(),
                &before_provider
            ));
            let frame = resume_wait_payloads(
                &mut supply,
                &mut pending,
                &fixture.path,
                "lazy-reader",
                instant,
            )
            .await
            .unwrap()
            .expect("a provider-only change must complete the selected read");
            let reader = &frame.observation.snapshot;
            let news = frame.news;
            assert_eq!(frame.persona, persona);
            assert_eq!(reader.instant(), instant);
            assert!(!wait_storage_changed(&frame.watermark, &watermark));
            assert_eq!(
                sources
                    .observations
                    .load(std::sync::atomic::Ordering::Relaxed),
                1
            );
            assert_eq!(supply.requested, [handle, handle]);
            assert!(!frozen.contains_blob(handle).unwrap());
            assert!(!reader.contains_blob(unrelated).unwrap());
            assert_eq!(frame.observation.facts.messages.support(), &support);
            assert_ne!(
                reader.collection(supply.rank9).unwrap().support().unwrap(),
                &support
            );
            assert!(reader.wants().unwrap().next().is_none());
            let News::Report { text, events } = &news else {
                panic!("the acquired body must make the selected message readable")
            };
            assert!(text.contains("newly synced message body"));
            assert_eq!(events, &[event]);
            assert!(stored_presentations(&mut supply.store, &fixture.signer, persona).is_empty());

            let mut output = Vec::new();
            apply_news_to_writer(
                &mut supply.store,
                &fixture.signer,
                persona,
                false,
                &news,
                "",
                &mut output,
            )
            .unwrap();
            assert!(String::from_utf8(output)
                .unwrap()
                .contains("newly synced message body"));
            assert_eq!(
                stored_presentations(&mut supply.store, &fixture.signer, persona),
                BTreeSet::from([event]),
            );
            supply.store.close().unwrap();
        });
    }

    #[test]
    fn a_missing_persona_preserves_the_wait_watermark() {
        pollster::block_on(a_missing_persona_preserves_the_wait_watermark_async())
    }

    async fn a_missing_persona_preserves_the_wait_watermark_async() {
        let fixture = TestPile::new();
        let mut pile = open_store(&fixture.path).unwrap();
        let sources = OrientSources::open(&mut pile, &fixture.signer, true)
            .await
            .unwrap();
        let watermark = pile.snapshot().unwrap();

        let attempt = load_wait_frame(
            &mut pile,
            &sources,
            watermark.clone(),
            &mut None,
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
        write_report_to_writer(&mut writer, "complete", "test report").unwrap();
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
        let mut pile = open_store(&fixture.path).unwrap();
        let error = apply_news_to_writer(
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
        apply_news_to_writer(
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
        let mut pile = open_store(&fixture.path).unwrap();
        let mut output = Vec::new();
        apply_news_to_writer(
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
        let mut pile = open_store(&fixture.path).unwrap();

        save_presentations(&mut pile, &fixture.signer, view.ids()).unwrap();
        let presented = stored_presentations(&mut pile, &fixture.signer, persona);
        assert_eq!(presented, BTreeSet::from([first, second]));
        let projected = EntityIdSet::try_from_blob(entity_id_set::encode(presented)).unwrap();
        assert!(view.pending(&projected).is_empty());
        pile.close().unwrap();
    }

    #[test]
    fn becoming_relevant_late_does_not_retroactively_present_an_event() {
        let event = id(10);
        let initial = AttentionView::default();
        let presented = EntityIdSet::try_from_blob(entity_id_set::encode(initial.ids())).unwrap();

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
