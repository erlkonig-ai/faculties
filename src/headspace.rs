//! Collection-native Headspace state and its fork-visible snapshot algebra.
//!
//! Headspace has exactly two kinds of changing state: one global config track
//! and one profile track per authored profile anchor. Every change is a
//! complete snapshot. `metadata::supersedes` carries lineage, set
//! union preserves concurrent heads, and wall-clock time is absent from state
//! and identity. If occurrence provenance later has a concrete consumer, it
//! belongs outside these snapshots. This module is the sole projector used by
//! the CLI, viewer, Web, and Triage; storage and effects remain at those
//! command boundaries.
//!
//! Native records contain only exact immutable Secrets-version ids. Generic
//! secret labels remain discovery/display conveniences and never participate
//! in runtime selection. Historical plaintext facts coexist in the same
//! collection after migration, but lack the live marker and are semantically
//! inert. Ordinary consumers query current typed frontiers directly. The
//! complete historical catalog remains only for reconciliation and strict
//! migration boundaries.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::schemas::cognition::DEFAULT_SCOPE_ID as COGNITION_SCOPE_ID;
use crate::schemas::headspace::{
    playground_config, DEFAULT_AUTHOR, DEFAULT_AUTHOR_ROLE, DEFAULT_BASE_URL,
    DEFAULT_CHARS_PER_TOKEN, DEFAULT_CONTEXT_SAFETY_MARGIN_TOKENS, DEFAULT_CONTEXT_WINDOW_TOKENS,
    DEFAULT_MAX_OUTPUT_TOKENS, DEFAULT_MODEL, DEFAULT_POLL_MS, DEFAULT_STREAM,
    DEFAULT_SYSTEM_PROMPT, KIND_CONFIG_ID, KIND_LIVE_RECORD, KIND_MODEL_PROFILE_ID,
    KIND_PROFILE_ANCHOR_ID,
};
use crate::secrets::SecretsSnapshot;

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type CountValue = Inline<inlineencodings::U256BE>;

/// One complete model-profile value.
///
/// `model_secret_version` names one exact immutable Secrets version. It is
/// deliberately not a label, scope, or "latest" selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileValue {
    pub anchor: Id,
    pub name: String,
    pub model: String,
    pub base_url: String,
    pub model_secret_version: Option<Id>,
    pub reasoning_effort: Option<String>,
    pub stream: bool,
    pub context_window_tokens: u64,
    pub max_output_tokens: u64,
    pub context_safety_margin_tokens: u64,
    pub chars_per_token: u64,
}

/// One complete global Headspace configuration value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigValue {
    pub active_profile: Id,
    pub system_prompt: String,
    pub cognition_scope: Id,
    pub author: String,
    pub author_role: String,
    pub persona: Option<Id>,
    pub poll_ms: u64,
    pub tavily_secret_version: Option<Id>,
    pub exa_secret_version: Option<Id>,
    pub exec_default_cwd: Option<String>,
    pub exec_sandbox_profile: Option<Id>,
}

/// One live or historical immutable snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot<T> {
    pub id: Id,
    pub value: T,
    pub predecessors: Vec<Id>,
}

/// Current state of one snapshot track.
///
/// `Agreed` retains every provenance head even though their complete values are
/// equal. A successor must therefore use [`Self::head_ids`] rather than taking
/// one representative.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resolution<T> {
    Missing,
    Unique(Snapshot<T>),
    Agreed(Vec<Snapshot<T>>),
    Forked(Vec<Snapshot<T>>),
    Invalid(String),
}

impl<T> Resolution<T> {
    pub fn head_ids(&self) -> Vec<Id> {
        match self {
            Self::Missing | Self::Invalid(_) => Vec::new(),
            Self::Unique(snapshot) => vec![snapshot.id],
            Self::Agreed(snapshots) | Self::Forked(snapshots) => {
                snapshots.iter().map(|snapshot| snapshot.id).collect()
            }
        }
    }

    pub fn snapshots(&self) -> &[Snapshot<T>] {
        match self {
            Self::Unique(snapshot) => std::slice::from_ref(snapshot),
            Self::Agreed(snapshots) | Self::Forked(snapshots) => snapshots,
            Self::Missing | Self::Invalid(_) => &[],
        }
    }

    pub fn settled_value(&self, label: &str) -> Result<Option<&T>> {
        match self {
            Self::Missing => Ok(None),
            Self::Unique(snapshot) => Ok(Some(&snapshot.value)),
            Self::Agreed(snapshots) => Ok(snapshots.first().map(|snapshot| &snapshot.value)),
            Self::Forked(snapshots) => bail!(
                "{label} is forked across heads {}",
                format_ids(snapshots.iter().map(|snapshot| snapshot.id))
            ),
            Self::Invalid(error) => bail!("{label} is invalid: {error}"),
        }
    }
}

/// Complete retained Headspace history for reconciliation and migration.
///
/// Ordinary readers should use [`current_config`], [`current_profile`], or
/// [`current_profiles`] instead of materializing this historical domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Catalog {
    pub config: Resolution<ConfigValue>,
    pub profiles: BTreeMap<Id, Resolution<ProfileValue>>,
    config_snapshots: BTreeMap<Id, Snapshot<ConfigValue>>,
    profile_snapshots: BTreeMap<Id, Snapshot<ProfileValue>>,
}

/// Decrypted credentials for one already-resolved Headspace state.
///
/// This value is intentionally ephemeral. No constructor can turn it back
/// into a Headspace fragment, which keeps plaintext out of native records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenedSecrets {
    pub model_api_key: Option<String>,
    pub tavily_api_key: Option<String>,
    pub exa_api_key: Option<String>,
}

impl Catalog {
    fn invalid(error: anyhow::Error) -> Self {
        Self {
            config: Resolution::Invalid(format!("{error:#}")),
            profiles: BTreeMap::new(),
            config_snapshots: BTreeMap::new(),
            profile_snapshots: BTreeMap::new(),
        }
    }

    pub fn config_snapshot(&self, id: Id) -> Option<&Snapshot<ConfigValue>> {
        self.config_snapshots.get(&id)
    }

    pub fn profile_snapshot(&self, id: Id) -> Option<&Snapshot<ProfileValue>> {
        self.profile_snapshots.get(&id)
    }

    pub fn snapshot_ids(&self) -> BTreeSet<Id> {
        self.config_snapshots
            .keys()
            .chain(self.profile_snapshots.keys())
            .copied()
            .collect()
    }

    /// Re-express an existing complete snapshot as the intended value while
    /// superseding every currently live head on its track.
    ///
    /// A single head already carrying the intended value is a no-op. Multiple
    /// equal-value heads still need an explicit join so the DAG itself is
    /// reconciled rather than merely semantically agreed.
    pub fn reconcile_fragment(&self, chosen: Id) -> Result<Option<(Fragment, Id)>> {
        if let Some(snapshot) = self.config_snapshots.get(&chosen) {
            if resolution_is_unique_value(&self.config, &snapshot.value) {
                return Ok(None);
            }
            return config_snapshot_fragment(&snapshot.value, &self.config.head_ids()).map(Some);
        }
        if let Some(snapshot) = self.profile_snapshots.get(&chosen) {
            let resolution = self
                .profiles
                .get(&snapshot.value.anchor)
                .ok_or_else(|| anyhow!("profile {:x} has no track", snapshot.value.anchor))?;
            if resolution_is_unique_value(resolution, &snapshot.value) {
                return Ok(None);
            }
            return profile_snapshot_fragment(&snapshot.value, &resolution.head_ids()).map(Some);
        }
        bail!("unknown Headspace snapshot {chosen:x}")
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CurrentProfileRow {
    id: Id,
    anchor: Id,
    name: TextHandle,
    model: TextHandle,
    base_url: TextHandle,
    stream: u64,
    context_window_tokens: u64,
    max_output_tokens: u64,
    context_safety_margin_tokens: u64,
    chars_per_token: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CurrentConfigRow {
    id: Id,
    active_profile: Id,
    system_prompt: TextHandle,
    cognition_scope: Id,
    author: TextHandle,
    author_role: TextHandle,
    poll_ms: u64,
}

fn optional_variants<T: Copy + Ord>(values: impl IntoIterator<Item = T>) -> Vec<Option<T>> {
    let values: BTreeSet<_> = values.into_iter().collect();
    if values.is_empty() {
        vec![None]
    } else {
        values.into_iter().map(Some).collect()
    }
}

fn direct_predecessors<P>(facts: &P, id: Id) -> Vec<Id>
where
    P: TriblePattern + ?Sized,
{
    sorted_ids(find!(
        predecessor: Id,
        pattern!(facts, [{ id @ metadata::supersedes: ?predecessor }])
    ))
}

/// Resolve one explicitly scoped observation-DAG frontier.
///
/// Only complete typed candidates participate. Incomplete rows, unknown
/// schema generations, and cross-track edges are therefore inert rather than
/// poisoning an open-world reader. Immediate edges suffice because every
/// candidate named by another typed candidate is below the frontier.
fn typed_frontier<P>(facts: &P, candidates: &BTreeSet<Id>) -> BTreeSet<Id>
where
    P: TriblePattern + ?Sized,
{
    let mut superseded = BTreeSet::new();
    for successor in candidates {
        superseded.extend(
            find!(
                predecessor: Id,
                pattern!(facts, [{ successor @ metadata::supersedes: ?predecessor }])
            )
            .filter(|predecessor| candidates.contains(predecessor)),
        );
    }
    candidates.difference(&superseded).copied().collect()
}

fn resolve_variants<T: Clone + Eq>(snapshots: Vec<Snapshot<T>>) -> Resolution<T> {
    match snapshots.as_slice() {
        [] => Resolution::Missing,
        [snapshot] => Resolution::Unique(snapshot.clone()),
        _ if snapshots
            .iter()
            .all(|snapshot| snapshot.value == snapshots[0].value) =>
        {
            Resolution::Agreed(snapshots)
        }
        _ => Resolution::Forked(snapshots),
    }
}

fn current_profile_rows<P>(facts: &P, anchor: Id) -> BTreeSet<CurrentProfileRow>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (
            id: Id,
            name: TextHandle,
            model: TextHandle,
            base_url: TextHandle,
            stream: u64,
            context_window_tokens: u64,
            max_output_tokens: u64,
            context_safety_margin_tokens: u64,
            chars_per_token: u64
        ),
        pattern!(facts, [{
            ?id @
                metadata::tag: KIND_LIVE_RECORD,
                metadata::tag: KIND_MODEL_PROFILE_ID,
                playground_config::model_profile_id: &anchor,
                metadata::name: ?name,
                playground_config::model_name: ?model,
                playground_config::model_base_url: ?base_url,
                playground_config::model_stream: ?stream,
                playground_config::model_context_window_tokens: ?context_window_tokens,
                playground_config::model_max_output_tokens: ?max_output_tokens,
                playground_config::model_context_safety_margin_tokens: ?context_safety_margin_tokens,
                playground_config::model_chars_per_token: ?chars_per_token,
        }])
    )
    .filter_map(
        |(
            id,
            name,
            model,
            base_url,
            stream,
            context_window_tokens,
            max_output_tokens,
            context_safety_margin_tokens,
            chars_per_token,
        )| {
            (stream <= 1).then_some(CurrentProfileRow {
                id,
                anchor,
                name,
                model,
                base_url,
                stream,
                context_window_tokens,
                max_output_tokens,
                context_safety_margin_tokens,
                chars_per_token,
            })
        },
    )
    .collect()
}

/// Project the current typed state of one profile track.
///
/// Scalar multiplicity yields multiple interpretations instead of a hidden
/// cardinality error or iterator-order winner. Additional facts are ignored,
/// entity ids remain opaque, and only frontier payloads are read.
pub fn current_profile<P>(
    reader: &PileSnapshot,
    facts: &P,
    anchor: Id,
) -> Result<Resolution<ProfileValue>>
where
    P: TriblePattern + ?Sized,
{
    let rows = current_profile_rows(facts, anchor);
    let candidates = rows.iter().map(|row| row.id).collect::<BTreeSet<_>>();
    let heads = typed_frontier(facts, &candidates);
    let mut snapshots = Vec::new();

    for id in heads {
        let predecessors = direct_predecessors(facts, id);
        let model_secrets = optional_variants(find!(
            value: Id,
            pattern!(facts, [{ id @ playground_config::model_secret_version: ?value }])
        ));
        let reasoning_efforts = optional_variants(find!(
            value: TextHandle,
            pattern!(facts, [{ id @ playground_config::model_reasoning_effort: ?value }])
        ));
        for row in rows.iter().filter(|row| row.id == id) {
            let name = load_text_from(reader, row.name)?;
            let model = load_text_from(reader, row.model)?;
            let base_url = load_text_from(reader, row.base_url)?;
            for model_secret_version in &model_secrets {
                for reasoning_effort in &reasoning_efforts {
                    let value = ProfileValue {
                        anchor: row.anchor,
                        name: name.clone(),
                        model: model.clone(),
                        base_url: base_url.clone(),
                        model_secret_version: *model_secret_version,
                        reasoning_effort: reasoning_effort
                            .map(|handle| load_text_from(reader, handle))
                            .transpose()?,
                        stream: row.stream == 1,
                        context_window_tokens: row.context_window_tokens,
                        max_output_tokens: row.max_output_tokens,
                        context_safety_margin_tokens: row.context_safety_margin_tokens,
                        chars_per_token: row.chars_per_token,
                    };
                    let snapshot = Snapshot {
                        id,
                        value,
                        predecessors: predecessors.clone(),
                    };
                    if !snapshots.contains(&snapshot) {
                        snapshots.push(snapshot);
                    }
                }
            }
        }
    }
    Ok(resolve_variants(snapshots))
}

/// Project every declared or typed profile track independently at its current
/// frontier. This explicit roster result is for callers which actually need
/// every profile; point readers should call [`current_profile`] instead.
pub fn current_profiles<P>(
    reader: &PileSnapshot,
    facts: &P,
) -> Result<BTreeMap<Id, Resolution<ProfileValue>>>
where
    P: TriblePattern + ?Sized,
{
    let declared = find!(
        anchor: Id,
        pattern!(facts, [{
            ?anchor @
                metadata::tag: KIND_LIVE_RECORD,
                metadata::tag: KIND_PROFILE_ANCHOR_ID,
        }])
    );
    let referenced = find!(
        anchor: Id,
        pattern!(facts, [{
            _?snapshot @
                metadata::tag: KIND_LIVE_RECORD,
                metadata::tag: KIND_MODEL_PROFILE_ID,
                playground_config::model_profile_id: ?anchor,
        }])
    );
    declared
        .chain(referenced)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|anchor| current_profile(reader, facts, anchor).map(|profile| (anchor, profile)))
        .collect()
}

fn current_config_rows<P>(facts: &P) -> BTreeSet<CurrentConfigRow>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (
            id: Id,
            active_profile: Id,
            system_prompt: TextHandle,
            cognition_scope: Id,
            author: TextHandle,
            author_role: TextHandle,
            poll_ms: u64
        ),
        pattern!(facts, [{
            ?id @
                metadata::tag: KIND_LIVE_RECORD,
                metadata::tag: KIND_CONFIG_ID,
                playground_config::active_model_profile_id: ?active_profile,
                playground_config::system_prompt: ?system_prompt,
                playground_config::cognition_scope: ?cognition_scope,
                playground_config::author: ?author,
                playground_config::author_role: ?author_role,
                playground_config::poll_ms: ?poll_ms,
        }])
    )
    .map(
        |(id, active_profile, system_prompt, cognition_scope, author, author_role, poll_ms)| {
            CurrentConfigRow {
                id,
                active_profile,
                system_prompt,
                cognition_scope,
                author,
                author_role,
                poll_ms,
            }
        },
    )
    .collect()
}

/// Project the global current Headspace configuration directly from typed
/// rows. Only its explicit observation DAG chooses the frontier.
pub fn current_config<P>(reader: &PileSnapshot, facts: &P) -> Result<Resolution<ConfigValue>>
where
    P: TriblePattern + ?Sized,
{
    let rows = current_config_rows(facts);
    let candidates = rows.iter().map(|row| row.id).collect::<BTreeSet<_>>();
    let heads = typed_frontier(facts, &candidates);
    let mut snapshots = Vec::new();

    for id in heads {
        let predecessors = direct_predecessors(facts, id);
        let personas = optional_variants(find!(
            value: Id,
            pattern!(facts, [{ id @ playground_config::persona_id: ?value }])
        ));
        let tavily_secrets = optional_variants(find!(
            value: Id,
            pattern!(facts, [{ id @ playground_config::tavily_secret_version: ?value }])
        ));
        let exa_secrets = optional_variants(find!(
            value: Id,
            pattern!(facts, [{ id @ playground_config::exa_secret_version: ?value }])
        ));
        let exec_cwds = optional_variants(find!(
            value: TextHandle,
            pattern!(facts, [{ id @ playground_config::exec_default_cwd: ?value }])
        ));
        let sandbox_profiles = optional_variants(find!(
            value: Id,
            pattern!(facts, [{ id @ playground_config::exec_sandbox_profile: ?value }])
        ));
        for row in rows.iter().filter(|row| row.id == id) {
            let system_prompt = load_text_from(reader, row.system_prompt)?;
            let author = load_text_from(reader, row.author)?;
            let author_role = load_text_from(reader, row.author_role)?;
            for persona in &personas {
                for tavily_secret_version in &tavily_secrets {
                    for exa_secret_version in &exa_secrets {
                        for exec_cwd in &exec_cwds {
                            for exec_sandbox_profile in &sandbox_profiles {
                                let value = ConfigValue {
                                    active_profile: row.active_profile,
                                    system_prompt: system_prompt.clone(),
                                    cognition_scope: row.cognition_scope,
                                    author: author.clone(),
                                    author_role: author_role.clone(),
                                    persona: *persona,
                                    poll_ms: row.poll_ms,
                                    tavily_secret_version: *tavily_secret_version,
                                    exa_secret_version: *exa_secret_version,
                                    exec_default_cwd: exec_cwd
                                        .map(|handle| load_text_from(reader, handle))
                                        .transpose()?,
                                    exec_sandbox_profile: *exec_sandbox_profile,
                                };
                                let snapshot = Snapshot {
                                    id,
                                    value,
                                    predecessors: predecessors.clone(),
                                };
                                if !snapshots.contains(&snapshot) {
                                    snapshots.push(snapshot);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(resolve_variants(snapshots))
}

/// Validate only exact Secrets references visible at selected current
/// frontiers. Historical snapshots remain irrelevant to ordinary reads.
pub fn validate_current_secret_references<'a, R>(
    config: &Resolution<ConfigValue>,
    profiles: impl IntoIterator<Item = &'a Resolution<ProfileValue>>,
    secrets: &SecretsSnapshot<R>,
) -> Result<()> {
    for snapshot in config.snapshots() {
        for (role, secret) in [
            ("Tavily", snapshot.value.tavily_secret_version),
            ("Exa", snapshot.value.exa_secret_version),
        ] {
            if let Some(secret) = secret.filter(|secret| !secrets.contains(*secret)) {
                bail!(
                    "Headspace snapshot {:x} references missing exact {role} Secrets version {secret:x}",
                    snapshot.id
                );
            }
        }
    }
    for profile in profiles {
        for snapshot in profile.snapshots() {
            if let Some(secret) = snapshot
                .value
                .model_secret_version
                .filter(|secret| !secrets.contains(*secret))
            {
                bail!(
                    "Headspace snapshot {:x} references missing exact model Secrets version {secret:x}",
                    snapshot.id
                );
            }
        }
    }
    Ok(())
}

fn resolution_is_unique_value<T: Eq>(resolution: &Resolution<T>, intended: &T) -> bool {
    matches!(resolution, Resolution::Unique(snapshot) if &snapshot.value == intended)
}

pub fn default_profile(anchor: Id, name: impl Into<String>) -> ProfileValue {
    ProfileValue {
        anchor,
        name: name.into(),
        model: DEFAULT_MODEL.to_owned(),
        base_url: DEFAULT_BASE_URL.to_owned(),
        model_secret_version: None,
        reasoning_effort: None,
        stream: DEFAULT_STREAM,
        context_window_tokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
        max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
        context_safety_margin_tokens: DEFAULT_CONTEXT_SAFETY_MARGIN_TOKENS,
        chars_per_token: DEFAULT_CHARS_PER_TOKEN,
    }
}

pub fn default_config(active_profile: Id) -> ConfigValue {
    ConfigValue {
        active_profile,
        system_prompt: DEFAULT_SYSTEM_PROMPT.to_owned(),
        cognition_scope: COGNITION_SCOPE_ID,
        author: DEFAULT_AUTHOR.to_owned(),
        author_role: DEFAULT_AUTHOR_ROLE.to_owned(),
        persona: None,
        poll_ms: DEFAULT_POLL_MS,
        tavily_secret_version: None,
        exa_secret_version: None,
        exec_default_cwd: Some("/workspace".to_owned()),
        exec_sandbox_profile: None,
    }
}

pub fn profile_anchor_fragment(anchor: Id) -> Fragment {
    entity! { ExclusiveId::force_ref(&anchor) @
        metadata::tag: &KIND_LIVE_RECORD,
        metadata::tag: &KIND_PROFILE_ANCHOR_ID,
    }
}

pub fn profile_snapshot_fragment(
    value: &ProfileValue,
    predecessors: &[Id],
) -> Result<(Fragment, Id)> {
    validate_profile_value(value)?;
    let predecessors = sorted_ids(predecessors.iter().copied());
    let mut fragment = Fragment::empty();
    let name = fragment.put(value.name.clone());
    let model = fragment.put(value.model.clone());
    let base_url = fragment.put(value.base_url.clone());
    let reasoning_effort = value
        .reasoning_effort
        .clone()
        .map(|value| fragment.put(value));
    fragment += entity! {
        metadata::tag: &KIND_LIVE_RECORD,
        metadata::tag: &KIND_MODEL_PROFILE_ID,
        playground_config::model_profile_id: &value.anchor,
        metadata::name: name,
        playground_config::model_name: model,
        playground_config::model_base_url: base_url,
        playground_config::model_secret_version?: value.model_secret_version,
        playground_config::model_reasoning_effort?: reasoning_effort,
        playground_config::model_stream: bool_count(value.stream),
        playground_config::model_context_window_tokens: value.context_window_tokens.to_inline(),
        playground_config::model_max_output_tokens: value.max_output_tokens.to_inline(),
        playground_config::model_context_safety_margin_tokens: value.context_safety_margin_tokens.to_inline(),
        playground_config::model_chars_per_token: value.chars_per_token.to_inline(),
        metadata::supersedes*: predecessors.iter(),
    };
    let id = fragment
        .root()
        .ok_or_else(|| anyhow!("profile snapshot has no unique intrinsic root"))?;
    Ok((fragment, id))
}

pub fn config_snapshot_fragment(
    value: &ConfigValue,
    predecessors: &[Id],
) -> Result<(Fragment, Id)> {
    validate_config_value(value)?;
    let predecessors = sorted_ids(predecessors.iter().copied());
    let mut fragment = Fragment::empty();
    let system_prompt = fragment.put(value.system_prompt.clone());
    let author = fragment.put(value.author.clone());
    let author_role = fragment.put(value.author_role.clone());
    let exec_default_cwd = value
        .exec_default_cwd
        .clone()
        .map(|value| fragment.put(value));
    fragment += entity! {
        metadata::tag: &KIND_LIVE_RECORD,
        metadata::tag: &KIND_CONFIG_ID,
        playground_config::active_model_profile_id: &value.active_profile,
        playground_config::system_prompt: system_prompt,
        playground_config::cognition_scope: &value.cognition_scope,
        playground_config::author: author,
        playground_config::author_role: author_role,
        playground_config::persona_id?: value.persona,
        playground_config::poll_ms: value.poll_ms.to_inline(),
        playground_config::tavily_secret_version?: value.tavily_secret_version,
        playground_config::exa_secret_version?: value.exa_secret_version,
        playground_config::exec_default_cwd?: exec_default_cwd,
        playground_config::exec_sandbox_profile?: value.exec_sandbox_profile,
        metadata::supersedes*: predecessors.iter(),
    };
    let id = fragment
        .root()
        .ok_or_else(|| anyhow!("config snapshot has no unique intrinsic root"))?;
    Ok((fragment, id))
}

/// Construct profile genesis and the activating config successor as one
/// self-contained fragment suitable for one signed COMMIT.
pub fn add_profile_fragment(
    profile: &ProfileValue,
    config: &ConfigValue,
    config_predecessors: &[Id],
) -> Result<(Fragment, Id, Id)> {
    if profile.anchor != config.active_profile {
        bail!(
            "new profile anchor {:x} does not match activating config anchor {:x}",
            profile.anchor,
            config.active_profile
        );
    }
    let mut fragment = profile_anchor_fragment(profile.anchor);
    let (profile_fragment, profile_id) = profile_snapshot_fragment(profile, &[])?;
    let (config_fragment, config_id) = config_snapshot_fragment(config, config_predecessors)?;
    fragment += profile_fragment;
    fragment += config_fragment;
    Ok((fragment, profile_id, config_id))
}

struct RawProfileSnapshot {
    anchor: Id,
    name: TextHandle,
    model: TextHandle,
    base_url: TextHandle,
    model_secret_version: Option<Id>,
    reasoning_effort: Option<TextHandle>,
    stream: CountValue,
    context_window_tokens: CountValue,
    max_output_tokens: CountValue,
    context_safety_margin_tokens: CountValue,
    chars_per_token: CountValue,
    predecessors: Vec<Id>,
}

struct RawConfigSnapshot {
    active_profile: Id,
    system_prompt: TextHandle,
    cognition_scope: Id,
    author: TextHandle,
    author_role: TextHandle,
    persona: Option<Id>,
    poll_ms: CountValue,
    tavily_secret_version: Option<Id>,
    exa_secret_version: Option<Id>,
    exec_default_cwd: Option<TextHandle>,
    exec_sandbox_profile: Option<Id>,
    predecessors: Vec<Id>,
}

#[derive(Default)]
struct RawCatalog {
    config: BTreeMap<Id, RawConfigSnapshot>,
    profiles: BTreeMap<Id, RawProfileSnapshot>,
    config_heads: Vec<Id>,
    profile_heads: BTreeMap<Id, Vec<Id>>,
}

fn bool_count(value: bool) -> CountValue {
    if value { 1u64 } else { 0u64 }.to_inline()
}

fn count_u64(value: CountValue, entity: Id, field: &str) -> Result<u64> {
    if value.raw[..24].iter().any(|byte| *byte != 0) {
        bail!("Headspace entity {entity:x} has non-u64 value for {field}");
    }
    let bytes: [u8; 8] = value.raw[24..32]
        .try_into()
        .expect("fixed U256BE lower word");
    Ok(u64::from_be_bytes(bytes))
}

fn exactly_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<T> {
    let count = values.len();
    if count != 1 {
        bail!("Headspace entity {entity:x} has {count} values for {field}; expected exactly one");
    }
    Ok(values.into_iter().next().unwrap())
}

fn at_most_one<T>(values: Vec<T>, entity: Id, field: &str) -> Result<Option<T>> {
    let count = values.len();
    if count > 1 {
        bail!("Headspace entity {entity:x} has {count} values for {field}; expected at most one");
    }
    Ok(values.into_iter().next())
}

fn sorted_ids(values: impl IntoIterator<Item = Id>) -> Vec<Id> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_unstable();
    values.dedup();
    values
}

fn ids_of_kind<P>(facts: &P, kind: Id) -> BTreeSet<Id>
where
    P: TriblePattern + ?Sized,
{
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: kind }])).collect()
}

/// Project the only facts that carry live Headspace meaning.
///
/// Exact legacy facts may coexist in the same collection, but migration never
/// adds this marker to them. A record becomes active as a whole entity so an
/// attempted marker graft cannot smuggle unaccounted fields past validation.
pub fn active_facts(facts: &TribleSet) -> TribleSet {
    let active = ids_of_kind(facts, KIND_LIVE_RECORD);
    facts
        .iter()
        .filter(|fact| active.contains(fact.e()))
        .copied()
        .collect()
}

fn raw_profile<P>(facts: &P, id: Id) -> Result<RawProfileSnapshot>
where
    P: TriblePattern + ?Sized,
{
    Ok(RawProfileSnapshot {
        anchor: exactly_one(
            find!(v: Id, pattern!(facts, [{ id @ playground_config::model_profile_id: ?v }]))
                .collect(),
            id,
            "model_profile_id",
        )?,
        name: exactly_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ metadata::name: ?v }])).collect(),
            id,
            "metadata::name",
        )?,
        model: exactly_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ playground_config::model_name: ?v }]))
                .collect(),
            id,
            "model_name",
        )?,
        base_url: exactly_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ playground_config::model_base_url: ?v }]))
                .collect(),
            id,
            "model_base_url",
        )?,
        model_secret_version: at_most_one(
            find!(v: Id, pattern!(facts, [{ id @ playground_config::model_secret_version: ?v }]))
                .collect(),
            id,
            "model_secret_version",
        )?,
        reasoning_effort: at_most_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ playground_config::model_reasoning_effort: ?v }])).collect(),
            id,
            "model_reasoning_effort",
        )?,
        stream: exactly_one(
            find!(v: CountValue, pattern!(facts, [{ id @ playground_config::model_stream: ?v }]))
                .collect(),
            id,
            "model_stream",
        )?,
        context_window_tokens: exactly_one(
            find!(v: CountValue, pattern!(facts, [{ id @ playground_config::model_context_window_tokens: ?v }])).collect(),
            id,
            "model_context_window_tokens",
        )?,
        max_output_tokens: exactly_one(
            find!(v: CountValue, pattern!(facts, [{ id @ playground_config::model_max_output_tokens: ?v }])).collect(),
            id,
            "model_max_output_tokens",
        )?,
        context_safety_margin_tokens: exactly_one(
            find!(v: CountValue, pattern!(facts, [{ id @ playground_config::model_context_safety_margin_tokens: ?v }])).collect(),
            id,
            "model_context_safety_margin_tokens",
        )?,
        chars_per_token: exactly_one(
            find!(v: CountValue, pattern!(facts, [{ id @ playground_config::model_chars_per_token: ?v }])).collect(),
            id,
            "model_chars_per_token",
        )?,
        predecessors: sorted_ids(find!(v: Id, pattern!(facts, [{ id @ metadata::supersedes: ?v }]))),
    })
}

fn raw_config<P>(facts: &P, id: Id) -> Result<RawConfigSnapshot>
where
    P: TriblePattern + ?Sized,
{
    Ok(RawConfigSnapshot {
        active_profile: exactly_one(
            find!(v: Id, pattern!(facts, [{ id @ playground_config::active_model_profile_id: ?v }])).collect(),
            id,
            "active_model_profile_id",
        )?,
        system_prompt: exactly_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ playground_config::system_prompt: ?v }])).collect(),
            id,
            "system_prompt",
        )?,
        cognition_scope: exactly_one(
            find!(v: Id, pattern!(facts, [{ id @ playground_config::cognition_scope: ?v }])).collect(),
            id,
            "cognition_scope",
        )?,
        author: exactly_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ playground_config::author: ?v }])).collect(),
            id,
            "author",
        )?,
        author_role: exactly_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ playground_config::author_role: ?v }])).collect(),
            id,
            "author_role",
        )?,
        persona: at_most_one(
            find!(v: Id, pattern!(facts, [{ id @ playground_config::persona_id: ?v }])).collect(),
            id,
            "persona_id",
        )?,
        poll_ms: exactly_one(
            find!(v: CountValue, pattern!(facts, [{ id @ playground_config::poll_ms: ?v }])).collect(),
            id,
            "poll_ms",
        )?,
        tavily_secret_version: at_most_one(
            find!(v: Id, pattern!(facts, [{ id @ playground_config::tavily_secret_version: ?v }])).collect(),
            id,
            "tavily_secret_version",
        )?,
        exa_secret_version: at_most_one(
            find!(v: Id, pattern!(facts, [{ id @ playground_config::exa_secret_version: ?v }])).collect(),
            id,
            "exa_secret_version",
        )?,
        exec_default_cwd: at_most_one(
            find!(v: TextHandle, pattern!(facts, [{ id @ playground_config::exec_default_cwd: ?v }])).collect(),
            id,
            "exec_default_cwd",
        )?,
        exec_sandbox_profile: at_most_one(
            find!(v: Id, pattern!(facts, [{ id @ playground_config::exec_sandbox_profile: ?v }])).collect(),
            id,
            "exec_sandbox_profile",
        )?,
        predecessors: sorted_ids(find!(v: Id, pattern!(facts, [{ id @ metadata::supersedes: ?v }]))),
    })
}

fn dag_heads(nodes: &BTreeMap<Id, Vec<Id>>, label: &str) -> Result<Vec<Id>> {
    for (&node, predecessors) in nodes {
        for predecessor in predecessors {
            if !nodes.contains_key(predecessor) {
                bail!("{label} snapshot {node:x} names missing or wrong-track predecessor {predecessor:x}");
            }
        }
    }

    fn visit(
        node: Id,
        nodes: &BTreeMap<Id, Vec<Id>>,
        visiting: &mut BTreeSet<Id>,
        done: &mut BTreeSet<Id>,
        label: &str,
    ) -> Result<()> {
        if done.contains(&node) {
            return Ok(());
        }
        if !visiting.insert(node) {
            bail!("{label} predecessor graph contains a cycle at {node:x}");
        }
        for predecessor in &nodes[&node] {
            visit(*predecessor, nodes, visiting, done, label)?;
        }
        visiting.remove(&node);
        done.insert(node);
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    let mut done = BTreeSet::new();
    for &node in nodes.keys() {
        visit(node, nodes, &mut visiting, &mut done, label)?;
    }

    fn reaches(start: Id, target: Id, nodes: &BTreeMap<Id, Vec<Id>>) -> bool {
        nodes[&start]
            .iter()
            .any(|predecessor| *predecessor == target || reaches(*predecessor, target, nodes))
    }
    for (&node, predecessors) in nodes {
        for (index, predecessor) in predecessors.iter().enumerate() {
            if predecessors.iter().enumerate().any(|(other_index, other)| {
                index != other_index && reaches(*other, *predecessor, nodes)
            }) {
                bail!(
                    "{label} snapshot {node:x} has non-antichain predecessors; {:x} is already an ancestor of another direct predecessor",
                    predecessor
                );
            }
        }
    }

    let superseded: BTreeSet<_> = nodes
        .values()
        .flat_map(|predecessors| predecessors.iter().copied())
        .collect();
    let heads: Vec<_> = nodes
        .keys()
        .filter(|id| !superseded.contains(*id))
        .copied()
        .collect();
    if !nodes.is_empty() && heads.is_empty() {
        bail!("{label} has no live head");
    }
    Ok(heads)
}

fn project_structure<P>(facts: &P) -> Result<RawCatalog>
where
    P: TriblePattern + ?Sized,
{
    let live = ids_of_kind(facts, KIND_LIVE_RECORD);
    let anchors = ids_of_kind(facts, KIND_PROFILE_ANCHOR_ID)
        .intersection(&live)
        .copied()
        .collect::<BTreeSet<_>>();
    let profile_ids = ids_of_kind(facts, KIND_MODEL_PROFILE_ID)
        .intersection(&live)
        .copied()
        .collect::<BTreeSet<_>>();
    let config_ids = ids_of_kind(facts, KIND_CONFIG_ID)
        .intersection(&live)
        .copied()
        .collect::<BTreeSet<_>>();
    if let Some(id) = anchors.intersection(&profile_ids).next() {
        bail!("Headspace entity {id:x} is both an anchor and profile snapshot");
    }
    if let Some(id) = anchors.intersection(&config_ids).next() {
        bail!("Headspace entity {id:x} is both an anchor and config snapshot");
    }
    if let Some(id) = profile_ids.intersection(&config_ids).next() {
        bail!("Headspace entity {id:x} is both a profile and config snapshot");
    }

    let mut raw = RawCatalog::default();
    let mut profile_graphs: BTreeMap<Id, BTreeMap<Id, Vec<Id>>> = BTreeMap::new();
    for id in profile_ids {
        let snapshot = raw_profile(facts, id)?;
        if !anchors.contains(&snapshot.anchor) {
            bail!(
                "profile snapshot {id:x} names undeclared anchor {:x}",
                snapshot.anchor
            );
        }
        profile_graphs
            .entry(snapshot.anchor)
            .or_default()
            .insert(id, snapshot.predecessors.clone());
        raw.profiles.insert(id, snapshot);
    }
    for &anchor in &anchors {
        let Some(graph) = profile_graphs.get(&anchor) else {
            bail!("profile anchor {anchor:x} has no profile snapshot");
        };
        raw.profile_heads.insert(
            anchor,
            dag_heads(graph, &format!("profile track {anchor:x}"))?,
        );
    }

    let mut config_graph = BTreeMap::new();
    for id in config_ids {
        let snapshot = raw_config(facts, id)?;
        if !anchors.contains(&snapshot.active_profile) {
            bail!(
                "config snapshot {id:x} names undeclared active profile {:x}",
                snapshot.active_profile
            );
        }
        config_graph.insert(id, snapshot.predecessors.clone());
        raw.config.insert(id, snapshot);
    }
    raw.config_heads = dag_heads(&config_graph, "config track")?;

    Ok(raw)
}

fn required_trimmed(value: &str, field: &str) -> Result<()> {
    if value.is_empty() || value.trim() != value || value.bytes().any(|byte| byte == 0) {
        bail!("Headspace {field} is empty, contains NUL, or has surrounding whitespace");
    }
    Ok(())
}

fn non_nul(value: &str, field: &str) -> Result<()> {
    if value.bytes().any(|byte| byte == 0) {
        bail!("Headspace {field} contains NUL");
    }
    Ok(())
}

fn validate_profile_value(value: &ProfileValue) -> Result<()> {
    required_trimmed(&value.name, "profile name")?;
    required_trimmed(&value.model, "model name")?;
    required_trimmed(&value.base_url, "model base URL")?;
    if let Some(value) = value.reasoning_effort.as_deref() {
        required_trimmed(value, "reasoning effort")?;
    }
    Ok(())
}

fn validate_config_value(value: &ConfigValue) -> Result<()> {
    non_nul(&value.system_prompt, "system prompt")?;
    required_trimmed(&value.author, "author")?;
    required_trimmed(&value.author_role, "author role")?;
    if let Some(value) = value.exec_default_cwd.as_deref() {
        non_nul(value, "execution cwd")?;
    }
    Ok(())
}

fn load_text_from(reader: &PileSnapshot, handle: TextHandle) -> Result<String> {
    let view: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Headspace text payload {}", hex::encode(handle.raw)))?;
    Ok(view.to_string())
}

fn load_text_overlay<Overlay>(
    reader: &PileSnapshot,
    overlay: Option<&Overlay>,
    handle: TextHandle,
) -> Result<String>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    if let Some(overlay) = overlay {
        if overlay
            .metadata(handle)
            .expect("memory metadata lookup is infallible")
            .is_some()
        {
            let view: View<str> = overlay.get(handle).with_context(|| {
                format!(
                    "read staged Headspace text payload {}",
                    hex::encode(handle.raw)
                )
            })?;
            return Ok(view.to_string());
        }
    }
    load_text_from(reader, handle)
}

fn project_catalog<P, Overlay>(
    reader: &PileSnapshot,
    overlay: Option<&Overlay>,
    facts: &P,
) -> Result<Catalog>
where
    P: TriblePattern + ?Sized,
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    let raw = project_structure(facts)?;
    let mut profile_snapshots = BTreeMap::new();
    let mut profiles_by_anchor: BTreeMap<Id, BTreeMap<Id, Snapshot<ProfileValue>>> =
        BTreeMap::new();
    for (&id, snapshot) in &raw.profiles {
        let stream = count_u64(snapshot.stream, id, "model_stream")?;
        if stream > 1 {
            bail!("Headspace profile {id:x} has model_stream {stream}; expected 0 or 1");
        }
        let value = ProfileValue {
            anchor: snapshot.anchor,
            name: load_text_overlay(reader, overlay, snapshot.name)?,
            model: load_text_overlay(reader, overlay, snapshot.model)?,
            base_url: load_text_overlay(reader, overlay, snapshot.base_url)?,
            model_secret_version: snapshot.model_secret_version,
            reasoning_effort: snapshot
                .reasoning_effort
                .map(|handle| load_text_overlay(reader, overlay, handle))
                .transpose()?,
            stream: stream == 1,
            context_window_tokens: count_u64(
                snapshot.context_window_tokens,
                id,
                "model_context_window_tokens",
            )?,
            max_output_tokens: count_u64(
                snapshot.max_output_tokens,
                id,
                "model_max_output_tokens",
            )?,
            context_safety_margin_tokens: count_u64(
                snapshot.context_safety_margin_tokens,
                id,
                "model_context_safety_margin_tokens",
            )?,
            chars_per_token: count_u64(snapshot.chars_per_token, id, "model_chars_per_token")?,
        };
        let snapshot = Snapshot {
            id,
            value,
            predecessors: snapshot.predecessors.clone(),
        };
        profiles_by_anchor
            .entry(snapshot.value.anchor)
            .or_default()
            .insert(id, snapshot.clone());
        profile_snapshots.insert(id, snapshot);
    }

    let mut config_snapshots = BTreeMap::new();
    for (&id, snapshot) in &raw.config {
        let value = ConfigValue {
            active_profile: snapshot.active_profile,
            system_prompt: load_text_overlay(reader, overlay, snapshot.system_prompt)?,
            cognition_scope: snapshot.cognition_scope,
            author: load_text_overlay(reader, overlay, snapshot.author)?,
            author_role: load_text_overlay(reader, overlay, snapshot.author_role)?,
            persona: snapshot.persona,
            poll_ms: count_u64(snapshot.poll_ms, id, "poll_ms")?,
            tavily_secret_version: snapshot.tavily_secret_version,
            exa_secret_version: snapshot.exa_secret_version,
            exec_default_cwd: snapshot
                .exec_default_cwd
                .map(|handle| load_text_overlay(reader, overlay, handle))
                .transpose()?,
            exec_sandbox_profile: snapshot.exec_sandbox_profile,
        };
        config_snapshots.insert(
            id,
            Snapshot {
                id,
                value,
                predecessors: snapshot.predecessors.clone(),
            },
        );
    }

    let config = resolve_track(&config_snapshots, &raw.config_heads);
    let profiles = profiles_by_anchor
        .into_iter()
        .map(|(anchor, snapshots)| {
            let resolution = resolve_track(&snapshots, &raw.profile_heads[&anchor]);
            (anchor, resolution)
        })
        .collect();
    Ok(Catalog {
        config,
        profiles,
        config_snapshots,
        profile_snapshots,
    })
}

/// Strictly validate one materialized import value.
///
/// Ordinary reads deliberately use the direct current-state queries instead:
/// derived ids are opaque, and unknown additive facts are legal in the
/// open-world model. This exact reconstruction remains only for explicit
/// untrusted migration and import boundaries where the historical format
/// itself is what is being checked.
fn parse_catalog_strict<Overlay>(
    reader: &PileSnapshot,
    overlay: Option<&Overlay>,
    facts: &TribleSet,
) -> Result<Catalog>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    let facts = active_facts(facts);
    let catalog = project_catalog(reader, overlay, &facts)?;
    let mut expected = TribleSet::new();
    for &anchor in catalog.profiles.keys() {
        expected += profile_anchor_fragment(anchor);
    }
    for (&id, snapshot) in &catalog.profile_snapshots {
        let (canonical, canonical_id) =
            profile_snapshot_fragment(&snapshot.value, &snapshot.predecessors)?;
        if id != canonical_id {
            bail!("profile snapshot {id:x} does not match intrinsic root {canonical_id:x}");
        }
        expected += canonical.into_facts();
    }
    for (&id, snapshot) in &catalog.config_snapshots {
        let (canonical, canonical_id) =
            config_snapshot_fragment(&snapshot.value, &snapshot.predecessors)?;
        if id != canonical_id {
            bail!("config snapshot {id:x} does not match intrinsic root {canonical_id:x}");
        }
        expected += canonical.into_facts();
    }
    if expected != facts {
        let missing = expected.difference(&facts).len();
        let unexpected = facts.difference(&expected).len();
        bail!(
            "Headspace import is not an exact canonical ontology ({missing} missing, {unexpected} unexpected facts)"
        );
    }
    Ok(catalog)
}

/// Validate one exact materialized Headspace collection. Forks are valid;
/// malformed records, wrong-track lineage, cycles, and missing payloads are
/// not.
pub fn validate_catalog(reader: &PileSnapshot, facts: &TribleSet) -> Result<()> {
    parse_catalog_strict(reader, None::<&PileSnapshot>, facts).map(drop)
}

/// Preflight the exact set union publication would create, including staged
/// text payloads, without writing pile bytes.
pub fn validate_catalog_union(
    reader: &PileSnapshot,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<Catalog> {
    let mut union = current.clone();
    union += fragment.facts().clone();
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .snapshot()
        .expect("MemoryBlobStore reader creation is infallible");
    parse_catalog_strict(reader, Some(&overlay), &union)
}

/// Project complete retained history, representing structural or payload
/// failure as `Resolution::Invalid` rather than choosing an implicit winner.
pub fn project<P>(reader: &PileSnapshot, facts: &P) -> Catalog
where
    P: TriblePattern + ?Sized,
{
    project_result(reader, facts).unwrap_or_else(Catalog::invalid)
}

/// Project complete retained history for an explicit historical operation.
pub fn project_result<P>(reader: &PileSnapshot, facts: &P) -> Result<Catalog>
where
    P: TriblePattern + ?Sized,
{
    project_catalog(reader, None::<&PileSnapshot>, facts)
}

/// Require every exact credential reference in every native snapshot to name
/// one extant immutable Secrets version.
///
/// Labels and timestamps are intentionally irrelevant: Headspace stores and
/// validates the exact version ids it will later open.
fn validate_secret_references_by(
    catalog: &Catalog,
    mut contains: impl FnMut(Id) -> bool,
) -> Result<()> {
    let mut references = Vec::new();
    for snapshot in catalog.profile_snapshots.values() {
        if let Some(secret) = snapshot.value.model_secret_version {
            references.push((snapshot.id, "model", secret));
        }
    }
    for snapshot in catalog.config_snapshots.values() {
        if let Some(secret) = snapshot.value.tavily_secret_version {
            references.push((snapshot.id, "Tavily", secret));
        }
        if let Some(secret) = snapshot.value.exa_secret_version {
            references.push((snapshot.id, "Exa", secret));
        }
    }
    for (snapshot, role, secret) in references {
        if !contains(secret) {
            bail!(
                "Headspace snapshot {snapshot:x} references missing exact {role} Secrets version {secret:x}"
            );
        }
    }
    Ok(())
}

/// Validate exact references against the aggregate configured Secrets view.
pub fn validate_secret_references<R>(
    catalog: &Catalog,
    secrets: &SecretsSnapshot<R>,
) -> Result<()> {
    validate_secret_references_by(catalog, |secret| secrets.contains(secret))
}

/// Resolve the one active config and its one settled profile.
///
/// Missing state and forks are visible failures rather than defaults or
/// timestamp arbitration. A caller wishing to bootstrap state must author a
/// profile/config genesis explicitly.
pub fn settled_active(catalog: &Catalog) -> Result<(&ConfigValue, &ProfileValue)> {
    let config = catalog
        .config
        .settled_value("Headspace config")?
        .ok_or_else(|| anyhow!("Headspace has no active configuration; add a profile first"))?;
    let profile = catalog
        .profiles
        .get(&config.active_profile)
        .ok_or_else(|| anyhow!("active profile {:x} is missing", config.active_profile))?
        .settled_value(&format!("profile {:x}", config.active_profile))?
        .ok_or_else(|| anyhow!("active profile {:x} has no snapshot", config.active_profile))?;
    Ok((config, profile))
}

fn open_utf8_secret<R: BlobStoreGet>(
    secrets: &SecretsSnapshot<R>,
    secret: Option<Id>,
    signing_key: &SigningKey,
    role: &str,
) -> Result<Option<String>> {
    let Some(secret) = secret else {
        return Ok(None);
    };
    let plaintext = secrets
        .open(secret, signing_key)
        .with_context(|| format!("open exact {role} Secrets version {secret:x}"))?;
    String::from_utf8(plaintext)
        .with_context(|| format!("exact {role} Secrets version {secret:x} is not UTF-8"))
        .map(Some)
}

/// Open the credentials referenced by the resolved active Headspace.
///
/// Each lookup is by the exact immutable version id stored in the snapshot;
/// this function never invokes Secrets' label-based latest-version helper.
pub fn open_active_secrets<R: BlobStoreGet>(
    headspace: &Catalog,
    secrets: &SecretsSnapshot<R>,
    signing_key: &SigningKey,
) -> Result<OpenedSecrets> {
    let (config, profile) = settled_active(headspace)?;
    Ok(OpenedSecrets {
        model_api_key: open_utf8_secret(
            secrets,
            profile.model_secret_version,
            signing_key,
            "model",
        )?,
        tavily_api_key: open_utf8_secret(
            secrets,
            config.tavily_secret_version,
            signing_key,
            "Tavily",
        )?,
        exa_api_key: open_utf8_secret(secrets, config.exa_secret_version, signing_key, "Exa")?,
    })
}

/// Strictly load direct legacy Headspace text attachments.
///
/// Generic migration additionally carries the complete resident closure, so
/// unknown future payloads remain preserved rather than filtered out.
pub fn validate_known_payloads(reader: &PileSnapshot, facts: &TribleSet) -> Result<()> {
    let text_attributes = [
        metadata::name.id(),
        metadata::description.id(),
        playground_config::system_prompt.id(),
        playground_config::branch.id(),
        playground_config::author.id(),
        playground_config::author_role.id(),
        playground_config::model_name.id(),
        playground_config::model_base_url.id(),
        playground_config::model_api_key.id(),
        playground_config::tavily_api_key.id(),
        playground_config::exa_api_key.id(),
        playground_config::model_reasoning_effort.id(),
        playground_config::exec_default_cwd.id(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    for fact in facts {
        if text_attributes.contains(fact.a()) {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "read frozen Headspace text payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

fn resolve_track<T: Clone + Eq>(
    snapshots: &BTreeMap<Id, Snapshot<T>>,
    heads: &[Id],
) -> Resolution<T> {
    if snapshots.is_empty() {
        return Resolution::Missing;
    }
    let heads: Vec<_> = heads.iter().map(|id| snapshots[id].clone()).collect();
    match heads.as_slice() {
        [] => unreachable!("validated non-empty track has a head"),
        [snapshot] => Resolution::Unique(snapshot.clone()),
        _ if heads
            .iter()
            .all(|snapshot| snapshot.value == heads[0].value) =>
        {
            Resolution::Agreed(heads)
        }
        _ => Resolution::Forked(heads),
    }
}

fn format_ids(ids: impl IntoIterator<Item = Id>) -> String {
    ids.into_iter()
        .map(|id| format!("{id:x}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::path::Path;

    use ed25519_dalek::SigningKey;
    use triblespace::core::collection::CollectionSnapshotExt;
    use triblespace::core::repo::pile::Pile;

    use crate::collection_names::open_configured;
    use crate::schemas::headspace::{playground_config, DEFAULT_SCOPE_ID, KIND_LIVE_RECORD};
    use crate::secrets;
    use crate::storage::{
        open_secrets_collection, open_secrets_collection_read, FactArchive, FactCollection,
    };
    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at(second: i64) -> Inline<inlineencodings::NsTAIInterval> {
        let epoch = hifitime::Epoch::from_unix_seconds(second as f64);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn test_pile(path: &Path) -> Pile {
        File::create(path).unwrap();
        let mut pile = Pile::open(path).unwrap();
        pile.refresh().unwrap();
        pile
    }

    fn materialize(pile: &mut Pile, scope: Id, signer: &SigningKey) -> (FactArchive, PileSnapshot) {
        let source = open_configured(pile, scope, signer.verifying_key()).unwrap();
        let collection = FactCollection::new(pile, source).unwrap();
        let instant = crate::clock::now().unwrap();
        let before = pile.snapshot().unwrap();
        let reader = pollster::block_on(collection.maintain_at(pile, &before, instant)).unwrap();
        drop(before);
        let facts = reader
            .collection_at(collection.rank9(), instant)
            .unwrap()
            .view::<FactArchive>()
            .unwrap();
        (facts, reader)
    }

    fn commit(pile: &mut Pile, scope: Id, signer: &SigningKey, fragment: Fragment) {
        let collection = open_configured(pile, scope, signer.verifying_key()).unwrap();
        pile.commit(collection, signer, fragment).unwrap();
    }

    #[test]
    fn snapshot_identity_is_retry_stable_and_predecessor_order_independent() {
        let value = default_profile(test_id(0x12), "stable");
        let a = test_id(0x13);
        let b = test_id(0x14);
        let (first, first_id) = profile_snapshot_fragment(&value, &[b, a, b]).unwrap();
        let (second, second_id) = profile_snapshot_fragment(&value, &[a, b]).unwrap();
        assert_eq!(first, second);
        assert_eq!(first_id, second_id);
    }

    #[test]
    fn fork_visible_resolution_keeps_divergent_and_agreed_heads() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("headspace.pile");
        let mut pile = test_pile(&path);
        let signer = SigningKey::from_bytes(&[0x21; 32]);
        let anchor = test_id(0x11);
        let profile = default_profile(anchor, "default");
        let config = default_config(anchor);
        let (genesis, profile_head, _) = add_profile_fragment(&profile, &config, &[]).unwrap();
        commit(&mut pile, DEFAULT_SCOPE_ID, &signer, genesis);

        let mut left = profile.clone();
        left.model = "left".to_owned();
        let mut right = profile.clone();
        right.model = "right".to_owned();
        let (left_fragment, left_id) = profile_snapshot_fragment(&left, &[profile_head]).unwrap();
        let (right_fragment, right_id) =
            profile_snapshot_fragment(&right, &[profile_head]).unwrap();
        commit(&mut pile, DEFAULT_SCOPE_ID, &signer, left_fragment);
        commit(&mut pile, DEFAULT_SCOPE_ID, &signer, right_fragment);

        let (facts, reader) = materialize(&mut pile, DEFAULT_SCOPE_ID, &signer);
        let catalog = project_result(&reader, &facts).unwrap();
        assert!(matches!(
            catalog.profiles[&anchor],
            Resolution::Forked(ref heads) if heads.len() == 2
        ));

        let (left_join, left_join_id) = profile_snapshot_fragment(&profile, &[left_id]).unwrap();
        let (right_join, right_join_id) = profile_snapshot_fragment(&profile, &[right_id]).unwrap();
        commit(&mut pile, DEFAULT_SCOPE_ID, &signer, left_join);
        commit(&mut pile, DEFAULT_SCOPE_ID, &signer, right_join);

        let (facts, reader) = materialize(&mut pile, DEFAULT_SCOPE_ID, &signer);
        let catalog = project_result(&reader, &facts).unwrap();
        assert!(matches!(
            catalog.profiles[&anchor],
            Resolution::Agreed(ref heads)
                if heads.iter().map(|head| head.id).collect::<BTreeSet<_>>()
                    == BTreeSet::from([left_join_id, right_join_id])
        ));
        pile.close().unwrap();
    }

    #[test]
    fn missing_and_ambiguous_config_are_visible_failures() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("headspace.pile");
        let mut pile = test_pile(&path);
        let signer = SigningKey::from_bytes(&[0x22; 32]);
        let anchor = test_id(0x23);
        let profile = default_profile(anchor, "only-profile");
        let mut profile_only = profile_anchor_fragment(anchor);
        profile_only += profile_snapshot_fragment(&profile, &[]).unwrap().0;
        commit(&mut pile, DEFAULT_SCOPE_ID, &signer, profile_only);

        let (facts, reader) = materialize(&mut pile, DEFAULT_SCOPE_ID, &signer);
        let catalog = project_result(&reader, &facts).unwrap();
        assert!(matches!(catalog.config, Resolution::Missing));
        assert!(format!("{:#}", settled_active(&catalog).unwrap_err())
            .contains("no active configuration"));

        let first = default_config(anchor);
        let mut second = first.clone();
        second.author = "other".to_owned();
        commit(
            &mut pile,
            DEFAULT_SCOPE_ID,
            &signer,
            config_snapshot_fragment(&first, &[]).unwrap().0,
        );
        commit(
            &mut pile,
            DEFAULT_SCOPE_ID,
            &signer,
            config_snapshot_fragment(&second, &[]).unwrap().0,
        );
        let (facts, reader) = materialize(&mut pile, DEFAULT_SCOPE_ID, &signer);
        let catalog = project_result(&reader, &facts).unwrap();
        assert!(matches!(catalog.config, Resolution::Forked(ref heads) if heads.len() == 2));
        assert!(format!("{:#}", settled_active(&catalog).unwrap_err()).contains("forked"));
        pile.close().unwrap();
    }

    #[test]
    fn native_records_hold_exact_secret_ids_and_no_plaintext_payload() {
        let anchor = test_id(0x31);
        let secret = test_id(0x32);
        let mut profile = default_profile(anchor, "private");
        profile.model_secret_version = Some(secret);
        let mut config = default_config(anchor);
        config.tavily_secret_version = Some(secret);
        config.exa_secret_version = Some(secret);
        let (fragment, _, _) = add_profile_fragment(&profile, &config, &[]).unwrap();
        let secret_inline: Inline<inlineencodings::GenId> = secret.to_inline();

        assert!(!fragment.facts().iter().any(|fact| {
            [
                playground_config::model_api_key.id(),
                playground_config::tavily_api_key.id(),
                playground_config::exa_api_key.id(),
            ]
            .contains(fact.a())
        }));
        assert!(fragment
            .facts()
            .iter()
            .filter(|fact| {
                [
                    playground_config::model_secret_version.id(),
                    playground_config::tavily_secret_version.id(),
                    playground_config::exa_secret_version.id(),
                ]
                .contains(fact.a())
            })
            .all(|fact| fact.v::<inlineencodings::GenId>() == &secret_inline));
    }

    #[test]
    fn exact_secret_opening_ignores_a_newer_same_label_version() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("headspace.pile");
        let mut pile = test_pile(&path);
        let signer = SigningKey::from_bytes(&[0x41; 32]);
        let collection = open_secrets_collection(&mut pile, signer.verifying_key()).unwrap();
        let first_id = secrets::storage::add_secret(
            &mut pile,
            &signer,
            collection,
            "hs/model",
            b"first",
            at(3),
        )
        .unwrap();
        secrets::storage::add_secret(&mut pile, &signer, collection, "hs/model", b"second", at(4))
            .unwrap();
        let instant = triblespace::core::clock::epoch_now();
        let collection =
            open_secrets_collection_read(&mut pile, signer.verifying_key(), instant).unwrap();
        let secrets = pollster::block_on(secrets::storage::ensure_and_snapshot(
            &mut pile,
            [collection],
            instant,
        ))
        .unwrap();

        let anchor = test_id(0x42);
        let mut profile = default_profile(anchor, "exact");
        profile.model_secret_version = Some(first_id);
        let config = default_config(anchor);
        commit(
            &mut pile,
            DEFAULT_SCOPE_ID,
            &signer,
            add_profile_fragment(&profile, &config, &[]).unwrap().0,
        );

        let (headspace_facts, headspace_reader) = materialize(&mut pile, DEFAULT_SCOPE_ID, &signer);
        let headspace = project_result(&headspace_reader, &headspace_facts).unwrap();
        validate_secret_references(&headspace, &secrets).unwrap();
        let opened = open_active_secrets(&headspace, &secrets, &signer).unwrap();
        assert_eq!(opened.model_api_key.as_deref(), Some("first"));
        pile.close().unwrap();
    }

    #[test]
    fn missing_exact_secret_reference_is_rejected() {
        let anchor = test_id(0x51);
        let mut profile = default_profile(anchor, "missing");
        profile.model_secret_version = Some(test_id(0x52));
        let (fragment, _, _) =
            add_profile_fragment(&profile, &default_config(anchor), &[]).unwrap();

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("headspace.pile");
        let mut pile = test_pile(&path);
        let signer = SigningKey::from_bytes(&[0x53; 32]);
        commit(&mut pile, DEFAULT_SCOPE_ID, &signer, fragment);
        let (facts, reader) = materialize(&mut pile, DEFAULT_SCOPE_ID, &signer);
        let catalog = project_result(&reader, &facts).unwrap();
        let instant = triblespace::core::clock::epoch_now();
        let collection =
            open_secrets_collection_read(&mut pile, signer.verifying_key(), instant).unwrap();
        let secrets = pollster::block_on(secrets::storage::ensure_and_snapshot(
            &mut pile,
            [collection],
            instant,
        ))
        .unwrap();
        let error = validate_secret_references(&catalog, &secrets).unwrap_err();
        assert!(format!("{error:#}").contains("missing exact model"));
        pile.close().unwrap();
    }

    #[test]
    fn historical_plaintext_is_exactly_present_but_semantically_inert() {
        let legacy_subject = test_id(0x61);
        let legacy_id = ExclusiveId::force_ref(&legacy_subject);
        let mut legacy = Fragment::empty();
        let plaintext = legacy.put("do-not-activate".to_owned());
        legacy += entity! { legacy_id @
            metadata::tag: &KIND_MODEL_PROFILE_ID,
            playground_config::model_api_key: plaintext,
        };
        assert!(active_facts(legacy.facts()).is_empty());

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("headspace.pile");
        let mut pile = test_pile(&path);
        let signer = SigningKey::from_bytes(&[0x62; 32]);
        commit(&mut pile, DEFAULT_SCOPE_ID, &signer, legacy.clone());
        let (facts, reader) = materialize(&mut pile, DEFAULT_SCOPE_ID, &signer);
        let materialized = facts.iter().collect::<TribleSet>();
        assert!(legacy
            .facts()
            .iter()
            .all(|fact| materialized.contains(fact)));
        let catalog = project_result(&reader, &facts).unwrap();
        assert!(matches!(catalog.config, Resolution::Missing));
        assert!(catalog.profiles.is_empty());

        let graft = entity! { legacy_id @ metadata::tag: &KIND_LIVE_RECORD };
        let error = validate_catalog_union(&reader, &materialized, &graft).unwrap_err();
        assert!(
            format!("{error:#}").contains("expected exactly one")
                || format!("{error:#}").contains("exact canonical ontology")
        );
        pile.close().unwrap();
    }
}
