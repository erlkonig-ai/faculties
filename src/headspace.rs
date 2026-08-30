//! Collection-native Headspace state and its fork-visible snapshot algebra.
//!
//! Headspace has exactly two kinds of changing state: one global config track
//! and one profile track per authored profile anchor. Every change is a
//! complete intrinsic snapshot. `metadata::supersedes` carries lineage, set
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
//! inert.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
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
/// one representative. Exact-ontology failures are catalog-wide: [`project`]
/// exposes them as `Catalog::config = Invalid` and no partial profile view,
/// while [`project_result`] returns the error directly.
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

/// The complete shared projection consumed by every Headspace reader.
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

fn ids_of_kind(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
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

fn raw_profile(facts: &TribleSet, id: Id) -> Result<RawProfileSnapshot> {
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

fn raw_config(facts: &TribleSet, id: Id) -> Result<RawConfigSnapshot> {
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

fn validate_structure(facts: &TribleSet) -> Result<RawCatalog> {
    let anchors = ids_of_kind(facts, KIND_PROFILE_ANCHOR_ID);
    let profile_ids = ids_of_kind(facts, KIND_MODEL_PROFILE_ID);
    let config_ids = ids_of_kind(facts, KIND_CONFIG_ID);
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

fn load_text_from(reader: &PileReader, handle: TextHandle) -> Result<String> {
    let view: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Headspace text payload {}", hex::encode(handle.raw)))?;
    Ok(view.to_string())
}

fn load_text_overlay<Overlay>(
    reader: &PileReader,
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

fn parse_catalog<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    facts: &TribleSet,
) -> Result<Catalog>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    let facts = active_facts(facts);
    let raw = validate_structure(&facts)?;
    let mut expected = TribleSet::new();
    for &anchor in raw.profile_heads.keys() {
        expected += profile_anchor_fragment(anchor);
    }
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
        let (canonical, canonical_id) = profile_snapshot_fragment(&value, &snapshot.predecessors)?;
        if id != canonical_id {
            bail!("profile snapshot {id:x} does not match intrinsic root {canonical_id:x}");
        }
        expected += canonical.into_facts();
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
        let (canonical, canonical_id) = config_snapshot_fragment(&value, &snapshot.predecessors)?;
        if id != canonical_id {
            bail!("config snapshot {id:x} does not match intrinsic root {canonical_id:x}");
        }
        expected += canonical.into_facts();
        config_snapshots.insert(
            id,
            Snapshot {
                id,
                value,
                predecessors: snapshot.predecessors.clone(),
            },
        );
    }

    if expected != facts {
        let missing = expected.difference(&facts).len();
        let unexpected = facts.difference(&expected).len();
        bail!(
            "Headspace catalog is not an exact canonical ontology ({missing} missing, {unexpected} unexpected facts)"
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

/// Validate one exact materialized Headspace collection. Forks are valid;
/// malformed records, wrong-track lineage, cycles, and missing payloads are
/// not.
pub fn validate_catalog(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    parse_catalog(reader, None::<&PileReader>, facts).map(drop)
}

/// Preflight the exact set union publication would create, including staged
/// text payloads, without writing pile bytes.
pub fn validate_catalog_union(
    reader: &PileReader,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<Catalog> {
    let mut union = current.clone();
    union += fragment.facts().clone();
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .expect("MemoryBlobStore reader creation is infallible");
    parse_catalog(reader, Some(&overlay), &union)
}

/// Resolve the exact catalog. Structural or payload failure is represented as
/// `Resolution::Invalid`, never as defaults or an implicit winner.
pub fn project(reader: &PileReader, facts: &TribleSet) -> Catalog {
    project_result(reader, facts).unwrap_or_else(Catalog::invalid)
}

pub fn project_result(reader: &PileReader, facts: &TribleSet) -> Result<Catalog> {
    parse_catalog(reader, None::<&PileReader>, facts)
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

/// Validate exact references against the aggregate of ready vault epochs.
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
    validate_secret_references(headspace, secrets)?;
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
pub fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
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
    use triblespace::core::collection::CollectionStoreExt;
    use triblespace::core::repo::pile::Pile;
    use triblespace::core::repo::BlobStore;

    use crate::legacy_hint::open_scope;
    use crate::schemas::headspace::{playground_config, DEFAULT_SCOPE_ID, KIND_LIVE_RECORD};
    use crate::secrets;
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

    fn materialize(pile: &mut Pile, scope: Id, signer: &SigningKey) -> (TribleSet, PileReader) {
        let collection = open_scope(pile, scope, signer).unwrap();
        let (facts, _, reader) = pile.snapshot(collection).unwrap().into_parts();
        (facts, reader)
    }

    fn commit(pile: &mut Pile, scope: Id, signer: &SigningKey, fragment: Fragment) {
        let collection = open_scope(pile, scope, signer).unwrap();
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
        let vault = test_id(0x40);
        let location =
            secrets::storage::create_vault(&mut pile, &signer, vault, "headspace-test", at(2))
                .unwrap();
        let discovery = secrets::storage::discover_local_vaults(&mut pile, &signer).unwrap();
        let first_id = secrets::storage::add_secret(
            &mut pile,
            &signer,
            &location,
            discovery.snapshot(),
            "hs/model",
            b"first",
            at(3),
        )
        .unwrap();
        drop(discovery);
        let discovery = secrets::storage::discover_local_vaults(&mut pile, &signer).unwrap();
        secrets::storage::add_secret(
            &mut pile,
            &signer,
            &location,
            discovery.snapshot(),
            "hs/model",
            b"second",
            at(4),
        )
        .unwrap();
        drop(discovery);
        let discovery = secrets::storage::discover_local_vaults(&mut pile, &signer).unwrap();
        let secrets = discovery.snapshot();

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
        validate_secret_references(&headspace, secrets).unwrap();
        let opened = open_active_secrets(&headspace, secrets, &signer).unwrap();
        assert_eq!(opened.model_api_key.as_deref(), Some("first"));
        drop(discovery);
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
        let mut empty = Fragment::empty();
        let secrets = SecretsSnapshot::new(
            empty.blobs_mut().reader().unwrap(),
            Vec::<(Id, TribleSet)>::new(),
        )
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
        assert!(legacy.facts().iter().all(|fact| facts.contains(fact)));
        let catalog = project_result(&reader, &facts).unwrap();
        assert!(matches!(catalog.config, Resolution::Missing));
        assert!(catalog.profiles.is_empty());

        let graft = entity! { legacy_id @ metadata::tag: &KIND_LIVE_RECORD };
        let error = validate_catalog_union(&reader, &facts, &graft).unwrap_err();
        assert!(
            format!("{error:#}").contains("expected exactly one")
                || format!("{error:#}").contains("exact canonical ontology")
        );
        pile.close().unwrap();
    }
}
