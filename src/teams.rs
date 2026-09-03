//! Canonical Teams collection semantics shared by the faculty and cutovers.
//!
//! Network transport, OAuth, and CLI presentation live in `bin/teams.rs`.
//! This module owns the monotone data model: intrinsic source/context/receipt
//! construction, receipt-DAG evaluation, and catalog validation. Keeping that
//! seam shared is especially important for the generation-0 legacy snapshot:
//! migrated history and the first genuine Graph page must agree on one causal
//! interpretation.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{bail, Context, Result};
use hifitime::Epoch;
use triblespace::core::blob::Bytes;
use triblespace::core::inline::encodings::genid::GenId;
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, ShortString, U256BE};
use triblespace::prelude::*;

use crate::files;
use crate::schemas::archive::archive;
use crate::schemas::files::{file, KIND_FILE, KIND_MEDIA_TYPE};
use crate::schemas::teams::teams;
use crate::secrets::SecretsSnapshot;

const SNAPSHOT_COORDINATE_PREFIX: &str = "teams-legacy-snapshot-v1:";

// These identifiers were published by the legacy Teams Repository schema.
// They are recognized only to keep plaintext OAuth evidence out of the
// semantic Teams collection. The migration module remains the sole decoder of the
// retired rows.
const RETIRED_OAUTH_KINDS: [Id; 2] = [
    id_hex!("7B6DBE9FD29182D97F1699437CF6627C"),
    id_hex!("0D7F4BBE36BD0D6FF4E6C651110D6E8B"),
];
const RETIRED_OAUTH_SECRET_ATTRIBUTES: [Id; 3] = [
    id_hex!("438A29922F91F873A69C3856AA7A553F"),
    id_hex!("60C85DD37D09D3D27BC6BFA0E8040EA9"),
    id_hex!("0E734F66EBBA45ED022D1EE539B11EBE"),
];

pub type TextHandle = Inline<Handle<UTF8String>>;

/// One usable head of the source-scoped receipt DAG.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageHead {
    pub id: Id,
    pub generation: u128,
    /// Absent only for a generation-0 frozen legacy snapshot. The next pull
    /// must then use Graph's base endpoint and supersede this head.
    pub cursor: Option<String>,
}

/// Complete public state of one immutable Teams authentication profile.
/// Secret-bearing values live in explicit Secrets vault epochs; these fields
/// are exact immutable version references, never names resolved by time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthProfileRecord {
    pub id: Id,
    pub source: Id,
    pub client_id: TextHandle,
    pub user_id: TextHandle,
    pub scopes: TextHandle,
    pub client_secret_version: Option<Id>,
    pub delegated_token_version: Option<Id>,
    pub predecessors: Vec<Id>,
}

/// Explicit state of a source-scoped auth-profile frontier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthProfileHead {
    Missing,
    Unique(Id),
    Forked(Vec<Id>),
}

/// Causally selected current visibility of one logical message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurrentMessageState {
    Present(Id),
    Deleted(Option<Id>),
}

/// Canonical current presentation of one logical Teams message.
///
/// The receipt DAG, rather than timestamps or iteration order, selects the
/// observation. A source-level causal fork is returned as an error by
/// [`current_messages`] and must remain visible at the caller boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentMessage {
    pub message: Id,
    pub observation: Option<Id>,
    pub chat: Id,
    pub deleted: bool,
    pub created_at: Option<Inline<NsTAIInterval>>,
    pub modified_at: Option<Inline<NsTAIInterval>>,
    pub author: Option<Id>,
    pub author_names: Vec<TextHandle>,
    pub content: Option<TextHandle>,
    pub attachments: Vec<Id>,
}

/// Construct the intrinsic source entity for one concrete tenant.
pub fn source_fragment(tenant: &str) -> Fragment {
    let mut source = Fragment::empty();
    let tenant = source.put::<UTF8String, _>(canonical_tenant(tenant));
    source += entity! {
        metadata::tag: teams::kind_source,
        teams::tenant_id: tenant,
    };
    source
}

/// Construct one immutable professional-context version.
pub fn context_fragment(
    source: Id,
    created_at: Inline<NsTAIInterval>,
    predecessors: impl IntoIterator<Item = Id>,
    name: &str,
    boundary: &str,
) -> Result<Fragment> {
    let name = name.trim();
    let boundary = boundary.trim();
    if name.is_empty() || boundary.is_empty() {
        bail!("Teams context name and boundary must not be empty");
    }
    let predecessors = predecessors.into_iter().collect::<BTreeSet<_>>();
    let mut fragment = Fragment::empty();
    let name = fragment.put::<UTF8String, _>(name.to_owned());
    let boundary = fragment.put::<UTF8String, _>(boundary.to_owned());
    fragment += entity! {
        metadata::tag: teams::kind_context,
        teams::source: source,
        metadata::created_at: created_at,
        metadata::supersedes*: predecessors,
        metadata::name: name,
        metadata::description: boundary,
    };
    Ok(fragment)
}

fn canonical_nonempty(value: &str, field: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("{field} must not be empty");
    }
    Ok(value.to_owned())
}

/// Canonicalize delegated OAuth scopes as a set. OAuth scope order carries no
/// meaning, so profile identity must not depend on caller ordering.
pub fn canonical_auth_scopes(scopes: &str) -> Result<String> {
    let values = scopes
        .split_whitespace()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if values.is_empty() {
        bail!("Teams delegated scopes must not be empty");
    }
    Ok(values.into_iter().collect::<Vec<_>>().join(" "))
}

fn auth_profile_record(record: &AuthProfileRecord) -> Fragment {
    entity! {
        metadata::tag: teams::kind_auth_profile,
        teams::source: record.source,
        teams::auth_client_id: record.client_id,
        teams::auth_user_id: record.user_id,
        teams::auth_scopes: record.scopes,
        teams::auth_client_secret_version?: record.client_secret_version,
        teams::auth_delegated_token_version?: record.delegated_token_version,
        metadata::supersedes*: record.predecessors.iter(),
    }
}

/// Construct one intrinsic full-state authentication profile.
///
/// At least one exact Secrets version is required. A delegated-only profile
/// can drive user operations; adding a client-secret version also enables the
/// app-only delta endpoint. Replacing either secret produces a successor that
/// retains the independently rotating other reference.
#[allow(clippy::too_many_arguments)]
pub fn auth_profile_fragment(
    source: Id,
    client_id: &str,
    user_id: &str,
    scopes: &str,
    client_secret_version: Option<Id>,
    delegated_token_version: Option<Id>,
    predecessors: impl IntoIterator<Item = Id>,
) -> Result<(Fragment, Id)> {
    if client_secret_version.is_none() && delegated_token_version.is_none() {
        bail!("Teams auth profile requires at least one exact Secrets version");
    }
    let client_id = canonical_nonempty(client_id, "Teams client id")?;
    let user_id = canonical_nonempty(user_id, "Teams user id")?;
    let scopes = canonical_auth_scopes(scopes)?;
    let predecessors = predecessors.into_iter().collect::<BTreeSet<_>>();
    let mut fragment = Fragment::empty();
    let record = AuthProfileRecord {
        id: source,
        source,
        client_id: fragment.put::<UTF8String, _>(client_id),
        user_id: fragment.put::<UTF8String, _>(user_id),
        scopes: fragment.put::<UTF8String, _>(scopes),
        client_secret_version,
        delegated_token_version,
        predecessors: predecessors.into_iter().collect(),
    };
    let profile = auth_profile_record(&record);
    let id = profile.root().expect("Teams auth profile has one root");
    fragment += profile;
    Ok((fragment, id))
}

/// Decode one auth-profile record without selecting a current head.
pub fn auth_profile<P>(catalog: &P, id: Id) -> Result<AuthProfileRecord>
where
    P: TriblePattern,
{
    Ok(AuthProfileRecord {
        id,
        source: one_required(
            find!(value: Id, pattern!(catalog, [{ id @ teams::source: ?value }])).collect(),
            "Teams auth-profile source",
        )?,
        client_id: one_required(
            find!(value: TextHandle, pattern!(catalog, [{ id @ teams::auth_client_id: ?value }]))
                .collect(),
            "Teams auth-profile client id",
        )?,
        user_id: one_required(
            find!(value: TextHandle, pattern!(catalog, [{ id @ teams::auth_user_id: ?value }]))
                .collect(),
            "Teams auth-profile user id",
        )?,
        scopes: one_required(
            find!(value: TextHandle, pattern!(catalog, [{ id @ teams::auth_scopes: ?value }]))
                .collect(),
            "Teams auth-profile scopes",
        )?,
        client_secret_version: one_optional(
            find!(value: Id, pattern!(catalog, [{ id @ teams::auth_client_secret_version: ?value }]))
                .collect(),
            "Teams auth-profile client-secret version",
        )?,
        delegated_token_version: one_optional(
            find!(value: Id, pattern!(catalog, [{ id @ teams::auth_delegated_token_version: ?value }]))
                .collect(),
            "Teams auth-profile delegated-token version",
        )?,
        predecessors: find!(
            value: Id,
            pattern!(catalog, [{ id @ metadata::supersedes: ?value }])
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect(),
    })
}

pub fn auth_profile_ids<P>(catalog: &P, source: Id) -> BTreeSet<Id>
where
    P: TriblePattern,
{
    find!(
        profile: Id,
        pattern!(catalog, [{
            ?profile @
            metadata::tag: teams::kind_auth_profile,
            teams::source: source,
        }])
    )
    .collect()
}

/// Sources for which at least one auth-profile version exists.
pub fn auth_profile_sources<P>(catalog: &P) -> BTreeSet<Id>
where
    P: TriblePattern,
{
    find!(
        source: Id,
        pattern!(catalog, [{
            _?profile @
            metadata::tag: teams::kind_auth_profile,
            teams::source: ?source,
        }])
    )
    .collect()
}

pub fn auth_profile_head_ids<P>(catalog: &P, source: Id) -> BTreeSet<Id>
where
    P: TriblePattern,
{
    let profiles = auth_profile_ids(catalog, source);
    let superseded = find!(
        predecessor: Id,
        pattern!(catalog, [{
            _?successor @
            metadata::tag: teams::kind_auth_profile,
            teams::source: source,
            metadata::supersedes: ?predecessor,
        }])
    )
    .collect::<BTreeSet<_>>();
    profiles.difference(&superseded).copied().collect()
}

pub fn auth_profile_head<P>(catalog: &P, source: Id) -> AuthProfileHead
where
    P: TriblePattern,
{
    let heads = auth_profile_head_ids(catalog, source)
        .into_iter()
        .collect::<Vec<_>>();
    match heads.as_slice() {
        [] => AuthProfileHead::Missing,
        [id] => AuthProfileHead::Unique(*id),
        _ => AuthProfileHead::Forked(heads),
    }
}

/// Validate the active auth-profile references against one discovered Secrets
/// vault snapshot. This deliberately performs no name or timestamp resolution.
///
/// Superseded profiles are provenance, not live configuration. Their exact
/// secret versions may legitimately have been left behind by a vault cutover;
/// requiring those historical versions would make an additive successor
/// unable to repair the active profile.
pub fn validate_auth_secret_references<R, P>(
    teams_catalog: &P,
    secrets: &SecretsSnapshot<R>,
) -> Result<()>
where
    P: TriblePattern,
{
    validate_auth_secret_references_for_sources(
        teams_catalog,
        secrets,
        auth_profile_sources(teams_catalog),
    )
}

/// Validate active auth-profile references only for the named sources.
///
/// This is the publication-boundary form: a candidate update cannot be
/// blocked by unrelated historical profiles elsewhere in the collection.
pub fn validate_auth_secret_references_for_sources<R, P>(
    teams_catalog: &P,
    secrets: &SecretsSnapshot<R>,
    sources: impl IntoIterator<Item = Id>,
) -> Result<()>
where
    P: TriblePattern,
{
    for source in sources {
        for profile in auth_profile_head_ids(teams_catalog, source) {
            let record = auth_profile(teams_catalog, profile)?;
            for (label, secret) in [
                ("client secret", record.client_secret_version),
                ("delegated token bundle", record.delegated_token_version),
            ] {
                if let Some(secret) = secret {
                    if !secrets.contains(secret) {
                        bail!(
                            "Teams auth profile {profile:x} names unknown {label} Secrets version {secret:x}"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

/// Optional canonical byte materialization of one attachment occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentMaterialization {
    pub bytes: Vec<u8>,
    pub file_name: String,
    pub media_type: String,
}

/// Exact source evidence for one attachment occurrence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentInput {
    pub kind: String,
    pub source_id: String,
    pub name: Option<String>,
    pub source_pointers: BTreeSet<String>,
    pub materialization: Option<AttachmentMaterialization>,
}

/// One complete immutable Graph message observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageObservationInput {
    pub chat_id: String,
    pub message_id: String,
    /// Exact source representations. Distinct raw encodings of the same Graph
    /// version are additive evidence and therefore repeated values.
    pub raw: BTreeSet<String>,
    pub author_user_id: Option<String>,
    pub author_name: Option<String>,
    pub content: Option<String>,
    pub created_at: Option<Inline<NsTAIInterval>>,
    pub modified_at: Inline<NsTAIInterval>,
    pub deleted_at: Option<Inline<NsTAIInterval>>,
    pub etag: String,
    pub attachments: Vec<AttachmentInput>,
}

/// Construct a complete independently valid observation transaction.
///
/// The returned fragment includes the source identity closure expected by a
/// signed Teams COMMIT. It does not include a receipt; callers may aggregate
/// several observations and then add one exact page/snapshot receipt.
pub fn observation_fragment(
    tenant: &str,
    expected_source: Id,
    input: MessageObservationInput,
) -> Result<(Fragment, Id)> {
    if input.raw.is_empty() {
        bail!("Teams observation requires at least one raw source representation");
    }
    if input.etag.trim().is_empty() {
        bail!("Teams observation requires a Graph etag");
    }
    let deleted = input.deleted_at.is_some();
    if !deleted && (input.created_at.is_none() || input.content.is_none()) {
        bail!("present Teams observation requires created time and content");
    }

    let mut fragment = source_fragment(tenant);
    if fragment.root() != Some(expected_source) {
        bail!("Teams tenant/source identity mismatch while constructing observation");
    }
    let chat_external = fragment.put::<UTF8String, _>(input.chat_id);
    let chat = entity! {
        metadata::tag: teams::kind_chat,
        teams::source: expected_source,
        teams::chat_id: chat_external,
    };
    let chat_id = chat.root().expect("Teams chat has one root");
    fragment += chat;
    let message_external = fragment.put::<UTF8String, _>(input.message_id);
    let message = entity! {
        metadata::tag: archive::kind_message,
        teams::chat: chat_id,
        teams::message_id: message_external,
    };
    let message_id = message.root().expect("Teams message has one root");
    fragment += message;

    let author = input
        .author_user_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|external| {
            let external = fragment.put::<UTF8String, _>(external.to_owned());
            let author = entity! {
                metadata::tag: archive::kind_author,
                teams::source: expected_source,
                teams::user_id: external,
            };
            let id = author.root().expect("Teams author has one root");
            fragment += author;
            id
        });

    let mut attachment_ids = BTreeSet::new();
    for attachment in input.attachments {
        let kind = attachment.kind.trim();
        let source_id = attachment.source_id.trim();
        if !matches!(kind, "attachment" | "hosted-content") || source_id.is_empty() {
            bail!("invalid Teams attachment source evidence");
        }
        let source_handle = fragment.put::<UTF8String, _>(source_id.to_owned());
        let name_text = attachment
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned);
        let name = name_text
            .as_ref()
            .map(|name| fragment.put::<UTF8String, _>(name.clone()));
        let occurrence = entity! {
            metadata::tag: archive::kind_attachment,
            archive::attachment_source_id: source_handle,
            teams::attachment_message: message_id,
            teams::attachment_kind: kind,
            archive::attachment_name?: name,
        };
        let occurrence_id = occurrence.root().expect("Teams attachment has one root");
        fragment += occurrence;
        let pointers = attachment
            .source_pointers
            .into_iter()
            .map(|pointer| fragment.put::<UTF8String, _>(pointer))
            .collect::<BTreeSet<_>>();
        let (file_id, size) = if let Some(materialization) = attachment.materialization {
            let file_name = materialization.file_name.trim();
            if file_name.is_empty() {
                bail!("materialized Teams attachment has an empty file name");
            }
            let size: Inline<U256BE> = (materialization.bytes.len() as u128).to_inline();
            let media_type = files::normalize_media_type_or_default(&materialization.media_type);
            let file = files::stage(materialization.bytes, file_name, &media_type)?;
            let file_id = file.root().expect("canonical file has one root");
            fragment += file;
            (Some(file_id), Some(size))
        } else {
            (None, None)
        };
        fragment += entity! { ExclusiveId::force_ref(&occurrence_id) @
            archive::attachment_source_pointer*: pointers,
            archive::attachment_file?: file_id,
            archive::attachment_size_bytes?: size,
        };
        attachment_ids.insert(occurrence_id);
    }

    let etag = fragment.put::<UTF8String, _>(input.etag);
    let observation = entity! {
        metadata::tag: teams::kind_message_observation,
        teams::message: message_id,
        teams::modified_at: input.modified_at,
        teams::etag: etag,
    };
    let observation_id = observation.root().expect("Teams observation has one root");
    fragment += observation;
    let raw = input
        .raw
        .into_iter()
        .map(|raw| fragment.put::<UTF8String, _>(raw))
        .collect::<BTreeSet<_>>();
    let author_name = input
        .author_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| fragment.put::<UTF8String, _>(name.to_owned()));
    let content = input
        .content
        .map(|content| fragment.put::<UTF8String, _>(content));
    let state = if deleted { "deleted" } else { "present" };
    fragment += entity! { ExclusiveId::force_ref(&observation_id) @
        teams::message_state: state,
        metadata::created_at?: input.created_at,
        teams::deleted_at?: input.deleted_at,
        archive::author?: author,
        teams::author_name?: author_name,
        archive::content?: content,
        archive::attachment*: attachment_ids,
        teams::message_raw*: raw,
    };
    Ok((fragment, observation_id))
}

/// Canonical, inspectable coordinate of the exact frozen legacy source.
///
/// This deliberately serializes the branch/pin/head values into a UTF8String
/// instead of storing raw repository handles as trible values. Conservative
/// blob discovery therefore retains the coordinate, not the secret-bearing
/// legacy commit closure which the cutover is replacing.
pub fn snapshot_source_coordinate(branch: Id, pin: [u8; 32], head: [u8; 32]) -> String {
    format!(
        "{SNAPSHOT_COORDINATE_PREFIX}{:X}:{}:{}",
        branch,
        hex::encode_upper(pin),
        hex::encode_upper(head)
    )
}

pub fn is_canonical_snapshot_source_coordinate(value: &str) -> bool {
    let Some(rest) = value.strip_prefix(SNAPSHOT_COORDINATE_PREFIX) else {
        return false;
    };
    let mut parts = rest.split(':');
    let Some(branch) = parts.next() else {
        return false;
    };
    let Some(pin) = parts.next() else {
        return false;
    };
    let Some(head) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && branch.len() == 32
        && pin.len() == 64
        && head.len() == 64
        && [branch, pin, head].into_iter().all(|part| {
            part.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte))
        })
}

/// Construct a source-scoped generation-0 frozen snapshot receipt.
pub fn legacy_snapshot_fragment(
    source: Id,
    coordinate: &str,
    observations: impl IntoIterator<Item = Id>,
) -> Result<Fragment> {
    if !is_canonical_snapshot_source_coordinate(coordinate) {
        bail!("non-canonical Teams legacy snapshot source coordinate");
    }
    let observations = observations.into_iter().collect::<BTreeSet<_>>();
    let mut fragment = Fragment::empty();
    let coordinate = fragment.put::<UTF8String, _>(coordinate.to_owned());
    let generation: Inline<U256BE> = 0_u128.to_inline();
    fragment += entity! {
        metadata::tag: teams::kind_legacy_snapshot,
        teams::source: source,
        teams::coverage_generation: generation,
        teams::snapshot_source_coordinate: coordinate,
        teams::coverage_observation*: observations,
    };
    Ok(fragment)
}

/// Construct one ordinary Graph page receipt.
pub fn coverage_fragment(
    source: Id,
    generation: u128,
    predecessors: impl IntoIterator<Item = Id>,
    request: &str,
    cursor: &str,
    kind: &str,
    observations: impl IntoIterator<Item = Id>,
) -> Result<Fragment> {
    if kind != "next" && kind != "delta" {
        bail!("invalid Teams coverage cursor kind {kind:?}");
    }
    let predecessors = predecessors.into_iter().collect::<BTreeSet<_>>();
    let observations = observations.into_iter().collect::<BTreeSet<_>>();
    let mut fragment = Fragment::empty();
    let request = fragment.put::<UTF8String, _>(request.to_owned());
    let cursor = fragment.put::<UTF8String, _>(cursor.to_owned());
    let generation: Inline<U256BE> = generation.to_inline();
    fragment += entity! {
        metadata::tag: teams::kind_coverage,
        teams::source: source,
        teams::coverage_generation: generation,
        teams::coverage_request: request,
        teams::coverage_cursor: cursor,
        teams::coverage_kind: kind,
        metadata::supersedes*: predecessors,
        teams::coverage_observation*: observations,
    };
    Ok(fragment)
}

pub fn coverage_head_ids<P>(catalog: &P, source: Id) -> BTreeSet<Id>
where
    P: TriblePattern,
{
    let receipts = receipt_ids(catalog, source);
    let superseded = find!(
        predecessor: Id,
        pattern!(catalog, [{
            _?successor @
            teams::source: source,
            metadata::supersedes: ?predecessor,
        }])
    )
    .collect::<BTreeSet<_>>();
    receipts.difference(&superseded).copied().collect()
}

pub fn coverage_head<P>(
    reader: &PileSnapshot,
    catalog: &P,
    source: Id,
) -> Result<Option<CoverageHead>>
where
    P: TriblePattern,
{
    let receipts = receipt_ids(catalog, source);
    if receipts.is_empty() {
        return Ok(None);
    }
    let id = one_required(coverage_head_ids(catalog, source), "Teams coverage head")?;
    let generation = inline_u256_to_u128(one_required(
        find!(
            generation: Inline<U256BE>,
            pattern!(catalog, [{ id @ teams::coverage_generation: ?generation }])
        )
        .collect(),
        "Teams coverage generation",
    )?)?;
    let cursor = one_optional(
        find!(
            cursor: Inline<Handle<UTF8String>>,
            pattern!(catalog, [{ id @ teams::coverage_cursor: ?cursor }])
        )
        .collect(),
        "Teams coverage cursor",
    )?
    .map(|cursor| read_utf8string(reader, cursor, "Teams coverage cursor"))
    .transpose()?;
    Ok(Some(CoverageHead {
        id,
        generation,
        cursor,
    }))
}

/// Evaluate the receipt DAG and return one unambiguous visibility per logical
/// message. Unversioned tombstones remain causally ordered by their receipts;
/// full observations use Graph's source modification time.
pub fn current_message_states<P>(
    catalog: &P,
    source: Id,
) -> Result<BTreeMap<Id, CurrentMessageState>>
where
    P: TriblePattern,
{
    let heads = coverage_head_ids(catalog, source);
    if heads.is_empty() {
        return Ok(BTreeMap::new());
    }
    let head = one_required(heads, "Teams coverage head")?;

    let mut observations = BTreeMap::new();
    for (observation, message, modified) in find!(
        (
            observation: Id,
            message: Id,
            modified: Inline<NsTAIInterval>
        ),
        pattern!(catalog, [{
            ?observation @
            metadata::tag: teams::kind_message_observation,
            teams::message: ?message,
            teams::modified_at: ?modified,
        }])
    ) {
        let state = one_required(
            find!(
                value: Inline<ShortString>,
                pattern!(catalog, [{ observation @ teams::message_state: ?value }])
            )
            .collect(),
            "Teams observation state",
        )?;
        let state = String::try_from_inline(&state)
            .map_err(|error| anyhow::anyhow!("decode Teams observation state: {error:?}"))?;
        observations.insert(
            observation,
            ObservationOrder {
                message,
                modified: interval_key(modified),
                deleted: state == "deleted",
            },
        );
    }
    let tombstones = find!(
        (tombstone: Id, message: Id),
        pattern!(catalog, [{
            ?tombstone @
            metadata::tag: teams::kind_message_tombstone,
            teams::message: ?message,
        }])
    )
    .collect::<BTreeMap<_, _>>();

    let mut receipts = Vec::new();
    for receipt in receipt_ids(catalog, source) {
        let generation = one_required(
            find!(
                value: Inline<U256BE>,
                pattern!(catalog, [{ receipt @ teams::coverage_generation: ?value }])
            )
            .collect(),
            "Teams receipt generation",
        )?;
        receipts.push(ReceiptOrder {
            id: receipt,
            generation: inline_u256_to_u128(generation)?,
            predecessors: find!(
                value: Id,
                pattern!(catalog, [{ receipt @ metadata::supersedes: ?value }])
            )
            .collect(),
            events: find!(
                value: Id,
                pattern!(catalog, [{ receipt @ teams::coverage_observation: ?value }])
            )
            .collect(),
        });
    }
    receipts.sort_by_key(|receipt| (receipt.generation, receipt.id));

    let mut remaining_children = BTreeMap::<Id, usize>::new();
    for receipt in &receipts {
        for predecessor in &receipt.predecessors {
            *remaining_children.entry(*predecessor).or_default() += 1;
        }
    }

    let mut states = BTreeMap::<Id, BTreeMap<Id, CausalMessageState>>::new();
    for receipt in receipts {
        let mut state = if receipt.predecessors.len() == 1 {
            let predecessor = *receipt.predecessors.first().expect("one predecessor");
            let remaining = remaining_children
                .get_mut(&predecessor)
                .expect("predecessor child count was collected");
            let take_parent = *remaining == 1;
            *remaining -= 1;
            if take_parent {
                states.remove(&predecessor).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Teams coverage {:x} names an unavailable predecessor {predecessor:x}",
                        receipt.id
                    )
                })?
            } else {
                states.get(&predecessor).cloned().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Teams coverage {:x} names an unavailable predecessor {predecessor:x}",
                        receipt.id
                    )
                })?
            }
        } else {
            let mut merged = BTreeMap::new();
            for predecessor in &receipt.predecessors {
                let parent = states.get(predecessor).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Teams coverage {:x} names an unavailable predecessor {predecessor:x}",
                        receipt.id
                    )
                })?;
                merge_causal_states(&mut merged, parent, &observations)?;
                let remaining = remaining_children
                    .get_mut(predecessor)
                    .expect("predecessor child count was collected");
                *remaining -= 1;
            }
            for predecessor in &receipt.predecessors {
                if remaining_children.get(predecessor) == Some(&0) {
                    states.remove(predecessor);
                }
            }
            merged
        };

        let mut page_observations = BTreeMap::<Id, BTreeSet<Id>>::new();
        let mut page_tombstones = BTreeSet::new();
        for event in &receipt.events {
            if let Some(observation) = observations.get(event) {
                page_observations
                    .entry(observation.message)
                    .or_default()
                    .insert(*event);
            } else if let Some(message) = tombstones.get(event) {
                page_tombstones.insert(*message);
            } else {
                bail!(
                    "Teams coverage {:x} carries unknown event {event:x}",
                    receipt.id
                );
            }
        }
        if let Some(message) = page_tombstones
            .iter()
            .find(|message| page_observations.contains_key(*message))
        {
            bail!(
                "Teams coverage {:x} carries unordered full and @removed events for message {message:x}",
                receipt.id
            );
        }
        for (message, page_versions) in page_observations {
            apply_page_observations(&mut state, message, &page_versions, &observations)?;
        }
        for message in page_tombstones {
            state.entry(message).or_default().visible = CausalVisible::Deleted(None);
        }
        states.insert(receipt.id, state);
    }

    let current = states
        .get(&head)
        .ok_or_else(|| anyhow::anyhow!("Teams coverage head {head:x} was not evaluable"))?;
    current
        .iter()
        .filter_map(|(message, state)| match state.visible {
            CausalVisible::Unknown => None,
            CausalVisible::Present(observation) => {
                Some(Ok((*message, CurrentMessageState::Present(observation))))
            }
            CausalVisible::Deleted(observation) => {
                Some(Ok((*message, CurrentMessageState::Deleted(observation))))
            }
            CausalVisible::Conflict => Some(Err(anyhow::anyhow!(
                "current Teams state for message {message:x} is causally ambiguous"
            ))),
        })
        .collect()
}

/// Stable native Teams sources present in the materialized collection.
pub fn source_ids<P>(catalog: &P) -> BTreeSet<Id>
where
    P: TriblePattern,
{
    find!(
        source: Id,
        pattern!(catalog, [{ ?source @ metadata::tag: teams::kind_source }])
    )
    .collect()
}

/// Decode the exact tenant coordinate of a native source.
pub fn source_label<P>(reader: &PileSnapshot, catalog: &P, source: Id) -> Result<String>
where
    P: TriblePattern,
{
    let handle = one_required(
        find!(
            value: TextHandle,
            pattern!(catalog, [{ source @ metadata::tag: teams::kind_source, teams::tenant_id: ?value }])
        )
        .collect(),
        "Teams source tenant",
    )?;
    read_utf8string(reader, handle, "Teams source tenant")
}

/// Decode every source-scoped chat identity without choosing among conflicting
/// values. Structural ambiguity is an error, not a display-name fallback.
pub fn chat_labels<P>(
    reader: &PileSnapshot,
    catalog: &P,
    source: Id,
) -> Result<BTreeMap<Id, String>>
where
    P: TriblePattern,
{
    let mut handles = BTreeMap::<Id, BTreeSet<TextHandle>>::new();
    for (chat, handle) in find!(
        (chat: Id, handle: TextHandle),
        pattern!(catalog, [{
            ?chat @
            metadata::tag: teams::kind_chat,
            teams::source: source,
            teams::chat_id: ?handle,
        }])
    ) {
        handles.entry(chat).or_default().insert(handle);
    }
    handles
        .into_iter()
        .map(|(chat, values)| {
            let handle = one_required(values, &format!("Teams chat {chat:x} external id"))?;
            Ok((
                chat,
                read_utf8string(reader, handle, "Teams chat external id")?,
            ))
        })
        .collect()
}

/// Evaluate the source receipt DAG and materialize its selected message
/// observations as reusable presentation records.
pub fn current_messages<P>(catalog: &P, source: Id) -> Result<Vec<CurrentMessage>>
where
    P: TriblePattern,
{
    let mut message_chats = BTreeMap::<Id, BTreeSet<Id>>::new();
    for (message, chat) in find!(
        (message: Id, chat: Id),
        pattern!(catalog, [
            {
                ?message @
                metadata::tag: archive::kind_message,
                teams::chat: ?chat,
                teams::message_id: _?external,
            },
            {
                ?chat @
                metadata::tag: teams::kind_chat,
                teams::source: source,
            }
        ])
    ) {
        message_chats.entry(message).or_default().insert(chat);
    }

    let mut rows = Vec::new();
    for (message, state) in current_message_states(catalog, source)? {
        let chat = one_required(
            message_chats.remove(&message).unwrap_or_default(),
            &format!("Teams message {message:x} chat in source {source:x}"),
        )?;
        match state {
            CurrentMessageState::Present(observation) => rows.push(current_message_record(
                catalog,
                message,
                chat,
                Some(observation),
                false,
            )?),
            CurrentMessageState::Deleted(observation) => rows.push(current_message_record(
                catalog,
                message,
                chat,
                observation,
                true,
            )?),
        }
    }
    rows.sort_by_key(|row| {
        (
            row.created_at.map(interval_key).unwrap_or(i128::MIN),
            row.message,
            row.observation,
        )
    });
    Ok(rows)
}

fn current_message_record<P>(
    catalog: &P,
    message: Id,
    chat: Id,
    observation: Option<Id>,
    deleted: bool,
) -> Result<CurrentMessage>
where
    P: TriblePattern,
{
    let Some(observation_id) = observation else {
        return Ok(CurrentMessage {
            message,
            observation: None,
            chat,
            deleted,
            created_at: None,
            modified_at: None,
            author: None,
            author_names: Vec::new(),
            content: None,
            attachments: Vec::new(),
        });
    };

    let created_at = one_optional(
        find!(
            value: Inline<NsTAIInterval>,
            pattern!(catalog, [{ observation_id @ metadata::created_at: ?value }])
        )
        .collect(),
        "Teams message creation time",
    )?;
    let modified_at = one_required(
        find!(
            value: Inline<NsTAIInterval>,
            pattern!(catalog, [{ observation_id @ teams::modified_at: ?value }])
        )
        .collect(),
        "Teams message modification time",
    )?;
    let content = one_optional(
        find!(
            value: TextHandle,
            pattern!(catalog, [{ observation_id @ archive::content: ?value }])
        )
        .collect(),
        "Teams message content",
    )?;
    let author = one_optional(
        find!(
            value: Id,
            pattern!(catalog, [{ observation_id @ archive::author: ?value }])
        )
        .collect(),
        "Teams message author",
    )?;
    let author_names = find!(
        value: TextHandle,
        pattern!(catalog, [{ observation_id @ teams::author_name: ?value }])
    )
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect();
    let attachments = find!(
        value: Id,
        pattern!(catalog, [{ observation_id @ archive::attachment: ?value }])
    )
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect();
    if !deleted && (created_at.is_none() || content.is_none()) {
        bail!("present Teams observation {observation_id:x} lacks creation time or content");
    }
    Ok(CurrentMessage {
        message,
        observation: Some(observation_id),
        chat,
        deleted,
        created_at: created_at.or(Some(modified_at)),
        modified_at: Some(modified_at),
        author,
        author_names,
        content,
        attachments,
    })
}

#[derive(Clone, Copy, Debug)]
struct ObservationOrder {
    message: Id,
    modified: i128,
    deleted: bool,
}

#[derive(Clone, Debug)]
struct ReceiptOrder {
    id: Id,
    generation: u128,
    predecessors: BTreeSet<Id>,
    events: BTreeSet<Id>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CausalVisible {
    Unknown,
    Present(Id),
    Deleted(Option<Id>),
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CausalMessageState {
    max_seen_modified: Option<i128>,
    visible: CausalVisible,
}

impl Default for CausalMessageState {
    fn default() -> Self {
        Self {
            max_seen_modified: None,
            visible: CausalVisible::Unknown,
        }
    }
}

fn merge_causal_states(
    target: &mut BTreeMap<Id, CausalMessageState>,
    parent: &BTreeMap<Id, CausalMessageState>,
    observations: &BTreeMap<Id, ObservationOrder>,
) -> Result<()> {
    for (message, incoming) in parent {
        let entry = target.entry(*message).or_default();
        entry.visible = merge_causal_visible(entry.visible, incoming.visible, observations)?;
        entry.max_seen_modified = entry.max_seen_modified.max(incoming.max_seen_modified);
    }
    Ok(())
}

fn merge_causal_visible(
    left: CausalVisible,
    right: CausalVisible,
    observations: &BTreeMap<Id, ObservationOrder>,
) -> Result<CausalVisible> {
    use CausalVisible::{Conflict, Deleted, Present, Unknown};
    Ok(match (left, right) {
        (Unknown, value) | (value, Unknown) => value,
        (Conflict, _) | (_, Conflict) => Conflict,
        (Present(left), Present(right)) if left == right => Present(left),
        (Deleted(Some(left)), Deleted(Some(right))) if left == right => Deleted(Some(left)),
        (Present(left), Present(right)) => {
            newer_versioned_visible(Present(left), left, Present(right), right, observations)?
        }
        (Present(left), Deleted(Some(right))) => newer_versioned_visible(
            Present(left),
            left,
            Deleted(Some(right)),
            right,
            observations,
        )?,
        (Deleted(Some(left)), Present(right)) => newer_versioned_visible(
            Deleted(Some(left)),
            left,
            Present(right),
            right,
            observations,
        )?,
        (Deleted(Some(left)), Deleted(Some(right))) => newer_versioned_visible(
            Deleted(Some(left)),
            left,
            Deleted(Some(right)),
            right,
            observations,
        )?,
        (Deleted(None), Deleted(None)) => Deleted(None),
        (Deleted(None), Present(_) | Deleted(Some(_)))
        | (Present(_) | Deleted(Some(_)), Deleted(None)) => Conflict,
    })
}

fn newer_versioned_visible(
    left_visible: CausalVisible,
    left: Id,
    right_visible: CausalVisible,
    right: Id,
    observations: &BTreeMap<Id, ObservationOrder>,
) -> Result<CausalVisible> {
    let left_order = observations
        .get(&left)
        .ok_or_else(|| anyhow::anyhow!("missing Teams observation {left:x}"))?;
    let right_order = observations
        .get(&right)
        .ok_or_else(|| anyhow::anyhow!("missing Teams observation {right:x}"))?;
    Ok(match left_order.modified.cmp(&right_order.modified) {
        std::cmp::Ordering::Less => right_visible,
        std::cmp::Ordering::Greater => left_visible,
        std::cmp::Ordering::Equal => CausalVisible::Conflict,
    })
}

fn apply_page_observations(
    states: &mut BTreeMap<Id, CausalMessageState>,
    message: Id,
    page_versions: &BTreeSet<Id>,
    observations: &BTreeMap<Id, ObservationOrder>,
) -> Result<()> {
    let newest_time = page_versions
        .iter()
        .map(|id| {
            observations
                .get(id)
                .map(|observation| observation.modified)
                .ok_or_else(|| anyhow::anyhow!("missing Teams observation {id:x}"))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .expect("page observation group is nonempty");
    let newest = one_required(
        page_versions
            .iter()
            .filter(|id| {
                observations
                    .get(*id)
                    .is_some_and(|value| value.modified == newest_time)
            })
            .copied()
            .collect(),
        &format!("latest source version in one Teams page for message {message:x}"),
    )?;
    let order = observations
        .get(&newest)
        .expect("newest observation came from map");
    let state = states.entry(message).or_default();
    let before = state.max_seen_modified;
    state.max_seen_modified = Some(before.map_or(newest_time, |old| old.max(newest_time)));

    if before.is_none_or(|old| newest_time > old) {
        state.visible = if order.deleted {
            CausalVisible::Deleted(Some(newest))
        } else {
            CausalVisible::Present(newest)
        };
        return Ok(());
    }
    if newest_time < before.expect("checked Some above") {
        return Ok(());
    }
    state.visible = match state.visible {
        CausalVisible::Present(current) if current == newest && !order.deleted => {
            CausalVisible::Present(current)
        }
        CausalVisible::Deleted(Some(current)) if current == newest && order.deleted => {
            CausalVisible::Deleted(Some(current))
        }
        CausalVisible::Deleted(None) => CausalVisible::Deleted(None),
        _ => CausalVisible::Conflict,
    };
    Ok(())
}

fn receipt_ids<P>(catalog: &P, source: Id) -> BTreeSet<Id>
where
    P: TriblePattern,
{
    let mut receipts = find!(
        receipt: Id,
        pattern!(catalog, [{
            ?receipt @
            metadata::tag: teams::kind_coverage,
            teams::source: source,
        }])
    )
    .collect::<BTreeSet<_>>();
    receipts.extend(find!(
        receipt: Id,
        pattern!(catalog, [{
            ?receipt @
            metadata::tag: teams::kind_legacy_snapshot,
            teams::source: source,
        }])
    ));
    receipts
}

pub fn canonical_tenant(tenant: &str) -> String {
    tenant.trim().to_ascii_lowercase()
}

pub fn is_generic_tenant(tenant: &str) -> bool {
    matches!(
        tenant.trim().to_ascii_lowercase().as_str(),
        "common" | "organizations" | "consumers"
    )
}

/// Parse the timestamp shapes emitted by Microsoft Graph.
pub fn parse_graph_datetime(value: &str) -> Option<Epoch> {
    let value = value.trim();
    let (date, time) = value.split_once('T')?;
    let mut date = date.splitn(3, '-');
    let year = date.next()?.parse::<i32>().ok()?;
    let month = date.next()?.parse::<u8>().ok()?;
    let day = date.next()?.parse::<u8>().ok()?;
    let (time, offset) = parse_time_and_offset(time)?;
    let (hour, minute, second, nanos) = time;
    let mut epoch = Epoch::from_gregorian_utc(year, month, day, hour, minute, second, nanos);
    if offset != 0 {
        epoch -= hifitime::Duration::from_seconds(offset as f64);
    }
    Some(epoch)
}

fn parse_time_and_offset(value: &str) -> Option<((u8, u8, u8, u32), i32)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(value) = value.strip_suffix('Z') {
        return Some((parse_hms_fraction(value)?, 0));
    }
    if let Some((time, offset)) = split_timezone_offset(value) {
        return Some((parse_hms_fraction(time)?, parse_offset_seconds(offset)?));
    }
    Some((parse_hms_fraction(value)?, 0))
}

fn split_timezone_offset(value: &str) -> Option<(&str, &str)> {
    for index in (0..value.len()).rev() {
        let byte = value.as_bytes()[index];
        if byte == b'+' || byte == b'-' {
            let (time, offset) = value.split_at(index);
            return (offset.len() >= 3).then_some((time, offset));
        }
    }
    None
}

fn parse_offset_seconds(offset: &str) -> Option<i32> {
    let offset = offset.trim();
    let sign = if offset.starts_with('+') {
        1
    } else if offset.starts_with('-') {
        -1
    } else {
        return None;
    };
    let (hours, minutes) = offset[1..].split_once(':')?;
    Some(sign * (hours.parse::<i32>().ok()? * 3600 + minutes.parse::<i32>().ok()? * 60))
}

fn parse_hms_fraction(value: &str) -> Option<(u8, u8, u8, u32)> {
    let (hms, fraction) = value.trim().split_once('.').unwrap_or((value.trim(), ""));
    let mut hms = hms.splitn(3, ':');
    let hour = hms.next()?.parse().ok()?;
    let minute = hms.next()?.parse().ok()?;
    let second = hms.next()?.parse().ok()?;
    let nanos = if fraction.is_empty() {
        0
    } else {
        let mut digits = fraction
            .chars()
            .take_while(|character| character.is_ascii_digit())
            .collect::<String>();
        if digits.is_empty() {
            0
        } else {
            digits.truncate(9);
            while digits.len() < 9 {
                digits.push('0');
            }
            digits.parse().ok()?
        }
    };
    Some((hour, minute, second, nanos))
}

/// Extract unique hosted-content identifiers in source order from a Graph
/// message body. These references are source evidence even when their bytes
/// have not yet been materialized.
pub fn extract_hosted_content_ids(content: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    let needle = "/hostedContents/";
    let mut position = 0;
    while let Some(offset) = content[position..].find(needle) {
        let start = position + offset + needle.len();
        let rest = &content[start..];
        let end = rest.find('/').unwrap_or(rest.len());
        let id = rest[..end].trim();
        if !id.is_empty() && seen.insert(id.to_owned()) {
            ids.push(id.to_owned());
        }
        position = start + end;
    }
    ids
}

pub fn interval_key(interval: Inline<NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().unwrap();
    lower.to_tai_duration().total_nanoseconds()
}

fn inline_u256_to_u128(value: Inline<U256BE>) -> Result<u128> {
    let raw = value.raw;
    if raw[..16].iter().any(|byte| *byte != 0) {
        bail!("Teams coverage generation exceeds u128");
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&raw[16..]);
    Ok(u128::from_be_bytes(bytes))
}

fn one_optional<T: Ord>(values: BTreeSet<T>, field: &str) -> Result<Option<T>> {
    match values.len() {
        0 => Ok(None),
        1 => Ok(values.into_iter().next()),
        count => bail!("{field} has {count} values; refusing arbitrary selection"),
    }
}

fn one_required<T: Ord>(values: BTreeSet<T>, field: &str) -> Result<T> {
    one_optional(values, field)?.ok_or_else(|| anyhow::anyhow!("{field} is missing"))
}

fn entity_facts(facts: &TribleSet, entity: Id) -> TribleSet {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity)
        .copied()
        .collect()
}

fn read_utf8string(
    reader: &PileSnapshot,
    handle: Inline<Handle<UTF8String>>,
    field: &str,
) -> Result<String> {
    let view: anybytes::View<str> = reader
        .get(handle)
        .with_context(|| format!("read {field} payload {}", hex::encode_upper(handle.raw)))?;
    Ok(view.as_ref().to_owned())
}

/// Decode one Teams text attachment with field-specific context.
pub fn read_text(reader: &PileSnapshot, handle: TextHandle, field: &str) -> Result<String> {
    read_utf8string(reader, handle, field)
}

/// Enforce the independently signed Teams transaction boundary.
pub fn validate_commit_fragment(facts: &TribleSet) -> Result<()> {
    reject_retired_oauth_evidence(facts)?;
    let mut receipts = find!(
        receipt: Id,
        pattern!(facts, [{ ?receipt @ metadata::tag: teams::kind_coverage }])
    )
    .collect::<BTreeSet<_>>();
    receipts.extend(find!(
        receipt: Id,
        pattern!(facts, [{ ?receipt @ metadata::tag: teams::kind_legacy_snapshot }])
    ));
    let observations = find!(
        observation: Id,
        pattern!(facts, [{ ?observation @ metadata::tag: teams::kind_message_observation }])
    )
    .collect::<BTreeSet<_>>();
    let tombstones = find!(
        tombstone: Id,
        pattern!(facts, [{ ?tombstone @ metadata::tag: teams::kind_message_tombstone }])
    )
    .collect::<BTreeSet<_>>();

    if receipts.is_empty() && observations.is_empty() && tombstones.is_empty() {
        return Ok(());
    }
    let receipt = one_required(receipts, "Teams page receipt in one COMMIT")?;
    let covered = find!(
        event: Id,
        pattern!(facts, [{ receipt @ teams::coverage_observation: ?event }])
    )
    .collect::<BTreeSet<_>>();
    let mut events = observations.clone();
    events.extend(tombstones.iter().copied());
    if covered != events {
        bail!("Teams page COMMIT receipt coverage does not exactly match its message events");
    }

    let source = one_required(
        find!(source: Id, pattern!(facts, [{ receipt @ teams::source: ?source }])).collect(),
        "Teams page receipt source",
    )?;
    let sources = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: teams::kind_source }])
    )
    .collect::<BTreeSet<_>>();
    if sources != BTreeSet::from([source]) {
        bail!("Teams page COMMIT must contain exactly its receipt source identity {source:x}");
    }
    validate_source_identity(facts, source)?;

    let chats = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: teams::kind_chat }])
    )
    .collect::<BTreeSet<_>>();
    for chat in &chats {
        validate_chat_identity(facts, *chat, &sources)?;
    }
    let authors = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: archive::kind_author }])
    )
    .collect::<BTreeSet<_>>();
    for author in &authors {
        validate_author_identity(facts, *author, &sources)?;
    }
    let messages = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: archive::kind_message }])
    )
    .collect::<BTreeSet<_>>();
    for message in &messages {
        validate_message_identity(facts, *message, &chats)?;
    }
    let attachments = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: archive::kind_attachment }])
    )
    .collect::<BTreeSet<_>>();
    for attachment in &attachments {
        validate_attachment(facts, *attachment, &messages)?;
    }
    for observation in &observations {
        validate_observation(facts, *observation, &messages, &attachments, &authors)?;
    }
    for tombstone in &tombstones {
        validate_tombstone(facts, *tombstone, &messages)?;
    }
    validate_receipt_shape(facts, receipt)?;
    validate_attachment_file_structure(facts, &attachments)
}

fn validate_source_identity(facts: &TribleSet, source: Id) -> Result<()> {
    let _tenant = one_required(
        find!(
            value: Inline<Handle<UTF8String>>,
            pattern!(facts, [{ source @ teams::tenant_id: ?value }])
        )
        .collect(),
        "Teams source tenant",
    )?;
    Ok(())
}

fn validate_chat_identity(facts: &TribleSet, chat: Id, sources: &BTreeSet<Id>) -> Result<()> {
    let source = one_required(
        find!(value: Id, pattern!(facts, [{ chat @ teams::source: ?value }])).collect(),
        "Teams chat source",
    )?;
    if !sources.contains(&source) {
        bail!("Teams chat {chat:x} names an unknown source");
    }
    let _external = one_required(
        find!(
            value: Inline<Handle<UTF8String>>,
            pattern!(facts, [{ chat @ teams::chat_id: ?value }])
        )
        .collect(),
        "Teams chat external id",
    )?;
    Ok(())
}

fn validate_author_identity(facts: &TribleSet, author: Id, sources: &BTreeSet<Id>) -> Result<()> {
    let source = one_required(
        find!(value: Id, pattern!(facts, [{ author @ teams::source: ?value }])).collect(),
        "Teams user source",
    )?;
    if !sources.contains(&source) {
        bail!("Teams user {author:x} names an unknown source");
    }
    let _external = one_required(
        find!(
            value: Inline<Handle<UTF8String>>,
            pattern!(facts, [{ author @ teams::user_id: ?value }])
        )
        .collect(),
        "Teams user external id",
    )?;
    Ok(())
}

fn validate_message_identity(facts: &TribleSet, message: Id, chats: &BTreeSet<Id>) -> Result<()> {
    let chat = one_required(
        find!(value: Id, pattern!(facts, [{ message @ teams::chat: ?value }])).collect(),
        "Teams message chat",
    )?;
    if !chats.contains(&chat) {
        bail!("Teams message {message:x} names an unknown chat");
    }
    let _external = one_required(
        find!(
            value: Inline<Handle<UTF8String>>,
            pattern!(facts, [{ message @ teams::message_id: ?value }])
        )
        .collect(),
        "Teams message external id",
    )?;
    Ok(())
}

fn validate_receipt_shape(facts: &TribleSet, receipt: Id) -> Result<()> {
    let tag = one_required(
        find!(value: Id, pattern!(facts, [{ receipt @ metadata::tag: ?value }])).collect(),
        "Teams receipt kind",
    )?;
    let generation = one_required(
        find!(
            value: Inline<U256BE>,
            pattern!(facts, [{ receipt @ teams::coverage_generation: ?value }])
        )
        .collect(),
        "Teams receipt generation",
    )?;
    let generation_value = inline_u256_to_u128(generation)?;
    let request = one_optional(
        find!(
            value: Inline<Handle<UTF8String>>,
            pattern!(facts, [{ receipt @ teams::coverage_request: ?value }])
        )
        .collect(),
        "Teams coverage request",
    )?;
    let cursor = one_optional(
        find!(
            value: Inline<Handle<UTF8String>>,
            pattern!(facts, [{ receipt @ teams::coverage_cursor: ?value }])
        )
        .collect(),
        "Teams coverage cursor",
    )?;
    let kind = one_optional(
        find!(
            value: Inline<ShortString>,
            pattern!(facts, [{ receipt @ teams::coverage_kind: ?value }])
        )
        .collect(),
        "Teams coverage kind",
    )?;
    let predecessors = find!(
        value: Id,
        pattern!(facts, [{ receipt @ metadata::supersedes: ?value }])
    )
    .collect::<BTreeSet<_>>();
    let coordinate = one_optional(
        find!(
            value: Inline<Handle<UTF8String>>,
            pattern!(facts, [{ receipt @ teams::snapshot_source_coordinate: ?value }])
        )
        .collect(),
        "Teams legacy snapshot source coordinate",
    )?;

    if tag == teams::kind_coverage {
        request.ok_or_else(|| anyhow::anyhow!("Teams coverage request is missing"))?;
        cursor.ok_or_else(|| anyhow::anyhow!("Teams coverage cursor is missing"))?;
        let kind = kind.ok_or_else(|| anyhow::anyhow!("Teams coverage kind is missing"))?;
        let kind_text = String::try_from_inline(&kind)
            .map_err(|error| anyhow::anyhow!("decode Teams coverage kind: {error:?}"))?;
        if kind_text != "next" && kind_text != "delta" {
            bail!("invalid Teams coverage kind {kind_text:?}");
        }
        if coordinate.is_some() {
            bail!("Graph Teams coverage receipt carries a legacy source coordinate");
        }
    } else if tag == teams::kind_legacy_snapshot {
        if generation_value != 0
            || request.is_some()
            || cursor.is_some()
            || kind.is_some()
            || !predecessors.is_empty()
        {
            bail!("legacy Teams snapshot has Graph cursor state, a predecessor, or nonzero generation");
        }
        coordinate
            .ok_or_else(|| anyhow::anyhow!("legacy Teams snapshot source coordinate is missing"))?;
    } else {
        bail!("unknown Teams receipt kind {tag:x}");
    }
    Ok(())
}

fn validate_attachment_file_structure(facts: &TribleSet, attachments: &BTreeSet<Id>) -> Result<()> {
    let referenced_files = attachments
        .iter()
        .flat_map(|attachment| {
            find!(
                value: Id,
                pattern!(facts, [{ *attachment @ archive::attachment_file: ?value }])
            )
        })
        .collect::<BTreeSet<_>>();
    let files_present = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: KIND_FILE }])
    )
    .collect::<BTreeSet<_>>();
    let media_types = find!(
        value: Id,
        pattern!(facts, [{ ?value @ metadata::tag: KIND_MEDIA_TYPE }])
    )
    .collect::<BTreeSet<_>>();
    if !referenced_files.is_subset(&files_present) {
        let missing = referenced_files
            .difference(&files_present)
            .next()
            .expect("non-subset has a witness");
        bail!("Teams facts omit attachment file {missing:x}");
    }
    for media_type in &media_types {
        let _name = one_required(
            find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(facts, [{ *media_type @ metadata::name: ?value }])
            )
            .collect(),
            "attachment media type name",
        )?;
    }
    for file_id in files_present {
        let _content = one_required(
            find!(
                value: Inline<Handle<RawBytes>>,
                pattern!(facts, [{ file_id @ file::content: ?value }])
            )
            .collect(),
            "attachment file content",
        )?;
        let _name = one_required(
            find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(facts, [{ file_id @ file::name: ?value }])
            )
            .collect(),
            "attachment file name",
        )?;
        let media_type = one_required(
            find!(value: Id, pattern!(facts, [{ file_id @ file::media_type: ?value }])).collect(),
            "attachment file media type",
        )?;
        if !media_types.contains(&media_type) {
            bail!("Teams facts omit media-type identity {media_type:x}");
        }
    }
    Ok(())
}

/// Validate the complete materialized Teams collection and all referenced
/// payload bytes.
pub fn validate_catalog(reader: &PileSnapshot, catalog: &TribleSet) -> Result<()> {
    reject_retired_oauth_evidence(catalog)?;
    // Native Teams meaning is rooted in source-scoped coverage receipts,
    // presentation contexts, and auth profiles. Historical facts copied by a
    // sanitized cutover are not silently reinterpreted current state.
    let active = active_catalog(catalog);
    validate_known_payloads(reader, &active)?;
    validate_catalog_structure(&active)?;
    validate_attachment_payload_sizes(reader, None::<&PileSnapshot>, &active)?;

    let sources = find!(
        source: Id,
        pattern!(&active, [{ ?source @ metadata::tag: teams::kind_source }])
    )
    .collect::<BTreeSet<_>>();
    for source in sources {
        let tenant = one_required(
            find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(&active, [{ source @ teams::tenant_id: ?value }])
            )
            .collect(),
            "Teams source tenant",
        )?;
        let tenant = read_utf8string(reader, tenant, "Teams source tenant")?;
        if tenant.is_empty() || tenant != canonical_tenant(&tenant) || is_generic_tenant(&tenant) {
            bail!("Teams source {source:x} has a non-canonical tenant identity");
        }
    }
    for snapshot in find!(
        snapshot: Id,
        pattern!(&active, [{ ?snapshot @ metadata::tag: teams::kind_legacy_snapshot }])
    ) {
        let coordinate = one_required(
            find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(&active, [{ snapshot @ teams::snapshot_source_coordinate: ?value }])
            )
            .collect(),
            "Teams legacy snapshot source coordinate",
        )?;
        let coordinate = read_utf8string(reader, coordinate, "Teams legacy source coordinate")?;
        if !is_canonical_snapshot_source_coordinate(&coordinate) {
            bail!("Teams legacy snapshot {snapshot:x} has a non-canonical source coordinate");
        }
    }
    for source in auth_profile_sources(&active) {
        for profile in auth_profile_ids(&active, source) {
            let record = auth_profile(&active, profile)?;
            let client_id = read_utf8string(reader, record.client_id, "Teams auth client id")?;
            let user_id = read_utf8string(reader, record.user_id, "Teams auth user id")?;
            let scopes = read_utf8string(reader, record.scopes, "Teams auth scopes")?;
            if canonical_nonempty(&client_id, "Teams client id")? != client_id
                || canonical_nonempty(&user_id, "Teams user id")? != user_id
                || canonical_auth_scopes(&scopes)? != scopes
            {
                bail!("Teams auth profile {profile:x} contains non-canonical public fields");
            }
        }
    }
    Ok(())
}

fn reject_retired_oauth_evidence(catalog: &TribleSet) -> Result<()> {
    let retired_kinds = RETIRED_OAUTH_KINDS
        .into_iter()
        .map(|kind| {
            let encoded: Inline<GenId> = kind.to_inline();
            encoded.raw
        })
        .collect::<BTreeSet<_>>();

    if let Some(fact) = catalog.iter().find(|fact| {
        RETIRED_OAUTH_SECRET_ATTRIBUTES.contains(fact.a())
            || (fact.a() == &metadata::tag.id()
                && retired_kinds.contains(&fact.v::<UnknownInline>().raw))
    }) {
        bail!(
            "native Teams collection contains retired plaintext OAuth evidence on entity {:x}; migrate into an empty native collection",
            fact.e()
        );
    }
    Ok(())
}

/// Project the semantic Teams subgraph from an additive evidence catalog.
///
/// Coverage receipts are the sole roots for synchronized message state;
/// source-scoped context and authentication versions are independent roots.
/// Every fact whose subject is in their typed dependency closure is retained.
/// This deliberately has no heuristic recognition of legacy rows.
fn active_catalog(catalog: &TribleSet) -> TribleSet {
    let mut entities = BTreeSet::new();

    let graph_receipts = find!(
        receipt: Id,
        pattern!(catalog, [{ ?receipt @ metadata::tag: teams::kind_coverage }])
    )
    .collect::<BTreeSet<_>>();
    let snapshots = find!(
        receipt: Id,
        pattern!(catalog, [{ ?receipt @ metadata::tag: teams::kind_legacy_snapshot }])
    )
    .collect::<BTreeSet<_>>();
    entities.extend(graph_receipts.iter().copied());
    entities.extend(snapshots.iter().copied());

    // Old context rows used the same tag but had no source. Requiring the
    // native source edge keeps them inert without naming old vocabulary.
    let contexts = find!(
        (context: Id, _source: Id),
        pattern!(catalog, [{
            ?context @
            metadata::tag: teams::kind_context,
            teams::source: ?_source,
        }])
    )
    .map(|(context, _)| context)
    .collect::<BTreeSet<_>>();
    entities.extend(contexts.iter().copied());

    let auth_profiles = find!(
        (profile: Id, _source: Id),
        pattern!(catalog, [{
            ?profile @
            metadata::tag: teams::kind_auth_profile,
            teams::source: ?_source,
        }])
    )
    .map(|(profile, _)| profile)
    .collect::<BTreeSet<_>>();
    entities.extend(auth_profiles.iter().copied());

    let mut roots = graph_receipts;
    roots.extend(snapshots);
    roots.extend(contexts);
    roots.extend(auth_profiles);

    let sources = roots
        .iter()
        .flat_map(|root| find!(source: Id, pattern!(catalog, [{ *root @ teams::source: ?source }])))
        .collect::<BTreeSet<_>>();
    entities.extend(sources);

    let events = roots
        .iter()
        .flat_map(|root| {
            find!(event: Id, pattern!(catalog, [{ *root @ teams::coverage_observation: ?event }]))
        })
        .collect::<BTreeSet<_>>();
    entities.extend(events.iter().copied());

    let messages = events
        .iter()
        .flat_map(
            |event| find!(message: Id, pattern!(catalog, [{ *event @ teams::message: ?message }])),
        )
        .collect::<BTreeSet<_>>();
    entities.extend(messages.iter().copied());

    let chats = messages
        .iter()
        .flat_map(|message| find!(chat: Id, pattern!(catalog, [{ *message @ teams::chat: ?chat }])))
        .collect::<BTreeSet<_>>();
    entities.extend(chats);

    let authors = events
        .iter()
        .flat_map(
            |event| find!(author: Id, pattern!(catalog, [{ *event @ archive::author: ?author }])),
        )
        .collect::<BTreeSet<_>>();
    entities.extend(authors);

    let attachments = events
        .iter()
        .flat_map(|event| {
            find!(attachment: Id, pattern!(catalog, [{ *event @ archive::attachment: ?attachment }]))
        })
        .collect::<BTreeSet<_>>();
    entities.extend(attachments.iter().copied());

    let files = attachments
        .iter()
        .flat_map(|attachment| {
            find!(file_id: Id, pattern!(catalog, [{ *attachment @ archive::attachment_file: ?file_id }]))
        })
        .collect::<BTreeSet<_>>();
    entities.extend(files.iter().copied());

    let media_types = files
        .iter()
        .flat_map(|file_id| {
            find!(media_type: Id, pattern!(catalog, [{ *file_id @ file::media_type: ?media_type }]))
        })
        .collect::<BTreeSet<_>>();
    entities.extend(media_types);

    catalog
        .iter()
        .filter(|fact| entities.contains(fact.e()))
        .copied()
        .collect()
}

fn validate_catalog_structure(catalog: &TribleSet) -> Result<()> {
    let sources = find!(
        source: Id,
        pattern!(catalog, [{ ?source @ metadata::tag: teams::kind_source }])
    )
    .collect::<BTreeSet<_>>();
    for source in &sources {
        validate_source_identity(catalog, *source)?;
    }
    let chats = find!(
        chat: Id,
        pattern!(catalog, [{ ?chat @ metadata::tag: teams::kind_chat }])
    )
    .collect::<BTreeSet<_>>();
    for chat in &chats {
        validate_chat_identity(catalog, *chat, &sources)?;
    }
    let authors = find!(
        author: Id,
        pattern!(catalog, [{ ?author @ metadata::tag: archive::kind_author }])
    )
    .collect::<BTreeSet<_>>();
    for author in &authors {
        validate_author_identity(catalog, *author, &sources)?;
    }
    let messages = find!(
        message: Id,
        pattern!(catalog, [{ ?message @ metadata::tag: archive::kind_message }])
    )
    .collect::<BTreeSet<_>>();
    for message in &messages {
        validate_message_identity(catalog, *message, &chats)?;
    }
    let attachments = find!(
        attachment: Id,
        pattern!(catalog, [{ ?attachment @ metadata::tag: archive::kind_attachment }])
    )
    .collect::<BTreeSet<_>>();
    for attachment in &attachments {
        validate_attachment(catalog, *attachment, &messages)?;
    }
    validate_attachment_file_structure(catalog, &attachments)?;

    let observations = find!(
        observation: Id,
        pattern!(catalog, [{
            ?observation @ metadata::tag: teams::kind_message_observation
        }])
    )
    .collect::<BTreeSet<_>>();
    for observation in &observations {
        validate_observation(catalog, *observation, &messages, &attachments, &authors)?;
    }
    let tombstones = find!(
        tombstone: Id,
        pattern!(catalog, [{ ?tombstone @ metadata::tag: teams::kind_message_tombstone }])
    )
    .collect::<BTreeSet<_>>();
    for tombstone in &tombstones {
        validate_tombstone(catalog, *tombstone, &messages)?;
    }
    let mut events = observations;
    events.extend(tombstones);
    validate_coverage(catalog, &sources, &events)?;
    validate_contexts(catalog, &sources)?;
    validate_auth_profiles(catalog, &sources)?;
    for source in sources {
        if !receipt_ids(catalog, source).is_empty() {
            let _ = one_required(coverage_head_ids(catalog, source), "Teams coverage head")?;
        }
        let contexts = context_ids(catalog, source);
        if !contexts.is_empty() {
            let _ = one_required(context_head_ids(catalog, source), "Teams context head")?;
        }
        let states = current_message_states(catalog, source)?;
        for message in states.keys() {
            let chat = one_required(
                find!(value: Id, pattern!(catalog, [{ *message @ teams::chat: ?value }])).collect(),
                "Teams current message chat",
            )?;
            let message_source = one_required(
                find!(value: Id, pattern!(catalog, [{ chat @ teams::source: ?value }])).collect(),
                "Teams current message source",
            )?;
            if message_source != source {
                bail!("Teams causal state crosses source boundaries");
            }
        }
    }
    Ok(())
}

fn validate_known_payloads(reader: &PileSnapshot, catalog: &TribleSet) -> Result<()> {
    let text_attributes = text_attributes();
    for fact in catalog {
        if text_attributes.contains(fact.a()) {
            let handle = *fact.v::<Handle<UTF8String>>();
            let _: anybytes::View<str> = reader.get(handle).with_context(|| {
                format!("read Teams text payload {}", hex::encode_upper(handle.raw))
            })?;
        }
    }
    Ok(())
}

fn validate_attachment_payload_sizes<Overlay>(
    reader: &PileSnapshot,
    overlay: Option<&Overlay>,
    catalog: &TribleSet,
) -> Result<()>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    for (attachment, file_id, declared_size) in find!(
        (attachment: Id, file_id: Id, declared_size: Inline<U256BE>),
        pattern!(catalog, [{
            ?attachment @
            metadata::tag: archive::kind_attachment,
            archive::attachment_file: ?file_id,
            archive::attachment_size_bytes: ?declared_size,
        }])
    ) {
        let content = one_required(
            find!(
                value: Inline<Handle<RawBytes>>,
                pattern!(catalog, [{ file_id @ file::content: ?value }])
            )
            .collect(),
            "attachment file content",
        )?;
        let bytes: Bytes = if let Some(overlay) = overlay {
            if overlay
                .metadata(content)
                .context("inspect staged attachment bytes")?
                .is_some()
            {
                overlay.get(content).with_context(|| {
                    format!(
                        "read staged Teams attachment bytes {}",
                        hex::encode_upper(content.raw)
                    )
                })?
            } else {
                reader.get(content).with_context(|| {
                    format!(
                        "read Teams attachment bytes {}",
                        hex::encode_upper(content.raw)
                    )
                })?
            }
        } else {
            reader.get(content).with_context(|| {
                format!(
                    "read Teams attachment bytes {}",
                    hex::encode_upper(content.raw)
                )
            })?
        };
        let declared_size = inline_u256_to_u128(declared_size)?;
        let actual_size = bytes.len() as u128;
        if declared_size != actual_size {
            bail!(
                "Teams attachment {attachment:x} declares {declared_size} bytes, but canonical file {file_id:x} contains {actual_size}"
            );
        }
    }
    Ok(())
}

fn text_attributes() -> HashSet<Id> {
    [
        teams::chat_id.id(),
        teams::message_id.id(),
        teams::message_raw.id(),
        teams::user_id.id(),
        teams::tenant_id.id(),
        teams::etag.id(),
        teams::author_name.id(),
        teams::coverage_request.id(),
        teams::coverage_cursor.id(),
        teams::snapshot_source_coordinate.id(),
        teams::auth_client_id.id(),
        teams::auth_user_id.id(),
        teams::auth_scopes.id(),
        archive::content.id(),
        archive::attachment_source_id.id(),
        archive::attachment_source_pointer.id(),
        archive::attachment_name.id(),
        file::name.id(),
        metadata::name.id(),
        metadata::description.id(),
    ]
    .into_iter()
    .collect()
}

fn validate_attachment(catalog: &TribleSet, attachment: Id, messages: &BTreeSet<Id>) -> Result<()> {
    let message = one_required(
        find!(
            value: Id,
            pattern!(catalog, [{ attachment @ teams::attachment_message: ?value }])
        )
        .collect(),
        "Teams attachment message",
    )?;
    if !messages.contains(&message) {
        bail!("Teams attachment {attachment:x} names an unknown message");
    }
    let _source = one_required(
        find!(
            value: Inline<Handle<UTF8String>>,
            pattern!(catalog, [{ attachment @ archive::attachment_source_id: ?value }])
        )
        .collect(),
        "Teams attachment source id",
    )?;
    let kind = one_required(
        find!(
            value: Inline<ShortString>,
            pattern!(catalog, [{ attachment @ teams::attachment_kind: ?value }])
        )
        .collect(),
        "Teams attachment kind",
    )?;
    let kind_text = String::try_from_inline(&kind)
        .map_err(|error| anyhow::anyhow!("decode Teams attachment kind: {error:?}"))?;
    if kind_text != "attachment" && kind_text != "hosted-content" {
        bail!("invalid Teams attachment kind {kind_text:?}");
    }
    let _name = one_optional(
        find!(
            value: Inline<Handle<UTF8String>>,
            pattern!(catalog, [{ attachment @ archive::attachment_name: ?value }])
        )
        .collect(),
        "Teams attachment name",
    )?;
    let _pointers = find!(
        value: Inline<Handle<UTF8String>>,
        pattern!(catalog, [{ attachment @ archive::attachment_source_pointer: ?value }])
    )
    .collect::<BTreeSet<_>>();
    let file = one_optional(
        find!(
            value: Id,
            pattern!(catalog, [{ attachment @ archive::attachment_file: ?value }])
        )
        .collect(),
        "Teams attachment file",
    )?;
    let size = one_optional(
        find!(
            value: Inline<U256BE>,
            pattern!(catalog, [{ attachment @ archive::attachment_size_bytes: ?value }])
        )
        .collect(),
        "Teams attachment size",
    )?;
    if file.is_some() != size.is_some() {
        bail!("Teams attachment {attachment:x} must carry file and byte size together");
    }
    Ok(())
}

fn validate_observation(
    catalog: &TribleSet,
    observation: Id,
    messages: &BTreeSet<Id>,
    attachments: &BTreeSet<Id>,
    authors: &BTreeSet<Id>,
) -> Result<()> {
    let message = one_required(
        find!(value: Id, pattern!(catalog, [{ observation @ teams::message: ?value }])).collect(),
        "Teams observation message",
    )?;
    if !messages.contains(&message) {
        bail!("Teams observation {observation:x} names an unknown message");
    }
    let state = one_required(
        find!(
            value: Inline<ShortString>,
            pattern!(catalog, [{ observation @ teams::message_state: ?value }])
        )
        .collect(),
        "Teams observation state",
    )?;
    let state_text = String::try_from_inline(&state)
        .map_err(|error| anyhow::anyhow!("decode Teams observation state: {error:?}"))?;
    if state_text != "present" && state_text != "deleted" {
        bail!("invalid Teams observation state {state_text:?}");
    }
    let created = one_optional(
        find!(
            value: Inline<NsTAIInterval>,
            pattern!(catalog, [{ observation @ metadata::created_at: ?value }])
        )
        .collect(),
        "Teams observation created time",
    )?;
    let _modified = one_required(
        find!(
            value: Inline<NsTAIInterval>,
            pattern!(catalog, [{ observation @ teams::modified_at: ?value }])
        )
        .collect(),
        "Teams observation modified time",
    )?;
    let deleted = one_optional(
        find!(
            value: Inline<NsTAIInterval>,
            pattern!(catalog, [{ observation @ teams::deleted_at: ?value }])
        )
        .collect(),
        "Teams observation deleted time",
    )?;
    let author = one_optional(
        find!(value: Id, pattern!(catalog, [{ observation @ archive::author: ?value }])).collect(),
        "Teams observation author",
    )?;
    if author.is_some_and(|author| !authors.contains(&author)) {
        bail!("Teams observation {observation:x} names an unknown author");
    }
    let _author_names = find!(
        value: Inline<Handle<UTF8String>>,
        pattern!(catalog, [{ observation @ teams::author_name: ?value }])
    )
    .collect::<BTreeSet<_>>();
    let content = one_optional(
        find!(
            value: Inline<Handle<UTF8String>>,
            pattern!(catalog, [{ observation @ archive::content: ?value }])
        )
        .collect(),
        "Teams observation content",
    )?;
    let _etag = one_required(
        find!(
            value: Inline<Handle<UTF8String>>,
            pattern!(catalog, [{ observation @ teams::etag: ?value }])
        )
        .collect(),
        "Teams observation etag",
    )?;
    let observation_attachments = find!(
        value: Id,
        pattern!(catalog, [{ observation @ archive::attachment: ?value }])
    )
    .collect::<BTreeSet<_>>();
    if !observation_attachments.is_subset(attachments) {
        bail!("Teams observation {observation:x} names an unknown attachment");
    }
    for attachment in &observation_attachments {
        let owner = one_required(
            find!(
                value: Id,
                pattern!(catalog, [{ *attachment @ teams::attachment_message: ?value }])
            )
            .collect(),
            "Teams attachment owner",
        )?;
        if owner != message {
            bail!("Teams observation {observation:x} links an attachment owned by another message");
        }
    }
    let raw = find!(
        value: Inline<Handle<UTF8String>>,
        pattern!(catalog, [{ observation @ teams::message_raw: ?value }])
    )
    .collect::<BTreeSet<_>>();
    if raw.is_empty() {
        bail!("Teams observation {observation:x} has no raw source representation");
    }
    if state_text == "present" && (created.is_none() || content.is_none()) {
        bail!("present Teams observation {observation:x} lacks created time or content");
    }
    if state_text == "present" && deleted.is_some() {
        bail!("present Teams observation {observation:x} carries a deletion time");
    }
    if state_text == "deleted" && deleted.is_none() {
        bail!("versioned deleted Teams observation {observation:x} lacks deletedDateTime");
    }
    Ok(())
}

fn validate_tombstone(catalog: &TribleSet, tombstone: Id, messages: &BTreeSet<Id>) -> Result<()> {
    let message = one_required(
        find!(value: Id, pattern!(catalog, [{ tombstone @ teams::message: ?value }])).collect(),
        "Teams tombstone message",
    )?;
    if !messages.contains(&message) {
        bail!("Teams tombstone {tombstone:x} names an unknown message");
    }
    let state = one_required(
        find!(
            value: Inline<ShortString>,
            pattern!(catalog, [{ tombstone @ teams::message_state: ?value }])
        )
        .collect(),
        "Teams tombstone state",
    )?;
    let state = String::try_from_inline(&state)
        .map_err(|error| anyhow::anyhow!("decode Teams tombstone state: {error:?}"))?;
    if state != "deleted" {
        bail!("invalid Teams tombstone state {state:?}");
    }
    if find!(
        value: Inline<Handle<UTF8String>>,
        pattern!(catalog, [{ tombstone @ teams::message_raw: ?value }])
    )
    .next()
    .is_none()
    {
        bail!("Teams tombstone {tombstone:x} has no raw source representation");
    }
    Ok(())
}

fn validate_coverage(
    catalog: &TribleSet,
    sources: &BTreeSet<Id>,
    events: &BTreeSet<Id>,
) -> Result<()> {
    let graph_receipts = find!(
        receipt: Id,
        pattern!(catalog, [{ ?receipt @ metadata::tag: teams::kind_coverage }])
    )
    .collect::<BTreeSet<_>>();
    let snapshots = find!(
        receipt: Id,
        pattern!(catalog, [{ ?receipt @ metadata::tag: teams::kind_legacy_snapshot }])
    )
    .collect::<BTreeSet<_>>();
    let mut receipts = graph_receipts;
    receipts.extend(snapshots.iter().copied());
    let mut generations = BTreeMap::new();
    let mut snapshot_sources = BTreeSet::new();

    for receipt in receipts {
        let is_snapshot = snapshots.contains(&receipt);
        let source = one_required(
            find!(value: Id, pattern!(catalog, [{ receipt @ teams::source: ?value }])).collect(),
            "Teams receipt source",
        )?;
        if !sources.contains(&source) {
            bail!("Teams receipt {receipt:x} names an unknown source");
        }
        let generation_inline = one_required(
            find!(
                value: Inline<U256BE>,
                pattern!(catalog, [{ receipt @ teams::coverage_generation: ?value }])
            )
            .collect(),
            "Teams receipt generation",
        )?;
        let generation = inline_u256_to_u128(generation_inline)?;
        let request = one_optional(
            find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(catalog, [{ receipt @ teams::coverage_request: ?value }])
            )
            .collect(),
            "Teams coverage request",
        )?;
        let cursor = one_optional(
            find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(catalog, [{ receipt @ teams::coverage_cursor: ?value }])
            )
            .collect(),
            "Teams coverage cursor",
        )?;
        let kind = one_optional(
            find!(
                value: Inline<ShortString>,
                pattern!(catalog, [{ receipt @ teams::coverage_kind: ?value }])
            )
            .collect(),
            "Teams coverage kind",
        )?;
        let coordinate = one_optional(
            find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(catalog, [{ receipt @ teams::snapshot_source_coordinate: ?value }])
            )
            .collect(),
            "Teams legacy snapshot source coordinate",
        )?;
        let predecessors = find!(
            value: Id,
            pattern!(catalog, [{ receipt @ metadata::supersedes: ?value }])
        )
        .collect::<BTreeSet<_>>();
        let covered = find!(
            value: Id,
            pattern!(catalog, [{ receipt @ teams::coverage_observation: ?value }])
        )
        .collect::<BTreeSet<_>>();
        if !covered.is_subset(events) {
            bail!("Teams receipt {receipt:x} names an unknown message event");
        }
        for event in &covered {
            let message = one_required(
                find!(value: Id, pattern!(catalog, [{ *event @ teams::message: ?value }]))
                    .collect(),
                "Teams covered event message",
            )?;
            let chat = one_required(
                find!(value: Id, pattern!(catalog, [{ message @ teams::chat: ?value }])).collect(),
                "Teams covered event chat",
            )?;
            let event_source = one_required(
                find!(value: Id, pattern!(catalog, [{ chat @ teams::source: ?value }])).collect(),
                "Teams covered event source",
            )?;
            if event_source != source {
                bail!("Teams receipt {receipt:x} carries an event from another source");
            }
        }

        let expected = if is_snapshot {
            if generation != 0
                || request.is_some()
                || cursor.is_some()
                || kind.is_some()
                || !predecessors.is_empty()
            {
                bail!("legacy Teams snapshot {receipt:x} has non-snapshot fields");
            }
            let coordinate = coordinate.ok_or_else(|| {
                anyhow::anyhow!("legacy Teams snapshot {receipt:x} lacks its source coordinate")
            })?;
            if !snapshot_sources.insert(source) {
                bail!("Teams source {source:x} has more than one legacy snapshot receipt");
            }
            entity! {
                metadata::tag: teams::kind_legacy_snapshot,
                teams::source: source,
                teams::coverage_generation: generation_inline,
                teams::snapshot_source_coordinate: coordinate,
                teams::coverage_observation*: covered,
            }
            .root()
            .expect("legacy snapshot identity has one root")
        } else {
            let request = request
                .ok_or_else(|| anyhow::anyhow!("Teams coverage {receipt:x} lacks its request"))?;
            let cursor = cursor
                .ok_or_else(|| anyhow::anyhow!("Teams coverage {receipt:x} lacks its cursor"))?;
            let kind =
                kind.ok_or_else(|| anyhow::anyhow!("Teams coverage {receipt:x} lacks its kind"))?;
            let kind_text = String::try_from_inline(&kind)
                .map_err(|error| anyhow::anyhow!("decode Teams coverage kind: {error:?}"))?;
            if kind_text != "next" && kind_text != "delta" {
                bail!("invalid Teams coverage kind {kind_text:?}");
            }
            if coordinate.is_some() {
                bail!("Graph Teams coverage {receipt:x} carries a legacy source coordinate");
            }
            entity! {
                metadata::tag: teams::kind_coverage,
                teams::source: source,
                teams::coverage_generation: generation_inline,
                teams::coverage_request: request,
                teams::coverage_cursor: cursor,
                teams::coverage_kind: kind,
                metadata::supersedes*: predecessors.clone(),
                teams::coverage_observation*: covered,
            }
            .root()
            .expect("coverage identity has one root")
        };
        if expected != receipt {
            bail!("Teams receipt {receipt:x} is not intrinsic");
        }
        generations.insert(receipt, (source, generation, predecessors, is_snapshot));
    }

    for (receipt, (source, generation, predecessors, is_snapshot)) in &generations {
        if *is_snapshot {
            continue;
        }
        if predecessors.is_empty() {
            if *generation != 1 {
                bail!("root Teams coverage {receipt:x} has generation {generation}, not 1");
            }
            if snapshot_sources.contains(source) {
                bail!("first Graph coverage for source {source:x} does not supersede its legacy snapshot");
            }
            continue;
        }
        let mut parent_generation = None;
        for predecessor in predecessors {
            let Some((parent_source, parent, _, _)) = generations.get(predecessor) else {
                bail!("Teams coverage {receipt:x} names unknown predecessor {predecessor:x}");
            };
            if parent_source != source {
                bail!("Teams coverage {receipt:x} crosses source boundaries");
            }
            parent_generation =
                Some(parent_generation.map_or(*parent, |old: u128| old.max(*parent)));
        }
        if parent_generation.and_then(|parent| parent.checked_add(1)) != Some(*generation) {
            bail!("Teams coverage {receipt:x} generation is not max(parent)+1");
        }
    }
    Ok(())
}

fn validate_contexts(catalog: &TribleSet, sources: &BTreeSet<Id>) -> Result<()> {
    let contexts = find!(
        context: Id,
        pattern!(catalog, [{ ?context @ metadata::tag: teams::kind_context }])
    )
    .collect::<BTreeSet<_>>();
    for context in &contexts {
        let source = one_required(
            find!(value: Id, pattern!(catalog, [{ *context @ teams::source: ?value }])).collect(),
            "Teams context source",
        )?;
        if !sources.contains(&source) {
            bail!("Teams context {context:x} names an unknown source");
        }
        let created = one_required(
            find!(
                value: Inline<NsTAIInterval>,
                pattern!(catalog, [{ *context @ metadata::created_at: ?value }])
            )
            .collect(),
            "Teams context created time",
        )?;
        let name = one_required(
            find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(catalog, [{ *context @ metadata::name: ?value }])
            )
            .collect(),
            "Teams context name",
        )?;
        let boundary = one_required(
            find!(
                value: Inline<Handle<UTF8String>>,
                pattern!(catalog, [{ *context @ metadata::description: ?value }])
            )
            .collect(),
            "Teams context boundary",
        )?;
        let predecessors = find!(
            value: Id,
            pattern!(catalog, [{ *context @ metadata::supersedes: ?value }])
        )
        .collect::<BTreeSet<_>>();
        for predecessor in &predecessors {
            if !contexts.contains(predecessor) {
                bail!("Teams context {context:x} names an unknown predecessor");
            }
            let predecessor_source = one_required(
                find!(
                    value: Id,
                    pattern!(catalog, [{ *predecessor @ teams::source: ?value }])
                )
                .collect(),
                "Teams predecessor context source",
            )?;
            if predecessor_source != source {
                bail!("Teams context {context:x} crosses source boundaries");
            }
        }
        let expected = entity! {
            metadata::tag: teams::kind_context,
            teams::source: source,
            metadata::created_at: created,
            metadata::supersedes*: predecessors,
            metadata::name: name,
            metadata::description: boundary,
        }
        .root()
        .expect("context identity has one root");
        if expected != *context {
            bail!("Teams context {context:x} is not an immutable snapshot");
        }
    }
    Ok(())
}

fn validate_auth_profiles(catalog: &TribleSet, sources: &BTreeSet<Id>) -> Result<()> {
    let profiles = find!(
        profile: Id,
        pattern!(catalog, [{ ?profile @ metadata::tag: teams::kind_auth_profile }])
    )
    .collect::<BTreeSet<_>>();
    let mut records = BTreeMap::new();
    for profile in &profiles {
        let record = auth_profile(catalog, *profile)?;
        if !sources.contains(&record.source) {
            bail!("Teams auth profile {profile:x} names an unknown source");
        }
        if record.client_secret_version.is_none() && record.delegated_token_version.is_none() {
            bail!("Teams auth profile {profile:x} names no Secrets version");
        }
        let expected = auth_profile_record(&record);
        if expected.root() != Some(*profile) || entity_facts(catalog, *profile) != *expected.facts()
        {
            bail!("Teams auth profile {profile:x} is not one immutable full-state snapshot");
        }
        records.insert(*profile, record);
    }

    for (&profile, record) in &records {
        for predecessor in &record.predecessors {
            let Some(parent) = records.get(predecessor) else {
                bail!("Teams auth profile {profile:x} names unknown predecessor {predecessor:x}");
            };
            if parent.source != record.source {
                bail!("Teams auth profile {profile:x} crosses source boundaries");
            }
        }
    }

    fn visit(
        profile: Id,
        records: &BTreeMap<Id, AuthProfileRecord>,
        visiting: &mut BTreeSet<Id>,
        done: &mut BTreeSet<Id>,
    ) -> Result<()> {
        if done.contains(&profile) {
            return Ok(());
        }
        if !visiting.insert(profile) {
            bail!("Teams auth-profile DAG contains a cycle through {profile:x}");
        }
        for predecessor in &records[&profile].predecessors {
            visit(*predecessor, records, visiting, done)?;
        }
        visiting.remove(&profile);
        done.insert(profile);
        Ok(())
    }
    let mut visiting = BTreeSet::new();
    let mut done = BTreeSet::new();
    for &profile in records.keys() {
        visit(profile, &records, &mut visiting, &mut done)?;
    }
    Ok(())
}

fn context_ids<P>(catalog: &P, source: Id) -> BTreeSet<Id>
where
    P: TriblePattern,
{
    find!(
        context: Id,
        pattern!(catalog, [{
            ?context @
            metadata::tag: teams::kind_context,
            teams::source: source,
        }])
    )
    .collect()
}

pub fn context_head_ids<P>(catalog: &P, source: Id) -> BTreeSet<Id>
where
    P: TriblePattern,
{
    let contexts = context_ids(catalog, source);
    let superseded = find!(
        predecessor: Id,
        pattern!(catalog, [{
            _?successor @
            metadata::tag: teams::kind_context,
            teams::source: source,
            metadata::supersedes: ?predecessor,
        }])
    )
    .collect::<BTreeSet<_>>();
    contexts.difference(&superseded).copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use triblespace::core::blob::encodings::UnknownBlob;
    use triblespace::core::repo::pile::Pile;
    use triblespace::core::repo::BlobStorePut;

    fn point(second: f64) -> Inline<NsTAIInterval> {
        let epoch = Epoch::from_tai_seconds(second);
        (epoch, epoch).try_to_inline().unwrap()
    }

    #[test]
    fn native_admission_rejects_retired_oauth_evidence_before_projection() {
        let retired = entity! { metadata::tag: RETIRED_OAUTH_KINDS[0] };
        let error = validate_commit_fragment(retired.facts()).unwrap_err();
        assert!(error
            .to_string()
            .contains("retired plaintext OAuth evidence"));

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("retired-oauth.pile");
        std::fs::File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let reader = pile.snapshot().unwrap();
        let error = validate_catalog(&reader, retired.facts()).unwrap_err();
        assert!(error
            .to_string()
            .contains("retired plaintext OAuth evidence"));
        pile.close().unwrap();
    }

    #[test]
    fn auth_reference_validation_uses_exact_vault_snapshot_ids() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("teams-secrets.pile");
        std::fs::File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let signer = SigningKey::from_bytes(&[0x31; 32]);
        let vault = Id::new([0x32; 16]).unwrap();
        let location =
            crate::secrets::storage::create_vault(&mut pile, &signer, vault, "teams", point(1.0))
                .unwrap();

        let discovery = crate::secrets::storage::discover_local_vaults(&mut pile, &signer).unwrap();
        let exact = crate::secrets::storage::add_secret(
            &mut pile,
            &signer,
            &location,
            discovery.snapshot(),
            "same-name",
            b"exact",
            point(2.0),
        )
        .unwrap();
        drop(discovery);

        let discovery = crate::secrets::storage::discover_local_vaults(&mut pile, &signer).unwrap();
        let later = crate::secrets::storage::add_secret(
            &mut pile,
            &signer,
            &location,
            discovery.snapshot(),
            "same-name",
            b"later",
            point(3.0),
        )
        .unwrap();
        assert_ne!(exact, later);
        drop(discovery);

        let discovery = crate::secrets::storage::discover_local_vaults(&mut pile, &signer).unwrap();
        let secrets = discovery.snapshot();
        assert_eq!(secrets.open(exact, &signer).unwrap(), b"exact");

        let source_identity = source_fragment("tenant.example");
        let source = source_identity.root().unwrap();
        let (profile, _) = auth_profile_fragment(
            source,
            "client",
            "user",
            "offline_access",
            None,
            Some(exact),
            [],
        )
        .unwrap();
        let mut teams = source_identity;
        teams += profile;
        validate_auth_secret_references(teams.facts(), secrets).unwrap();

        let unknown = Id::new([0x33; 16]).unwrap();
        let (profile, dangling_profile) = auth_profile_fragment(
            source,
            "client",
            "user",
            "offline_access",
            None,
            Some(unknown),
            [],
        )
        .unwrap();
        let mut dangling = source_fragment("tenant.example");
        dangling += profile;
        let error = validate_auth_secret_references(dangling.facts(), secrets).unwrap_err();
        assert!(format!("{error:#}").contains(&format!("{unknown:x}")));

        let (successor, _) = auth_profile_fragment(
            source,
            "client",
            "user",
            "offline_access",
            None,
            Some(exact),
            [dangling_profile],
        )
        .unwrap();
        dangling += successor;
        validate_auth_secret_references(dangling.facts(), secrets).unwrap();

        drop(discovery);
        pile.close().unwrap();
    }

    #[test]
    fn auth_profiles_form_an_explicit_source_scoped_dag_without_clock_selection() {
        let source_identity = source_fragment("tenant.example");
        let source = source_identity.root().unwrap();
        let client_secret = Id::new([0x11; 16]).unwrap();
        let token_root = Id::new([0x22; 16]).unwrap();
        let token_left = Id::new([0x33; 16]).unwrap();
        let token_right = Id::new([0x44; 16]).unwrap();

        let (root, root_id) = auth_profile_fragment(
            source,
            "client",
            "user",
            "offline_access Chat.ReadWrite offline_access",
            Some(client_secret),
            Some(token_root),
            [],
        )
        .unwrap();
        assert!(find!(
            value: Inline<NsTAIInterval>,
            pattern!(&root, [{ root_id @ metadata::created_at: ?value }])
        )
        .next()
        .is_none());
        let root_record = auth_profile(root.facts(), root_id).unwrap();

        let (left, left_id) = auth_profile_fragment(
            source,
            "client",
            "user",
            "Chat.ReadWrite offline_access",
            Some(client_secret),
            Some(token_left),
            [root_id],
        )
        .unwrap();
        let (right, right_id) = auth_profile_fragment(
            source,
            "client",
            "user",
            "offline_access Chat.ReadWrite",
            Some(client_secret),
            Some(token_right),
            [root_id],
        )
        .unwrap();

        let mut forked = source_identity;
        forked += root;
        forked += left;
        forked += right;
        assert_eq!(
            auth_profile_head(forked.facts(), source),
            AuthProfileHead::Forked(BTreeSet::from([left_id, right_id]).into_iter().collect())
        );
        assert_eq!(
            read_text(
                &{
                    let directory = tempfile::tempdir().unwrap();
                    let path = directory.path().join("auth.pile");
                    std::fs::File::create(&path).unwrap();
                    let mut pile = Pile::open(&path).unwrap();
                    let mut blobs = forked.blobs().clone();
                    for (_, blob) in blobs.snapshot().unwrap() {
                        pile.put::<UnknownBlob, _>(blob).unwrap();
                    }
                    pile.snapshot().unwrap()
                },
                root_record.scopes,
                "test scopes",
            )
            .unwrap(),
            "Chat.ReadWrite offline_access"
        );

        let (reconciled, reconciled_id) = auth_profile_fragment(
            source,
            "client",
            "user",
            "Chat.ReadWrite offline_access",
            Some(client_secret),
            Some(token_right),
            [left_id, right_id],
        )
        .unwrap();
        forked += reconciled;
        assert_eq!(
            auth_profile_head(forked.facts(), source),
            AuthProfileHead::Unique(reconciled_id)
        );

        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("teams-auth.pile");
        std::fs::File::create(&pile_path).unwrap();
        let mut pile = Pile::open(&pile_path).unwrap();
        let mut blobs = forked.blobs().clone();
        for (_, blob) in blobs.snapshot().unwrap() {
            pile.put::<UnknownBlob, _>(blob).unwrap();
        }
        validate_catalog(&pile.snapshot().unwrap(), forked.facts()).unwrap();
    }

    #[test]
    fn graph_page_advances_generation_zero_snapshot_and_pointer_only_hosted_content_is_valid() {
        let tenant = "tenant.example";
        let source_identity = source_fragment(tenant);
        let source = source_identity.root().unwrap();
        let (mut snapshot_commit, observation) = observation_fragment(
            tenant,
            source,
            MessageObservationInput {
                chat_id: "chat".to_owned(),
                message_id: "message".to_owned(),
                raw: BTreeSet::from(["{\"id\":\"message\"}".to_owned()]),
                author_user_id: Some("author".to_owned()),
                author_name: Some("Author".to_owned()),
                content: Some("hello".to_owned()),
                created_at: Some(point(1.0)),
                modified_at: point(2.0),
                deleted_at: None,
                etag: "etag".to_owned(),
                attachments: vec![
                    AttachmentInput {
                        kind: "hosted-content".to_owned(),
                        source_id: "hosted".to_owned(),
                        name: None,
                        source_pointers: BTreeSet::from([
                            "https://graph.microsoft.test/hosted".to_owned()
                        ]),
                        materialization: None,
                    },
                    AttachmentInput {
                        kind: "attachment".to_owned(),
                        source_id: "materialized".to_owned(),
                        name: Some("materialized.bin".to_owned()),
                        source_pointers: BTreeSet::new(),
                        materialization: Some(AttachmentMaterialization {
                            bytes: vec![1, 2, 3],
                            file_name: "materialized.bin".to_owned(),
                            media_type: "application/octet-stream".to_owned(),
                        }),
                    },
                ],
            },
        )
        .unwrap();
        let coordinate =
            snapshot_source_coordinate(Id::new([0x11; 16]).unwrap(), [0x22; 32], [0x33; 32]);
        let snapshot = legacy_snapshot_fragment(source, &coordinate, [observation]).unwrap();
        let snapshot_id = snapshot.root().unwrap();
        snapshot_commit += snapshot;
        validate_commit_fragment(snapshot_commit.facts()).unwrap();

        let mut graph_commit = source_identity;
        let graph = coverage_fragment(
            source,
            1,
            [snapshot_id],
            "https://graph.microsoft.test/messages/delta",
            "https://graph.microsoft.test/messages/delta?cursor=one",
            "delta",
            [],
        )
        .unwrap();
        let graph_id = graph.root().unwrap();
        graph_commit += graph;
        validate_commit_fragment(graph_commit.facts()).unwrap();

        let mut catalog = snapshot_commit;
        catalog += graph_commit;
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("teams.pile");
        std::fs::File::create(&pile_path).unwrap();
        let mut pile = Pile::open(&pile_path).unwrap();
        let mut blobs = catalog.blobs().clone();
        for (_, blob) in blobs.snapshot().unwrap() {
            pile.put::<UnknownBlob, _>(blob).unwrap();
        }
        let reader = pile.snapshot().unwrap();
        validate_catalog(&reader, catalog.facts()).unwrap();

        assert_eq!(
            coverage_head_ids(catalog.facts(), source),
            BTreeSet::from([graph_id])
        );
        assert_eq!(
            coverage_head(&reader, catalog.facts(), source).unwrap(),
            Some(CoverageHead {
                id: graph_id,
                generation: 1,
                cursor: Some("https://graph.microsoft.test/messages/delta?cursor=one".to_owned()),
            })
        );
        assert_eq!(
            current_message_states(catalog.facts(), source)
                .unwrap()
                .values()
                .copied()
                .collect::<Vec<_>>(),
            vec![CurrentMessageState::Present(observation)]
        );
        assert_eq!(source_ids(catalog.facts()), BTreeSet::from([source]));
        assert_eq!(
            source_label(&reader, catalog.facts(), source).unwrap(),
            tenant
        );
        assert_eq!(
            chat_labels(&reader, catalog.facts(), source)
                .unwrap()
                .into_values()
                .collect::<Vec<_>>(),
            vec!["chat".to_owned()]
        );
        let presented = current_messages(catalog.facts(), source).unwrap();
        assert_eq!(presented.len(), 1);
        assert_eq!(presented[0].observation, Some(observation));
        assert!(!presented[0].deleted);
        assert_eq!(
            read_text(
                &reader,
                presented[0].content.expect("present content"),
                "test content"
            )
            .unwrap(),
            "hello"
        );

        let pointer_only = find!(
            attachment: Id,
            pattern!(catalog.facts(), [{ ?attachment @ metadata::tag: archive::kind_attachment }])
        )
        .find(|attachment| {
            find!(
                file_id: Id,
                pattern!(catalog.facts(), [{ *attachment @ archive::attachment_file: ?file_id }])
            )
            .next()
            .is_none()
        })
        .unwrap();
        let mut missing_file = catalog.clone();
        let size: Inline<U256BE> = 1_u128.to_inline();
        missing_file += entity! { ExclusiveId::force_ref(&pointer_only) @
            archive::attachment_size_bytes: size,
        };
        assert!(validate_catalog(&reader, missing_file.facts())
            .unwrap_err()
            .to_string()
            .contains("file and byte size together"));

        let (materialized, declared_size) = find!(
            (attachment: Id, declared_size: Inline<U256BE>),
            pattern!(catalog.facts(), [{
                ?attachment @
                archive::attachment_file: _?file_id,
                archive::attachment_size_bytes: ?declared_size,
            }])
        )
        .next()
        .unwrap();
        let declared_size_fact = entity! { ExclusiveId::force_ref(&materialized) @
            archive::attachment_size_bytes: declared_size,
        };
        let mut wrong_size = catalog.facts().difference(declared_size_fact.facts());
        let incorrect: Inline<U256BE> = 4_u128.to_inline();
        wrong_size += entity! { ExclusiveId::force_ref(&materialized) @
            archive::attachment_size_bytes: incorrect,
        }
        .into_facts();
        assert!(validate_catalog(&reader, &wrong_size)
            .unwrap_err()
            .to_string()
            .contains("contains 3"));
        drop(reader);
        pile.close().unwrap();
    }

    #[test]
    fn graph_datetime_and_hosted_content_parsers_are_shared_source_semantics() {
        let utc = parse_graph_datetime("2026-08-09T12:34:56.1234567Z").unwrap();
        let offset = parse_graph_datetime("2026-08-09T14:34:56.1234567+02:00").unwrap();
        assert_eq!(utc, offset);
        assert_eq!(
            extract_hosted_content_ids(
                "a /hostedContents/one/$value b /hostedContents/two/$value c /hostedContents/one/$value"
            ),
            vec!["one".to_owned(), "two".to_owned()]
        );
    }

    #[test]
    fn causal_merge_orders_full_versions_but_not_unversioned_tombstones() {
        let message = Id::new([9; 16]).unwrap();
        let present = Id::new([1; 16]).unwrap();
        let deleted = Id::new([2; 16]).unwrap();
        let observations = BTreeMap::from([
            (
                present,
                ObservationOrder {
                    message,
                    modified: 10,
                    deleted: false,
                },
            ),
            (
                deleted,
                ObservationOrder {
                    message,
                    modified: 11,
                    deleted: true,
                },
            ),
        ]);
        assert_eq!(
            merge_causal_visible(
                CausalVisible::Present(present),
                CausalVisible::Deleted(Some(deleted)),
                &observations,
            )
            .unwrap(),
            CausalVisible::Deleted(Some(deleted))
        );
        assert_eq!(
            merge_causal_visible(
                CausalVisible::Deleted(None),
                CausalVisible::Present(present),
                &observations,
            )
            .unwrap(),
            CausalVisible::Conflict
        );
    }
}
