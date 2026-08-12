//! Canonical live Voice records and strict collection admission.
//!
//! Live semantics begin only at records carrying [`KIND_LIVE_RECORD`]. The
//! native writer always emits that marker, and the stopped-world cutover
//! reconstructs validated historical records with it under current intrinsic
//! identities. Marker-free historical evidence may coexist in an already
//! migrated collection, but remains semantically inert.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::core::trible::intrinsic_entity_id_v1;
use triblespace::prelude::*;

use crate::schemas::voice::{
    route, utterance, CHANNEL_SAY, CHANNEL_SHOUT, KIND_LIVE_RECORD, KIND_ROUTE, KIND_UTTERANCE,
};

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type PriorityValue = Inline<inlineencodings::U256BE>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
pub type AudioHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;

pub const AUDIO_WAV_MIME: &str = "audio/wav";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRow {
    pub id: Id,
    pub channel: String,
    pub device: String,
    pub priority: PriorityValue,
    pub updated_at: IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtteranceRow {
    pub id: Id,
    pub channel: String,
    pub text: TextHandle,
    pub audio: Option<AudioHandle>,
    pub mime: Option<String>,
    pub created_at: IntervalValue,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VoiceCatalog {
    pub routes: BTreeMap<Id, RouteRow>,
    pub utterances: BTreeMap<Id, UtteranceRow>,
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn exactly_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<T> {
    if values.len() != 1 {
        bail!(
            "live Voice entity {} has {} values for {field}; expected exactly one",
            fmt_id(entity),
            values.len()
        );
    }
    Ok(values.pop().expect("length checked"))
}

fn at_most_one<T>(entity: Id, field: &str, mut values: Vec<T>) -> Result<Option<T>> {
    if values.len() > 1 {
        bail!(
            "live Voice entity {} has {} values for {field}; expected at most one",
            fmt_id(entity),
            values.len()
        );
    }
    Ok(values.pop())
}

fn validate_channel(entity: Id, channel: &str) -> Result<()> {
    if !matches!(channel, CHANNEL_SAY | CHANNEL_SHOUT) {
        bail!(
            "live Voice entity {} has invalid channel {channel:?}; expected say or shout",
            fmt_id(entity)
        );
    }
    Ok(())
}

fn validate_point(entity: Id, field: &str, interval: IntervalValue) -> Result<()> {
    let (lower, upper): (i128, i128) = interval.try_from_inline().map_err(|error| {
        anyhow!(
            "decode {field} on live Voice entity {}: {error:?}",
            fmt_id(entity)
        )
    })?;
    if lower != upper {
        bail!(
            "live Voice entity {} has a non-point {field}",
            fmt_id(entity)
        );
    }
    Ok(())
}

fn priority_u64(entity: Id, priority: PriorityValue) -> Result<u64> {
    if priority.raw[..24].iter().any(|byte| *byte != 0) {
        bail!(
            "live Voice route {} priority exceeds the writer's u64 domain",
            fmt_id(entity)
        );
    }
    Ok(u64::from_be_bytes(
        priority.raw[24..].try_into().expect("eight-byte suffix"),
    ))
}

fn validate_audio_mime(row: &UtteranceRow) -> Result<()> {
    match (row.audio, row.mime.as_deref()) {
        (None, None) | (Some(_), Some(AUDIO_WAV_MIME)) => Ok(()),
        (Some(_), Some(mime)) => bail!(
            "live Voice utterance {} has unsupported audio MIME {mime:?}; expected {AUDIO_WAV_MIME}",
            fmt_id(row.id)
        ),
        (Some(_), None) => bail!(
            "live Voice utterance {} has audio without a MIME type",
            fmt_id(row.id)
        ),
        (None, Some(_)) => bail!(
            "live Voice utterance {} has a MIME type without audio",
            fmt_id(row.id)
        ),
    }
}

/// Construct one exact live route preference.
pub fn route_record(
    channel: &str,
    device: &str,
    priority: PriorityValue,
    updated_at: IntervalValue,
) -> Fragment {
    entity! {
        metadata::tag: &KIND_LIVE_RECORD,
        metadata::tag: &KIND_ROUTE,
        metadata::updated_at: updated_at,
        route::channel: channel,
        route::device: device,
        route::priority: priority,
    }
}

/// Construct one exact live utterance around already-stored payloads.
pub fn utterance_record(
    channel: &str,
    text: TextHandle,
    audio: Option<AudioHandle>,
    mime: Option<&str>,
    created_at: IntervalValue,
) -> Fragment {
    entity! {
        metadata::tag: &KIND_LIVE_RECORD,
        metadata::tag: &KIND_UTTERANCE,
        metadata::created_at: created_at,
        utterance::channel: channel,
        utterance::text: text,
        utterance::audio?: audio.as_ref(),
        utterance::mime?: mime,
    }
}

// Exact marker-free constructors for validating the pre-native identity
// epoch. They are intentionally private: all newly authored Voice records use
// the public constructors above and therefore carry KIND_LIVE_RECORD.
fn legacy_route_record(
    channel: &str,
    device: &str,
    priority: PriorityValue,
    updated_at: IntervalValue,
) -> Fragment {
    entity! {
        metadata::tag: &KIND_ROUTE,
        metadata::updated_at: updated_at,
        route::channel: channel,
        route::device: device,
        route::priority: priority,
    }
}

fn legacy_utterance_record(
    channel: &str,
    text: TextHandle,
    audio: Option<AudioHandle>,
    mime: Option<&str>,
    created_at: IntervalValue,
) -> Fragment {
    entity! {
        metadata::tag: &KIND_UTTERANCE,
        metadata::created_at: created_at,
        utterance::channel: channel,
        utterance::text: text,
        utterance::audio?: audio.as_ref(),
        utterance::mime?: mime,
    }
}

/// Build one complete live utterance and carry its text/audio payloads.
pub fn utterance_fragment(
    channel: &str,
    text: &str,
    audio: Option<Vec<u8>>,
    created_at: IntervalValue,
) -> Result<Fragment> {
    if !matches!(channel, CHANNEL_SAY | CHANNEL_SHOUT) {
        bail!("new Voice utterance has invalid channel {channel:?}; expected say or shout");
    }
    let (lower, upper): (i128, i128) = created_at
        .try_from_inline()
        .map_err(|error| anyhow!("decode new Voice utterance timestamp: {error:?}"))?;
    if lower != upper {
        bail!("new Voice utterance timestamp must be a point interval");
    }
    let mut fragment = Fragment::empty();
    let text = fragment.put::<blobencodings::LongString, _>(text.to_owned());
    let audio = audio.map(|bytes| fragment.put::<blobencodings::RawBytes, _>(bytes));
    fragment += utterance_record(
        channel,
        text,
        audio,
        audio.map(|_| AUDIO_WAV_MIME),
        created_at,
    );
    Ok(fragment)
}

fn tagged_entities(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(entity: Id, pattern!(facts, [{ ?entity @ metadata::tag: kind }])).collect()
}

/// Project the only facts that have live Voice meaning.
///
/// Exact legacy facts coexist in the same collection but lack the live marker,
/// so they never influence routing, utterance admission, or future writes.
pub fn active_facts(facts: &TribleSet) -> TribleSet {
    let active = tagged_entities(facts, KIND_LIVE_RECORD);
    facts
        .iter()
        .filter(|fact| active.contains(fact.e()))
        .copied()
        .collect()
}

fn load_route(facts: &TribleSet, id: Id) -> Result<RouteRow> {
    let row = RouteRow {
        id,
        channel: exactly_one(
            id,
            "route::channel",
            find!(value: String, pattern!(facts, [{ id @ route::channel: ?value }])).collect(),
        )?,
        device: exactly_one(
            id,
            "route::device",
            find!(value: String, pattern!(facts, [{ id @ route::device: ?value }])).collect(),
        )?,
        priority: exactly_one(
            id,
            "route::priority",
            find!(value: PriorityValue, pattern!(facts, [{ id @ route::priority: ?value }]))
                .collect(),
        )?,
        updated_at: exactly_one(
            id,
            "metadata::updated_at",
            find!(value: IntervalValue, pattern!(facts, [{ id @ metadata::updated_at: ?value }]))
                .collect(),
        )?,
    };
    validate_channel(id, &row.channel)?;
    validate_point(id, "route update timestamp", row.updated_at)?;
    priority_u64(id, row.priority)?;
    Ok(row)
}

fn load_utterance(facts: &TribleSet, id: Id) -> Result<UtteranceRow> {
    let row = UtteranceRow {
        id,
        channel: exactly_one(
            id,
            "utterance::channel",
            find!(value: String, pattern!(facts, [{ id @ utterance::channel: ?value }])).collect(),
        )?,
        text: exactly_one(
            id,
            "utterance::text",
            find!(value: TextHandle, pattern!(facts, [{ id @ utterance::text: ?value }])).collect(),
        )?,
        audio: at_most_one(
            id,
            "utterance::audio",
            find!(value: AudioHandle, pattern!(facts, [{ id @ utterance::audio: ?value }]))
                .collect(),
        )?,
        mime: at_most_one(
            id,
            "utterance::mime",
            find!(value: String, pattern!(facts, [{ id @ utterance::mime: ?value }])).collect(),
        )?,
        created_at: exactly_one(
            id,
            "metadata::created_at",
            find!(value: IntervalValue, pattern!(facts, [{ id @ metadata::created_at: ?value }]))
                .collect(),
        )?,
    };
    validate_channel(id, &row.channel)?;
    validate_point(id, "utterance creation timestamp", row.created_at)?;
    validate_audio_mime(&row)?;
    Ok(row)
}

fn record_pairs(facts: &TribleSet, entity: Id) -> BTreeSet<(Id, [u8; 32])> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity)
        .map(|fact| (*fact.a(), fact.v::<inlineencodings::R256>().raw))
        .collect()
}

fn expected_pairs(fragment: &Fragment) -> BTreeSet<(Id, [u8; 32])> {
    fragment
        .facts()
        .iter()
        .map(|fact| (*fact.a(), fact.v::<inlineencodings::R256>().raw))
        .collect()
}

fn validate_identity(facts: &TribleSet, id: Id, kind: &str, expected: &Fragment) -> Result<()> {
    if record_pairs(facts, id) != expected_pairs(expected) {
        bail!(
            "live Voice {kind} {} has facts outside its exact record",
            fmt_id(id)
        );
    }
    let canonical = expected
        .root()
        .expect("canonical Voice record has one root");
    if canonical != id {
        bail!(
            "live Voice {kind} {} is not intrinsic; canonical identity is {}",
            fmt_id(id),
            fmt_id(canonical)
        );
    }
    Ok(())
}

fn validate_legacy_identity(
    facts: &TribleSet,
    id: Id,
    kind: &str,
    expected: &Fragment,
) -> Result<()> {
    let pairs = expected_pairs(expected);
    if record_pairs(facts, id) != pairs {
        bail!(
            "historical Voice {kind} {} has facts outside its exact marker-free record",
            fmt_id(id)
        );
    }
    let canonical = intrinsic_entity_id_v1(pairs.into_iter().collect());
    if canonical != id {
        bail!(
            "historical Voice {kind} {} is not intrinsic under the historical v1 identity; canonical identity is {}",
            fmt_id(id),
            fmt_id(canonical)
        );
    }
    Ok(())
}

/// Strictly load the marker-free historical Voice ontology under the v1
/// intrinsic-identity rule. This seam exists only for stopped-world cutover.
pub(crate) fn validate_legacy_catalog_v1(
    reader: &PileReader,
    facts: &TribleSet,
) -> Result<VoiceCatalog> {
    let route_ids = tagged_entities(facts, KIND_ROUTE);
    let utterance_ids = tagged_entities(facts, KIND_UTTERANCE);
    if let Some(id) = route_ids.intersection(&utterance_ids).next() {
        bail!(
            "historical Voice entity {} is both a route and an utterance",
            fmt_id(*id)
        );
    }

    let mut catalog = VoiceCatalog::default();
    for id in route_ids {
        let row = load_route(facts, id)?;
        let expected = legacy_route_record(&row.channel, &row.device, row.priority, row.updated_at);
        validate_legacy_identity(facts, id, "route", &expected)?;
        catalog.routes.insert(id, row);
    }
    for id in utterance_ids {
        let row = load_utterance(facts, id)?;
        let expected = legacy_utterance_record(
            &row.channel,
            row.text,
            row.audio,
            row.mime.as_deref(),
            row.created_at,
        );
        validate_legacy_identity(facts, id, "utterance", &expected)?;
        catalog.utterances.insert(id, row);
    }

    let accounted: usize = catalog
        .routes
        .keys()
        .chain(catalog.utterances.keys())
        .map(|id| facts.iter().filter(|fact| fact.e() == id).count())
        .sum();
    if accounted != facts.len() {
        bail!(
            "historical Voice catalog has {} facts outside exact route and utterance records",
            facts.len().saturating_sub(accounted)
        );
    }
    validate_payloads(reader, None::<&PileReader>, &catalog)?;
    Ok(catalog)
}

/// Load the exact live projection. Historical evidence is ignored by design.
pub fn load_catalog(facts: &TribleSet) -> Result<VoiceCatalog> {
    let facts = active_facts(facts);
    let route_ids = tagged_entities(&facts, KIND_ROUTE);
    let utterance_ids = tagged_entities(&facts, KIND_UTTERANCE);
    if let Some(id) = route_ids.intersection(&utterance_ids).next() {
        bail!(
            "live Voice entity {} is both a route and an utterance",
            fmt_id(*id)
        );
    }

    let mut catalog = VoiceCatalog::default();
    for id in route_ids {
        let row = load_route(&facts, id)?;
        let expected = route_record(&row.channel, &row.device, row.priority, row.updated_at);
        validate_identity(&facts, id, "route", &expected)?;
        catalog.routes.insert(id, row);
    }
    for id in utterance_ids {
        let row = load_utterance(&facts, id)?;
        let expected = utterance_record(
            &row.channel,
            row.text,
            row.audio,
            row.mime.as_deref(),
            row.created_at,
        );
        validate_identity(&facts, id, "utterance", &expected)?;
        catalog.utterances.insert(id, row);
    }

    let accounted: usize = catalog
        .routes
        .keys()
        .chain(catalog.utterances.keys())
        .map(|id| facts.iter().filter(|fact| fact.e() == id).count())
        .sum();
    if accounted != facts.len() {
        bail!(
            "live Voice projection has {} facts outside exact route and utterance records",
            facts.len().saturating_sub(accounted)
        );
    }
    Ok(catalog)
}

fn read_text_overlay<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    handle: TextHandle,
) -> Result<anybytes::View<str>>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    if let Some(overlay) = overlay {
        if overlay.metadata(handle)?.is_some() {
            return overlay.get(handle).map_err(Into::into);
        }
    }
    reader.get(handle).map_err(Into::into)
}

fn read_audio_overlay<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    handle: AudioHandle,
) -> Result<anybytes::Bytes>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    if let Some(overlay) = overlay {
        if overlay.metadata(handle)?.is_some() {
            return overlay.get(handle).map_err(Into::into);
        }
    }
    reader.get(handle).map_err(Into::into)
}

fn validate_payloads<Overlay>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    catalog: &VoiceCatalog,
) -> Result<()>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    for row in catalog.utterances.values() {
        let _: anybytes::View<str> = read_text_overlay(reader, overlay, row.text)
            .with_context(|| format!("read live Voice utterance {} text", fmt_id(row.id)))?;
        if let Some(audio) = row.audio {
            let _: anybytes::Bytes = read_audio_overlay(reader, overlay, audio)
                .with_context(|| format!("read live Voice utterance {} audio", fmt_id(row.id)))?;
        }
    }
    Ok(())
}

/// Validate one complete materialized collection's live projection.
pub fn validate_catalog(reader: &PileReader, facts: &TribleSet) -> Result<VoiceCatalog> {
    let catalog = load_catalog(facts)?;
    validate_payloads(reader, None::<&PileReader>, &catalog)?;
    Ok(catalog)
}

/// Validate a complete materialized Voice value while resolving newly staged
/// payloads from an overlay before they have crossed the commit boundary.
pub(crate) fn validate_catalog_with_overlay<Overlay>(
    reader: &PileReader,
    overlay: &Overlay,
    facts: &TribleSet,
) -> Result<VoiceCatalog>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    let catalog = load_catalog(facts)?;
    validate_payloads(reader, Some(overlay), &catalog)?;
    Ok(catalog)
}

/// Enforce the independently signed native Voice transaction boundary.
pub fn validate_commit_fragment(facts: &TribleSet) -> Result<VoiceCatalog> {
    let active = active_facts(facts);
    if active != *facts {
        bail!("a live Voice commit may not smuggle inert historical facts");
    }
    let catalog = load_catalog(facts)?;
    match (catalog.routes.len(), catalog.utterances.len()) {
        (0, 1) => Ok(catalog),
        (routes, 0) if routes > 0 => {
            let channels = catalog
                .routes
                .values()
                .map(|row| row.channel.as_str())
                .collect::<BTreeSet<_>>();
            let times = catalog
                .routes
                .values()
                .map(|row| row.updated_at.raw)
                .collect::<BTreeSet<_>>();
            let devices = catalog
                .routes
                .values()
                .map(|row| row.device.as_str())
                .collect::<BTreeSet<_>>();
            let priorities = catalog
                .routes
                .values()
                .map(|row| priority_u64(row.id, row.priority))
                .collect::<Result<BTreeSet<_>>>()?;
            let expected = (0..routes as u64).collect::<BTreeSet<_>>();
            if channels.len() != 1
                || times.len() != 1
                || devices.len() != routes
                || priorities != expected
            {
                bail!(
                    "a Voice route commit must be one complete generation with one channel/time, unique devices, and contiguous priorities"
                );
            }
            Ok(catalog)
        }
        _ => bail!("a live Voice commit must contain one utterance or one route generation"),
    }
}

/// Preflight the exact union produced by one native Voice commit.
pub fn validate_candidate(
    reader: &PileReader,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<VoiceCatalog> {
    validate_commit_fragment(fragment.facts())?;
    let mut union = current.clone();
    union += fragment.facts().clone();
    let catalog = load_catalog(&union)?;
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .context("snapshot staged Voice attachments")?;
    validate_payloads(reader, Some(&overlay), &catalog)?;
    Ok(catalog)
}

/// Strictly load every direct Voice payload named by a legacy authored commit.
///
/// This validates transport closure without granting live semantics.
pub fn validate_known_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts {
        if fact.a() == &utterance::text.id() || fact.a() == &metadata::description.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
            let _: anybytes::View<str> = reader.get(handle).with_context(|| {
                format!(
                    "read historical Voice text payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if fact.a() == &utterance::audio.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::RawBytes>>();
            let _: anybytes::Bytes = reader.get(handle).with_context(|| {
                format!(
                    "read historical Voice audio payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use hifitime::Epoch;
    use triblespace::core::id::ExclusiveId;
    use triblespace::core::repo::BlobStore;

    use super::*;
    use crate::collection_cutover::open_pile_strict;

    fn point(seconds: f64) -> IntervalValue {
        let epoch = Epoch::from_tai_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    #[test]
    fn historical_records_are_exactly_present_but_semantically_inert() {
        let legacy = entity! {
            metadata::tag: &KIND_ROUTE,
            metadata::updated_at: point(1.0),
            route::channel: CHANNEL_SAY,
            route::device: "Legacy speaker",
            route::priority: 0_u64.to_inline(),
        };
        assert!(!legacy.facts().is_empty());
        assert!(load_catalog(legacy.facts()).unwrap().routes.is_empty());
        assert!(active_facts(legacy.facts()).is_empty());
    }

    #[test]
    fn exact_live_records_validate_and_extra_facts_do_not_hide() {
        let route = route_record(CHANNEL_SAY, "AirPods", 0_u64.to_inline(), point(2.0));
        assert_eq!(load_catalog(route.facts()).unwrap().routes.len(), 1);

        let id = route.root().unwrap();
        let mut malformed = route.into_facts();
        malformed += entity! { ExclusiveId::force_ref(&id) @
            metadata::created_at: point(3.0)
        }
        .into_facts();
        assert!(format!("{:#}", load_catalog(&malformed).unwrap_err()).contains("outside"));
    }

    #[test]
    fn route_commit_is_one_dense_generation() {
        let at = point(4.0);
        let good = route_record(CHANNEL_SHOUT, "Reachy", 0_u64.to_inline(), at)
            + route_record(CHANNEL_SHOUT, "MacBook", 1_u64.to_inline(), at);
        validate_commit_fragment(good.facts()).unwrap();

        let sparse = route_record(CHANNEL_SHOUT, "Reachy", 0_u64.to_inline(), at)
            + route_record(CHANNEL_SHOUT, "MacBook", 2_u64.to_inline(), at);
        assert!(format!(
            "{:#}",
            validate_commit_fragment(sparse.facts()).unwrap_err()
        )
        .contains("complete generation"));
    }

    #[test]
    fn missing_live_payload_is_a_hard_failure() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("empty.pile");
        File::create(&pile_path).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();

        let missing =
            utterance_record(CHANNEL_SAY, Inline::new([0x71; 32]), None, None, point(5.0));
        let error = validate_catalog(&reader, missing.facts()).unwrap_err();
        assert!(format!("{error:#}").contains("text"));
    }
}
