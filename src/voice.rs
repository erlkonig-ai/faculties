//! Canonical Voice records and narrow, query-driven projections.
//!
//! Live semantics begin only at records carrying [`KIND_LIVE_RECORD`]. The
//! native writer emits that marker; marker-free historical evidence may
//! coexist in the collection but is semantically inert. Ordinary reads query
//! the maintained fact archive at the point of use. They never materialize a
//! second catalog, validate intrinsic ids, or impose a closed-world shape on
//! the collection.

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::{BlobStoreGet, SnapshotSource};
use triblespace::prelude::*;

use crate::schemas::voice::{
    route, utterance, CHANNEL_SAY, CHANNEL_SHOUT, KIND_LIVE_RECORD, KIND_ROUTE, KIND_UTTERANCE,
};

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type PriorityValue = Inline<inlineencodings::U256BE>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type AudioHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;

pub const AUDIO_WAV_MIME: &str = "audio/wav";

/// One decodable route row selected by a point-of-use query.
///
/// Several rows may describe the same entity in an open-world collection.
/// Callers choose the generation and ordering relevant to their operation;
/// this projection deliberately does not impose hidden cardinality rules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteRow {
    pub id: Id,
    pub channel: String,
    pub device: String,
    pub priority: u64,
    pub updated_at: (i128, i128),
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// Construct one live route preference.
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

/// Construct one live utterance around already-stored payloads.
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
    let text = fragment.put::<blobencodings::UTF8String, _>(text.to_owned());
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

/// Query the complete, decodable live route rows for one channel.
///
/// Typed query conversion is the compatibility boundary: evidence written by
/// a different schema generation is skipped rather than turning one unknown
/// row into a failure for the whole collection. Unknown additional facts and
/// non-canonical entity ids have no effect on this projection.
pub fn route_rows<P>(facts: &P, channel: &str) -> Vec<RouteRow>
where
    P: TriblePattern,
{
    find!(
        (
            id: Id,
            device: String,
            priority: u64,
            updated_at: (i128, i128)
        ),
        pattern!(facts, [{
            ?id @
                metadata::tag: KIND_LIVE_RECORD,
                metadata::tag: KIND_ROUTE,
                route::channel: channel.to_owned(),
                route::device: ?device,
                route::priority: ?priority,
                metadata::updated_at: ?updated_at,
        }])
    )
    .map(|(id, device, priority, updated_at)| RouteRow {
        id,
        channel: channel.to_owned(),
        device,
        priority,
        updated_at,
    })
    .collect()
}

/// Validate only payloads carried by one staged Voice fragment.
///
/// This is a publication-boundary check over the fragment's own attachment
/// store, not a rescan of ambient Voice history. Record constructors already
/// establish their modeled shape. The query merely finds every staged live
/// utterance payload and proves that the fragment itself carries decodable
/// bytes for it before publication.
pub fn validate_staged_payloads(fragment: &mut Fragment) -> Result<()> {
    let attachments = fragment
        .blobs_mut()
        .snapshot()
        .context("freeze staged Voice attachments")?;

    for (id, text) in find!(
        (id: Id, text: TextHandle),
        pattern!(fragment.facts(), [{
            ?id @
                metadata::tag: KIND_LIVE_RECORD,
                metadata::tag: KIND_UTTERANCE,
                utterance::text: ?text,
        }])
    ) {
        let _: anybytes::View<str> = attachments
            .get(text)
            .with_context(|| format!("read staged Voice utterance {} text", fmt_id(id)))?;
    }

    for (id, audio) in find!(
        (id: Id, audio: AudioHandle),
        pattern!(fragment.facts(), [{
            ?id @
                metadata::tag: KIND_LIVE_RECORD,
                metadata::tag: KIND_UTTERANCE,
                utterance::audio: ?audio,
        }])
    ) {
        let _: anybytes::Bytes = attachments
            .get(audio)
            .with_context(|| format!("read staged Voice utterance {} audio", fmt_id(id)))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use hifitime::Epoch;
    use triblespace::core::id::ExclusiveId;

    use super::*;

    fn point(seconds: f64) -> IntervalValue {
        let epoch = Epoch::from_tai_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    #[test]
    fn marker_free_history_is_semantically_inert() {
        let legacy = entity! {
            metadata::tag: &KIND_ROUTE,
            metadata::updated_at: point(1.0),
            route::channel: CHANNEL_SAY,
            route::device: "Legacy speaker",
            route::priority: 0_u64.to_inline(),
        };
        assert!(!legacy.facts().is_empty());
        assert!(route_rows(legacy.facts(), CHANNEL_SAY).is_empty());
    }

    #[test]
    fn live_projection_is_open_world_and_treats_ids_as_opaque() {
        let route = route_record(CHANNEL_SAY, "AirPods", 0_u64.to_inline(), point(2.0));
        assert_eq!(route_rows(route.facts(), CHANNEL_SAY).len(), 1);

        let id = route.root().unwrap();
        let mut extended = route.into_facts();
        extended += entity! { ExclusiveId::force_ref(&id) @
            metadata::created_at: point(3.0)
        }
        .into_facts();
        let rows = route_rows(&extended, CHANNEL_SAY);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id);
    }

    #[test]
    fn route_query_projects_a_complete_generation() {
        let at = point(4.0);
        let generation = route_record(CHANNEL_SHOUT, "Reachy", 0_u64.to_inline(), at)
            + route_record(CHANNEL_SHOUT, "MacBook", 1_u64.to_inline(), at);
        let mut rows = route_rows(generation.facts(), CHANNEL_SHOUT);
        rows.sort_by_key(|row| row.priority);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].device, "Reachy");
        assert_eq!(rows[1].device, "MacBook");
    }

    #[test]
    fn staged_payload_validation_never_falls_back_to_ambient_storage() {
        let mut missing =
            utterance_record(CHANNEL_SAY, Inline::new([0x71; 32]), None, None, point(5.0));
        let error = validate_staged_payloads(&mut missing).unwrap_err();
        assert!(format!("{error:#}").contains("text"));

        let mut complete = utterance_fragment(
            CHANNEL_SAY,
            "carried locally",
            Some(vec![1, 2, 3]),
            point(6.0),
        )
        .unwrap();
        validate_staged_payloads(&mut complete).unwrap();
    }
}
