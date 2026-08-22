//! Shared Discord collection semantics.
//!
//! This module is the single read model used by both the CLI and the GORBIE
//! widget. It deliberately knows nothing about HTTP or mutable cursors: it
//! selects immutable semantic message versions, presents independently
//! observed user profiles, and computes the connected coverage frontier from
//! explicit numeric intervals.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{bail, Context, Result};
use hifitime::Epoch;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::blobencodings::UTF8String;
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;

use crate::schemas::archive::archive;
use crate::schemas::discord::discord;

pub type TextHandle = Inline<Handle<UTF8String>>;

/// Validate and decode Discord's canonical decimal representation of a
/// snowflake. Zero is not a Discord object id; coverage boundaries may use
/// zero internally and are stored as numeric values instead.
pub fn validate_snowflake(raw: &str) -> Result<u64> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("snowflake must contain only decimal digits");
    }
    let value = raw
        .parse::<u64>()
        .with_context(|| format!("snowflake '{raw}' is outside u64"))?;
    if value == 0 || value.to_string() != raw {
        bail!("snowflake must be a canonical positive u64");
    }
    Ok(value)
}

pub fn message_anchor_fragment(external_id: &str) -> Result<Fragment> {
    validate_snowflake(external_id).context("invalid Discord message id")?;
    Ok(entity! { _ @ discord::message_id: external_id.to_owned() })
}

pub fn channel_fragment(external_id: &str) -> Result<Fragment> {
    validate_snowflake(external_id).context("invalid Discord channel id")?;
    Ok(entity! { _ @
        metadata::tag: discord::kind_channel,
        discord::channel_id: external_id.to_owned(),
    })
}

pub fn user_fragment(external_id: &str) -> Result<Fragment> {
    validate_snowflake(external_id).context("invalid Discord user id")?;
    Ok(entity! { _ @
        metadata::tag: discord::kind_user,
        discord::user_id: external_id.to_owned(),
    })
}

pub fn interval_key(interval: Inline<NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().expect("valid TAI interval");
    lower.to_tai_duration().total_nanoseconds()
}

pub fn read_text(reader: &PileReader, handle: TextHandle, label: &str) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read {label} blob {}", hex::encode_upper(handle.raw)))?;
    Ok(value.to_string())
}

fn read_text_overlay<Store, Overlay>(
    reader: &Store,
    overlay: Option<&Overlay>,
    handle: TextHandle,
    label: &str,
) -> Result<String>
where
    Store: BlobStoreGet + ?Sized,
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    if let Some(overlay) = overlay {
        if overlay
            .metadata(handle)
            .with_context(|| format!("inspect staged {label} blob"))?
            .is_some()
        {
            let value: View<str> = overlay.get(handle).with_context(|| {
                format!("read staged {label} blob {}", hex::encode_upper(handle.raw))
            })?;
            return Ok(value.to_string());
        }
    }
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read {label} blob {}", hex::encode_upper(handle.raw)))?;
    Ok(value.to_string())
}

/// Validate every live Discord observation and receipt in a materialized
/// collection. Exact legacy rows copied by migration remain inert: only the
/// immutable observation link and native coverage tags establish meaning.
pub fn validate_catalog<Store>(reader: &Store, facts: &TribleSet) -> Result<()>
where
    Store: BlobStoreGet + ?Sized,
{
    validate_catalog_with(reader, None::<&PileReader>, facts)
}

/// Validate the exact union which would result from one new signed COMMIT.
/// Candidate attachments are read from the fragment's local overlay, so a bad
/// payload fails before any append reaches the pile.
pub fn validate_candidate<Store>(
    reader: &Store,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<()>
where
    Store: BlobStoreGet + ?Sized,
{
    let mut union = current.clone();
    union += fragment.facts().clone();
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .expect("MemoryBlobStore reader creation is infallible");
    validate_catalog_with(reader, Some(&overlay), &union)
}

fn validate_catalog_with<Store, Overlay>(
    reader: &Store,
    overlay: Option<&Overlay>,
    facts: &TribleSet,
) -> Result<()>
where
    Store: BlobStoreGet + ?Sized,
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    // This checks every immutable observation, including divergent and older
    // semantic versions; selection only changes presentation.
    let _ = select_messages(facts, None, None)?;

    let observations = find!(
        (observation: Id, anchor: Id, author: Id, channel: Id, content: TextHandle),
        pattern!(facts, [{
            ?observation @
            metadata::tag: archive::kind_message,
            discord::message: ?anchor,
            archive::author: ?author,
            discord::channel: ?channel,
            archive::content: ?content,
        }])
    )
    .collect::<Vec<_>>();

    let mut message_anchors = BTreeSet::new();
    let mut authors = BTreeSet::new();
    let mut channels = BTreeSet::new();
    for (_observation, anchor, author, channel, content) in observations {
        message_anchors.insert(anchor);
        authors.insert(author);
        channels.insert(channel);
        read_text_overlay(reader, overlay, content, "Discord message content")?;
    }
    for reply in find!(
        reply: Id,
        pattern!(facts, [{
            _?observation @
            metadata::tag: archive::kind_message,
            discord::message: _?anchor,
            archive::reply_to: ?reply,
        }])
    ) {
        message_anchors.insert(reply);
    }

    for anchor in message_anchors {
        let handles = find!(
            handle: TextHandle,
            pattern!(facts, [{ anchor @ discord::message_id: ?handle }])
        )
        .collect::<BTreeSet<_>>();
        if handles.len() != 1 {
            bail!(
                "Discord message anchor {anchor:X} has {} external ids",
                handles.len()
            );
        }
        let value = read_text_overlay(
            reader,
            overlay,
            *handles.iter().next().expect("one message id"),
            "Discord message id",
        )?;
        validate_snowflake(&value).context("invalid persisted Discord message id")?;
    }

    for author in authors {
        let handles = find!(
            handle: TextHandle,
            pattern!(facts, [{ author @ discord::user_id: ?handle }])
        )
        .collect::<BTreeSet<_>>();
        if handles.len() != 1 {
            bail!(
                "Discord user anchor {author:X} has {} external ids",
                handles.len()
            );
        }
        let value = read_text_overlay(
            reader,
            overlay,
            *handles.iter().next().expect("one user id"),
            "Discord user id",
        )?;
        validate_snowflake(&value).context("invalid persisted Discord user id")?;
    }

    for (_receipt, channel) in find!(
        (receipt: Id, channel: Id),
        or!(
            pattern!(facts, [{
                ?receipt @
                metadata::tag: discord::kind_ingestion_baseline,
                discord::channel: ?channel,
            }]),
            pattern!(facts, [{
                ?receipt @
                metadata::tag: discord::kind_ingestion_receipt,
                discord::channel: ?channel,
            }]),
        )
    ) {
        channels.insert(channel);
    }
    for channel in channels {
        let handles = find!(
            handle: TextHandle,
            pattern!(facts, [{
                channel @
                metadata::tag: discord::kind_channel,
                discord::channel_id: ?handle,
            }])
        )
        .collect::<BTreeSet<_>>();
        if handles.len() != 1 {
            bail!(
                "Discord channel anchor {channel:X} has {} external ids",
                handles.len()
            );
        }
        let value = read_text_overlay(
            reader,
            overlay,
            *handles.iter().next().expect("one channel id"),
            "Discord channel id",
        )?;
        validate_snowflake(&value).context("invalid persisted Discord channel id")?;
        channel_coverage(facts, channel)?;
    }

    for (_profile, user, name) in find!(
        (profile: Id, user: Id, name: TextHandle),
        pattern!(facts, [{
            ?profile @
            metadata::tag: discord::kind_user_profile,
            discord::user: ?user,
            archive::author_name: ?name,
        }])
    ) {
        let value = read_text_overlay(reader, overlay, name, "Discord user profile name")?;
        if value.is_empty() {
            bail!("Discord profile for user {user:X} has an empty display name");
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RequiredMessageFields {
    anchor: Id,
    content: TextHandle,
    author: Id,
    created_at: Inline<NsTAIInterval>,
    channel: Id,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SemanticState {
    fields: RequiredMessageFields,
    edited_at: Option<Inline<NsTAIInterval>>,
    reply_to: Option<Id>,
    attachments: BTreeSet<Id>,
}

/// One distinct semantic state at the maximal official version timestamp for
/// a Discord message anchor.
///
/// Ordinarily `variant_count == 1`. If Discord supplied two different states
/// with the same maximal `edited_timestamp`, every state is returned and the
/// caller can expose the conflict instead of selecting one arbitrarily.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedMessageVersion {
    pub observation: Id,
    pub anchor: Id,
    pub content: TextHandle,
    pub author: Id,
    pub created_at: Inline<NsTAIInterval>,
    pub edited_at: Option<Inline<NsTAIInterval>>,
    pub channel: Id,
    pub reply_to: Option<Id>,
    pub attachments: BTreeSet<Id>,
    pub variant_index: usize,
    pub variant_count: usize,
}

/// Select the maximal official semantic version(s) of every message.
///
/// Identity is the full modeled semantic state, not a serialized REST payload.
/// Equal states collapse even if redundant provenance happened to give them
/// distinct entity ids; divergent maximal states remain visible.
pub fn select_messages(
    facts: &TribleSet,
    channel_filter: Option<Id>,
    since: Option<Inline<NsTAIInterval>>,
) -> Result<Vec<SelectedMessageVersion>> {
    let since_key = since.map(interval_key);
    let mut required: BTreeMap<Id, BTreeSet<RequiredMessageFields>> = BTreeMap::new();
    for (observation, anchor, content, author, created_at, channel) in find!(
        (
            observation: Id,
            anchor: Id,
            content: TextHandle,
            author: Id,
            created_at: Inline<NsTAIInterval>,
            channel: Id,
        ),
        pattern!(facts, [{
            ?observation @
            metadata::tag: archive::kind_message,
            discord::message: ?anchor,
            archive::content: ?content,
            archive::author: ?author,
            metadata::created_at: ?created_at,
            discord::channel: ?channel,
        }])
    ) {
        required
            .entry(observation)
            .or_default()
            .insert(RequiredMessageFields {
                anchor,
                content,
                author,
                created_at,
                channel,
            });
    }

    let mut edits: BTreeMap<Id, BTreeSet<Inline<NsTAIInterval>>> = BTreeMap::new();
    for (observation, edited_at) in find!(
        (observation: Id, edited_at: Inline<NsTAIInterval>),
        pattern!(facts, [{
            ?observation @
            metadata::tag: archive::kind_message,
            archive::edited_at: ?edited_at,
        }])
    ) {
        edits.entry(observation).or_default().insert(edited_at);
    }

    let mut replies: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
    for (observation, reply_to) in find!(
        (observation: Id, reply_to: Id),
        pattern!(facts, [{
            ?observation @
            metadata::tag: archive::kind_message,
            archive::reply_to: ?reply_to,
        }])
    ) {
        replies.entry(observation).or_default().insert(reply_to);
    }

    let mut attachments: BTreeMap<Id, BTreeSet<Id>> = BTreeMap::new();
    for (observation, attachment) in find!(
        (observation: Id, attachment: Id),
        pattern!(facts, [{
            ?observation @
            metadata::tag: archive::kind_message,
            archive::attachment: ?attachment,
        }])
    ) {
        attachments
            .entry(observation)
            .or_default()
            .insert(attachment);
    }

    let mut by_anchor: BTreeMap<Id, BTreeMap<SemanticState, BTreeSet<Id>>> = BTreeMap::new();
    for (observation, candidates) in required {
        if candidates.len() != 1 {
            bail!(
                "Discord observation {observation:X} has {} conflicting required projections",
                candidates.len()
            );
        }
        let fields = candidates
            .into_iter()
            .next()
            .expect("one required projection");
        let edited_values = edits.remove(&observation).unwrap_or_default();
        if edited_values.len() > 1 {
            bail!("Discord observation {observation:X} has conflicting edited timestamps");
        }
        let reply_values = replies.remove(&observation).unwrap_or_default();
        if reply_values.len() > 1 {
            bail!("Discord observation {observation:X} has conflicting reply targets");
        }
        let state = SemanticState {
            edited_at: edited_values.into_iter().next(),
            reply_to: reply_values.into_iter().next(),
            attachments: attachments.remove(&observation).unwrap_or_default(),
            fields: fields.clone(),
        };
        by_anchor
            .entry(fields.anchor)
            .or_default()
            .entry(state)
            .or_default()
            .insert(observation);
    }

    let mut selected = Vec::new();
    for (anchor, states) in by_anchor {
        let maximal_time = states
            .keys()
            .map(|state| interval_key(state.edited_at.unwrap_or(state.fields.created_at)))
            .max()
            .expect("message anchor group is non-empty");
        let maximal = states
            .into_iter()
            .filter(|(state, _)| {
                interval_key(state.edited_at.unwrap_or(state.fields.created_at)) == maximal_time
            })
            .collect::<Vec<_>>();
        let variant_count = maximal.len();
        for (variant_index, (state, observations)) in maximal.into_iter().enumerate() {
            if channel_filter.is_some_and(|channel| state.fields.channel != channel) {
                continue;
            }
            if since_key.is_some_and(|floor| interval_key(state.fields.created_at) < floor) {
                continue;
            }
            selected.push(SelectedMessageVersion {
                observation: observations
                    .into_iter()
                    .next()
                    .expect("semantic state has an observation"),
                anchor,
                content: state.fields.content,
                author: state.fields.author,
                created_at: state.fields.created_at,
                edited_at: state.edited_at,
                channel: state.fields.channel,
                reply_to: state.reply_to,
                attachments: state.attachments,
                variant_index,
                variant_count,
            });
        }
    }
    selected.sort_by_key(|row| {
        (
            interval_key(row.created_at),
            row.anchor,
            row.variant_index,
            row.observation,
        )
    });
    Ok(selected)
}

/// Deterministic, honest labels for stable user anchors.
///
/// Discord's REST message object does not version profile fields. If several
/// names have been observed, all distinct names are shown rather than making a
/// false latest-name claim.
pub fn user_labels(facts: &TribleSet, reader: &PileReader) -> Result<BTreeMap<Id, String>> {
    let mut names: BTreeMap<Id, BTreeSet<String>> = BTreeMap::new();
    for (user, handle) in find!(
        (user: Id, handle: TextHandle),
        pattern!(facts, [{
            _?profile @
            metadata::tag: discord::kind_user_profile,
            discord::user: ?user,
            archive::author_name: ?handle,
        }])
    ) {
        names.entry(user).or_default().insert(read_text(
            reader,
            handle,
            "Discord observed user name",
        )?);
    }

    let mut external: BTreeMap<Id, BTreeSet<String>> = BTreeMap::new();
    for (user, handle) in find!(
        (user: Id, handle: TextHandle),
        pattern!(facts, [{
            ?user @
            metadata::tag: discord::kind_user,
            discord::user_id: ?handle,
        }])
    ) {
        external
            .entry(user)
            .or_default()
            .insert(read_text(reader, handle, "Discord user id")?);
    }

    for (user, ids) in &external {
        if ids.len() != 1 {
            bail!(
                "Discord user anchor {user:X} has {} conflicting external ids",
                ids.len()
            );
        }
    }
    for user in names.keys() {
        if !external.contains_key(user) {
            bail!("Discord profile points to untyped user anchor {user:X}");
        }
    }

    let mut labels = BTreeMap::new();
    for (user, ids) in external {
        let observed = names.remove(&user).unwrap_or_default();
        let label = if observed.is_empty() {
            ids.into_iter().next().expect("one validated user id")
        } else {
            observed.into_iter().collect::<Vec<_>>().join(" / ")
        };
        labels.insert(user, label);
    }
    Ok(labels)
}

pub fn channel_labels(facts: &TribleSet, reader: &PileReader) -> Result<BTreeMap<Id, String>> {
    let mut values: BTreeMap<Id, BTreeSet<String>> = BTreeMap::new();
    for (channel, handle) in find!(
        (channel: Id, handle: TextHandle),
        pattern!(facts, [{
            ?channel @
            metadata::tag: discord::kind_channel,
            discord::channel_id: ?handle,
        }])
    ) {
        values
            .entry(channel)
            .or_default()
            .insert(read_text(reader, handle, "Discord channel id")?);
    }
    exact_labels(values, "channel")
}

fn exact_labels(
    values: BTreeMap<Id, BTreeSet<String>>,
    subject: &str,
) -> Result<BTreeMap<Id, String>> {
    values
        .into_iter()
        .map(|(id, candidates)| {
            if candidates.len() != 1 {
                bail!(
                    "Discord {subject} anchor {id:X} has {} conflicting external ids",
                    candidates.len()
                );
            }
            Ok((id, candidates.into_iter().next().expect("one value")))
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CoverageInterval {
    pub after_exclusive: u64,
    pub through_inclusive: u64,
    pub baseline: bool,
}

impl CoverageInterval {
    pub fn new(after_exclusive: u64, through_inclusive: u64, baseline: bool) -> Result<Self> {
        if after_exclusive >= through_inclusive {
            bail!(
                "Discord coverage interval must be non-empty: ({after_exclusive}, {through_inclusive}]"
            );
        }
        Ok(Self {
            after_exclusive,
            through_inclusive,
            baseline,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageFrontier {
    pub floor_exclusive: u64,
    pub through_inclusive: u64,
}

type CoverageReceipts = BTreeMap<Id, (bool, BTreeSet<(u64, u64)>)>;

/// Return the connected cover rooted at the canonical oldest baseline.
///
/// The smallest `after_exclusive` fixes the collection's lower scope boundary.
/// Baselines with that same floor overlap and join normally. A concurrently
/// published later baseline remains evidence, but cannot silently narrow the
/// established scope or skip the gap before it. Adding a still-older baseline
/// may therefore conservatively move the effective frontier backwards until
/// stored intervals connect the newly expanded scope. The interval evidence
/// remains monotone; only the derived continuous-coverage frontier changes as
/// its obligation expands. This is fail-closed rather than a false
/// completeness claim.
pub fn connected_frontier(intervals: &[CoverageInterval]) -> Option<CoverageFrontier> {
    let floor = intervals
        .iter()
        .filter(|interval| interval.baseline)
        .map(|interval| interval.after_exclusive)
        .min()?;
    let mut frontier = intervals
        .iter()
        .filter(|interval| interval.baseline && interval.after_exclusive == floor)
        .map(|interval| interval.through_inclusive)
        .max()?;
    let mut ordered = intervals.to_vec();
    ordered.sort_by_key(|interval| (interval.after_exclusive, interval.through_inclusive));
    for interval in ordered {
        if interval.after_exclusive <= frontier && interval.through_inclusive > frontier {
            frontier = interval.through_inclusive;
        }
    }
    Some(CoverageFrontier {
        floor_exclusive: floor,
        through_inclusive: frontier,
    })
}

pub fn channel_coverage(facts: &TribleSet, channel: Id) -> Result<Option<CoverageFrontier>> {
    let mut by_receipt = CoverageReceipts::new();
    collect_intervals(
        facts,
        channel,
        discord::kind_ingestion_baseline,
        true,
        &mut by_receipt,
    )?;
    collect_intervals(
        facts,
        channel,
        discord::kind_ingestion_receipt,
        false,
        &mut by_receipt,
    )?;

    let mut intervals = Vec::with_capacity(by_receipt.len());
    for (receipt, (baseline, endpoints)) in by_receipt {
        if endpoints.len() != 1 {
            bail!(
                "Discord coverage receipt {receipt:X} has {} conflicting endpoint pairs",
                endpoints.len()
            );
        }
        let (after, through) = endpoints.into_iter().next().expect("one endpoint pair");
        intervals.push(CoverageInterval::new(after, through, baseline)?);
    }
    Ok(connected_frontier(&intervals))
}

fn collect_intervals(
    facts: &TribleSet,
    channel: Id,
    kind: Id,
    baseline: bool,
    output: &mut CoverageReceipts,
) -> Result<()> {
    for (receipt, after, through) in find!(
        (
            receipt: Id,
            after: Inline<U256BE>,
            through: Inline<U256BE>,
        ),
        pattern!(facts, [{
            ?receipt @
            metadata::tag: &kind,
            discord::channel: &channel,
            discord::receipt_after_exclusive: ?after,
            discord::receipt_through_inclusive: ?through,
        }])
    ) {
        let after = u64::try_from_inline(&after)
            .map_err(|_| anyhow::anyhow!("Discord coverage lower endpoint exceeds u64"))?;
        let through = u64::try_from_inline(&through)
            .map_err(|_| anyhow::anyhow!("Discord coverage upper endpoint exceeds u64"))?;
        let entry = output
            .entry(receipt)
            .or_insert_with(|| (baseline, BTreeSet::new()));
        if entry.0 != baseline {
            bail!("Discord coverage receipt {receipt:X} is both baseline and forward");
        }
        entry.1.insert((after, through));
    }
    Ok(())
}

pub fn coverage_fragment(channel: Id, interval: CoverageInterval) -> Fragment {
    let kind = if interval.baseline {
        discord::kind_ingestion_baseline
    } else {
        discord::kind_ingestion_receipt
    };
    entity! { _ @
        metadata::tag: kind,
        discord::channel: channel,
        discord::receipt_after_exclusive: interval.after_exclusive,
        discord::receipt_through_inclusive: interval.through_inclusive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnected_intervals_do_not_advance_the_frontier() {
        let intervals = [
            CoverageInterval::new(100, 150, true).unwrap(),
            CoverageInterval::new(200, 250, false).unwrap(),
        ];
        assert_eq!(
            connected_frontier(&intervals),
            Some(CoverageFrontier {
                floor_exclusive: 100,
                through_inclusive: 150,
            })
        );

        let equal_floor = [
            intervals[0],
            intervals[1],
            CoverageInterval::new(100, 175, true).unwrap(),
        ];
        assert_eq!(
            connected_frontier(&equal_floor),
            Some(CoverageFrontier {
                floor_exclusive: 100,
                through_inclusive: 175,
            })
        );

        let connected = [
            intervals[0],
            intervals[1],
            CoverageInterval::new(150, 220, false).unwrap(),
        ];
        assert_eq!(
            connected_frontier(&connected).unwrap().through_inclusive,
            250
        );

        let mut facts = channel_fragment("100000000000000001").unwrap();
        let channel = facts.root().expect("channel has one root");
        facts += coverage_fragment(channel, intervals[0]);
        facts += coverage_fragment(channel, intervals[1]);
        assert_eq!(
            channel_coverage(&facts, channel).unwrap(),
            Some(CoverageFrontier {
                floor_exclusive: 100,
                through_inclusive: 150,
            })
        );

        // A racing fresh importer cannot redefine the established lower scope
        // boundary by publishing a disconnected later baseline.
        let concurrent_baseline = CoverageInterval::new(300, 350, true).unwrap();
        facts += coverage_fragment(channel, concurrent_baseline);
        assert_eq!(
            channel_coverage(&facts, channel)
                .unwrap()
                .unwrap()
                .through_inclusive,
            150
        );

        // Only explicit connected evidence may bridge to that later interval.
        facts += coverage_fragment(channel, CoverageInterval::new(150, 320, false).unwrap());
        assert_eq!(
            channel_coverage(&facts, channel)
                .unwrap()
                .unwrap()
                .through_inclusive,
            350
        );
    }

    #[test]
    fn late_older_baseline_expands_scope_until_a_bridge_heals_it() {
        let mut facts = channel_fragment("100000000000000002").unwrap();
        let channel = facts.root().expect("channel has one root");

        facts += coverage_fragment(channel, CoverageInterval::new(300, 350, true).unwrap());
        assert_eq!(
            channel_coverage(&facts, channel).unwrap(),
            Some(CoverageFrontier {
                floor_exclusive: 300,
                through_inclusive: 350,
            })
        );

        // A delayed importer proves an older baseline. The union only grew,
        // but continuous coverage now owes the larger (100, ...] scope.
        facts += coverage_fragment(channel, CoverageInterval::new(100, 150, true).unwrap());
        assert_eq!(
            channel_coverage(&facts, channel).unwrap(),
            Some(CoverageFrontier {
                floor_exclusive: 100,
                through_inclusive: 150,
            })
        );

        facts += coverage_fragment(channel, CoverageInterval::new(150, 320, false).unwrap());
        assert_eq!(
            channel_coverage(&facts, channel).unwrap(),
            Some(CoverageFrontier {
                floor_exclusive: 100,
                through_inclusive: 350,
            })
        );
    }
}
