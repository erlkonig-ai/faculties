//! Canonical collection-native Status events and read semantics.
//!
//! Status is an immutable event set. Every event is the intrinsic identity of
//! its exact `(window, text handle, point timestamp)` record. The current view
//! is a pure maximum over `(timestamp, event id)`, so collection union cannot
//! make iteration order or process arrival order observable.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::metadata;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreList};
use triblespace::prelude::*;

use crate::schemas::status::{status, KIND_STATUS_UPDATE};

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

/// One complete immutable Status event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusRow {
    pub event: Id,
    pub window: Id,
    pub text: TextHandle,
    pub at: IntervalValue,
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// Decode a Status timestamp and require its interval to name one point.
pub fn point_timestamp(interval: IntervalValue) -> Result<i128> {
    let (lower, upper): (i128, i128) = interval
        .try_from_inline()
        .map_err(|error| anyhow!("decode Status timestamp: {error:?}"))?;
    if lower != upper {
        bail!("Status timestamp must be a point interval");
    }
    Ok(lower)
}

fn exactly_one<T>(event: Id, field: &str, values: Vec<T>) -> Result<T> {
    let count = values.len();
    if count != 1 {
        bail!(
            "Status event {} has {count} values for {field}; expected exactly one",
            fmt_id(event)
        );
    }
    Ok(values.into_iter().next().expect("one value"))
}

/// Build the canonical intrinsic record around an already-stored text handle.
///
/// The stopped-world transform uses this same constructor as the live writer,
/// so migration cannot accidentally introduce a second identity protocol.
pub fn status_record(window: Id, text: TextHandle, at: IntervalValue) -> Fragment {
    entity! {
        metadata::tag: &KIND_STATUS_UPDATE,
        status::window: window,
        status::text: text,
        metadata::created_at: at,
    }
}

/// Build one intrinsic immutable point-valued Status event and carry its text
/// attachment across the collection publication boundary.
pub fn status_fragment(window: Id, text: &str, at: IntervalValue) -> Result<Fragment> {
    point_timestamp(at)?;
    let mut fragment = Fragment::empty();
    let text: TextHandle = fragment.put(text.to_owned());
    fragment += status_record(window, text, at);
    Ok(fragment)
}

/// Project every tagged Status-shaped record, rejecting missing or
/// multi-valued scalar fields rather than allowing query iteration order to
/// choose one.
///
/// This is crate-visible for the stopped-world legacy validator. Ordinary
/// readers use [`load_status_rows`], which selects only intrinsic records and
/// thereby leaves preserved legacy facts inert.
pub fn load_tagged_status_rows(facts: &TribleSet) -> Result<Vec<StatusRow>> {
    let events: BTreeSet<Id> = find!(
        event: Id,
        pattern!(facts, [{ ?event @ metadata::tag: &KIND_STATUS_UPDATE }])
    )
    .collect();

    events
        .into_iter()
        .map(|event| {
            let window = exactly_one(
                event,
                "status::window",
                find!(
                    window: Id,
                    pattern!(facts, [{ event @ status::window: ?window }])
                )
                .collect(),
            )?;
            let text = exactly_one(
                event,
                "status::text",
                find!(
                    text: TextHandle,
                    pattern!(facts, [{ event @ status::text: ?text }])
                )
                .collect(),
            )?;
            let at = exactly_one(
                event,
                "metadata::created_at",
                find!(
                    at: IntervalValue,
                    pattern!(facts, [{ event @ metadata::created_at: ?at }])
                )
                .collect(),
            )?;
            Ok(StatusRow {
                event,
                window,
                text,
                at,
            })
        })
        .collect()
}

/// Project the canonical intrinsic Status events from a generic collection.
///
/// A migrated collection may also contain the exact legacy random-id records
/// that attest its history. Those records remain queryable as facts, but are
/// not Status events in the native view. Identity is therefore the selector:
/// only a row whose entity is the intrinsic id of its own tuple is returned.
pub fn load_status_rows(facts: &TribleSet) -> Result<Vec<StatusRow>> {
    Ok(load_tagged_status_rows(facts)?
        .into_iter()
        .filter(|row| status_record(row.window, row.text, row.at).root() == Some(row.event))
        .collect())
}

/// Canonical ordering coordinate for one immutable event.
pub fn event_key(row: &StatusRow) -> Result<(i128, Id)> {
    Ok((
        point_timestamp(row.at)
            .with_context(|| format!("validate timestamp on Status event {}", row.event))?,
        row.event,
    ))
}

/// Resolve one deterministic current event per window.
///
/// A larger point timestamp wins. Equal-time events coexist, and the larger
/// intrinsic event id breaks the tie. This is a pure maximum in a total order:
/// it is permutation-independent and commutes with set union.
pub fn latest_per_window(
    rows: impl IntoIterator<Item = StatusRow>,
) -> Result<BTreeMap<Id, StatusRow>> {
    let mut latest = BTreeMap::<Id, ((i128, Id), StatusRow)>::new();
    for row in rows {
        let key = event_key(&row)?;
        let replace = latest
            .get(&row.window)
            .is_none_or(|(current, _)| key > *current);
        if replace {
            latest.insert(row.window, (key, row));
        }
    }
    Ok(latest
        .into_iter()
        .map(|(window, (_, row))| (window, row))
        .collect())
}

fn load_text_from<Store>(reader: &Store, handle: TextHandle) -> Result<String>
where
    Store: BlobStoreGet + ?Sized,
{
    let text: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Status text payload {}", hex::encode(handle.raw)))?;
    Ok(text.to_string())
}

fn load_text_overlay<Store, Overlay>(
    reader: &Store,
    overlay: &Overlay,
    handle: TextHandle,
) -> Result<String>
where
    Store: BlobStoreGet + ?Sized,
    Overlay: BlobStoreGet + BlobStoreList,
{
    if overlay
        .contains_blob(handle)
        .context("inspect staged Status text payloads")?
    {
        let text: View<str> = overlay.get(handle).with_context(|| {
            format!(
                "read staged Status text payload {}",
                hex::encode(handle.raw)
            )
        })?;
        return Ok(text.to_string());
    }
    load_text_from(reader, handle)
}

/// Strictly read one Status text attachment.
pub fn read_text<Store>(reader: &Store, handle: TextHandle) -> Result<String>
where
    Store: BlobStoreGet + ?Sized,
{
    load_text_from(reader, handle)
}

fn validate_structure(facts: &TribleSet) -> Result<Vec<StatusRow>> {
    let rows = load_tagged_status_rows(facts)?;
    let mut facts_by_entity = BTreeMap::<Id, usize>::new();
    for fact in facts {
        *facts_by_entity.entry(*fact.e()).or_default() += 1;
    }

    let mut canonical = Vec::new();
    for row in &rows {
        let expected = status_record(row.window, row.text, row.at);
        let expected_event = expected
            .root()
            .expect("canonical Status record has one intrinsic root");
        if row.event != expected_event {
            continue;
        }

        point_timestamp(row.at)
            .with_context(|| format!("validate timestamp on Status event {}", row.event))?;

        let expected_facts = expected.facts().len();
        let actual_facts = facts_by_entity.get(&row.event).copied().unwrap_or_default();
        if actual_facts != expected_facts {
            bail!(
                "Status event {} has {actual_facts} facts; expected exactly {expected_facts}",
                fmt_id(row.event),
            );
        }
        canonical.push(*row);
    }
    Ok(canonical)
}

/// Validate the complete materialized Status collection and every referenced
/// text attachment.
pub fn validate_catalog<Store>(reader: &Store, facts: &TribleSet) -> Result<()>
where
    Store: BlobStoreGet + ?Sized,
{
    let rows = validate_structure(facts)?;
    let handles: BTreeSet<TextHandle> = rows.into_iter().map(|row| row.text).collect();
    for handle in handles {
        load_text_from(reader, handle)?;
    }
    Ok(())
}

/// Preflight the exact union that publishing `fragment` would produce.
/// Staged attachments are read through the fragment overlay; this function
/// performs no pile writes.
pub fn validate_catalog_union<Store>(
    reader: &Store,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<TribleSet>
where
    Store: BlobStoreGet + ?Sized,
{
    let mut expected = current.clone();
    expected += fragment.facts().clone();
    let rows = validate_structure(&expected)?;
    let handles: BTreeSet<TextHandle> = rows.into_iter().map(|row| row.text).collect();
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .expect("MemoryBlobStore reader creation is infallible");
    for handle in handles {
        load_text_overlay(reader, &overlay, handle)?;
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use anybytes::Bytes;
    use hifitime::Epoch;
    use triblespace::core::blob::Blob;
    use triblespace::core::repo::memoryrepo::MemoryRepo;

    use super::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at(seconds: f64) -> IntervalValue {
        let epoch = Epoch::from_unix_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn row(event: u8, window: Id, seconds: f64) -> StatusRow {
        StatusRow {
            event: id(event),
            window,
            text: Inline::new([event; 32]),
            at: at(seconds),
        }
    }

    #[test]
    fn published_status_ids_remain_byte_exact() {
        assert_eq!(
            KIND_STATUS_UPDATE,
            Id::from_hex("1622DB88E9D9B455EEE1E82470E6730C").unwrap()
        );
        assert_eq!(
            status::window.id(),
            Id::from_hex("51D3C4DEDA7BCFCCA4C3D85FFB7CCFAC").unwrap()
        );
        assert_eq!(
            status::text.id(),
            Id::from_hex("0DB5E52B99D75A09E666718147C45208").unwrap()
        );
        assert_eq!(
            crate::schemas::status::DEFAULT_SCOPE_ID,
            Id::from_hex("5C563832935FD4CFC726D63D2631DC5D").unwrap()
        );
    }

    #[test]
    fn intrinsic_constructor_is_order_stable_and_exact_replay_is_identical() {
        let first = status_fragment(id(1), "mapping the lattice", at(10.0)).unwrap();
        let second = status_fragment(id(1), "mapping the lattice", at(10.0)).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.root(), second.root());
        assert_eq!(first.facts().len(), 4);
    }

    #[test]
    fn constructor_rejects_non_point_time() {
        let interval = (
            Epoch::from_unix_seconds(10.0),
            Epoch::from_unix_seconds(11.0),
        )
            .try_to_inline()
            .unwrap();
        assert!(format!(
            "{:#}",
            status_fragment(id(1), "range", interval).unwrap_err()
        )
        .contains("must be a point interval"));
    }

    #[test]
    fn staged_attachment_validates_before_publication() {
        let mut storage = MemoryRepo::default();
        let reader = storage.reader().unwrap();
        let fragment = status_fragment(id(2), "staged", at(20.0)).unwrap();
        let expected = validate_catalog_union(&reader, &TribleSet::new(), &fragment).unwrap();
        assert_eq!(expected, fragment.facts().clone());
        assert!(storage.blobs.is_empty());
    }

    #[test]
    fn catalog_rejects_missing_and_malformed_text_payloads() {
        let missing: TextHandle = Inline::new([0xA5; 32]);
        let missing_record = status_record(id(3), missing, at(30.0));
        let mut storage = MemoryRepo::default();
        let reader = storage.reader().unwrap();
        assert!(format!(
            "{:#}",
            validate_catalog(&reader, missing_record.facts()).unwrap_err()
        )
        .contains("read Status text payload"));

        let invalid = Blob::<blobencodings::LongString>::new(Bytes::from(vec![0xFF]));
        let invalid_handle = invalid.get_handle();
        storage.blobs.insert(invalid);
        let reader = storage.reader().unwrap();
        let invalid_record = status_record(id(4), invalid_handle, at(31.0));
        assert!(validate_catalog(&reader, invalid_record.facts()).is_err());
    }

    #[test]
    fn catalog_ignores_legacy_and_unrelated_facts_but_rejects_malformed_canonical_events() {
        let mut storage = MemoryRepo::default();
        let text: TextHandle = storage.put("legacy".to_owned()).unwrap();
        let reader = storage.reader().unwrap();
        let legacy = ufoid();
        let random = entity! { &legacy @
            metadata::tag: &KIND_STATUS_UPDATE,
            status::window: id(5),
            status::text: text,
            metadata::created_at: at(40.0),
        };
        validate_catalog(&reader, random.facts()).unwrap();
        assert!(load_status_rows(random.facts()).unwrap().is_empty());

        let mut extra = status_record(id(6), text, at(41.0));
        let event = extra.root().unwrap();
        extra += entity! { ExclusiveId::force_ref(&event) @ metadata::tag: &id(7) };
        assert!(format!(
            "{:#}",
            validate_catalog(&reader, extra.facts()).unwrap_err()
        )
        .contains("expected exactly 4"));

        let mut outside = status_record(id(8), text, at(42.0));
        outside += entity! { metadata::tag: &id(9) };
        validate_catalog(&reader, outside.facts()).unwrap();
        assert_eq!(load_status_rows(outside.facts()).unwrap().len(), 1);
    }

    #[test]
    fn latest_is_permutation_independent_and_equal_time_uses_event_id() {
        let window = id(10);
        let low = row(11, window, 50.0);
        let high = row(12, window, 50.0);
        for rows in [vec![low, high], vec![high, low]] {
            assert_eq!(latest_per_window(rows).unwrap()[&window], high);
        }
    }

    #[test]
    fn later_time_dominates_any_equal_time_pair() {
        let window = id(13);
        let low = row(14, window, 60.0);
        let high = row(15, window, 60.0);
        let later = row(1, window, 61.0);
        for rows in [
            vec![low, high, later],
            vec![later, high, low],
            vec![high, later, low],
        ] {
            assert_eq!(latest_per_window(rows).unwrap()[&window], later);
        }
    }
}
