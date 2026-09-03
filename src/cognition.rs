//! Shared model and publication boundary for the Cognition event collection.
//!
//! Cognition is one immutable union of execution, model, context, explicit
//! reasoning, and timeout events.  Live writers publish one complete,
//! self-contained [`Fragment`] per event into one fixed native collection.
//! There is no branch, head, repository checkout, caller-selected scope, or
//! compare-and-swap cell in this layer.

use std::collections::BTreeMap;
use std::path::Path;

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use hifitime::Epoch;
use triblespace::core::collection::{CollectionCommit, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta, SnapshotSource};
use triblespace::macros::{find, id_hex, pattern};
use triblespace::prelude::*;

use crate::collection_names::open_configured;
use crate::schemas::cognition::DEFAULT_SCOPE_ID;
use crate::schemas::patience::{exec_schema as patience, KIND_TIMEOUT_EXTENSION_ID};
use crate::schemas::reason::{reason_schema as reason, KIND_REASON_ID};
use crate::schemas::triage::{cog, context, exec, model_chat, KIND_EXEC_RESULT_ID};
use crate::storage::{load_signer, open_pile_strict, FactArchive};

pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
type RawHandle = Inline<inlineencodings::Handle<blobencodings::UnknownBlob>>;

// Stable attributes currently authored by `drive` but not yet owned by a
// Faculties schema module.  These ids are copied verbatim from drive's schema;
// the Cognition cutover must validate their direct attachments before the old
// branch can ever be retired.  They are not new ontology.
const DRIVE_CWD: Id = id_hex!("4A7EA49FD72113D2DC497B407994B4F9");
const DRIVE_STDIN: Id = id_hex!("17F4EA6F885F359C4CA967EE8478FA13");
const DRIVE_STDIN_TEXT: Id = id_hex!("FC48EA2441A1EECAC29C6A2032C09C1E");
const DRIVE_STDOUT: Id = id_hex!("579EA2A82FB6A4D5B1E409D4F7747E2F");
const DRIVE_STDERR: Id = id_hex!("6F1CB839CAE28A34C5107F36EB7939C3");
const DRIVE_MONOLOGUE_SPAN: Id = id_hex!("3B005E98BAAFD9E9B227055D2EF8AC6B");
const DRIVE_DERIVED_COMMAND: Id = id_hex!("CAAF1B512303E7F36B2DF88D8D61755C");
const DRIVE_RATIONALE: Id = id_hex!("D1DDF218281C696CFCAFEE9EB9282A9C");
const DRIVE_SUMMARY_TEXT: Id = id_hex!("35C151D0779441A583437C5495BA58B9");
const DRIVE_RAW_RESULT_TEXT: Id = id_hex!("1068E3A296B8720B7FE7AEB2529ADC2F");
const DRIVE_WEIGHTS_PILE: Id = id_hex!("24A1712BC2D184A9FE3ACCA8C0B81082");
const DRIVE_SYSTEM_PROMPT: Id = id_hex!("E3DA554D3671ACB8179A38DBF9477EB9");
const DRIVE_LEDGER_PILE: Id = id_hex!("9B18A5970EC68F4854D76D3A2B14F86E");
const DRIVE_METRICS_PILE: Id = id_hex!("CE4CA2D9C8B2B03EB0932918CC76BF0C");

/// Build one self-contained, intrinsically identified explicit-reason event.
pub fn reason_fragment(
    turn_id: Option<Id>,
    worker_id: Option<Id>,
    text: &str,
    command_text: Option<&str>,
    created_at: IntervalValue,
) -> Fragment {
    let mut event = Fragment::empty();
    let text_handle = event.put(text.to_owned());
    let command_handle = command_text.map(|command| event.put(command.to_owned()));
    event += entity! { _ @
        metadata::tag: &KIND_REASON_ID,
        reason::text: text_handle,
        metadata::created_at: created_at,
        reason::about_turn?: turn_id,
        reason::worker?: worker_id,
        reason::command_text?: command_handle,
    };
    event
}

/// Build one intrinsically identified timeout-extension event.
pub fn timeout_extension_fragment(
    request_id: Id,
    worker_id: Id,
    timeout_ms: u64,
    requested_at: IntervalValue,
) -> Fragment {
    entity! { _ @
        metadata::tag: KIND_TIMEOUT_EXTENSION_ID,
        patience::about_request: request_id,
        patience::worker: worker_id,
        patience::timeout_ms: timeout_ms,
        patience::requested_at: requested_at,
    }
}

/// Publish one complete authored event to the fixed Cognition collection.
///
/// Authority is loaded before storage is touched.  The pile is opened once,
/// the exact prospective union is validated with staged attachments visible,
/// and only then is the signed collection commit appended.
pub fn publish_event(
    pile_path: &Path,
    key_path: Option<&Path>,
    fragment: Fragment,
) -> Result<CollectionCommit> {
    let mut commits = publish_events(pile_path, key_path, [fragment])?;
    Ok(commits
        .pop()
        .expect("one Cognition event produces one collection commit"))
}

/// Publish a command's complete event sequence with one pile lifetime.
///
/// Each event remains its own independently transferable commit. Every event
/// is validated before the first append, so a later invalid event cannot make
/// a multi-event command partially publish. Ambient history is deliberately
/// absent from this publication-unit invariant.
pub fn publish_events(
    pile_path: &Path,
    key_path: Option<&Path>,
    fragments: impl IntoIterator<Item = Fragment>,
) -> Result<Vec<CollectionCommit>> {
    let fragments: Vec<_> = fragments.into_iter().collect();
    for fragment in &fragments {
        validate_fragment(fragment).context("validate self-contained Cognition event")?;
    }
    let signer = load_signer(pile_path, key_path)?;
    let mut pile = open_pile_strict(pile_path)?;
    let collection = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
    let result = fragments
        .into_iter()
        .map(|fragment| {
            pile.commit(collection, &signer, fragment)
                .context("commit authored Cognition event")
        })
        .collect();
    finish_pile(pile, result)
}

/// Verify that one authored event is structurally valid and carries every
/// directly typed payload it names. Ambient pile contents do not participate:
/// this is the publication-unit invariant which makes an event independently
/// transferable and recoverable.
pub fn validate_fragment(fragment: &Fragment) -> Result<()> {
    validate_singleton_fields(fragment.facts().iter().copied())?;
    let facts = fragment.facts().clone();
    let metafacts = fragment.metafacts().clone();
    let mut local = fragment.clone();
    let reader = local
        .blobs_mut()
        .snapshot()
        .context("snapshot self-contained Cognition event attachments")?;
    validate_payloads_in_store(&reader, facts.iter().copied())?;
    validate_payloads_in_store(&reader, metafacts.iter().copied())?;
    Ok(())
}

/// Validate the known invariants and directly typed attachments of a complete
/// Cognition value. Unknown facts remain legal: Cognition is intentionally a
/// shared event ledger, and independent producers may extend its ontology.
pub fn validate_catalog(reader: &PileSnapshot, facts: &TribleSet) -> Result<()> {
    validate_singleton_fields(facts.iter().copied())?;
    validate_payloads(reader, None::<&PileSnapshot>, facts.iter().copied())
}

/// Explicitly validate a maintained Cognition archive without flattening its
/// physical shards into a second fact store.
pub fn validate_archive(reader: &PileSnapshot, facts: &FactArchive) -> Result<()> {
    validate_singleton_fields(facts.iter())?;
    validate_payloads(reader, None::<&PileSnapshot>, facts.iter())
}

/// Validate the union which a publication would create, including payloads
/// carried only by the staged fragment.
pub fn validate_candidate(
    reader: &PileSnapshot,
    current: &TribleSet,
    fragment: &Fragment,
) -> Result<()> {
    let mut union = current.clone();
    union += fragment.facts().clone();
    validate_singleton_fields(union.iter().copied())?;
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .snapshot()
        .context("snapshot staged Cognition attachments")?;
    validate_payloads(reader, Some(&overlay), union.iter().copied())
}

/// Strict payload validation used while projecting each frozen legacy delta.
/// This is crate-visible so the stopped-world migration can fail on a missing
/// typed attachment rather than silently relying on conservative reachability.
pub fn validate_known_payloads(reader: &PileSnapshot, facts: &TribleSet) -> Result<()> {
    validate_payloads(reader, None::<&PileSnapshot>, facts.iter().copied())
}

/// Exec results whose completion point lies in the inclusive interval,
/// ordered chronologically. Raw projected tuple identity is preserved.
pub fn exec_results_in_range<P>(
    facts: &P,
    query_start: Epoch,
    query_end: Epoch,
) -> Vec<(Id, IntervalValue)>
where
    P: TriblePattern + ?Sized,
{
    let start = query_start.to_tai_duration().total_nanoseconds();
    let end = query_end.to_tai_duration().total_nanoseconds();
    let mut results: Vec<_> = find!(
        (result: Id, finished: IntervalValue),
        pattern!(facts, [{
            ?result @
            metadata::tag: &KIND_EXEC_RESULT_ID,
            metadata::finished_at: ?finished,
        }])
    )
    .filter_map(|(result, finished)| {
        let point = interval_start(finished);
        (point >= start && point <= end).then_some((result, finished, point))
    })
    .collect();
    results.sort_unstable_by_key(|(result, _, point)| (*point, *result));
    results
        .into_iter()
        .map(|(result, finished, _)| (result, finished))
        .collect()
}

fn interval_start(interval: IntervalValue) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval
        .try_from_inline()
        .expect("NsTAIInterval values decode as epochs");
    lower.to_tai_duration().total_nanoseconds()
}

fn singleton_field(attribute: Id) -> Option<&'static str> {
    let field = if attribute == reason::text.id() {
        "reason::text"
    } else if attribute == reason::about_turn.id() {
        "reason::about_turn"
    } else if attribute == reason::worker.id() {
        "reason::worker"
    } else if attribute == reason::command_text.id() {
        "reason::command_text"
    } else if attribute == patience::about_request.id() {
        "patience::about_request"
    } else if attribute == patience::worker.id() {
        "patience::worker"
    } else if attribute == patience::timeout_ms.id() {
        "patience::timeout_ms"
    } else if attribute == patience::requested_at.id() {
        "patience::requested_at"
    } else if attribute == exec::command_text.id() {
        "exec::command_text"
    } else if attribute == exec::about_request.id() {
        "exec::about_request"
    } else if attribute == exec::attempt.id() {
        "exec::attempt"
    } else if attribute == exec::exit_code.id() {
        "exec::exit_code"
    } else if attribute == exec::stdout_text.id() {
        "exec::stdout_text"
    } else if attribute == exec::stderr_text.id() {
        "exec::stderr_text"
    } else if attribute == exec::error.id() {
        "exec::error"
    } else if attribute == exec::about_thought.id() {
        "exec::about_thought"
    } else if attribute == model_chat::about_request.id() {
        "model_chat::about_request"
    } else if attribute == model_chat::attempt.id() {
        "model_chat::attempt"
    } else if attribute == model_chat::about_thought.id() {
        "model_chat::about_thought"
    } else if attribute == model_chat::output_text.id() {
        "model_chat::output_text"
    } else if attribute == model_chat::reasoning_text.id() {
        "model_chat::reasoning_text"
    } else if attribute == model_chat::error.id() {
        "model_chat::error"
    } else if attribute == context::summary.id() {
        "context::summary"
    } else if attribute == context::start_at.id() {
        "context::start_at"
    } else if attribute == context::end_at.id() {
        "context::end_at"
    } else if attribute == context::left.id() {
        "context::left"
    } else if attribute == context::right.id() {
        "context::right"
    } else if attribute == context::about_exec_result.id() {
        "context::about_exec_result"
    } else if attribute == cog::context.id() {
        "cog::context"
    } else {
        return None;
    };
    Some(field)
}

fn validate_singleton_fields(facts: impl IntoIterator<Item = Trible>) -> Result<()> {
    let mut seen = BTreeMap::<(Id, Id), [u8; 32]>::new();
    for fact in facts {
        let entity = *fact.e();
        let attribute = *fact.a();
        let Some(field) = singleton_field(attribute) else {
            continue;
        };
        let value: [u8; 32] = fact.data[32..64].try_into().expect("inline width");
        if let Some(previous) = seen.insert((entity, attribute), value) {
            if previous != value {
                bail!("Cognition entity {entity:X} has conflicting {field} values");
            }
        }
    }
    Ok(())
}

fn long_string_field(attribute: Id) -> Option<&'static str> {
    let field = if attribute == reason::text.id() {
        "reason::text"
    } else if attribute == reason::command_text.id() {
        "reason::command_text"
    } else if attribute == exec::command_text.id() {
        "exec::command_text"
    } else if attribute == exec::stdout_text.id() {
        "exec::stdout_text"
    } else if attribute == exec::stderr_text.id() {
        "exec::stderr_text"
    } else if attribute == exec::error.id() {
        "exec::error"
    } else if attribute == model_chat::output_text.id() {
        "model_chat::output_text"
    } else if attribute == model_chat::reasoning_text.id() {
        "model_chat::reasoning_text"
    } else if attribute == model_chat::error.id() {
        "model_chat::error"
    } else if attribute == context::summary.id() {
        "context::summary"
    } else if attribute == cog::context.id() {
        "cog::context"
    } else if attribute == metadata::name.id() {
        "metadata::name"
    } else if attribute == metadata::description.id() {
        "metadata::description"
    } else if attribute == DRIVE_CWD {
        "drive::cwd"
    } else if attribute == DRIVE_STDIN_TEXT {
        "drive::stdin_text"
    } else if attribute == DRIVE_MONOLOGUE_SPAN {
        "drive::monologue_span"
    } else if attribute == DRIVE_DERIVED_COMMAND {
        "drive::derived_command"
    } else if attribute == DRIVE_RATIONALE {
        "drive::rationale"
    } else if attribute == DRIVE_SUMMARY_TEXT {
        "drive::summary_text"
    } else if attribute == DRIVE_RAW_RESULT_TEXT {
        "drive::raw_result_text"
    } else if attribute == DRIVE_WEIGHTS_PILE {
        "drive::weights_pile"
    } else if attribute == DRIVE_SYSTEM_PROMPT {
        "drive::system_prompt"
    } else if attribute == DRIVE_LEDGER_PILE {
        "drive::ledger_pile"
    } else if attribute == DRIVE_METRICS_PILE {
        "drive::metrics_pile"
    } else {
        return None;
    };
    Some(field)
}

fn raw_blob_field(attribute: Id) -> Option<&'static str> {
    if attribute == DRIVE_STDIN {
        Some("drive::stdin")
    } else if attribute == DRIVE_STDOUT {
        Some("drive::stdout")
    } else if attribute == DRIVE_STDERR {
        Some("drive::stderr")
    } else {
        None
    }
}

fn validate_payloads<Overlay>(
    reader: &PileSnapshot,
    overlay: Option<&Overlay>,
    facts: impl IntoIterator<Item = Trible>,
) -> Result<()>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    for fact in facts {
        if let Some(field) = long_string_field(*fact.a()) {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            read_text_overlay(reader, overlay, handle).with_context(|| {
                format!("read {field} payload {}", hex::encode_upper(handle.raw))
            })?;
        } else if let Some(field) = raw_blob_field(*fact.a()) {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UnknownBlob>>();
            read_raw_overlay(reader, overlay, handle).with_context(|| {
                format!("read {field} payload {}", hex::encode_upper(handle.raw))
            })?;
        }
    }
    Ok(())
}

fn validate_payloads_in_store<Store>(
    store: &Store,
    facts: impl IntoIterator<Item = Trible>,
) -> Result<()>
where
    Store: BlobStoreGet,
{
    for fact in facts {
        if let Some(field) = long_string_field(*fact.a()) {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            let value: std::result::Result<View<str>, _> = store.get(handle);
            value.map_err(|_| {
                anyhow!(
                    "self-contained event is missing {field} payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        } else if let Some(field) = raw_blob_field(*fact.a()) {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UnknownBlob>>();
            let value: std::result::Result<anybytes::Bytes, _> = store.get(handle);
            value.map_err(|_| {
                anyhow!(
                    "self-contained event is missing {field} payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

fn read_text_overlay<Overlay>(
    reader: &PileSnapshot,
    overlay: Option<&Overlay>,
    handle: TextHandle,
) -> Result<View<str>>
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

fn read_raw_overlay<Overlay>(
    reader: &PileSnapshot,
    overlay: Option<&Overlay>,
    handle: RawHandle,
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

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow!("close Cognition pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Cognition pile also failed: {close_error}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use crate::storage::{load_signer, FactCollection};
    use crate::test_support::initialize_open_collection_fixture;
    use triblespace::core::collection::CollectionSnapshotExt;

    use super::*;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn point(seconds: f64) -> IntervalValue {
        let at = Epoch::from_unix_seconds(seconds);
        (at, at).try_to_inline().unwrap()
    }

    #[test]
    fn reason_event_is_intrinsic_self_contained_and_exact_replay_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("cognition.pile");
        let key_path = directory.path().join("cognition.key");
        File::create(&pile_path).unwrap();
        initialize_open_collection_fixture(&pile_path, Some(&key_path));

        let event = reason_fragment(
            Some(id(1)),
            Some(id(2)),
            "follow the smallest frontier",
            Some("cargo test"),
            point(42.0),
        );
        let root = event.root().unwrap();
        let first = publish_event(&pile_path, Some(&key_path), event.clone()).unwrap();
        let after_first = std::fs::metadata(&pile_path).unwrap().len();
        let replay = publish_event(&pile_path, Some(&key_path), event.clone()).unwrap();
        assert_eq!(replay, first);
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), after_first);

        let signer = load_signer(&pile_path, Some(&key_path)).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let source = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap();
        let collection = FactCollection::new(&mut pile, source).unwrap();
        let instant = crate::clock::now().unwrap();
        let before = pile.snapshot().unwrap();
        drop(pollster::block_on(collection.maintain_at(&mut pile, &before, instant)).unwrap());
        drop(before);
        let snapshot = pile.snapshot().unwrap();
        let facts = snapshot
            .collection_at(collection.rank9(), instant)
            .unwrap()
            .view::<FactArchive>()
            .unwrap();
        validate_archive(&snapshot, &facts).unwrap();
        assert_eq!(facts.iter().collect::<TribleSet>(), event.into_facts());
        assert!(facts.iter().all(|fact| fact.e() == &root));
        drop(snapshot);
        pile.close().unwrap();
    }

    #[test]
    fn exec_range_is_inclusive_chronological_and_preserves_entity_ids() {
        let early = id(3);
        let late = id(4);
        let outside = id(5);
        let mut facts = entity! { ExclusiveId::force_ref(&early) @
            metadata::tag: &KIND_EXEC_RESULT_ID,
            metadata::finished_at: point(10.0),
        }
        .into_facts();
        facts += entity! { ExclusiveId::force_ref(&late) @
            metadata::tag: &KIND_EXEC_RESULT_ID,
            metadata::finished_at: point(20.0),
        }
        .into_facts();
        facts += entity! { ExclusiveId::force_ref(&outside) @
            metadata::tag: &KIND_EXEC_RESULT_ID,
            metadata::finished_at: point(21.0),
        }
        .into_facts();

        assert_eq!(
            exec_results_in_range(
                &facts,
                Epoch::from_unix_seconds(10.0),
                Epoch::from_unix_seconds(20.0)
            ),
            vec![(early, point(10.0)), (late, point(20.0))]
        );
    }

    #[test]
    fn conflicting_singleton_is_rejected() {
        let event = id(6);
        let mut facts = entity! { ExclusiveId::force_ref(&event) @
            reason::text: Inline::new([7; 32]),
        }
        .into_facts();
        facts += entity! { ExclusiveId::force_ref(&event) @
            reason::text: Inline::new([8; 32]),
        }
        .into_facts();
        let error = validate_singleton_fields(facts.iter().copied()).unwrap_err();
        assert!(format!("{error:#}").contains("conflicting reason::text"));
    }

    #[test]
    fn publication_unit_cannot_borrow_a_payload_from_ambient_storage() {
        let event = id(9);
        let missing: TextHandle = Inline::new([10; 32]);
        let fragment = entity! { ExclusiveId::force_ref(&event) @ reason::text: missing };
        let error = validate_fragment(&fragment).unwrap_err();
        assert!(format!("{error:#}").contains("self-contained event is missing reason::text"));
    }

    #[test]
    fn multi_event_preflight_rejects_a_late_invalid_event_before_append() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("cognition.pile");
        let key_path = directory.path().join("cognition.key");
        File::create(&pile_path).unwrap();
        initialize_open_collection_fixture(&pile_path, Some(&key_path));

        let valid = reason_fragment(None, None, "valid", None, point(1.0));
        let invalid_id = id(11);
        let missing: TextHandle = Inline::new([12; 32]);
        let invalid = entity! { ExclusiveId::force_ref(&invalid_id) @ reason::text: missing };
        let before = std::fs::metadata(&pile_path).unwrap().len();
        let error = publish_events(&pile_path, Some(&key_path), [valid, invalid]).unwrap_err();
        assert!(format!("{error:#}").contains("self-contained event is missing reason::text"));
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), before);
    }
}
