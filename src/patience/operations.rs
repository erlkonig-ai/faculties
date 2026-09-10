//! Direct Patience publication operations; no argv, output, or child processes.
use crate::storage::Storage;
use crate::{clock, cognition};
use anyhow::Result;
#[cfg(test)]
use hifitime::Epoch;
use std::path::PathBuf;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::prelude::*;

#[derive(Clone, Debug)]
pub struct Patience {
    storage: Storage,
}

impl Patience {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(Storage::new(pile, key))
    }
    pub fn with_storage(storage: Storage) -> Self {
        Self { storage }
    }
    /// Publish an extension request. Its receipt does not promise a runtime
    /// has observed or accepted the requested timeout.
    pub fn extend(&self, request: Id, worker: Id, timeout_ms: u64) -> Result<Id> {
        anyhow::ensure!(timeout_ms > 0, "duration must be greater than zero");
        append_timeout_extension(
            PatienceStorage {
                storage: &self.storage,
            },
            request,
            worker,
            timeout_ms,
        )
    }
}

#[cfg(test)]
fn epoch_interval(epoch: Epoch) -> Inline<inlineencodings::NsTAIInterval> {
    (epoch, epoch).try_to_inline().unwrap()
}

#[derive(Clone, Copy)]
struct PatienceStorage<'a> {
    storage: &'a Storage,
}

fn publish_timeout_extension(
    storage: PatienceStorage<'_>,
    request_id: Id,
    worker_id: Id,
    timeout_ms: u64,
    requested_at: Inline<inlineencodings::NsTAIInterval>,
) -> Result<(Id, CollectionCommit)> {
    let mut event =
        cognition::timeout_extension_fragment(request_id, worker_id, timeout_ms, requested_at);
    let event_id = event
        .root()
        .expect("timeout extension has one intrinsic root");
    event.describe_with(
        entity! { metadata::description: "playground_exec timeout_extension".to_owned() },
    );
    let commit = cognition::publish_event_with_storage(storage.storage, event)?;
    Ok((event_id, commit))
}

fn append_timeout_extension(
    storage: PatienceStorage<'_>,
    request_id: Id,
    worker_id: Id,
    timeout_ms: u64,
) -> Result<Id> {
    publish_timeout_extension(
        storage,
        request_id,
        worker_id,
        timeout_ms,
        clock::point_now()?,
    )
    .map(|(event, _)| event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patience::cli::Cli;
    use clap::CommandFactory;

    use crate::schemas::cognition::DEFAULT_SCOPE_ID;
    use crate::schemas::patience::{exec_schema, KIND_TIMEOUT_EXTENSION_ID};
    use crate::storage::{initialize_signer, load_signer, open_pile_strict};
    use std::fs::File;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at_unix(seconds: f64) -> Inline<inlineencodings::NsTAIInterval> {
        epoch_interval(Epoch::from_unix_seconds(seconds))
    }

    fn u256be_to_u64(value: Inline<inlineencodings::U256BE>) -> Option<u64> {
        if value.raw[..24].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(u64::from_be_bytes(value.raw[24..].try_into().ok()?))
    }

    #[test]
    fn exact_timeout_event_is_one_intrinsic_idempotent_commit() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("patience.pile");
        let key_path = directory.path().join("patience.key");
        File::create(&pile_path).unwrap();

        initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let storage = Storage::new(pile_path.clone(), Some(key_path.clone()));
        let storage = PatienceStorage { storage: &storage };
        let request = test_id(0x62);
        let worker = test_id(0x63);
        let requested_at = at_unix(42.0);
        let expected = cognition::timeout_extension_fragment(request, worker, 90_000, requested_at);
        let expected_id = expected.root().unwrap();

        let (event_id, first_commit) =
            publish_timeout_extension(storage, request, worker, 90_000, requested_at).unwrap();
        let length_after_first = std::fs::metadata(&pile_path).unwrap().len();
        let (replayed_id, replayed_commit) =
            publish_timeout_extension(storage, request, worker, 90_000, requested_at).unwrap();

        assert_eq!(event_id, expected_id);
        assert_eq!(replayed_id, event_id);
        assert_eq!(replayed_commit, first_commit);
        assert_eq!(
            std::fs::metadata(&pile_path).unwrap().len(),
            length_after_first
        );
        let signer = load_signer(&pile_path, Some(&key_path)).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let collection =
            crate::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())
                .unwrap();
        let reader = pile.snapshot().unwrap();
        let (facts, _) = crate::storage::read_fact_collection(collection, &reader).unwrap();
        assert_eq!(facts, expected.into_facts());
        cognition::validate_catalog(&reader, &facts).unwrap();

        let (found_request, found_worker, timeout, found_at) = find!(
            (request: Id, worker: Id, timeout: Inline<inlineencodings::U256BE>, at: Inline<inlineencodings::NsTAIInterval>),
            pattern!(&facts, [{ event_id @
                metadata::tag: KIND_TIMEOUT_EXTENSION_ID,
                exec_schema::about_request: ?request,
                exec_schema::worker: ?worker,
                exec_schema::timeout_ms: ?timeout,
                exec_schema::requested_at: ?at,
            }])
        )
        .next()
        .unwrap();
        assert_eq!(found_request, request);
        assert_eq!(found_worker, worker);
        assert_eq!(u256be_to_u64(timeout), Some(90_000));
        assert_eq!(found_at, requested_at);
        pile.close().unwrap();
    }

    #[test]
    fn missing_signer_fails_before_touching_pile() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("patience.pile");
        let key_path = directory.path().join("missing.key");
        File::create(&pile_path).unwrap();
        let before = std::fs::metadata(&pile_path).unwrap().len();

        let error = publish_timeout_extension(
            PatienceStorage {
                storage: &Storage::new(pile_path.clone(), Some(key_path.clone())),
            },
            test_id(0x65),
            test_id(0x66),
            1_000,
            at_unix(43.0),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("load durable signing key"));
        assert!(!key_path.exists());
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), before);
    }

    #[test]
    fn permanent_cli_has_no_scope_or_branch_selector() {
        let command = Cli::command();
        for forbidden in ["scope", "branch", "branch_id"] {
            assert!(!command
                .get_arguments()
                .any(|argument| argument.get_id() == forbidden));
        }
    }
}
