//! Direct Reason publication operations; no argv, output, or child processes.
use crate::{clock, cognition};
use anyhow::Result;
#[cfg(test)]
use hifitime::Epoch;
use std::path::{Path, PathBuf};
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::prelude::*;

#[derive(Clone, Debug)]
pub struct Reason {
    pile: PathBuf,
    key: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReasonAction {
    pub reason: Id,
    pub action: Id,
}

impl Reason {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self { pile, key }
    }
    fn storage(&self) -> ReasonStorage<'_> {
        ReasonStorage {
            pile: &self.pile,
            key: self.key.as_deref(),
        }
    }
    /// Record literal prose. Environment and command execution are not consulted.
    pub fn record(&self, text: &str, turn: Option<Id>, worker: Option<Id>) -> Result<Id> {
        anyhow::ensure!(!text.trim().is_empty(), "reason text is empty");
        append_reason(self.storage(), turn, worker, text, None)
    }
    /// Publish the reason and intended-action events after validating both.
    /// This records command text only; it never executes that command.
    pub fn record_action(
        &self,
        text: &str,
        command: &str,
        turn: Option<Id>,
        worker: Option<Id>,
    ) -> Result<ReasonAction> {
        anyhow::ensure!(!text.trim().is_empty(), "reason text is empty");
        anyhow::ensure!(!command.trim().is_empty(), "command text is empty");
        let created = clock::point_now()?;
        let (reason, reason_event) = described_reason_fragment(turn, worker, text, None, created);
        let (action, action_event) =
            described_reason_fragment(turn, worker, command, Some(command), created);
        cognition::publish_events(
            &self.pile,
            self.key.as_deref(),
            [reason_event, action_event],
        )?;
        Ok(ReasonAction { reason, action })
    }
}

#[cfg(test)]
fn epoch_interval(epoch: Epoch) -> Inline<inlineencodings::NsTAIInterval> {
    (epoch, epoch).try_to_inline().unwrap()
}

#[derive(Clone, Copy)]
struct ReasonStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

fn publish_reason(
    storage: ReasonStorage<'_>,
    turn_id: Option<Id>,
    worker_id: Option<Id>,
    text: &str,
    command_text: Option<&str>,
    created_at: Inline<inlineencodings::NsTAIInterval>,
) -> Result<(Id, CollectionCommit)> {
    let (event_id, event) =
        described_reason_fragment(turn_id, worker_id, text, command_text, created_at);
    let commit = cognition::publish_event(storage.pile, storage.key, event)?;
    Ok((event_id, commit))
}

fn described_reason_fragment(
    turn_id: Option<Id>,
    worker_id: Option<Id>,
    text: &str,
    command_text: Option<&str>,
    created_at: Inline<inlineencodings::NsTAIInterval>,
) -> (Id, Fragment) {
    let mut event = cognition::reason_fragment(turn_id, worker_id, text, command_text, created_at);
    let event_id = event.root().expect("reason event has one intrinsic root");
    event.describe_with(entity! { metadata::description: "reason".to_owned() });
    (event_id, event)
}

fn append_reason(
    storage: ReasonStorage<'_>,
    turn_id: Option<Id>,
    worker_id: Option<Id>,
    text: &str,
    command_text: Option<&str>,
) -> Result<Id> {
    publish_reason(
        storage,
        turn_id,
        worker_id,
        text,
        command_text,
        clock::point_now()?,
    )
    .map(|(event, _)| event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reason::cli::Cli;
    use clap::CommandFactory;

    use crate::schemas::cognition::DEFAULT_SCOPE_ID;
    use crate::schemas::reason::{reason_schema, KIND_REASON_ID};
    use crate::storage::{initialize_signer, load_signer, open_pile_strict};
    use anybytes::View;
    use std::fs::File;

    type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;

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

    #[test]
    fn exact_reason_event_is_one_intrinsic_idempotent_commit() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("reason.pile");
        let key_path = directory.path().join("reason.key");
        File::create(&pile_path).unwrap();

        initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let storage = ReasonStorage {
            pile: &pile_path,
            key: Some(&key_path),
        };
        let turn = test_id(0x72);
        let worker = test_id(0x73);
        let created = at_unix(42.0);
        let expected = cognition::reason_fragment(
            Some(turn),
            Some(worker),
            "choose the narrowest next constraint",
            Some("cargo test --lib"),
            created,
        );
        let expected_id = expected.root().unwrap();

        let (event_id, first_commit) = publish_reason(
            storage,
            Some(turn),
            Some(worker),
            "choose the narrowest next constraint",
            Some("cargo test --lib"),
            created,
        )
        .unwrap();
        let length_after_first = std::fs::metadata(&pile_path).unwrap().len();
        let (replayed_id, replayed_commit) = publish_reason(
            storage,
            Some(turn),
            Some(worker),
            "choose the narrowest next constraint",
            Some("cargo test --lib"),
            created,
        )
        .unwrap();

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

        let (text, command, found_turn, found_worker) = find!(
            (text: TextHandle, command: TextHandle, turn: Id, worker: Id),
            pattern!(&facts, [{ event_id @
                metadata::tag: KIND_REASON_ID,
                reason_schema::text: ?text,
                reason_schema::command_text: ?command,
                reason_schema::about_turn: ?turn,
                reason_schema::worker: ?worker,
            }])
        )
        .next()
        .unwrap();
        assert_eq!(found_turn, turn);
        assert_eq!(found_worker, worker);
        assert_eq!(
            &*reader.get::<View<str>, _>(text).unwrap(),
            "choose the narrowest next constraint"
        );
        assert_eq!(
            &*reader.get::<View<str>, _>(command).unwrap(),
            "cargo test --lib"
        );
        pile.close().unwrap();
    }

    #[test]
    fn missing_signer_fails_before_touching_pile() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("reason.pile");
        let key_path = directory.path().join("missing.key");
        File::create(&pile_path).unwrap();
        let before = std::fs::metadata(&pile_path).unwrap().len();

        let error = publish_reason(
            ReasonStorage {
                pile: &pile_path,
                key: Some(&key_path),
            },
            None,
            None,
            "must not land",
            None,
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
