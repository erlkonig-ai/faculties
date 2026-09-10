//! `status` — immutable per-window "currently doing X" events.
//!
//! Live data is one fixed native collection. Current status is the canonical
//! maximum `(point timestamp, intrinsic event id)` per window; history is the
//! complete event set. Relations is a separate native collection used only to
//! resolve human selectors and render labels.

use std::path::PathBuf;

use crate::clock;
use crate::collection_names::open_configured;
use crate::relations::{self, Head, SelectorOutcome};
use crate::schemas::relations::DEFAULT_SCOPE_ID as RELATIONS_SCOPE_ID;
use crate::schemas::status::DEFAULT_SCOPE_ID;
use crate::status;
use crate::storage::FactArchive;
#[cfg(test)]
use crate::storage::{load_signer, open_pile_strict};
use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{CollectionCommit, CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::*;

/// Configured Status operations. Selector and text inputs are literal; no
/// process persona or file/stdin expansion is consulted.
#[derive(Clone, Debug)]
pub struct Status {
    storage: crate::storage::Storage,
}

/// One authored intrinsic event, including its exact publication receipt.
#[derive(Clone, Debug)]
pub struct SetStatus {
    pub event: Id,
    pub commit: CollectionCommit,
    pub window: Id,
    pub text: String,
    pub at: status::IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusEntry {
    pub event: Id,
    pub text: String,
    pub at: status::IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowStatus {
    pub window: Id,
    pub label: String,
    pub status: StatusEntry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusHistory {
    pub window: Id,
    pub label: String,
    /// Complete selected-window event count before applying the requested limit.
    pub total: usize,
    pub entries: Vec<StatusEntry>,
}

impl Status {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self { storage }
    }

    fn storage(&self) -> StatusStorage<'_> {
        StatusStorage {
            storage: &self.storage,
        }
    }

    pub fn set(&self, persona: &str, text: &str) -> Result<SetStatus> {
        self.set_at(persona, text, clock::point_now()?)
    }

    /// Author an explicitly timed event. Replaying the same resolved window,
    /// trimmed text, and timestamp produces the same event and collection record.
    pub fn set_at(
        &self,
        persona: &str,
        text: &str,
        at: status::IntervalValue,
    ) -> Result<SetStatus> {
        let text = text.trim();
        if text.is_empty() {
            bail!("status text is empty");
        }
        store_status_at(self.storage(), persona, text, at)
    }

    /// Load only the current event text for each window, from one frozen view.
    pub fn list(&self) -> Result<Vec<WindowStatus>> {
        self.storage().with_pile(|pile, signer| {
            let observation = maintain_and_observe_status(pile, signer)?;
            let latest = status::latest_per_window(status::load_status_rows(&observation.status)?)?;
            let mut rows: Vec<WindowStatus> = latest
                .into_values()
                .map(|row| {
                    Ok(WindowStatus {
                        window: row.window,
                        label: window_label(
                            &observation.snapshot,
                            &observation.relations,
                            row.window,
                        )?,
                        status: StatusEntry {
                            event: row.event,
                            text: status::read_text(&observation.snapshot, row.text)?,
                            at: row.at,
                        },
                    })
                })
                .collect::<Result<_>>()?;
            rows.sort_by(|left, right| {
                (&left.label, left.window).cmp(&(&right.label, right.window))
            });
            Ok(rows)
        })
    }

    /// Select one window before acquiring any history text. A zero limit keeps
    /// the header/count while acquiring no event text.
    pub fn show(&self, selector: &str, limit: usize) -> Result<StatusHistory> {
        self.storage().with_pile(|pile, signer| {
            let observation = maintain_and_observe_status(pile, signer)?;
            let window =
                resolve_window_id(&observation.snapshot, &observation.relations, selector)?;
            let label = window_label(&observation.snapshot, &observation.relations, window)?;
            use crate::schemas::status::{status as attributes, KIND_STATUS_UPDATE};
            use triblespace::core::metadata;
            let mut rows = find!(
                (event: Id, text: status::TextHandle, at: status::IntervalValue),
                pattern!(&observation.status, [{ ?event @
                    metadata::tag: &KIND_STATUS_UPDATE,
                    attributes::window: &window,
                    attributes::text: ?text,
                    metadata::created_at: ?at,
                }])
            )
            .map(|(event, text, at)| Ok(((status::point_timestamp(at)?, event), text, at)))
            .collect::<Result<Vec<_>>>()?;
            rows.sort_by(|left, right| right.0.cmp(&left.0));
            let total = rows.len();
            let entries = rows
                .into_iter()
                .take(limit)
                .map(|((_, event), text, at)| {
                    Ok(StatusEntry {
                        event,
                        text: status::read_text(&observation.snapshot, text)?,
                        at,
                    })
                })
                .collect::<Result<_>>()?;
            Ok(StatusHistory {
                window,
                label,
                total,
                entries,
            })
        })
    }
}

#[derive(Clone, Copy)]
struct StatusStorage<'a> {
    storage: &'a crate::storage::Storage,
}

/// One immutable observation over two separately admitted Rank9 relations.
struct StatusObservation {
    status: FactArchive,
    relations: FactArchive,
    snapshot: PileSnapshot,
}

/// The maintained Relations relation needed while resolving a Status writer.
struct RelationsObservation {
    relations: FactArchive,
    snapshot: PileSnapshot,
}

impl StatusStorage<'_> {
    fn with_pile<T>(&self, f: impl FnOnce(&mut Pile, &SigningKey) -> Result<T>) -> Result<T> {
        // Authority is loaded before storage is touched. No ordinary command
        // mints an identity or substitutes an ephemeral signer.
        self.storage.with_pile(f)
    }
}

fn maintain_and_observe_status(pile: &mut Pile, signer: &SigningKey) -> Result<StatusObservation> {
    // Register every descriptor before advancing the two fact chains.
    let status_source = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
    let descriptor_snapshot = pile.snapshot()?;
    let policy = status_source.policy(&descriptor_snapshot)?;
    drop(descriptor_snapshot);
    let status_succinct = pile.derive::<SuccinctArchiveBlob>(status_source, (), policy.clone())?;
    let status_rank9 =
        pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(status_succinct, (), policy)?;
    let relations_source = open_configured(pile, RELATIONS_SCOPE_ID, signer.verifying_key())?;
    let descriptor_snapshot = pile.snapshot()?;
    let policy = relations_source.policy(&descriptor_snapshot)?;
    drop(descriptor_snapshot);
    let relations_succinct =
        pile.derive::<SuccinctArchiveBlob>(relations_source, (), policy.clone())?;
    let relations_rank9 =
        pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(relations_succinct, (), policy)?;

    pollster::block_on(async {
        drop(
            pile.ensure(status_source)
                .await
                .context("ensure Status source collection")?,
        );
        drop(
            pile.ensure(relations_source)
                .await
                .context("ensure Relations source collection")?,
        );
        drop(
            pile.maintain(status_succinct)
                .await
                .context("maintain Status fact collection")?,
        );
        drop(
            pile.maintain(status_rank9)
                .await
                .context("maintain Status fact collection")?,
        );
        drop(
            pile.maintain(relations_succinct)
                .await
                .context("maintain Relations fact collection")?,
        );
        drop(
            pile.maintain(relations_rank9)
                .await
                .context("maintain Relations fact collection")?,
        );
        Ok::<_, anyhow::Error>(())
    })?;

    let snapshot = pile
        .snapshot()
        .context("freeze maintained Status/Relations snapshot")?;
    let status = snapshot
        .collection(status_rank9)
        .context("observe Status Rank9 collection")?
        .view::<FactArchive>()
        .context("read Status Rank9 collection")?;
    let relations = snapshot
        .collection(relations_rank9)
        .context("observe Relations Rank9 collection")?
        .view::<FactArchive>()
        .context("read Relations Rank9 collection")?;
    Ok(StatusObservation {
        status,
        relations,
        snapshot,
    })
}

fn maintain_and_observe_relations(
    pile: &mut Pile,
    signer: &SigningKey,
) -> Result<RelationsObservation> {
    let source = open_configured(pile, RELATIONS_SCOPE_ID, signer.verifying_key())?;
    let descriptor_snapshot = pile.snapshot()?;
    let policy = source.policy(&descriptor_snapshot)?;
    drop(descriptor_snapshot);
    let collection_succinct = pile.derive::<SuccinctArchiveBlob>(source, (), policy.clone())?;
    let collection_rank9 =
        pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(collection_succinct, (), policy)?;
    let snapshot = pollster::block_on(async {
        drop(pile.ensure(source).await?);
        drop(pile.maintain(collection_succinct).await?);
        pile.maintain(collection_rank9).await
    })
    .context("maintain Relations fact collection")?;
    let relations = snapshot
        .collection(collection_rank9)
        .context("observe Relations Rank9 collection")?
        .view::<FactArchive>()
        .context("read Relations Rank9 collection")?;
    Ok(RelationsObservation {
        relations,
        snapshot,
    })
}

fn commit_status(
    pile: &mut Pile,
    signer: &SigningKey,
    fragment: Fragment,
) -> Result<CollectionCommit> {
    let collection = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
    pile.commit(collection, signer, fragment)
        .context("commit authored Status event")
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// Exact ids deliberately do not require Relations membership. Labels and
/// aliases use the complete native Relations read model and fail closed on
/// ambiguity or a forked profile/lifecycle track.
fn resolve_window_id<P>(reader: &PileSnapshot, facts: &P, input: &str) -> Result<Id>
where
    P: TriblePattern,
{
    let input = input.trim();
    if let Some(id) = Id::from_hex(input) {
        return Ok(id);
    }
    match relations::resolve_person(reader, facts, input, true)? {
        SelectorOutcome::Unique(id) => Ok(id),
        outcome => outcome.require_unique("person", input),
    }
}

/// Render a Relations label without hiding unsettled state. Unknown anchors
/// remain valid Status windows and render as their exact id.
fn window_label<P>(reader: &PileSnapshot, facts: &P, window: Id) -> Result<String>
where
    P: TriblePattern,
{
    if !relations::person_anchors(facts).contains(&window) {
        return Ok(fmt_id(window));
    }

    let mut label = match relations::profile_head(facts, window)? {
        Head::Unique(profile) => {
            let snapshot = relations::profile_snapshot(facts, profile)?;
            relations::read_text(reader, snapshot.label)?
        }
        Head::Forked(heads) => {
            return Ok(format!(
                "{} [profile fork: {} heads]",
                fmt_id(window),
                heads.len()
            ));
        }
        Head::Missing => return Ok(format!("{} [missing profile]", fmt_id(window))),
    };

    match relations::lifecycle_head(facts, window)? {
        Head::Forked(heads) => label.push_str(&format!(" [lifecycle fork: {} heads]", heads.len())),
        Head::Missing => label.push_str(" [missing lifecycle]"),
        Head::Unique(_) => {}
    }
    Ok(label)
}

fn store_status_at(
    storage: StatusStorage<'_>,
    selector: &str,
    text: &str,
    at: status::IntervalValue,
) -> Result<SetStatus> {
    storage.with_pile(|pile, signer| {
        let observation = maintain_and_observe_relations(pile, signer)?;
        let window = resolve_window_id(&observation.snapshot, &observation.relations, selector)?;
        drop(observation);
        let fragment = status::status_fragment(window, text, at)?;
        let event = fragment
            .root()
            .expect("Status event has one intrinsic root");
        let commit = commit_status(pile, signer, fragment)?;
        Ok(SetStatus {
            event,
            commit,
            window,
            text: text.to_owned(),
            at,
        })
    })
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};

    use crate::relations::ProfileInput;
    use crate::storage::initialize_signer;
    use hifitime::Epoch;

    use super::*;

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
        storage: crate::storage::Storage,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("status.pile");
        let key = directory.path().join("status.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Fixture {
            _directory: directory,
            storage: crate::storage::Storage::new(pile.clone(), Some(key.clone())),
            pile,
            key,
        }
    }

    fn at(seconds: f64) -> status::IntervalValue {
        let epoch = Epoch::from_unix_seconds(seconds);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn storage(fixture: &Fixture) -> StatusStorage<'_> {
        StatusStorage {
            storage: &fixture.storage,
        }
    }

    fn profile(label: &str, aliases: &[&str]) -> ProfileInput {
        ProfileInput {
            label: label.to_owned(),
            aliases: aliases.iter().map(|value| (*value).to_owned()).collect(),
            ..ProfileInput::default()
        }
    }

    fn publish_relations(fixture: &Fixture, fragment: Fragment) {
        storage(fixture)
            .with_pile(|pile, signer| {
                let collection = open_configured(pile, RELATIONS_SCOPE_ID, signer.verifying_key())?;
                pile.commit(collection, signer, fragment)?;
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn exact_replay_is_one_commit_and_does_not_grow_the_pile() {
        let fixture = fixture();
        let window = Id::new([0x81; 16]).unwrap();
        let first = store_status_at(storage(&fixture), &fmt_id(window), "same", at(10.0)).unwrap();
        let length = fs::metadata(&fixture.pile).unwrap().len();
        let second = store_status_at(storage(&fixture), &fmt_id(window), "same", at(10.0)).unwrap();
        assert_eq!(first.commit, second.commit);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), length);

        storage(&fixture)
            .with_pile(|pile, signer| {
                let observation = maintain_and_observe_status(pile, signer)?;
                assert_eq!(status::load_status_rows(&observation.status)?.len(), 1);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn independent_events_materialize_as_one_union_and_reads_are_immutable() {
        let fixture = fixture();
        let window = Id::new([0x82; 16]).unwrap();
        store_status_at(storage(&fixture), &fmt_id(window), "first", at(20.0)).unwrap();
        store_status_at(storage(&fixture), &fmt_id(window), "second", at(21.0)).unwrap();
        storage(&fixture)
            .with_pile(|pile, signer| {
                let observation = maintain_and_observe_status(pile, signer)?;
                assert_eq!(status::load_status_rows(&observation.status)?.len(), 2);
                Ok(())
            })
            .unwrap();
        let length = fs::metadata(&fixture.pile).unwrap().len();
        let key = fs::read(&fixture.key).unwrap();

        storage(&fixture)
            .with_pile(|pile, signer| {
                let observation = maintain_and_observe_status(pile, signer)?;
                assert_eq!(status::load_status_rows(&observation.status)?.len(), 2);
                Ok(())
            })
            .unwrap();
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), length);
        assert_eq!(fs::read(&fixture.key).unwrap(), key);
    }

    #[test]
    fn foreign_commit_is_resident_but_inert_without_write_proof() {
        let fixture = fixture();
        let window = Id::new([0x83; 16]).unwrap();
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        let local = load_signer(&fixture.pile, Some(&fixture.key)).unwrap();
        let foreign = SigningKey::from_bytes(&[0x84; 32]);
        let collection =
            open_configured(&mut pile, DEFAULT_SCOPE_ID, local.verifying_key()).unwrap();
        pile.commit(
            collection,
            &foreign,
            status::status_fragment(window, "foreign", at(30.0)).unwrap(),
        )
        .unwrap();
        pile.close().unwrap();

        storage(&fixture)
            .with_pile(|pile, signer| {
                let observation = maintain_and_observe_status(pile, signer)?;
                let rows = status::load_status_rows(&observation.status)?;
                assert!(rows.is_empty());

                let collection = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
                let store_snapshot = pile.snapshot()?;
                assert!(collection.admitted(&store_snapshot)?.is_empty());
                let discovered =
                    triblespace::core::collection::discover_collection_records(&store_snapshot)?;
                let resident = discovered
                    .commits()
                    .iter()
                    .filter(|commit| commit.collection() == collection.handle())
                    .collect::<Vec<_>>();
                assert_eq!(resident.len(), 1);
                assert_eq!(
                    resident[0].public_key().raw,
                    foreign.verifying_key().to_bytes()
                );
                assert_ne!(
                    resident[0].public_key().raw,
                    signer.verifying_key().to_bytes()
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn native_relations_resolves_labels_aliases_and_retired_people() {
        let fixture = fixture();
        let person = Id::new([0x85; 16]).unwrap();
        let (initial, _, lifecycle) =
            relations::person_fragment(person, profile("Example", &["sample"])).unwrap();
        publish_relations(&fixture, initial);
        publish_relations(
            &fixture,
            relations::lifecycle_fragment(person, true, &[lifecycle]),
        );

        storage(&fixture)
            .with_pile(|pile, signer| {
                let observation = maintain_and_observe_relations(pile, signer)?;
                assert_eq!(
                    resolve_window_id(&observation.snapshot, &observation.relations, "example")?,
                    person
                );
                assert_eq!(
                    resolve_window_id(&observation.snapshot, &observation.relations, "SAMPLE")?,
                    person
                );
                assert_eq!(
                    window_label(&observation.snapshot, &observation.relations, person)?,
                    "Example"
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn exact_unknown_id_passes_through_but_ambiguous_and_forked_labels_fail() {
        let fixture = fixture();
        let unknown = Id::new([0x86; 16]).unwrap();
        let first = Id::new([0x87; 16]).unwrap();
        let second = Id::new([0x88; 16]).unwrap();
        let (first_fragment, first_profile, _) =
            relations::person_fragment(first, profile("shared", &[])).unwrap();
        let (second_fragment, _, _) =
            relations::person_fragment(second, profile("shared", &[])).unwrap();
        publish_relations(&fixture, first_fragment);
        publish_relations(&fixture, second_fragment);

        storage(&fixture)
            .with_pile(|pile, signer| {
                let observation = maintain_and_observe_relations(pile, signer)?;
                assert_eq!(
                    resolve_window_id(
                        &observation.snapshot,
                        &observation.relations,
                        &fmt_id(unknown)
                    )?,
                    unknown
                );
                assert!(
                    resolve_window_id(&observation.snapshot, &observation.relations, "shared")
                        .is_err()
                );
                Ok(())
            })
            .unwrap();

        publish_relations(
            &fixture,
            relations::profile_fragment(first, profile("fork-a", &[]), &[first_profile]).unwrap(),
        );
        publish_relations(
            &fixture,
            relations::profile_fragment(first, profile("fork-b", &[]), &[first_profile]).unwrap(),
        );
        storage(&fixture)
            .with_pile(|pile, signer| {
                let observation = maintain_and_observe_relations(pile, signer)?;
                assert!(
                    resolve_window_id(&observation.snapshot, &observation.relations, "fork-a")
                        .is_err()
                );
                assert!(
                    window_label(&observation.snapshot, &observation.relations, first)?
                        .contains("profile fork")
                );
                Ok(())
            })
            .unwrap();
    }
}
