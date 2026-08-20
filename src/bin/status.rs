//! `status` — immutable per-window "currently doing X" events.
//!
//! Live data is one fixed native collection. Current status is the canonical
//! maximum `(point timestamp, intrinsic event id)` per window; history is the
//! complete event set. Relations is a separate native collection used only to
//! resolve human selectors and render labels.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::storage::{load_signer, open_pile_strict};
use faculties::relations::{self, Head, SelectorOutcome};
use faculties::schemas::relations::DEFAULT_SCOPE_ID as RELATIONS_SCOPE_ID;
use faculties::schemas::status::DEFAULT_SCOPE_ID;
use faculties::status;
use hifitime::Epoch;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::BlobStore;
use triblespace::prelude::*;
use faculties::legacy_hint::open_scope;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "status",
    about = "Per-window 'currently doing X' status"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Acting persona: Relations label/alias or exact 32-character id.
    #[arg(long, env = "PERSONA")]
    persona: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Set the current status for your window ($PERSONA).
    Set {
        #[arg(
            help = "Status text, e.g. \"porting SigLIP\". Use @path for file input or @- for stdin."
        )]
        text: String,
    },
    /// Show the latest status of every window.
    List,
    /// Show a window's current status and recent history.
    Show {
        /// Relations label/alias or exact 32-character id.
        window: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
}

#[derive(Clone, Copy)]
struct StatusStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

struct Catalogs {
    status: TribleSet,
    relations: TribleSet,
    reader: PileReader,
}

impl StatusStorage<'_> {
    fn with_loaded_pile<T>(
        &self,
        signer: &SigningKey,
        f: impl FnOnce(&mut Pile, &SigningKey) -> Result<T>,
    ) -> Result<T> {
        let mut pile = open_pile_strict(self.pile)?;
        let result = f(&mut pile, signer);
        let close = pile.close();
        match (result, close) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(anyhow!("close pile: {error}")),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(close_error)) => {
                Err(error.context(format!("closing pile also failed: {close_error}")))
            }
        }
    }

    fn with_pile<T>(&self, f: impl FnOnce(&mut Pile, &SigningKey) -> Result<T>) -> Result<T> {
        // Authority is loaded before storage is touched. No ordinary command
        // mints an identity or substitutes an ephemeral signer.
        let signer = load_signer(self.pile, self.key)?;
        self.with_loaded_pile(&signer, f)
    }
}

fn materialize_scope(
    pile: &mut Pile,
    signer: &SigningKey,
    scope: Id,
    label: &str,
) -> Result<TribleSet> {
    let mut collection = open_scope(&mut *pile, scope, signer.clone());
    collection
        .materialize()
        .with_context(|| format!("materialize authored {label} collection"))
}

fn load_catalogs(pile: &mut Pile, signer: &SigningKey) -> Result<Catalogs> {
    let status_facts = materialize_scope(pile, signer, DEFAULT_SCOPE_ID, "Status")?;
    let relations_facts = materialize_scope(pile, signer, RELATIONS_SCOPE_ID, "Relations")?;
    let reader = pile.reader().context("open Status/Relations blob reader")?;
    status::validate_catalog(&reader, &status_facts).context("validate Status collection")?;
    relations::validate_catalog(&reader, &relations_facts)
        .context("validate Relations collection")?;
    Ok(Catalogs {
        status: status_facts,
        relations: relations_facts,
        reader,
    })
}

fn commit_status(
    pile: &mut Pile,
    signer: &SigningKey,
    fragment: Fragment,
) -> Result<CollectionCommit> {
    let mut collection = open_scope(&mut *pile, DEFAULT_SCOPE_ID, signer.clone());
    collection
        .commit(fragment)
        .context("commit authored Status event")
}

fn now_interval() -> status::IntervalValue {
    let now = Epoch::now().unwrap_or_else(|_| Epoch::from_unix_seconds(0.0));
    (now, now)
        .try_to_inline()
        .expect("current point time is inline")
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// Compact age like "3m" / "2h" / "5d" from two nanosecond coordinates.
fn format_age(now: i128, past: i128) -> String {
    let secs = ((now - past) / 1_000_000_000).max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3_600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3_600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

/// Exact ids deliberately do not require Relations membership. Labels and
/// aliases use the complete native Relations read model and fail closed on
/// ambiguity or a forked profile/lifecycle track.
fn resolve_window_id(reader: &PileReader, facts: &TribleSet, input: &str) -> Result<Id> {
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
fn window_label(reader: &PileReader, facts: &TribleSet, window: Id) -> Result<String> {
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
) -> Result<(CollectionCommit, Id)> {
    storage.with_pile(|pile, signer| {
        let catalogs = load_catalogs(pile, signer)?;
        let window = resolve_window_id(&catalogs.reader, &catalogs.relations, selector)?;
        let fragment = status::status_fragment(window, text, at)?;
        status::validate_catalog_union(&catalogs.reader, &catalogs.status, &fragment)
            .context("preflight authored Status union")?;
        Ok((commit_status(pile, signer, fragment)?, window))
    })
}

fn cmd_set(storage: StatusStorage<'_>, persona: Option<&str>, text: String) -> Result<()> {
    let text = faculties::text_arg(&text, "status text")?;
    let text = text.trim();
    if text.is_empty() {
        bail!("status text is empty");
    }
    let persona = persona.ok_or_else(|| {
        anyhow!("no persona — set $PERSONA or pass --persona <Relations label or exact id>")
    })?;
    let (_, window) = store_status_at(storage, persona, text, now_interval())?;
    println!("{} → {text}", fmt_id(window));
    Ok(())
}

fn cmd_list(storage: StatusStorage<'_>) -> Result<()> {
    storage.with_pile(|pile, signer| {
        let catalogs = load_catalogs(pile, signer)?;
        let latest = status::latest_per_window(status::load_status_rows(&catalogs.status)?)?;
        if latest.is_empty() {
            println!("No statuses set yet.");
            return Ok(());
        }

        let now = status::point_timestamp(now_interval())?;
        let mut rows: Vec<(String, Id, String, String)> = latest
            .into_values()
            .map(|row| {
                let label = window_label(&catalogs.reader, &catalogs.relations, row.window)?;
                let text = status::read_text(&catalogs.reader, row.text)?;
                let age = format_age(now, status::point_timestamp(row.at)?);
                Ok((label, row.window, text, age))
            })
            .collect::<Result<_>>()?;
        rows.sort_by(|left, right| (&left.0, left.1).cmp(&(&right.0, right.1)));
        for (label, _, text, age) in rows {
            println!("{label}: {text}  ({age} ago)");
        }
        Ok(())
    })
}

fn cmd_show(storage: StatusStorage<'_>, selector: String, limit: usize) -> Result<()> {
    storage.with_pile(|pile, signer| {
        let catalogs = load_catalogs(pile, signer)?;
        let window = resolve_window_id(&catalogs.reader, &catalogs.relations, &selector)?;
        let label = window_label(&catalogs.reader, &catalogs.relations, window)?;
        let mut rows: Vec<((i128, Id), status::StatusRow)> =
            status::load_status_rows(&catalogs.status)?
                .into_iter()
                .filter(|row| row.window == window)
                .map(|row| Ok((status::event_key(&row)?, row)))
                .collect::<Result<_>>()?;
        rows.sort_by(|left, right| right.0.cmp(&left.0));

        println!("status for {label} ({})", fmt_id(window));
        if rows.is_empty() {
            println!("- (no status set)");
            return Ok(());
        }
        let now = status::point_timestamp(now_interval())?;
        for (index, ((at, _), row)) in rows.into_iter().take(limit).enumerate() {
            let text = status::read_text(&catalogs.reader, row.text)?;
            let age = format_age(now, at);
            let marker = if index == 0 { "*" } else { " " };
            println!("{marker} {text}  ({age} ago)");
        }
        Ok(())
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = StatusStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };
    match cli.command {
        Command::Set { text } => cmd_set(storage, cli.persona.as_deref(), text),
        Command::List => cmd_list(storage),
        Command::Show { window, limit } => cmd_show(storage, window, limit),
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::sync::atomic::{AtomicU64, Ordering};

    use faculties::storage::initialize_signer;
    use faculties::relations::ProfileInput;

    use super::*;

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "faculties-status-live-{}-{serial}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct Fixture {
        _directory: TestDirectory,
        pile: PathBuf,
        key: PathBuf,
    }

    fn fixture() -> Fixture {
        let directory = TestDirectory::new();
        let pile = directory.0.join("status.pile");
        let key = directory.0.join("status.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        Fixture {
            _directory: directory,
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
            pile: &fixture.pile,
            key: Some(&fixture.key),
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
                let current = materialize_scope(pile, signer, RELATIONS_SCOPE_ID, "Relations")?;
                let reader = pile.reader().unwrap();
                relations::validate_catalog_union(&reader, &current, &fragment)?;
                let mut collection =
                    faculties::collection_names::open(&mut *pile, RELATIONS_SCOPE_ID, signer.clone());
                collection.commit(fragment)?;
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
        assert_eq!(first.0, second.0);
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), length);

        storage(&fixture)
            .with_pile(|pile, signer| {
                let catalogs = load_catalogs(pile, signer)?;
                assert_eq!(status::load_status_rows(&catalogs.status)?.len(), 1);
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
        let length = fs::metadata(&fixture.pile).unwrap().len();
        let key = fs::read(&fixture.key).unwrap();

        for _ in 0..2 {
            storage(&fixture)
                .with_pile(|pile, signer| {
                    let catalogs = load_catalogs(pile, signer)?;
                    assert_eq!(status::load_status_rows(&catalogs.status)?.len(), 2);
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(fs::metadata(&fixture.pile).unwrap().len(), length);
        assert_eq!(fs::read(&fixture.key).unwrap(), key);
    }

    #[test]
    fn foreign_signer_does_not_introduce_status_membership() {
        let fixture = fixture();
        let window = Id::new([0x83; 16]).unwrap();
        let mut pile = open_pile_strict(&fixture.pile).unwrap();
        {
            let mut foreign = faculties::collection_names::open(
                &mut pile,
                DEFAULT_SCOPE_ID,
                SigningKey::from_bytes(&[0x84; 32]),
            );
            foreign
                .commit(status::status_fragment(window, "foreign", at(30.0)).unwrap())
                .unwrap();
        }
        pile.close().unwrap();

        storage(&fixture)
            .with_pile(|pile, signer| {
                assert!(load_catalogs(pile, signer)?.status.is_empty());
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
                let catalogs = load_catalogs(pile, signer)?;
                assert_eq!(
                    resolve_window_id(&catalogs.reader, &catalogs.relations, "example")?,
                    person
                );
                assert_eq!(
                    resolve_window_id(&catalogs.reader, &catalogs.relations, "SAMPLE")?,
                    person
                );
                assert_eq!(
                    window_label(&catalogs.reader, &catalogs.relations, person)?,
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
                let catalogs = load_catalogs(pile, signer)?;
                assert_eq!(
                    resolve_window_id(&catalogs.reader, &catalogs.relations, &fmt_id(unknown))?,
                    unknown
                );
                assert!(
                    resolve_window_id(&catalogs.reader, &catalogs.relations, "shared").is_err()
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
                let catalogs = load_catalogs(pile, signer)?;
                assert!(
                    resolve_window_id(&catalogs.reader, &catalogs.relations, "fork-a").is_err()
                );
                assert!(window_label(&catalogs.reader, &catalogs.relations, first)?
                    .contains("profile fork"));
                Ok(())
            })
            .unwrap();
    }

}
