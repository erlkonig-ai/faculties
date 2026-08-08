//! `status` — per-window "currently doing X" status.
//!
//! Status updates are immutable timestamped events in one union collection.
//! Latest-per-window is the current status; the complete event set is the
//! activity timeline. Until relations itself has collection-native semantics,
//! this CLI accepts exact persona ids and deliberately does not fall back to a
//! legacy relations branch for labels.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use faculties::collection_access::{self, CollectionSnapshot, CollectionView};
use faculties::schemas::status::DEFAULT_SCOPE_ID;
use faculties::status::{
    latest_per_window, load_status_rows, read_text, status_fragment, IntervalValue, StatusRow,
    TextHandle,
};
use hifitime::Epoch;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::prelude::*;

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
    /// Extrinsic collection scope. Defaults to the stable status scope.
    #[arg(long, value_parser = parse_id_arg)]
    scope: Option<Id>,
    /// Acting persona as an exact 32-character hex id.
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
        /// Window as an exact 32-character hex id.
        window: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
}

#[derive(Clone, Copy)]
struct StatusStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    scope: Id,
}

impl StatusStorage<'_> {
    fn view(&self) -> Result<CollectionView> {
        let signer = collection_access::load_signer(self.pile, self.key)?;
        let allowed = HashSet::from([signer.verifying_key()]);
        let view = CollectionSnapshot::open(self.pile)?.materialize_scope(self.scope, &allowed)?;
        faculties::status::validate_catalog(&view.reader, &view.facts)
            .context("validate Status collection")?;
        Ok(view)
    }

    fn publish(&self, fragment: Fragment, message: &str) -> Result<CollectionCommit> {
        let mut commit_metadata = Fragment::empty();
        let description: TextHandle = commit_metadata.put(message.to_owned());
        commit_metadata += entity! { metadata::description: description };
        collection_access::publish_fragment(
            self.pile,
            self.key,
            self.scope,
            fragment,
            commit_metadata,
        )
    }
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
}

fn exact_window_id(raw: &str) -> Result<Id> {
    Id::from_hex(raw.trim()).ok_or_else(|| {
        anyhow!(
            "window/persona must be an exact 32-character hex id until relations has a collection-native resolver; got '{raw}'"
        )
    })
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> IntervalValue {
    (epoch, epoch)
        .try_to_inline()
        .expect("valid point interval")
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval.try_from_inline().expect("valid status timestamp");
    lower
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// Compact age like "3m" / "2h" / "5d" from two ns keys.
fn format_age(now_key: i128, past_key: i128) -> String {
    let secs = ((now_key - past_key) / 1_000_000_000).max(0);
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

fn store_status_at(
    storage: StatusStorage<'_>,
    window: Id,
    text: &str,
    at: IntervalValue,
) -> Result<CollectionCommit> {
    storage.publish(status_fragment(window, text, at)?, "status set")
}

fn cmd_set(storage: StatusStorage<'_>, persona: Option<&str>, text: String) -> Result<()> {
    let text = faculties::text_arg(&text, "status text")?;
    let text = text.trim();
    if text.is_empty() {
        bail!("status text is empty");
    }
    let persona = persona.ok_or_else(|| {
        anyhow!("no persona — set $PERSONA or pass --persona <32-character hex id>")
    })?;
    let window = exact_window_id(persona)?;
    store_status_at(storage, window, text, epoch_interval(now_epoch()))?;
    println!("{} → {text}", fmt_id(window));
    Ok(())
}

fn cmd_list(storage: StatusStorage<'_>) -> Result<()> {
    let view = storage.view()?;
    let latest = latest_per_window(load_status_rows(&view.facts)?)?;
    if latest.is_empty() {
        println!("No statuses set yet.");
        return Ok(());
    }

    let now = interval_key(epoch_interval(now_epoch()));
    let mut rows: Vec<(Id, String, String)> = latest
        .into_values()
        .map(|row| {
            let text = read_text(&view.reader, row.text)?;
            let age = format_age(now, interval_key(row.at));
            Ok((row.window, text, age))
        })
        .collect::<Result<_>>()?;
    rows.sort_by_key(|(window, _, _)| *window);
    for (window, text, age) in rows {
        println!("{}: {text}  ({age} ago)", fmt_id(window));
    }
    Ok(())
}

fn cmd_show(storage: StatusStorage<'_>, window: String, limit: usize) -> Result<()> {
    let window = exact_window_id(&window)?;
    let view = storage.view()?;
    let mut rows: Vec<StatusRow> = load_status_rows(&view.facts)?
        .into_iter()
        .filter(|row| row.window == window)
        .collect();
    rows.sort_by(|left, right| {
        interval_key(right.at)
            .cmp(&interval_key(left.at))
            .then_with(|| left.event.cmp(&right.event))
    });

    println!("status for {}", fmt_id(window));
    if rows.is_empty() {
        println!("- (no status set)");
        return Ok(());
    }
    // A history can show concurrent equal-time events, but it must not mark
    // one as the current value. Validate the latest choice before rendering.
    latest_per_window(rows.iter().copied())?;
    let now = interval_key(epoch_interval(now_epoch()));
    for (index, row) in rows.into_iter().take(limit).enumerate() {
        let text = read_text(&view.reader, row.text)?;
        let age = format_age(now, interval_key(row.at));
        let marker = if index == 0 { "*" } else { " " };
        println!("{marker} {text}  ({age} ago)");
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = StatusStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
        scope: cli.scope.unwrap_or(DEFAULT_SCOPE_ID),
    };
    match cli.command {
        Command::Set { text } => cmd_set(storage, cli.persona.as_deref(), text),
        Command::List => cmd_list(storage),
        Command::Show { window, limit } => cmd_show(storage, window, limit),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    use faculties::schemas::status::{status as status_attrs, KIND_STATUS_UPDATE};
    use triblespace::core::collection::{discover_collection_records, simplearchive_union};

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at_unix(seconds: f64) -> IntervalValue {
        epoch_interval(Epoch::from_unix_seconds(seconds))
    }

    fn fresh_storage(directory: &tempfile::TempDir) -> (PathBuf, PathBuf, Id) {
        let pile = directory.path().join("status.pile");
        let key = directory.path().join("status.key");
        File::create(&pile).unwrap();
        collection_access::initialize_signer(&pile, Some(&key)).unwrap();
        (pile, key, test_id(0x81))
    }

    fn collection_commit_count(pile: &Path, key: &Path, scope: Id) -> usize {
        let signer = collection_access::load_signer(pile, Some(key)).unwrap();
        let definition = simplearchive_union::definition(scope);
        let mut pile_store = collection_access::open_pile_strict(pile).unwrap();
        let reader = pile_store.reader().unwrap();
        pile_store.close().unwrap();
        discover_collection_records(&reader)
            .unwrap()
            .commits()
            .iter()
            .filter(|commit| commit.collection() == definition.id())
            .filter(|commit| commit.public_key().raw == signer.verifying_key().to_bytes())
            .count()
    }

    #[test]
    fn duplicate_status_publication_is_idempotent_and_readable() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key, scope) = fresh_storage(&directory);
        let storage = StatusStorage {
            pile: &pile,
            key: Some(&key),
            scope,
        };
        let window = test_id(0x82);
        let first = store_status_at(storage, window, "mapping the lattice", at_unix(10.0)).unwrap();
        let length = std::fs::metadata(&pile).unwrap().len();
        let second =
            store_status_at(storage, window, "mapping the lattice", at_unix(10.0)).unwrap();

        assert_eq!(first, second);
        assert_eq!(collection_commit_count(&pile, &key, scope), 1);
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);
        let view = storage.view().unwrap();
        let rows = load_status_rows(&view.facts).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].window, window);
        assert_eq!(
            read_text(&view.reader, rows[0].text).unwrap(),
            "mapping the lattice"
        );
    }

    #[test]
    fn immutable_read_does_not_touch_pile_or_key() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key, scope) = fresh_storage(&directory);
        let storage = StatusStorage {
            pile: &pile,
            key: Some(&key),
            scope,
        };
        store_status_at(storage, test_id(0x83), "reading", at_unix(20.0)).unwrap();
        let pile_length = std::fs::metadata(&pile).unwrap().len();
        let key_bytes = std::fs::read(&key).unwrap();

        let first = storage.view().unwrap();
        let second = storage.view().unwrap();

        assert_eq!(first.revision, second.revision);
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), pile_length);
        assert_eq!(std::fs::read(&key).unwrap(), key_bytes);
    }

    #[test]
    fn status_constructor_rejects_non_point_time() {
        let at: IntervalValue = (
            Epoch::from_unix_seconds(20.0),
            Epoch::from_unix_seconds(21.0),
        )
            .try_to_inline()
            .unwrap();

        let error = status_fragment(test_id(0x90), "range", at).unwrap_err();

        assert!(format!("{error:#}").contains("must be a point interval"));
    }

    #[test]
    fn catalog_rejects_non_point_time() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key, scope) = fresh_storage(&directory);
        let storage = StatusStorage {
            pile: &pile,
            key: Some(&key),
            scope,
        };
        let at: IntervalValue = (
            Epoch::from_unix_seconds(20.0),
            Epoch::from_unix_seconds(21.0),
        )
            .try_to_inline()
            .unwrap();
        let mut fragment = Fragment::empty();
        let text: TextHandle = fragment.put("range".to_owned());
        fragment += entity! {
            metadata::tag: &KIND_STATUS_UPDATE,
            status_attrs::window: test_id(0x96),
            status_attrs::text: text,
            metadata::created_at: at,
        };
        storage.publish(fragment, "range status").unwrap();

        let error = storage.view().unwrap_err();

        assert!(format!("{error:#}").contains("must be a point interval"));
    }

    #[test]
    fn catalog_rejects_legacy_random_event_identity() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key, scope) = fresh_storage(&directory);
        let storage = StatusStorage {
            pile: &pile,
            key: Some(&key),
            scope,
        };
        let event = ufoid();
        let mut fragment = Fragment::empty();
        let text: TextHandle = fragment.put("legacy random event".to_owned());
        fragment += entity! { &event @
            metadata::tag: &KIND_STATUS_UPDATE,
            status_attrs::window: test_id(0x91),
            status_attrs::text: text,
            metadata::created_at: at_unix(22.0),
        };
        storage.publish(fragment, "legacy-shaped status").unwrap();

        let error = storage.view().unwrap_err();

        let message = format!("{error:#}");
        assert!(message.contains("is not intrinsic"));
        assert!(message.contains("explicit stopped-world transforming migration"));
    }

    #[test]
    fn catalog_rejects_extra_facts_on_intrinsic_event() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key, scope) = fresh_storage(&directory);
        let storage = StatusStorage {
            pile: &pile,
            key: Some(&key),
            scope,
        };
        let mut fragment = status_fragment(test_id(0x92), "working", at_unix(23.0)).unwrap();
        let event = fragment.root().unwrap();
        let other_kind = test_id(0x93);
        fragment += entity! { ExclusiveId::force_ref(&event) @
            metadata::tag: &other_kind,
        };
        storage.publish(fragment, "status with extra fact").unwrap();

        let error = storage.view().unwrap_err();

        assert!(format!("{error:#}").contains("expected exactly 4"));
    }

    #[test]
    fn catalog_rejects_facts_outside_status_events() {
        let directory = tempfile::tempdir().unwrap();
        let (pile, key, scope) = fresh_storage(&directory);
        let storage = StatusStorage {
            pile: &pile,
            key: Some(&key),
            scope,
        };
        let mut fragment = status_fragment(test_id(0x94), "working", at_unix(24.0)).unwrap();
        let other_kind = test_id(0x95);
        fragment += entity! { metadata::tag: &other_kind };
        storage.publish(fragment, "mixed ontology").unwrap();

        let error = storage.view().unwrap_err();

        assert!(format!("{error:#}").contains("outside canonical Status events"));
    }

    #[test]
    fn equal_time_distinct_updates_are_reported_as_a_fork() {
        let window = test_id(0x84);
        let at = at_unix(30.0);
        let left = status_fragment(window, "left", at).unwrap().into_facts();
        let right = status_fragment(window, "right", at).unwrap().into_facts();
        let mut facts = left;
        facts += right;

        let error = latest_per_window(load_status_rows(&facts).unwrap()).unwrap_err();
        assert!(format!("{error:#}").contains("ambiguous current status"));
    }

    #[test]
    fn later_update_resolves_an_older_equal_time_fork_independent_of_order() {
        let window = test_id(0x89);
        let older_at = at_unix(30.0);
        let later_at = at_unix(31.0);
        let left = StatusRow {
            event: test_id(0x8a),
            window,
            text: Inline::new([0x8b; 32]),
            at: older_at,
        };
        let right = StatusRow {
            event: test_id(0x8c),
            window,
            text: Inline::new([0x8d; 32]),
            at: older_at,
        };
        let later = StatusRow {
            event: test_id(0x8e),
            window,
            text: Inline::new([0x8f; 32]),
            at: later_at,
        };

        for rows in [
            vec![left, right, later],
            vec![right, later, left],
            vec![later, left, right],
        ] {
            let latest = latest_per_window(rows).unwrap();
            assert_eq!(latest[&window].event, later.event);
        }
    }

    #[test]
    fn non_hex_relations_label_fails_closed_without_touching_storage() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("absent.pile");
        let key = directory.path().join("absent.key");
        let storage = StatusStorage {
            pile: &pile,
            key: Some(&key),
            scope: test_id(0x88),
        };

        let error = cmd_set(storage, Some("named-persona"), "working".to_owned()).unwrap_err();

        assert!(format!("{error:#}").contains("until relations has a collection-native resolver"));
        assert!(!pile.exists());
        assert!(!key.exists());
    }
}
