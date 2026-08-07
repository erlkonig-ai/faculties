//! `status` — per-window "currently doing X" status.
//!
//! Status updates are immutable timestamped events in one union collection.
//! Latest-per-window is the current status; the complete event set is the
//! activity timeline. Until relations itself has collection-native semantics,
//! this CLI accepts exact persona ids and deliberately does not fall back to a
//! legacy relations branch for labels.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use faculties::collection_access::{self, CollectionSnapshot, CollectionView};
use faculties::schemas::status::{status, DEFAULT_SCOPE_ID, KIND_STATUS_UPDATE};
use hifitime::Epoch;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::prelude::*;

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

const LEGACY_STATUS_BRANCH_NAME: &str = "status";

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
    /// Publish the signed legacy `status` branch as collection commits, then
    /// verify the exact materialized view. Stop all legacy status writers and
    /// collection-native writers for this scope first. The legacy pin remains.
    MigrateLegacy {
        /// Exact legacy branch id, needed only if duplicate `status` names make
        /// name lookup ambiguous.
        #[arg(long, value_parser = parse_id_arg)]
        legacy_branch_id: Option<Id>,
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
        CollectionSnapshot::open(self.pile)?.materialize_scope(self.scope, &allowed)
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

fn status_fragment(window: Id, text: &str, at: IntervalValue) -> Fragment {
    let mut fragment = Fragment::empty();
    let text: TextHandle = fragment.put(text.to_owned());
    fragment += entity! {
        metadata::tag: &KIND_STATUS_UPDATE,
        status::window: window,
        status::text: text,
        metadata::created_at: at,
    };
    fragment
}

#[derive(Clone, Copy, Debug)]
struct StatusRow {
    event: Id,
    window: Id,
    text: TextHandle,
    at: IntervalValue,
}

fn exactly_one<T>(event: Id, field: &str, values: Vec<T>) -> Result<T> {
    let count = values.len();
    let mut values = values.into_iter();
    match (values.next(), count) {
        (Some(value), 1) => Ok(value),
        _ => bail!(
            "status event {} has {count} values for {field}; expected exactly one",
            fmt_id(event)
        ),
    }
}

fn load_status_rows(space: &TribleSet) -> Result<Vec<StatusRow>> {
    let mut events: Vec<Id> = find!(
        event: Id,
        pattern!(space, [{ ?event @ metadata::tag: &KIND_STATUS_UPDATE }])
    )
    .collect();
    events.sort_unstable();
    events.dedup();

    events
        .into_iter()
        .map(|event| {
            let window = exactly_one(
                event,
                "status::window",
                find!(
                    window: Id,
                    pattern!(space, [{ event @ status::window: ?window }])
                )
                .collect(),
            )?;
            let text = exactly_one(
                event,
                "status::text",
                find!(
                    text: TextHandle,
                    pattern!(space, [{ event @ status::text: ?text }])
                )
                .collect(),
            )?;
            let at = exactly_one(
                event,
                "metadata::created_at",
                find!(
                    at: IntervalValue,
                    pattern!(space, [{ event @ metadata::created_at: ?at }])
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

/// Latest event per window. Equal-time distinct events are a fork, not an
/// invitation to smuggle arbitrary iteration order in as last-write-wins.
fn latest_per_window(rows: impl IntoIterator<Item = StatusRow>) -> Result<HashMap<Id, StatusRow>> {
    let mut frontiers: HashMap<Id, (i128, BTreeMap<Id, StatusRow>)> = HashMap::new();
    for row in rows {
        let at = interval_key(row.at);
        let entry = frontiers
            .entry(row.window)
            .or_insert_with(|| (at, BTreeMap::new()));
        match at.cmp(&entry.0) {
            std::cmp::Ordering::Greater => {
                entry.0 = at;
                entry.1.clear();
                entry.1.insert(row.event, row);
            }
            std::cmp::Ordering::Equal => {
                entry.1.insert(row.event, row);
            }
            std::cmp::Ordering::Less => {}
        }
    }

    let mut latest = HashMap::with_capacity(frontiers.len());
    for (window, (_, frontier)) in frontiers {
        let mut rows = frontier.into_values();
        let row = rows.next().expect("status frontier is never empty");
        if let Some(other) = rows.next() {
            bail!(
                "ambiguous current status for window {}: distinct events {} and {} have the same maximal timestamp",
                fmt_id(window),
                fmt_id(row.event),
                fmt_id(other.event),
            );
        }
        latest.insert(window, row);
    }
    Ok(latest)
}

fn read_text(reader: &PileReader, handle: TextHandle) -> Result<String> {
    let text: anybytes::View<str> = reader.get(handle).context("read status text")?;
    Ok(text.to_string())
}

fn store_status_at(
    storage: StatusStorage<'_>,
    window: Id,
    text: &str,
    at: IntervalValue,
) -> Result<CollectionCommit> {
    storage.publish(status_fragment(window, text, at), "status set")
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

fn preflight_legacy_status_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts.iter().filter(|fact| fact.a() == &status::text.id()) {
        let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
        let _: anybytes::View<str> = reader.get(handle).with_context(|| {
            format!(
                "strictly read legacy status::text payload {}",
                hex::encode_upper(handle.raw)
            )
        })?;
    }
    Ok(())
}

fn migrate_legacy(
    storage: StatusStorage<'_>,
    explicit_branch: Option<Id>,
) -> Result<collection_access::LegacyMigrationReport> {
    collection_access::migrate_legacy_simplearchive_branch(
        storage.pile,
        storage.key,
        storage.scope,
        LEGACY_STATUS_BRANCH_NAME,
        explicit_branch,
        preflight_legacy_status_payloads,
        |_, _| Ok(()),
    )
}

fn cmd_migrate_legacy(storage: StatusStorage<'_>, explicit_branch: Option<Id>) -> Result<()> {
    let report = migrate_legacy(storage, explicit_branch)?;
    println!(
        "migrated {} authored commit{} ({} facts); skipped {} contentless merge{}",
        report.commits.len(),
        if report.commits.len() == 1 { "" } else { "s" },
        report.facts,
        report.skipped_merges,
        if report.skipped_merges == 1 { "" } else { "s" },
    );
    println!("  legacy branch {}", report.branch_id);
    println!(
        "  legacy head   {}",
        report
            .head
            .map(|head| hex::encode_upper(head.raw))
            .unwrap_or_else(|| "<empty>".to_owned())
    );
    println!(
        "  retention     {} direct + {} recursive roots (verified, not persisted)",
        report.retention_direct, report.retention_recursive
    );
    println!("  legacy pin remains in place until recurring retention policy exists");
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
        Command::MigrateLegacy { legacy_branch_id } => {
            cmd_migrate_legacy(storage, legacy_branch_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    use ed25519_dalek::SigningKey;
    use triblespace::core::collection::{discover_collection_records, simplearchive_union};
    use triblespace::core::repo::{PinStore, Repository};

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

    fn legacy_pin(
        pile: &Path,
        branch: Id,
    ) -> Inline<inlineencodings::Handle<blobencodings::SimpleArchive>> {
        let mut pile_store = collection_access::open_pile_strict(pile).unwrap();
        let pin = pile_store.head(branch).unwrap().unwrap();
        pile_store.close().unwrap();
        pin
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
    fn equal_time_distinct_updates_are_reported_as_a_fork() {
        let window = test_id(0x84);
        let at = at_unix(30.0);
        let left = status_fragment(window, "left", at).into_facts();
        let right = status_fragment(window, "right", at).into_facts();
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
    fn legacy_migration_is_idempotent_and_preserves_pin_and_payload() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("legacy-status.pile");
        let key = directory.path().join("collection.key");
        File::create(&pile).unwrap();

        let pile_store = collection_access::open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            pile_store,
            SigningKey::from_bytes(&[0x85; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository
            .create_branch(LEGACY_STATUS_BRANCH_NAME, None)
            .unwrap();
        let expected = {
            let mut workspace = repository.pull(branch).unwrap();
            let text: TextHandle = workspace.put("legacy status".to_owned());
            let facts = entity! { _ @
                metadata::tag: &KIND_STATUS_UPDATE,
                status::window: test_id(0x86),
                status::text: text,
                metadata::created_at: at_unix(40.0),
            }
            .into_facts();
            workspace.commit(facts.clone(), "legacy status");
            repository.push(&mut workspace).unwrap();
            facts
        };
        repository.close().unwrap();
        collection_access::initialize_signer(&pile, Some(&key)).unwrap();
        let storage = StatusStorage {
            pile: &pile,
            key: Some(&key),
            scope: test_id(0x87),
        };
        let pin = legacy_pin(&pile, branch);

        let first = migrate_legacy(storage, None).unwrap();
        let length = std::fs::metadata(&pile).unwrap().len();
        let second = migrate_legacy(storage, Some(branch)).unwrap();

        assert_eq!(first.commits, second.commits);
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);
        assert_eq!(legacy_pin(&pile, branch), pin);
        let view = storage.view().unwrap();
        assert_eq!(view.facts, expected);
        preflight_legacy_status_payloads(&view.reader, &view.facts).unwrap();
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
