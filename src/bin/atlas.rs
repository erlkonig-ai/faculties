use std::cmp::Ordering;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::collection_access::{self, CollectionSnapshot, CollectionView};
use faculties::schemas::atlas::DEFAULT_SCOPE_ID;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::Handle;
use triblespace::prelude::*;

const LEGACY_ATLAS_BRANCH_NAME: &str = "atlas";

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "atlas", about = "Schema metadata inspection faculty")]
struct Cli {
    /// Path to the pile file to use.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Extrinsic collection scope for schema metadata. Defaults to the stable
    /// atlas scope declared by this faculty.
    #[arg(long, value_parser = parse_id_arg)]
    scope: Option<Id>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// List entities that have metadata::name entries.
    List,
    /// Show metadata for a single id prefix.
    Show { id: String },
    /// Publish the signed legacy `atlas` branch as collection commits, then
    /// verify the exact materialized view. Stop every legacy atlas writer and
    /// every collection-native writer using the same target scope before
    /// running this command. It never removes the legacy pin.
    MigrateLegacy {
        /// Exact legacy atlas branch id. Needed only when duplicate `atlas`
        /// branch names make name lookup ambiguous.
        #[arg(long, value_parser = parse_id_arg)]
        legacy_branch_id: Option<Id>,
    },
}

#[derive(Clone)]
struct MetaRow {
    id: Id,
    name: String,
    description: Option<String>,
    source_module: Option<String>,
    tags: Vec<Id>,
    grouped_by: Vec<Id>,
}

fn main() -> Result<()> {
    let Cli {
        pile,
        key,
        scope,
        command,
    } = Cli::parse();
    let Some(cmd) = command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    let storage = AtlasStorage {
        pile: &pile,
        key: key.as_deref(),
        scope: scope.unwrap_or(DEFAULT_SCOPE_ID),
    };

    match cmd {
        Command::List => cmd_list(storage),
        Command::Show { id } => cmd_show(storage, &id),
        Command::MigrateLegacy { legacy_branch_id } => {
            cmd_migrate_legacy(storage, legacy_branch_id)
        }
    }
}

#[derive(Clone, Copy)]
struct AtlasStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    scope: Id,
}

impl AtlasStorage<'_> {
    fn view(&self) -> Result<CollectionView> {
        let signer = collection_access::load_signer(self.pile, self.key)?;
        let allowed = HashSet::from([signer.verifying_key()]);
        CollectionSnapshot::open(self.pile)?.materialize_scope(self.scope, &allowed)
    }
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
}

fn cmd_list(storage: AtlasStorage<'_>) -> Result<()> {
    let view = storage.view()?;
    let mut rows = collect_rows(&view.reader, &view.facts)?;
    rows.sort_by(|a, b| match a.name.cmp(&b.name) {
        Ordering::Equal => format!("{:x}", a.id).cmp(&format!("{:x}", b.id)),
        other => other,
    });

    for row in rows {
        let short_id = fmt_id(row.id);
        let tags = if row.tags.is_empty() {
            String::new()
        } else {
            format!(
                " [tags: {}]",
                row.tags
                    .iter()
                    .map(|id| fmt_id(*id))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let grouped_by = if row.grouped_by.is_empty() {
            String::new()
        } else {
            format!(
                " [groups: {}]",
                row.grouped_by
                    .iter()
                    .map(|id| fmt_id(*id))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let description = row
            .description
            .map(|d| format!(" - {d}"))
            .unwrap_or_default();
        let source_module = row
            .source_module
            .map(|m| format!(" @{m}"))
            .unwrap_or_default();
        println!(
            "{short_id} {name}{source_module}{tags}{grouped_by}{description}",
            name = row.name
        );
    }
    Ok(())
}

fn cmd_show(storage: AtlasStorage<'_>, prefix: &str) -> Result<()> {
    let view = storage.view()?;
    let rows = collect_rows(&view.reader, &view.facts)?;
    let row = resolve_prefix(rows, prefix)?;

    println!("id: {:x}", row.id);
    println!("name: {}", row.name);
    if let Some(description) = row.description {
        println!("description: {description}");
    }
    if let Some(source_module) = row.source_module {
        println!("source_module: {source_module}");
    }
    if !row.tags.is_empty() {
        let tags = row
            .tags
            .iter()
            .map(|id| format!("{id:x}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("tags: {tags}");
    }
    if !row.grouped_by.is_empty() {
        let groups = row
            .grouped_by
            .iter()
            .map(|id| format!("{id:x}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("grouped_by: {groups}");
    }
    Ok(())
}

fn collect_rows(reader: &PileReader, space: &TribleSet) -> Result<Vec<MetaRow>> {
    let mut rows = Vec::new();
    for (id, handle) in find!(
        (id: Id, handle: Inline<Handle<LongString>>),
        pattern!(space, [{ ?id @ metadata::name: ?handle }])
    ) {
        let name: View<str> = reader.get(handle).context("read name")?;
        let description = match find!(
            (handle: Inline<Handle<LongString>>),
            pattern!(space, [{ id @ metadata::description: ?handle }])
        )
        .into_iter()
        .next()
        {
            Some((handle,)) => {
                let view: View<str> = reader.get(handle).context("read description")?;
                Some(view.to_string())
            }
            None => None,
        };
        let source_module_value = match find!(
            (handle: Inline<Handle<LongString>>),
            pattern!(space, [{ id @ metadata::source_module: ?handle }])
        )
        .into_iter()
        .next()
        {
            Some((handle,)) => {
                let view: View<str> = reader.get(handle).context("read source module")?;
                Some(view.to_string())
            }
            None => None,
        };

        let mut tags = find!(
            (tag: Id),
            pattern!(space, [{ id @ metadata::tag: ?tag }])
        )
        .into_iter()
        .map(|(tag,)| tag)
        .collect::<Vec<_>>();
        tags.sort();
        tags.dedup();

        let mut grouped_by = find!(
            (group: Id),
            pattern!(space, [{ ?group @ metadata::tag: id }])
        )
        .into_iter()
        .map(|(group,)| group)
        .collect::<Vec<_>>();
        grouped_by.sort();
        grouped_by.dedup();

        rows.push(MetaRow {
            id,
            name: name.to_string(),
            description,
            source_module: source_module_value,
            tags,
            grouped_by,
        });
    }
    Ok(rows)
}

fn resolve_prefix(rows: Vec<MetaRow>, prefix: &str) -> Result<MetaRow> {
    let prefix = prefix.trim().to_lowercase();
    if prefix.is_empty() {
        bail!("id prefix is empty");
    }
    let mut matches = Vec::new();
    for row in rows {
        let hex = format!("{:x}", row.id);
        if hex.starts_with(&prefix) {
            matches.push(row);
        }
    }
    match matches.len() {
        0 => bail!("no id matches prefix '{prefix}'"),
        1 => Ok(matches.remove(0)),
        _ => bail!("multiple ids match prefix '{prefix}'"),
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn preflight_legacy_atlas_payloads(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    for fact in facts.iter() {
        let text_field = if fact.a() == &metadata::name.id() {
            Some("metadata::name")
        } else if fact.a() == &metadata::description.id() {
            Some("metadata::description")
        } else if fact.a() == &metadata::iri.id() {
            Some("metadata::iri")
        } else if fact.a() == &metadata::source.id() {
            Some("metadata::source")
        } else if fact.a() == &metadata::source_module.id() {
            Some("metadata::source_module")
        } else {
            None
        };
        if let Some(field) = text_field {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
            let _: View<str> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy atlas {field} payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
            continue;
        }

        if fact.a() == &metadata::value_formatter.id() {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::WasmCode>>();
            let _: Blob<blobencodings::WasmCode> = reader.get(handle).with_context(|| {
                format!(
                    "strictly read legacy atlas metadata::value_formatter payload {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
    }
    Ok(())
}

fn migrate_legacy(
    storage: AtlasStorage<'_>,
    explicit_branch: Option<Id>,
) -> Result<collection_access::LegacyMigrationReport> {
    collection_access::migrate_legacy_simplearchive_branch(
        storage.pile,
        storage.key,
        storage.scope,
        LEGACY_ATLAS_BRANCH_NAME,
        explicit_branch,
        preflight_legacy_atlas_payloads,
    )
}

fn cmd_migrate_legacy(storage: AtlasStorage<'_>, explicit_branch: Option<Id>) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use std::fs::File;
    use triblespace::core::collection::{discover_collection_records, simplearchive_union};
    use triblespace::core::repo::Repository;

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn fresh_storage(directory: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        let pile = directory.path().join("atlas.pile");
        let key = directory.path().join("atlas.key");
        File::create(&pile).unwrap();
        collection_access::initialize_signer(&pile, Some(&key)).unwrap();
        (pile, key)
    }

    fn atlas_fragment(entity: Id) -> Fragment {
        let mut fragment = Fragment::empty();
        let name: Inline<Handle<blobencodings::LongString>> =
            fragment.put("Fixture attribute".to_owned());
        let description: Inline<Handle<blobencodings::LongString>> =
            fragment.put("Fixture description".to_owned());
        let source_module: Inline<Handle<blobencodings::LongString>> =
            fragment.put("fixture::schema".to_owned());
        let formatter: Inline<Handle<blobencodings::WasmCode>> =
            fragment.put(vec![0x00, 0x61, 0x73, 0x6d]);
        fragment += entity! { ExclusiveId::force_ref(&entity) @
            metadata::name: name,
            metadata::description: description,
            metadata::source_module: source_module,
            metadata::value_formatter: formatter,
            metadata::tag: &metadata::KIND_ATTRIBUTE_USAGE,
        };
        fragment
    }

    fn pin_head(pile_path: &Path, branch: Id) -> Inline<Handle<blobencodings::SimpleArchive>> {
        let mut pile = collection_access::open_pile_strict(pile_path).unwrap();
        let head = pile.head(branch).unwrap().unwrap();
        pile.close().unwrap();
        head
    }

    #[test]
    fn collection_read_is_immutable_and_uses_snapshot_attachment_reader() {
        let directory = tempfile::tempdir().unwrap();
        let scope = test_id(0x41);
        let (pile, key) = fresh_storage(&directory);
        let entity = test_id(0x42);
        let fragment = atlas_fragment(entity);
        collection_access::publish_fragment(&pile, Some(&key), scope, fragment, Fragment::empty())
            .unwrap();
        let length = std::fs::metadata(&pile).unwrap().len();
        let storage = AtlasStorage {
            pile: &pile,
            key: Some(&key),
            scope,
        };

        let view = storage.view().unwrap();
        let rows = collect_rows(&view.reader, &view.facts).unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, entity);
        assert_eq!(rows[0].name, "Fixture attribute");
        preflight_legacy_atlas_payloads(&view.reader, &view.facts).unwrap();
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);
    }

    #[test]
    fn legacy_migration_is_idempotent_and_preserves_the_pin() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("legacy-atlas.pile");
        let key = directory.path().join("collection.key");
        File::create(&pile).unwrap();

        let legacy_pile = collection_access::open_pile_strict(&pile).unwrap();
        let mut repository = Repository::new(
            legacy_pile,
            SigningKey::from_bytes(&[0x35; 32]),
            Fragment::empty(),
        )
        .unwrap();
        let branch = *repository
            .create_branch(LEGACY_ATLAS_BRANCH_NAME, None)
            .unwrap();
        let content = atlas_fragment(test_id(0x43));
        let expected = content.facts().clone();
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(content, "legacy atlas snapshot");
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
        collection_access::initialize_signer(&pile, Some(&key)).unwrap();

        let scope = test_id(0x44);
        let storage = AtlasStorage {
            pile: &pile,
            key: Some(&key),
            scope,
        };
        let legacy_pin = pin_head(&pile, branch);

        let first = migrate_legacy(storage, None).unwrap();
        let length = std::fs::metadata(&pile).unwrap().len();
        let second = migrate_legacy(storage, Some(branch)).unwrap();

        assert_eq!(first.commits.len(), 1);
        assert_eq!(first.commits, second.commits);
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);
        assert_eq!(pin_head(&pile, branch), legacy_pin);
        let view = storage.view().unwrap();
        assert_eq!(view.facts, expected);
        preflight_legacy_atlas_payloads(&view.reader, &view.facts).unwrap();

        let signer = collection_access::load_signer(&pile, Some(&key)).unwrap();
        let definition = simplearchive_union::definition(scope);
        let mut opened = collection_access::open_pile_strict(&pile).unwrap();
        let reader = opened.reader().unwrap();
        opened.close().unwrap();
        let records = discover_collection_records(&reader).unwrap();
        let commits: Vec<_> = records
            .commits()
            .iter()
            .filter(|commit| commit.collection() == definition.id())
            .filter(|commit| commit.public_key().raw == signer.verifying_key().to_bytes())
            .collect();
        assert_eq!(commits.len(), 1);
    }

    #[test]
    fn legacy_preflight_checks_text_and_wasm_payloads() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("validator.pile");
        File::create(&pile).unwrap();
        let mut opened = collection_access::open_pile_strict(&pile).unwrap();
        let reader = opened.reader().unwrap();
        opened.close().unwrap();

        let missing_text: Inline<Handle<blobencodings::LongString>> = Inline::new([0x91; 32]);
        let missing_wasm: Inline<Handle<blobencodings::WasmCode>> = Inline::new([0x92; 32]);
        let cases = [
            (
                entity! { metadata::name: missing_text }.into_facts(),
                "metadata::name",
            ),
            (
                entity! { metadata::description: missing_text }.into_facts(),
                "metadata::description",
            ),
            (
                entity! { metadata::iri: missing_text }.into_facts(),
                "metadata::iri",
            ),
            (
                entity! { metadata::source: missing_text }.into_facts(),
                "metadata::source",
            ),
            (
                entity! { metadata::source_module: missing_text }.into_facts(),
                "metadata::source_module",
            ),
            (
                entity! { metadata::value_formatter: missing_wasm }.into_facts(),
                "metadata::value_formatter",
            ),
        ];

        for (facts, field) in cases {
            let error = preflight_legacy_atlas_payloads(&reader, &facts).unwrap_err();
            assert!(
                format!("{error:#}").contains(field),
                "missing diagnostic for {field}: {error:#}"
            );
        }
    }
}
