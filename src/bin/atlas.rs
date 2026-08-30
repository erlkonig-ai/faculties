use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey;
use faculties::atlas::{self, AtlasCatalog, AtlasEntry};
use faculties::legacy_hint::open_scope;
use faculties::out::Out;
use faculties::schemas::atlas::DEFAULT_SCOPE_ID;
use faculties::spec::{CliRequest, Faculty, Invocation, Param, Spec, Verb};
use faculties::storage::{load_signer, open_pile_strict};
use triblespace::core::collection::CollectionStoreExt;
use triblespace::core::repo::pile::Pile;
use triblespace::prelude::Id;

const SHARED: &[Param] = &[
    Param::caller("pile", "Path to the pile file to use")
        .ambient()
        .env("PILE"),
    Param::caller(
        "key",
        "Existing durable signing-key file. Reads and writes never create it.",
    )
    .ambient()
    .optional()
    .env("TRIBLESPACE_KEY"),
];

const VERBS: &[Verb] = &[
    Verb {
        name: "list",
        about: "List entities that have metadata::name entries",
        params: &[],
    },
    Verb {
        name: "show",
        about: "Show metadata for a single id prefix",
        params: &[Param::caller("id", "Entity id or unique prefix").positional()],
    },
];

static ATLAS_SPEC: Spec = Spec {
    name: "atlas",
    about: "Schema metadata inspection faculty",
    version: Some(faculties::GIT_VERSION),
    shared: SHARED,
    verbs: VERBS,
};

static ATLAS: Faculty<AtlasContext> = Faculty::new(&ATLAS_SPEC, handle);

struct AtlasContext {
    pile: Pile,
    signer: SigningKey,
}

impl AtlasContext {
    fn open(pile_path: &Path, key_path: Option<&Path>) -> Result<Self> {
        let signer = load_signer(pile_path, key_path)?;
        let pile = open_pile_strict(pile_path)?;
        Ok(Self { pile, signer })
    }

    fn with_catalog<T>(&mut self, operation: impl FnOnce(&AtlasCatalog) -> Result<T>) -> Result<T> {
        let collection = open_scope(&mut self.pile, DEFAULT_SCOPE_ID, &self.signer)?;
        let snapshot = self
            .pile
            .snapshot(collection)
            .context("materialize native Atlas collection")?;
        let (facts, _, reader) = snapshot.into_parts();
        let catalog =
            atlas::load_catalog(&reader, &facts).context("validate native Atlas catalog")?;
        operation(&catalog)
    }

    fn finish<T>(self, result: Result<T>) -> Result<T> {
        match (result, self.pile.close()) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(anyhow!("close Atlas pile: {error}")),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(close_error)) => {
                Err(error.context(format!("closing Atlas pile also failed: {close_error}")))
            }
        }
    }
}

fn main() -> Result<()> {
    let request = ATLAS_SPEC
        .lower_cli_from(std::env::args_os())
        .unwrap_or_else(|error| error.exit());
    match request {
        CliRequest::Help(help) => print!("{help}"),
        CliRequest::Invoke(invocation) => print!("{}", execute(&invocation)?.render()),
    }
    Ok(())
}

fn execute(invocation: &Invocation) -> Result<Out> {
    let pile_path = Path::new(invocation.require("pile")?);
    let key_path = invocation.get("key").map(Path::new);
    let mut context = AtlasContext::open(pile_path, key_path)?;
    let result = ATLAS.invoke(&mut context, invocation);
    context.finish(result)
}

fn handle(context: &mut AtlasContext, invocation: &Invocation, output: &mut Out) -> Result<()> {
    match invocation.verb().name {
        "list" => list(context, output),
        "show" => show(context, invocation.require("id")?, output),
        other => bail!("Atlas handler has no verb {other:?}"),
    }
}

fn list(context: &mut AtlasContext, output: &mut Out) -> Result<()> {
    context.with_catalog(|catalog| {
        let mut rows = catalog.entries().collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.names
                .cmp(&right.names)
                .then_with(|| left.id.cmp(&right.id))
        });

        for row in rows {
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
            let grouped_by = if row.members.is_empty() {
                String::new()
            } else {
                format!(
                    " [groups: {}]",
                    row.members
                        .iter()
                        .map(|id| fmt_id(*id))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            let description = (!row.descriptions.is_empty())
                .then(|| format!(" - {}", row.descriptions.join(" / ")))
                .unwrap_or_default();
            let source_module = (!row.source_modules.is_empty())
                .then(|| format!(" @{}", row.source_modules.join(" / ")))
                .unwrap_or_default();
            let variants = (row.names.len() > 1)
                .then(|| format!(" [{} name variants]", row.names.len()))
                .unwrap_or_default();
            output.line(format!(
                "{id} {name}{variants}{source_module}{tags}{grouped_by}{description}",
                id = fmt_id(row.id),
                name = row.names_label(),
            ));
        }
        Ok(())
    })
}

fn show(context: &mut AtlasContext, prefix: &str, output: &mut Out) -> Result<()> {
    context.with_catalog(|catalog| {
        let row = resolve_prefix(catalog, prefix)?;

        output.line(format!("id: {:x}", row.id));
        for name in &row.names {
            output.line(format!("name: {name}"));
        }
        for description in &row.descriptions {
            output.line(format!("description: {description}"));
        }
        for source_module in &row.source_modules {
            output.line(format!("source_module: {source_module}"));
        }
        if !row.tags.is_empty() {
            output.line(format!(
                "tags: {}",
                row.tags
                    .iter()
                    .map(|id| format!("{id:x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !row.members.is_empty() {
            output.line(format!(
                "grouped_by: {}",
                row.members
                    .iter()
                    .map(|id| format!("{id:x}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        Ok(())
    })
}

fn resolve_prefix<'a>(catalog: &'a AtlasCatalog, prefix: &str) -> Result<&'a AtlasEntry> {
    let prefix = prefix.trim().to_lowercase();
    if prefix.is_empty() {
        bail!("id prefix is empty");
    }
    let mut matches = catalog
        .entries()
        .filter(|entry| format!("{:x}", entry.id).starts_with(&prefix));
    match (matches.next(), matches.next()) {
        (None, _) => bail!("no id matches prefix '{prefix}'"),
        (Some(entry), None) => Ok(entry),
        (Some(_), Some(_)) => bail!("multiple ids match prefix '{prefix}'"),
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use faculties::spec::Arguments;
    use faculties::storage::{initialize_signer, publish_fragment};
    use triblespace::core::metadata;
    use triblespace::prelude::*;

    use super::*;

    #[test]
    fn generated_cli_retains_the_atlas_surface() {
        let command = ATLAS_SPEC.to_clap();
        assert_eq!(command.get_version(), Some(faculties::GIT_VERSION));
        assert_eq!(
            command
                .get_subcommands()
                .map(|command| command.get_name())
                .collect::<Vec<_>>(),
            ["list", "show"]
        );
        for forbidden in ["scope", "branch", "branch_id", "head", "repair"] {
            assert!(!command
                .get_arguments()
                .any(|argument| argument.get_id() == forbidden));
        }
        assert!(command
            .get_arguments()
            .any(|argument| argument.get_id() == "key"));
    }

    #[test]
    fn generated_cli_and_mcp_share_the_native_atlas_handler() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("atlas.pile");
        let key = directory.path().join("atlas.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();

        let id = Id::new([0x41; 16]).unwrap();
        let mut fragment = Fragment::empty();
        let name = fragment.put::<blobencodings::UTF8String, _>("Alpha".to_owned());
        fragment += entity! { ExclusiveId::force_ref(&id) @ metadata::name: name };
        publish_fragment(&pile, Some(&key), DEFAULT_SCOPE_ID, fragment).unwrap();
        let before_reads = std::fs::metadata(&pile).unwrap().len();
        let id = format!("{id:x}");

        let list = ATLAS_SPEC
            .lower_cli_from([
                "atlas",
                "--pile",
                pile.to_str().unwrap(),
                "--key",
                key.to_str().unwrap(),
                "list",
            ])
            .unwrap();
        let CliRequest::Invoke(list) = list else {
            panic!("expected list invocation")
        };
        assert_eq!(execute(&list).unwrap().render(), format!("{id} Alpha\n"));

        let cli = ATLAS_SPEC
            .lower_cli_from([
                "atlas",
                "--pile",
                pile.to_str().unwrap(),
                "--key",
                key.to_str().unwrap(),
                "show",
                &id,
            ])
            .unwrap();
        let CliRequest::Invoke(cli) = cli else {
            panic!("expected show invocation")
        };
        let cli_output = execute(&cli).unwrap();

        let mcp = ATLAS_SPEC
            .lower_mcp(
                "atlas_show",
                Arguments::new().with("id", id),
                Arguments::new()
                    .with("pile", pile.to_string_lossy())
                    .with("key", key.to_string_lossy()),
            )
            .unwrap();
        let mcp_output = execute(&mcp).unwrap();

        assert_eq!(cli_output, mcp_output);
        assert_eq!(cli_output.lines()[1], "name: Alpha");
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), before_reads);

        let show = ATLAS_SPEC
            .mcp_tools()
            .into_iter()
            .find(|tool| tool.name == "atlas_show")
            .unwrap();
        assert_eq!(show.parameters.len(), 1);
        assert_eq!(show.parameters[0].name, "id");
    }
}
