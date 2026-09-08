//! Explicit resident Wiki MCP tools. Caller content is literal, never @file or
//! stdin syntax. Pile/key configuration belongs to the trusted launcher.
//!
//! This is a local faculty adapter, not a hosted execution sandbox. Create/edit
//! retain normal Typst validation (a world which rejects external files), and
//! embedding tools use a configured local model. Untrusted hosted deployments
//! still need independent CPU/memory limits and model-execution policy.

use std::path::PathBuf;

use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use triblespace::prelude::Id;

use super::operations::{ImportDocument, ListOptions, Wiki as Operations};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;

pub struct Wiki {
    operations: Operations,
}

impl Wiki {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self {
            operations: Operations::new(pile, key),
        }
    }
}

const EMPTY: &str = r#"{"type":"object","properties":{},"additionalProperties":false}"#;
const ID: &str = r#"{"type":"object","properties":{"id":{"type":"string","description":"Revision id or unambiguous prefix"}},"required":["id"],"additionalProperties":false}"#;
const READ: &str = r#"{"type":"object","properties":{"id":{"type":"string"},"exact":{"type":"boolean","default":false}},"required":["id"],"additionalProperties":false}"#;
const TAG: &str = r#"{"type":"object","properties":{"id":{"type":"string"},"name":{"type":"string"}},"required":["id","name"],"additionalProperties":false}"#;
const TOOLS: &[Tool] = &[
    Tool { name: "wiki_create", description: "Create a revision from literal title/content and optional tags. Performs normal Typst/link validation; content is not a host path.", input_schema: r#"{"type":"object","properties":{"title":{"type":"string"},"content":{"type":"string"},"tags":{"type":"array","items":{"type":"string"},"default":[]},"force":{"type":"boolean","default":false}},"required":["title","content"],"additionalProperties":false}"# },
    Tool { name: "wiki_edit", description: "Join the complete current frontier with a successor. Omitted fields inherit only when the frontier agrees; tags omitted or empty inherit existing tags. Content is literal and validated.", input_schema: r#"{"type":"object","properties":{"id":{"type":"string"},"content":{"type":"string"},"title":{"type":"string"},"tags":{"type":"array","items":{"type":"string"},"default":[]},"force":{"type":"boolean","default":false}},"required":["id"],"additionalProperties":false}"# },
    Tool { name: "wiki_show", description: "Display the current frontier, including every fork head. exact=true pins the named immutable revision.", input_schema: READ },
    Tool { name: "wiki_export", description: "Export exact stored UTF-8 content bytes as a binary resource, without headers or added newlines. Follows the current frontier unless exact=true; an unresolved fork is an error. Never writes a host path.", input_schema: READ },
    Tool { name: "wiki_diff", description: "Compare revisions at one-based causal-history positions; defaults to the last two.", input_schema: r#"{"type":"object","properties":{"id":{"type":"string"},"from":{"type":"integer","minimum":1},"to":{"type":"integer","minimum":1}},"required":["id"],"additionalProperties":false}"# },
    Tool { name: "wiki_archive", description: "Publish an archived-tag successor without deleting history.", input_schema: ID },
    Tool { name: "wiki_restore", description: "Publish a successor without the archived tag.", input_schema: ID },
    Tool { name: "wiki_revert", description: "Publish a successor using a one-based historical revision; never rewrites old content.", input_schema: r#"{"type":"object","properties":{"id":{"type":"string"},"to":{"type":"integer","minimum":1}},"required":["id","to"],"additionalProperties":false}"# },
    Tool { name: "wiki_links", description: "Inspect one entry's citations or audit all frontier links. strict reports archived-target breakage as an error; unwritten targets are forward references.", input_schema: r#"{"type":"object","properties":{"id":{"type":"string"},"top":{"type":"integer","minimum":0,"default":15},"strict":{"type":"boolean","default":false}},"additionalProperties":false}"# },
    Tool { name: "wiki_list", description: "List current entries with optional tag/backlink filters; all includes archived entries.", input_schema: r#"{"type":"object","properties":{"tags":{"type":"array","items":{"type":"string"},"default":[]},"with_backlink_tag":{"type":"array","items":{"type":"string"},"default":[]},"without_backlink_tag":{"type":"array","items":{"type":"string"},"default":[]},"with_backlink_type":{"type":"array","items":{"type":"string"},"default":[]},"without_backlink_type":{"type":"array","items":{"type":"string"},"default":[]},"all":{"type":"boolean","default":false}},"additionalProperties":false}"# },
    Tool { name: "wiki_history", description: "Inspect causal revision history with all predecessor/frontier identities.", input_schema: ID },
    Tool { name: "wiki_tag_add", description: "Add a tag by publishing a successor when necessary.", input_schema: TAG },
    Tool { name: "wiki_tag_remove", description: "Remove a tag by publishing a successor when necessary.", input_schema: TAG },
    Tool { name: "wiki_tag_list", description: "List known tags and revision counts.", input_schema: EMPTY },
    Tool { name: "wiki_tag_mint", description: "Create or find a content-derived named tag and return its ID.", input_schema: r#"{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}"# },
    Tool { name: "wiki_search", description: "Search current revision titles/content with optional matching-line context.", input_schema: r#"{"type":"object","properties":{"query":{"type":"string"},"context":{"type":"boolean","default":false},"all":{"type":"boolean","default":false}},"required":["query"],"additionalProperties":false}"# },
    Tool { name: "wiki_embed", description: "Compute missing current-revision embeddings with the configured local model; requires local-embed support and local execution resources.", input_schema: EMPTY },
    Tool { name: "wiki_similar", description: "Find semantically similar current revisions using the configured local embedding model.", input_schema: r#"{"type":"object","properties":{"query":{"type":"string"}},"required":["query"],"additionalProperties":false}"# },
    Tool { name: "wiki_check", description: "Report live-frontier link integrity without requesting optional whole-corpus Typst compilation.", input_schema: EMPTY },
    Tool { name: "wiki_lint", description: "Report markup/reference normalization; fix publishes successors, check returns an error if changes are needed. Exact revision citations remain pinned.", input_schema: r#"{"type":"object","properties":{"fix":{"type":"boolean","default":false},"check":{"type":"boolean","default":false}},"additionalProperties":false}"# },
    Tool { name: "wiki_fix_truncated", description: "Resolve literal scheme:prefix lines and report expansions/errors. Does not read a local file or stdin and does not edit stored content.", input_schema: r#"{"type":"object","properties":{"input":{"type":"string"}},"required":["input"],"additionalProperties":false}"# },
    Tool { name: "wiki_import", description: "Import resident text documents in one publication. Titles are fallback labels, not paths; a Typst '= ' heading takes precedence. Validates content and permits forward references.", input_schema: r#"{"type":"object","properties":{"documents":{"type":"array","items":{"type":"object","properties":{"title":{"type":"string"},"content":{"type":"string"}},"required":["title","content"],"additionalProperties":false}},"tags":{"type":"array","items":{"type":"string"},"default":[]}},"required":["documents"],"additionalProperties":false}"# },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Read {
    id: String,
    #[serde(default)]
    exact: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    title: String,
    content: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    force: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit {
    id: String,
    content: Option<String>,
    title: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    force: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Diff {
    id: String,
    from: Option<usize>,
    to: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revert {
    id: String,
    to: usize,
}
fn default_top() -> usize {
    15
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Links {
    id: Option<String>,
    #[serde(default = "default_top")]
    top: usize,
    #[serde(default)]
    strict: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    with_backlink_tag: Vec<String>,
    #[serde(default)]
    without_backlink_tag: Vec<String>,
    #[serde(default)]
    with_backlink_type: Vec<String>,
    #[serde(default)]
    without_backlink_type: Vec<String>,
    #[serde(default)]
    all: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tag {
    id: String,
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Name {
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    query: String,
    #[serde(default)]
    context: bool,
    #[serde(default)]
    all: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    query: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lint {
    #[serde(default)]
    fix: bool,
    #[serde(default)]
    check: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    input: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    title: String,
    content: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    #[serde(deserialize_with = "crate::mcp::object::vec")]
    documents: Vec<Document>,
    #[serde(default)]
    tags: Vec<String>,
}

fn revision(out: &mut Out<'_>, id: Id) -> Result<()> {
    out.line(format!("revision {id:x}"))
}
fn tag_change(out: &mut Out<'_>, id: Option<Id>, name: &str, add: bool) -> Result<()> {
    match id {
        Some(id) => revision(out, id),
        None => out.line(format!(
            "already {} #{}",
            if add { "tagged" } else { "untagged" },
            name.trim().to_ascii_lowercase()
        )),
    }
}

impl Faculty for Wiki {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        let wiki = &self.operations;
        match name {
            "wiki_create" => {
                let args: Create = decode_arguments(arguments)?;
                revision(
                    out,
                    wiki.create(&args.title, &args.content, &args.tags, args.force)?,
                )
            }
            "wiki_edit" => {
                let args: Edit = decode_arguments(arguments)?;
                revision(
                    out,
                    wiki.edit(
                        &args.id,
                        args.content.as_deref(),
                        args.title.as_deref(),
                        &args.tags,
                        args.force,
                    )?,
                )
            }
            "wiki_show" => {
                let args: Read = decode_arguments(arguments)?;
                out.text(wiki.show(&args.id, args.exact)?)
            }
            "wiki_export" => {
                let args: Read = decode_arguments(arguments)?;
                let export = wiki.export(&args.id, args.exact)?;
                let uri = export.uri();
                out.blob(export.bytes, "text/plain; charset=utf-8", uri)
            }
            "wiki_diff" => {
                let args: Diff = decode_arguments(arguments)?;
                if args.from == Some(0) || args.to == Some(0) {
                    return Err(invalid_arguments("revision positions are one-based"));
                }
                out.text(wiki.diff(&args.id, args.from, args.to)?)
            }
            "wiki_archive" => {
                let args: Selector = decode_arguments(arguments)?;
                tag_change(out, wiki.archive(&args.id)?, "archived", true)
            }
            "wiki_restore" => {
                let args: Selector = decode_arguments(arguments)?;
                tag_change(out, wiki.restore(&args.id)?, "archived", false)
            }
            "wiki_revert" => {
                let args: Revert = decode_arguments(arguments)?;
                if args.to == 0 {
                    return Err(invalid_arguments("revision positions are one-based"));
                }
                revision(out, wiki.revert(&args.id, args.to)?)
            }
            "wiki_links" => {
                let args: Links = decode_arguments(arguments)?;
                wiki.links(args.id.as_deref(), args.top, args.strict, out)
            }
            "wiki_list" => {
                let args: List = decode_arguments(arguments)?;
                out.text(wiki.list(&ListOptions {
                    tags: args.tags,
                    with_backlink_tag: args.with_backlink_tag,
                    without_backlink_tag: args.without_backlink_tag,
                    with_backlink_type: args.with_backlink_type,
                    without_backlink_type: args.without_backlink_type,
                    all: args.all,
                })?)
            }
            "wiki_history" => {
                let args: Selector = decode_arguments(arguments)?;
                out.text(wiki.history(&args.id)?)
            }
            "wiki_tag_add" | "wiki_tag_remove" => {
                let args: Tag = decode_arguments(arguments)?;
                let add = name == "wiki_tag_add";
                tag_change(out, wiki.tag(&args.id, &args.name, add)?, &args.name, add)
            }
            "wiki_tag_list" => {
                let _: Empty = decode_arguments(arguments)?;
                wiki.tags(out)
            }
            "wiki_tag_mint" => {
                let args: Name = decode_arguments(arguments)?;
                out.line(format!(
                    "{:x}  {}",
                    wiki.mint_tag(&args.name)?,
                    args.name.trim().to_ascii_lowercase()
                ))
            }
            "wiki_search" => {
                let args: Search = decode_arguments(arguments)?;
                out.text(wiki.search(&args.query, args.context, args.all)?)
            }
            "wiki_embed" => {
                let _: Empty = decode_arguments(arguments)?;
                wiki.embed(out)
            }
            "wiki_similar" => {
                let args: Query = decode_arguments(arguments)?;
                out.text(wiki.similar(&args.query)?)
            }
            "wiki_check" => {
                let _: Empty = decode_arguments(arguments)?;
                wiki.check(false, out)
            }
            "wiki_lint" => {
                let args: Lint = decode_arguments(arguments)?;
                wiki.lint(args.fix, args.check, out)
            }
            "wiki_fix_truncated" => {
                let args: Input = decode_arguments(arguments)?;
                wiki.fix_truncated(&args.input, out)
            }
            "wiki_import" => {
                let args: Import = decode_arguments(arguments)?;
                let documents = args
                    .documents
                    .into_iter()
                    .map(|document| ImportDocument {
                        title: document.title,
                        content: document.content,
                    })
                    .collect();
                for id in wiki.import_texts(documents, &args.tags)? {
                    revision(out, id)?;
                }
                Ok(())
            }
            _ => bail!("unknown Wiki MCP tool {name:?}"),
        }
    }
}
