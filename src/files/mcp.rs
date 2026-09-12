//! Purpose-built Files MCP tools. No shell paths, stdin markers, or ambient
//! configuration are accepted as tool arguments.

use super::operations::{EmbeddingOptions, FetchOptions, Files as Operations, SimilarityOptions};
use super::presentation::ViewOptions;
use crate::mcp::{decode_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::Deserialize;
use std::path::PathBuf;

pub struct Files {
    operations: Operations,
}

impl Files {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }

    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            operations: Operations::with_storage(storage),
        }
    }
}

const ID_SCHEMA: &str = r#"{"type":"object","properties":{"id":{"type":"string","description":"Stored entity id, content hash, or unambiguous prefix"}},"required":["id"],"additionalProperties":false}"#;
const EMPTY_SCHEMA: &str = r#"{"type":"object","properties":{},"additionalProperties":false}"#;
const TOOLS: &[Tool] = &[
    Tool {
        name: "files_add",
        description: "Import a file from base64-encoded original bytes. Name is a leaf filename, never a server path. With local-embed builds, raster images also embed through nomic-vision into the shared 768-d text and image space and require the launcher-configured model/runtime.",
        input_schema: r#"{"type":"object","properties":{"data":{"type":"string","description":"Base64-encoded file bytes"},"name":{"type":"string"},"mime":{"type":"string"},"tags":{"type":"array","items":{"type":"string"},"default":[]}},"required":["data","name","mime"],"additionalProperties":false}"#,
    },
    Tool {
        name: "files_list",
        description: "List imported files, optionally filtered by tags and MIME prefix.",
        input_schema: r#"{"type":"object","properties":{"tags":{"type":"array","items":{"type":"string"},"default":[]},"mime":{"type":"string"}},"additionalProperties":false}"#,
    },
    Tool { name: "files_show", description: "Inspect metadata for a stored file, directory, or import.", input_schema: ID_SCHEMA },
    Tool {
        name: "files_view",
        description: "Present UTF-8 text, a still image, or accepted audio. Converts supported images to accepted PNG/JPEG, optionally resizing. Originals are unchanged; get retrieves exact bytes. Audio transcoding and PDF rendering are not supported.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string"},"accept":{"type":"array","items":{"type":"string"},"default":["text/*","image/png","image/jpeg","audio/*"]},"max_bytes":{"type":"integer","minimum":1,"default":4194304},"max_dimension":{"type":"integer","minimum":1}},"required":["id"],"additionalProperties":false}"#,
    },
    Tool { name: "files_get", description: "Return the original file bytes as an embedded binary resource. Never presents or converts content and never writes a server-local path. Directories require CLI extraction.", input_schema: ID_SCHEMA },
    Tool {
        name: "files_tag", description: "Add a tag to a stored file.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string"},"name":{"type":"string"}},"required":["id","name"],"additionalProperties":false}"#,
    },
    Tool {
        name: "files_fetch", description: "Fetch a URL and import its bytes as a file. With local-embed builds, raster images also embed through nomic-vision into the shared 768-d text and image space and require the launcher-configured model/runtime.",
        input_schema: r#"{"type":"object","properties":{"url":{"type":"string"},"mime":{"type":"string"},"name":{"type":"string"},"tags":{"type":"array","items":{"type":"string"},"default":[]},"max_bytes":{"type":"integer","minimum":1,"default":8388608}},"required":["url"],"additionalProperties":false}"#,
    },
    Tool {
        name: "files_search", description: "Search stored file names, media types, and tags.",
        input_schema: r#"{"type":"object","properties":{"query":{"type":"string"}},"required":["query"],"additionalProperties":false}"#,
    },
    Tool {
        name: "files_similar", description: "Semantic similarity search. Supply exactly one of id or text; requires a configured embedding model.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string"},"text":{"type":"string"},"floor":{"type":"number","minimum":0,"maximum":1,"default":0.15},"limit":{"type":"integer","minimum":0,"default":10},"tags":{"type":"array","items":{"type":"string"},"default":[]},"mm7b":{"type":"boolean","default":false}},"additionalProperties":false}"#,
    },
    Tool {
        name: "files_embed7b", description: "Compute stored image/PDF-page embeddings. Requires the local-embed build and a supported model/runtime.",
        input_schema: r#"{"type":"object","properties":{"force":{"type":"boolean","default":false},"pdf":{"type":"boolean","default":false},"dpi":{"type":"integer","minimum":1,"default":150},"limit":{"type":"integer","minimum":0,"default":0},"max_pages":{"type":"integer","minimum":0,"default":0}},"additionalProperties":false}"#,
    },
    Tool { name: "files_imports", description: "List stored imports.", input_schema: EMPTY_SCHEMA },
    Tool {
        name: "files_tree", description: "Inspect a stored directory or import tree.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string"},"depth":{"type":"integer","minimum":0}},"required":["id"],"additionalProperties":false}"#,
    },
    Tool {
        name: "files_resolve", description: "Resolve literal selectors in one collection view. Returns one result or diagnostic for each selector; never reads a local file or stdin.",
        input_schema: r#"{"type":"object","properties":{"selectors":{"type":"array","items":{"type":"string"}}},"required":["selectors"],"additionalProperties":false}"#,
    },
    Tool {
        name: "files_diff", description: "Compare stored files, directories, or imports.",
        input_schema: r#"{"type":"object","properties":{"left":{"type":"string"},"right":{"type":"string"}},"required":["left","right"],"additionalProperties":false}"#,
    },
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Id {
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Add {
    data: String,
    name: String,
    mime: String,
    #[serde(default)]
    tags: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    #[serde(default)]
    tags: Vec<String>,
    mime: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct View {
    id: String,
    accept: Option<Vec<String>>,
    #[serde(default = "view_budget")]
    max_bytes: usize,
    max_dimension: Option<u32>,
}
fn view_budget() -> usize {
    ViewOptions::default().max_bytes
}
fn fetch_budget() -> usize {
    8 * 1024 * 1024
}
fn similarity_floor() -> f32 {
    // Text-to-image matches in the nomic space sit near 0.06; a floor that
    // hides them hides the reason the space is shared.
    0.0
}
fn similarity_limit() -> usize {
    10
}
fn pdf_dpi() -> u32 {
    150
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tag {
    id: String,
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fetch {
    url: String,
    mime: Option<String>,
    name: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default = "fetch_budget")]
    max_bytes: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    query: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Similar {
    id: Option<String>,
    text: Option<String>,
    #[serde(default = "similarity_floor")]
    floor: f32,
    #[serde(default = "similarity_limit")]
    limit: usize,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    mm7b: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Embed {
    #[serde(default)]
    force: bool,
    #[serde(default)]
    pdf: bool,
    #[serde(default = "pdf_dpi")]
    dpi: u32,
    #[serde(default)]
    limit: usize,
    #[serde(default)]
    max_pages: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tree {
    id: String,
    depth: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolve {
    selectors: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Diff {
    left: String,
    right: String,
}

impl Faculty for Files {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        let files = &self.operations;
        match name {
            "files_add" => {
                let args: Add = decode_arguments(arguments)?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(args.data)
                    .context("file data must be base64")?;
                let id = files.add_bytes(bytes.into(), &args.name, &args.mime, &args.tags)?;
                out.line(format!("files:{id:x}"))
            }
            "files_list" => {
                let args: List = decode_arguments(arguments)?;
                out.text(files.list(&args.tags, args.mime.as_deref())?)
            }
            "files_show" => {
                let args: Id = decode_arguments(arguments)?;
                out.text(files.show(&args.id)?)
            }
            "files_view" => {
                let args: View = decode_arguments(arguments)?;
                let options = ViewOptions {
                    accept: args.accept.unwrap_or_else(|| ViewOptions::default().accept),
                    max_bytes: args.max_bytes,
                    max_dimension: args.max_dimension,
                };
                options.validate().map_err(crate::mcp::invalid_arguments)?;
                out.emit(files.view(&args.id, &options)?)
            }
            "files_get" => {
                let args: Id = decode_arguments(arguments)?;
                let export = files.get(&args.id)?;
                let uri = export.uri();
                out.blob(export.bytes, "application/octet-stream", uri)
            }
            "files_tag" => {
                let args: Tag = decode_arguments(arguments)?;
                files.tag(&args.id, &args.name, out)
            }
            "files_fetch" => {
                let args: Fetch = decode_arguments(arguments)?;
                files.fetch(
                    &FetchOptions {
                        url: &args.url,
                        mime: args.mime.as_deref(),
                        name: args.name.as_deref(),
                        tags: &args.tags,
                        max_bytes: args.max_bytes,
                    },
                    out,
                )
            }
            "files_search" => {
                let args: Search = decode_arguments(arguments)?;
                out.text(files.search(&args.query)?)
            }
            "files_similar" => {
                let args: Similar = decode_arguments(arguments)?;
                files.similar(
                    &SimilarityOptions {
                        id: args.id.as_deref(),
                        text: args.text.as_deref(),
                        floor: args.floor,
                        limit: args.limit,
                        tags: &args.tags,
                        mm7b: args.mm7b,
                    },
                    out,
                )
            }
            "files_embed7b" => {
                let args: Embed = decode_arguments(arguments)?;
                files.embed7b(
                    &EmbeddingOptions {
                        force: args.force,
                        pdf: args.pdf,
                        dpi: args.dpi,
                        limit: args.limit,
                        max_pages: args.max_pages,
                    },
                    out,
                )
            }
            "files_imports" => {
                let _: Empty = decode_arguments(arguments)?;
                out.text(files.imports()?)
            }
            "files_tree" => {
                let args: Tree = decode_arguments(arguments)?;
                out.text(files.tree(&args.id, args.depth)?)
            }
            "files_resolve" => {
                let args: Resolve = decode_arguments(arguments)?;
                for (selector, result) in args.selectors.iter().zip(files.resolve(&args.selectors)?)
                {
                    match result {
                        Ok(reference) => {
                            out.line(format!("{selector}\tfiles:{}", reference.hex()))?
                        }
                        Err(error) => out.line(format!("UNRESOLVED: {selector} — {error}"))?,
                    }
                }
                Ok(())
            }
            "files_diff" => {
                let args: Diff = decode_arguments(arguments)?;
                out.text(files.diff(&args.left, &args.right)?)
            }
            other => bail!("Files MCP has no tool {other:?}"),
        }
    }
}
