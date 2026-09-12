//! Files command-line UX. Paths, shell conventions, and Drive selection live here.

use super::operations::{EmbeddingOptions, FetchOptions, Files, SimilarityOptions};
use super::presentation::ViewOptions;
use crate::out::Out;
use crate::spec::{Invocation, Param, Spec, Verb};
use anyhow::{bail, Context, Result};
use std::path::Path;

const SHARED: &[Param] = &[
    Param::caller("pile", "Path to the pile file")
        .path()
        .ambient()
        .env("PILE"),
    Param::caller(
        "key",
        "Existing durable signing-key file; never created by commands",
    )
    .path()
    .ambient()
    .optional()
    .env("TRIBLESPACE_KEY"),
];

const VERBS: &[Verb] = &[
    Verb {
        name: "add",
        about: "Import a file or directory into the pile",
        params: &[
            Param::caller("path", "Path to a file or directory")
                .path()
                .positional(),
            Param::caller("mime", "Override MIME type (single file only)").optional(),
            Param::caller("tag", "Add tags to the import (repeatable)").repeated(),
            Param::caller(
                "dry-run",
                "Preview what would be imported without committing",
            )
            .flag(),
        ],
    },
    Verb {
        name: "list",
        about: "List all imported files",
        params: &[
            Param::caller("tag", "Filter by tag (repeatable)").repeated(),
            Param::caller("mime", "Filter by MIME type prefix").optional(),
        ],
    },
    Verb {
        name: "show",
        about: "Show metadata for a file, directory, or import",
        params: &[
            Param::caller("id", "Entity id/content hash or an unambiguous prefix").positional(),
        ],
    },
    Verb {
        name: "view",
        about: "Present content in a format accepted by the recipient",
        params: &[
            Param::caller("id", "Entity id/content hash or an unambiguous prefix").positional(),
            Param::caller("accept", "Accepted MIME type (repeatable; e.g. image/png)").repeated(),
            Param::caller("max-bytes", "Maximum presented payload bytes").default("4194304"),
            Param::caller("max-dimension", "Maximum image width/height").optional(),
        ],
    },
    Verb {
        name: "get",
        about: "Extract a file, directory, or import; use @- for byte-exact output",
        params: &[
            Param::caller("id", "Entity id/content hash or an unambiguous prefix").positional(),
            Param::caller(
                "output",
                "Output path; omit for stored filename, @- for output bytes",
            )
            .path()
            .positional()
            .optional(),
        ],
    },
    Verb {
        name: "tag",
        about: "Add a tag to a file",
        params: &[
            Param::caller("id", "Entity id/content hash or an unambiguous prefix").positional(),
            Param::caller("name", "Tag to add").positional(),
        ],
    },
    Verb {
        name: "fetch",
        about: "Fetch a URL and import it as a file",
        params: &[
            Param::caller("url", "URL to fetch").positional(),
            Param::caller("mime", "Override MIME type").optional(),
            Param::caller("name", "Override filename").optional(),
            Param::caller("tag", "Add tags to the import (repeatable)").repeated(),
            Param::caller(
                "max-bytes",
                "Maximum response size in bytes (default 8 MiB)",
            )
            .default("8388608"),
        ],
    },
    Verb {
        name: "search",
        about: "Search files by name or tag",
        params: &[
            Param::caller("query", "Search query (substring, case-insensitive)").positional(),
        ],
    },
    Verb {
        name: "similar",
        about: "Find semantically similar files by image id or cross-modal --text query",
        params: &[
            Param::caller("id", "Entity id/content hash or prefix; omit with --text")
                .positional()
                .optional(),
            Param::caller("text", "Text query for cross-modal search").optional(),
            Param::caller("floor", "Minimum cosine similarity, 0..1").default("0.15"),
            Param::caller("limit", "Maximum results")
                .default("10")
                .short('n'),
            Param::caller("tag", "Only results carrying all these tags (repeatable)").repeated(),
            Param::caller(
                "mm7b",
                "Search the nomic-embed-multimodal-7b space; run embed7b first",
            )
            .flag(),
        ],
    },
    Verb {
        name: "embed",
        about: "Embed every stored image into the shared text+image space with nomic-vision (requires local-embed)",
        params: &[Param::caller("force", "Re-embed files already carrying a shared-space embedding").flag()],
    },
    Verb {
        name: "embed7b",
        about: "Embed images or PDF pages with nomic-embed-multimodal-7b (requires local-embed)",
        params: &[
            Param::caller(
                "force",
                "Re-embed files/pages already carrying a 7b embedding",
            )
            .flag(),
            Param::caller("pdf", "Rasterize and embed PDF pages instead of images").flag(),
            Param::caller("dpi", "PDF rasterization resolution in DPI").default("150"),
            Param::caller("limit", "Process at most this many PDFs (0 = all)").default("0"),
            Param::caller(
                "max-pages",
                "Embed at most this many pages per PDF (0 = all)",
            )
            .default("0"),
        ],
    },
    Verb {
        name: "imports",
        about: "List imports (snapshots)",
        params: &[],
    },
    Verb {
        name: "tree",
        about: "Show the tree structure of an import or directory",
        params: &[
            Param::caller("id", "Import/directory entity id or an unambiguous prefix").positional(),
            Param::caller("depth", "Maximum depth (0 = root, 1 = immediate children)")
                .optional()
                .short('d'),
        ],
    },
    Verb {
        name: "resolve",
        about: "Expand selectors to canonical tokens; @path or @- for batches",
        params: &[Param::caller(
            "input",
            "Selector or @path/@- batch (one selector per line)",
        )
        .positional()],
    },
    Verb {
        name: "diff",
        about: "Compare two imports, directories, or files",
        params: &[
            Param::caller("left", "Left (older) entity/hash selector").positional(),
            Param::caller("right", "Right (newer) entity/hash selector").positional(),
        ],
    },
];

pub static SPEC: Spec = Spec {
    name: "files",
    about: "Content-addressed file storage in a TribleSpace pile",
    version: Some(crate::GIT_VERSION),
    shared: SHARED,
    verbs: VERBS,
};

pub fn execute(invocation: &Invocation, out: &mut Out<'_>) -> Result<()> {
    execute_with_input(invocation, out, &mut std::io::stdin().lock())
}

fn execute_with_input(
    invocation: &Invocation,
    out: &mut Out<'_>,
    input: &mut impl std::io::Read,
) -> Result<()> {
    let files = Files::new(
        invocation.require_path("pile")?.to_owned(),
        invocation.path("key").map(Path::to_owned),
    );
    match invocation.verb().name {
        "add" => files.add_path(
            invocation.require_path("path")?,
            invocation.get("mime"),
            invocation.values("tag"),
            invocation.flag("dry-run"),
            out,
        ),
        "list" => out.text(files.list(invocation.values("tag"), invocation.get("mime"))?),
        "show" => out.text(files.show(invocation.require("id")?)?),
        "view" => {
            let mut options = ViewOptions::default();
            options.max_bytes = invocation
                .require("max-bytes")?
                .parse()
                .context("invalid --max-bytes")?;
            options.max_dimension = invocation
                .get("max-dimension")
                .map(str::parse)
                .transpose()
                .context("invalid --max-dimension")?;
            let accept = invocation.values("accept");
            if !accept.is_empty() {
                options.accept = accept.to_vec();
            } else if std::env::var_os("DRIVE_ENDPOINT").is_some() {
                // WAV carries its own rate/channels and the Drive adapter
                // derives mono PCM16 from it. Stored L16 retains only a MIME
                // essence, so it cannot safely supply the required sample rate.
                options.accept = [
                    "text/*",
                    "image/png",
                    "image/jpeg",
                    "audio/wav",
                    "audio/x-wav",
                    "audio/vnd.wave",
                ]
                .map(str::to_owned)
                .to_vec();
            }
            out.emit(files.view(invocation.require("id")?, &options)?)
        }
        "get" => {
            let id = invocation.require("id")?;
            match invocation.path("output") {
                Some(path) if path == Path::new("@-") => {
                    let export = files.get(id)?;
                    let uri = export.uri();
                    out.blob(export.bytes, "application/octet-stream", uri)
                }
                destination => {
                    let plan = files.extract(id, destination)?;
                    let path = plan.destination.clone();
                    plan.write()?;
                    eprintln!("Extracted to {}", path.display());
                    Ok(())
                }
            }
        }
        "tag" => files.tag(invocation.require("id")?, invocation.require("name")?, out),
        "fetch" => files.fetch(
            &FetchOptions {
                url: invocation.require("url")?,
                mime: invocation.get("mime"),
                name: invocation.get("name"),
                tags: invocation.values("tag"),
                max_bytes: invocation
                    .require("max-bytes")?
                    .parse()
                    .context("invalid --max-bytes")?,
            },
            out,
        ),
        "search" => out.text(files.search(invocation.require("query")?)?),
        "similar" => files.similar(
            &SimilarityOptions {
                id: invocation.get("id"),
                text: invocation.get("text"),
                floor: invocation
                    .require("floor")?
                    .parse()
                    .context("invalid --floor")?,
                limit: invocation
                    .require("limit")?
                    .parse()
                    .context("invalid --limit")?,
                tags: invocation.values("tag"),
                mm7b: invocation.flag("mm7b"),
            },
            out,
        ),
        "embed" => files.embed(invocation.flag("force"), out),
        "embed7b" => files.embed7b(
            &EmbeddingOptions {
                force: invocation.flag("force"),
                pdf: invocation.flag("pdf"),
                dpi: invocation
                    .require("dpi")?
                    .parse()
                    .context("invalid --dpi")?,
                limit: invocation
                    .require("limit")?
                    .parse()
                    .context("invalid --limit")?,
                max_pages: invocation
                    .require("max-pages")?
                    .parse()
                    .context("invalid --max-pages")?,
            },
            out,
        ),
        "imports" => out.text(files.imports()?),
        "tree" => out.text(
            files.tree(
                invocation.require("id")?,
                invocation
                    .get("depth")
                    .map(str::parse)
                    .transpose()
                    .context("invalid --depth")?,
            )?,
        ),
        "resolve" => {
            let selector = invocation.require("input")?;
            if let Some(path) = selector.strip_prefix('@') {
                let content = if path == "-" {
                    let mut content = String::new();
                    input
                        .read_to_string(&mut content)
                        .context("read resolve batch from stdin")?;
                    content
                } else {
                    std::fs::read_to_string(path).with_context(|| format!("read {path}"))?
                };
                let selectors: Vec<String> = content
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(str::to_owned)
                    .collect();
                let results = files.resolve(&selectors)?;
                let mut resolved = 0;
                for (selector, result) in selectors.iter().zip(results) {
                    match result {
                        Ok(reference) => {
                            out.line(format!("{selector}\tfiles:{}", reference.hex()))?;
                            resolved += 1;
                        }
                        Err(error) => eprintln!("UNRESOLVED: {selector} — {error}"),
                    }
                }
                eprintln!(
                    "{resolved} resolved, {} unresolved",
                    selectors.len() - resolved
                );
                Ok(())
            } else {
                let mut results = files.resolve(&[selector.to_owned()])?;
                out.line(results.remove(0)?.hex())
            }
        }
        "diff" => out.text(files.diff(invocation.require("left")?, invocation.require("right")?)?),
        other => bail!("Files CLI has no command {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::CliRequest;

    #[test]
    fn invalid_options_fail_before_opening_storage() {
        for arguments in [
            vec!["fetch", "unused", "--max-bytes", "wrong"],
            vec!["tree", "unused", "--depth", "wrong"],
            vec!["similar", "--text", "query", "--floor", "wrong"],
            vec!["embed7b", "--dpi", "wrong"],
            vec!["view", "unused", "--max-dimension", "wrong"],
        ] {
            let mut argv = vec!["files", "--pile", "/does-not-exist/faculties.pile"];
            argv.extend(arguments);
            let CliRequest::Invoke(invocation) = SPEC.lower_cli_from(argv).unwrap() else {
                panic!("invoke");
            };
            let error = execute_with_input(
                &invocation,
                &mut Out::new(&mut |_| panic!("unexpected emission")),
                &mut std::io::empty(),
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("invalid --"), "{error:#}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_paths_include_non_utf8_output_destinations() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        for verb in ["add", "get"] {
            let path = OsString::from_vec(b"native-\xff".to_vec());
            let mut argv = vec!["files".into(), "--pile".into(), path.clone(), verb.into()];
            if verb == "get" {
                argv.push("file-id".into());
            }
            argv.push(path.clone());
            let CliRequest::Invoke(invocation) = SPEC.lower_cli_from(argv).unwrap() else {
                panic!("invoke");
            };
            assert_eq!(invocation.require_path("pile").unwrap().as_os_str(), &path);
            assert_eq!(
                invocation
                    .require_path(if verb == "get" { "output" } else { "path" })
                    .unwrap()
                    .as_os_str(),
                &path
            );
        }
    }

    #[test]
    fn dry_run_does_not_need_a_store_or_signer() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("local.txt");
        std::fs::write(&input, b"local preview").unwrap();
        let absent = directory.path().join("must-not-open.pile");
        let CliRequest::Invoke(invocation) = SPEC
            .lower_cli_from([
                "files",
                "--pile",
                absent.to_str().unwrap(),
                "add",
                input.to_str().unwrap(),
                "--dry-run",
                "--tag",
                "preview",
            ])
            .unwrap()
        else {
            panic!("invoke");
        };
        let mut parts = Vec::new();
        execute(
            &invocation,
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
        assert!(!absent.exists());
        assert!(parts.iter().any(
            |part| matches!(part, crate::out::Part::Text { text } if text == "Tags: preview\n")
        ));
    }
}
