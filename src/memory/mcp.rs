//! Explicit local MCP tools over resident Memory operations. Content is literal;
//! no @ expansion, ambient persona, host-cache cover paths, or argv dispatch.
//! Embedding tools retain the trusted local model configuration/compute boundary.
use super::operations::{parse_tai_timestamp, parse_time_range};
use super::{ChurnOptions, CoverOpts, CoverReport};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use base64::Engine as _;
use serde::Deserialize;
use std::path::PathBuf;

pub struct Memory {
    operations: super::Memory,
}
impl Memory {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            operations: super::Memory::with_storage(storage),
        }
    }
}

static TOOLS: &[Tool] = &[
    Tool {
        name: "memory_show",
        description: "Show one immutable episode by id/alias prefix or range. Images are native bounded derived image content, never host paths.",
        input_schema: r#"{"type":"object","properties":{"selector":{"type":"string","description":"Immutable chunk id/alias prefix or TAI from..to range."}},"required":["selector"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_turn",
        description: "Show the memory facets associated with an execution-result id prefix.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_meta",
        description: "Inspect immutable episode metadata and historical links.",
        input_schema: r#"{"type":"object","properties":{"selector":{"type":"string","description":"Immutable chunk id/alias prefix or TAI from..to range."}},"required":["selector"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_provenance",
        description: "List cognition/archive events overlapping an episode.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string"}},"required":["id"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_create",
        description: "Journal literal resident text, optionally over an explicit positive-duration TAI range; no host file/stdin expansion.",
        input_schema: r#"{"type":"object","properties":{"summary":{"type":"string","minLength":1},"range":{"type":"string"},"lens":{"type":"string","minLength":1}},"required":["summary"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_image",
        description: "Store exact base64-encoded image bytes as a wordless memory; when is a TAI point or from..to. Display validates/derives media separately.",
        input_schema: r#"{"type":"object","properties":{"when":{"type":"string"},"data":{"type":"string","minLength":1,"description":"Base64-encoded resident image bytes, not a path."}},"required":["when","data"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_respan",
        description: "Write identical text over corrected positive-duration coordinates; old id remains readable. Content cannot be edited here.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string"},"range":{"type":"string"}},"required":["id","range"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_respan_instants",
        description: "Repair zero/inverted text coordinates from their own prose or a journal moment; one publication, or dry-run report.",
        input_schema: r#"{"type":"object","properties":{"dry_run":{"type":"boolean","default":false}},"required":[],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_respan_seams",
        description: "Repair rounded small seams between wide stored arcs; one publication, or dry-run report. Does not alter the recollection sampler.",
        input_schema: r#"{"type":"object","properties":{"dry_run":{"type":"boolean","default":false}},"required":[],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_search",
        description: "Exact lexical retrieval rebuilt from one frozen maintained Memory view.",
        input_schema: r#"{"type":"object","properties":{"query":{"type":"string","minLength":1,"description":"Literal query; @ has no host-file meaning."}},"required":["query"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_embed",
        description: "Embed unembedded memory text/images into the shared nomic space. Requires trusted local model configuration and local-embed; may load models and use substantial compute.",
        input_schema: r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_similar",
        description: "Semantic retrieval over resident embeddings. Requires trusted local model configuration and local-embed.",
        input_schema: r#"{"type":"object","properties":{"query":{"type":"string","minLength":1,"description":"Literal query; @ has no host-file meaning."}},"required":["query"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_context",
        description: "Greedy density-shaped, deliberately lossy recollection in selected SPACE order. First text part is exact charged cover text; later diagnostic part is outside its budget. Filters are chunk-level: coarse prose can mention excluded material, and unscorable images fail open with explicit warnings.",
        input_schema: r#"{"type":"object","properties":{"budget_chars":{"type":"integer","minimum":0,"default":200000},"chunk_overhead":{"type":"integer","minimum":0,"default":0},"about":{"type":"string"},"filter":{"type":"string"},"remove":{"type":"string"},"sim_threshold":{"type":"number","minimum":0,"maximum":1,"default":0.55}},"required":[],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_lens",
        description: "List thematic lenses or show matching literal theme narratives.",
        input_schema: r#"{"type":"object","properties":{"theme":{"type":"string"}},"required":[],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_list",
        description: "Inspect time ranges as a containment outline or at a grain; this diagnostic does not reorder recollection.",
        input_schema: r#"{"type":"object","properties":{"grain":{"type":"string","description":"Positive duration such as 90m, 2h, 1d, 4w."}},"required":[],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_check",
        description: "Report coverage gaps at a positive diagnostic grain; perfect temporal coverage is not required for recollection.",
        input_schema: r#"{"type":"object","properties":{"grain":{"type":"string","description":"Positive duration such as 90m, 2h, 1d, 4w."}},"required":["grain"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_density",
        description: "Inspect stored density/containment, optionally at a diagnostic grain.",
        input_schema: r#"{"type":"object","properties":{"grain":{"type":"string","description":"Positive duration such as 90m, 2h, 1d, 4w."}},"required":[],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_churn",
        description: "Replay recollection over observation history without writing memories or changing the sampler.",
        input_schema: r#"{"type":"object","properties":{"budget_chars":{"type":"integer","minimum":0,"default":800000},"steps":{"type":"integer","minimum":0,"default":160},"step_units":{"type":"integer","minimum":1,"default":1}},"required":[],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_consolidate_start",
        description: "Set an explicit persona's consolidation edge.",
        input_schema: r#"{"type":"object","properties":{"persona":{"type":"string","minLength":1,"description":"Explicit session cursor identity; never inherited from the host."},"timestamp":{"type":"string","description":"TAI YYYY-MM-DDTHH:MM:SS."}},"required":["persona","timestamp"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_consolidate_stop",
        description: "Stop an explicit persona's consolidation cursor.",
        input_schema: r#"{"type":"object","properties":{"persona":{"type":"string","minLength":1,"description":"Explicit session cursor identity; never inherited from the host."}},"required":["persona"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_consolidate",
        description: "Journal literal text from the persona's open edge to until, then advance its cursor; interrupted Memory-then-Comb publication is retryable.",
        input_schema: r#"{"type":"object","properties":{"persona":{"type":"string","minLength":1,"description":"Explicit session cursor identity; never inherited from the host."},"until":{"type":"string","description":"TAI YYYY-MM-DDTHH:MM:SS."},"summary":{"type":"string","minLength":1}},"required":["persona","until","summary"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_replay_start",
        description: "Start chronological journal replay at a diagnostic grain for an explicit persona.",
        input_schema: r#"{"type":"object","properties":{"persona":{"type":"string","minLength":1,"description":"Explicit session cursor identity; never inherited from the host."},"grain":{"type":"string","description":"Positive duration such as 90m, 2h, 1d, 4w."},"from":{"type":"string","description":"TAI YYYY-MM-DDTHH:MM:SS."}},"required":["persona","grain"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_replay_stop",
        description: "Stop an explicit persona's journal replay.",
        input_schema: r#"{"type":"object","properties":{"persona":{"type":"string","minLength":1,"description":"Explicit session cursor identity; never inherited from the host."}},"required":["persona"],"additionalProperties":false}"#,
    },
    Tool {
        name: "memory_replay",
        description: "Deliver a coordinate-complete journal batch and then advance that persona's cursor; same-start episodes may exceed count.",
        input_schema: r#"{"type":"object","properties":{"persona":{"type":"string","minLength":1,"description":"Explicit session cursor identity; never inherited from the host."},"count":{"type":"integer","minimum":1,"default":5}},"required":["persona"],"additionalProperties":false}"#,
    },
];

macro_rules! arguments {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $name { $($field: $ty),* }
    };
}
arguments!(Empty {});
arguments!(Selector { selector: String });
arguments!(Id { id: String });
arguments!(Query { query: String });
arguments!(Create { summary: String, range: Option<String>, lens: Option<String> });
arguments!(Image {
    when: String,
    data: String
});
arguments!(Respan {
    id: String,
    range: String
});
arguments!(Repair { dry_run: Option<bool> });
arguments!(ContextArgs { budget_chars: Option<usize>, chunk_overhead: Option<usize>, about: Option<String>, filter: Option<String>, remove: Option<String>, sim_threshold: Option<f32> });
arguments!(Lens { theme: Option<String> });
arguments!(Grain { grain: String });
arguments!(OptionalGrain { grain: Option<String> });
arguments!(Churn { budget_chars: Option<usize>, steps: Option<usize>, step_units: Option<i128> });
arguments!(Persona { persona: String });
arguments!(ConsolidateStart {
    persona: String,
    timestamp: String
});
arguments!(Consolidate {
    persona: String,
    until: String,
    summary: String
});
arguments!(ReplayStart { persona: String, grain: String, from: Option<String> });
arguments!(Replay { persona: String, count: Option<usize> });

impl Faculty for Memory {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        let memory = &self.operations;
        match name {
            "memory_show" => {
                let args: Selector = decode_arguments(arguments)?;
                memory.show(&args.selector, out)
            }
            "memory_turn" => {
                let args: Id = decode_arguments(arguments)?;
                memory.turn(&args.id, out)
            }
            "memory_meta" => {
                let args: Selector = decode_arguments(arguments)?;
                memory.meta(&args.selector, out)
            }
            "memory_provenance" => {
                let args: Id = decode_arguments(arguments)?;
                memory.provenance(&args.id, out)
            }
            "memory_create" => {
                let args: Create = decode_arguments(arguments)?;
                let range = args
                    .range
                    .as_deref()
                    .map(parse_time_range)
                    .transpose()
                    .map_err(invalid_arguments)?;
                memory
                    .create(&args.summary, range, args.lens.as_deref())?
                    .emit(out)
            }
            "memory_image" => {
                let args: Image = decode_arguments(arguments)?;
                let range = if args.when.contains("..") {
                    parse_time_range(&args.when)
                } else {
                    parse_tai_timestamp(&args.when).map(|when| (when, when))
                }
                .map_err(invalid_arguments)?;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(args.data)
                    .map_err(invalid_arguments)?;
                memory.image(&bytes, range)?.emit(out)?;
                out.line(format!("({} image bytes stored; run `memory embed` to place it in the shared nomic space)", bytes.len()))
            }
            "memory_respan" => {
                let args: Respan = decode_arguments(arguments)?;
                memory
                    .respan(
                        &args.id,
                        parse_time_range(&args.range).map_err(invalid_arguments)?,
                    )?
                    .emit(out)
            }
            "memory_respan_instants" => {
                let args: Repair = decode_arguments(arguments)?;
                memory.respan_instants(args.dry_run.unwrap_or(false), out)
            }
            "memory_respan_seams" => {
                let args: Repair = decode_arguments(arguments)?;
                memory.respan_seams(args.dry_run.unwrap_or(false), out)
            }
            "memory_search" => {
                let args: Query = decode_arguments(arguments)?;
                memory.search(&args.query, out)
            }
            "memory_embed" => {
                let _: Empty = decode_arguments(arguments)?;
                memory.embed(out)
            }
            "memory_similar" => {
                let args: Query = decode_arguments(arguments)?;
                memory.similar(&args.query, out)
            }
            "memory_context" => {
                let args: ContextArgs = decode_arguments(arguments)?;
                let mut options = CoverOpts::plain(args.budget_chars.unwrap_or(200_000));
                options.chunk_overhead = args.chunk_overhead.unwrap_or(0);
                options.about = args.about;
                options.filter = args.filter;
                options.remove = args.remove;
                options.sim_threshold = args
                    .sim_threshold
                    .unwrap_or(crate::memory_cover::DEFAULT_SIM_THRESHOLD);
                emit_context(memory.context(&options)?, out)
            }
            "memory_lens" => {
                let args: Lens = decode_arguments(arguments)?;
                memory.lens(args.theme.as_deref(), out)
            }
            "memory_list" => {
                let args: OptionalGrain = decode_arguments(arguments)?;
                memory.list(args.grain.as_deref(), out)
            }
            "memory_check" => {
                let args: Grain = decode_arguments(arguments)?;
                memory.check(&args.grain, out)
            }
            "memory_density" => {
                let args: OptionalGrain = decode_arguments(arguments)?;
                memory.density(args.grain.as_deref(), out)
            }
            "memory_churn" => {
                let args: Churn = decode_arguments(arguments)?;
                let mut options = ChurnOptions::default();
                if let Some(value) = args.budget_chars {
                    options.budget_chars = value;
                }
                if let Some(value) = args.steps {
                    options.steps = value;
                }
                if let Some(value) = args.step_units {
                    options.step_units = value;
                }
                memory.churn(&options, out)
            }
            "memory_consolidate_start" => {
                let args: ConsolidateStart = decode_arguments(arguments)?;
                memory.consolidate_start(
                    &args.persona,
                    parse_tai_timestamp(&args.timestamp).map_err(invalid_arguments)?,
                )?;
                out.line(format!(
                    "consolidation edge set to {} (persona {})",
                    args.timestamp, args.persona
                ))
            }
            "memory_consolidate_stop" => {
                let args: Persona = decode_arguments(arguments)?;
                memory.consolidate_stop(&args.persona)?;
                out.line(format!("consolidation stopped (persona {})", args.persona))
            }
            "memory_consolidate" => {
                let args: Consolidate = decode_arguments(arguments)?;
                memory
                    .consolidate(
                        &args.persona,
                        parse_tai_timestamp(&args.until).map_err(invalid_arguments)?,
                        &args.summary,
                    )?
                    .emit(out)?;
                out.line(format!("edge → {}", args.until))
            }
            "memory_replay_start" => {
                let args: ReplayStart = decode_arguments(arguments)?;
                let from = args
                    .from
                    .as_deref()
                    .map(parse_tai_timestamp)
                    .transpose()
                    .map_err(invalid_arguments)?;
                memory.replay_start(&args.persona, &args.grain, from)?;
                out.line(format!(
                    "memory replay started at grain {} (persona {})",
                    args.grain, args.persona
                ))
            }
            "memory_replay_stop" => {
                let args: Persona = decode_arguments(arguments)?;
                memory.replay_stop(&args.persona)?;
                out.line(format!("memory replay stopped (persona {})", args.persona))
            }
            "memory_replay" => {
                let args: Replay = decode_arguments(arguments)?;
                memory.replay(&args.persona, args.count.unwrap_or(5), out)
            }
            _ => bail!("unknown Memory MCP tool {name}"),
        }
    }
}

fn emit_context(report: CoverReport, out: &mut Out<'_>) -> Result<()> {
    out.text(report.text)?;
    if !report.diagnostics.is_empty() {
        out.text(format!(
            "Memory diagnostics (outside the charged cover text):\n{}",
            report.diagnostics.join("\n")
        ))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::out::Part;

    #[test]
    fn fail_open_warning_is_delivered_separately_from_exact_charged_text() {
        let cover = "\n2026-09-01T00:00:00..2026-09-02T00:00:00\nexact recollection\n";
        let warning = "memory: unscorable images kept (fail-open)";
        let mut parts = Vec::new();
        emit_context(
            CoverReport {
                text: cover.to_owned(),
                diagnostics: vec![warning.to_owned()],
            },
            &mut Out::new(&mut |part| {
                parts.push(part);
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(
            parts[0],
            Part::Text {
                text: cover.to_owned()
            }
        );
        let Part::Text { text } = &parts[1] else {
            panic!("diagnostic must be text")
        };
        assert!(text.contains("outside the charged cover text"));
        assert!(text.contains(warning));
        assert!(!cover.contains(warning));
    }
}
