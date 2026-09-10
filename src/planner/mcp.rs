//! Resident Planner tools. Names and text are literal; no tool opens a
//! caller-selected file, reads stdin, or chooses the server's local calendar day.
use super::{presentation, AddOptions, CalendarInput, Planner as Operations};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;

pub struct Planner {
    operations: Operations,
}
impl Planner {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self {
            operations: Operations::with_storage(storage),
        }
    }
}
const TOOLS: &[Tool] = &[
    Tool {
        name: "planner_add",
        description: "Add an event and optional initial note in one publication. ISO dates and timezone-free datetimes are interpreted as UTC; timezone-bearing RFC3339 is respected. Missing end means one day for a date or one hour otherwise. All prose, including @ strings, is literal. Summary/location/RRULE use the current 32-UTF8-byte fields.",
        input_schema: r#"{"type":"object","properties":{"summary":{"type":"string","maxLength":32},"from":{"type":"string"},"to":{"type":"string"},"rrule":{"type":"string","maxLength":32},"location":{"type":"string","maxLength":32},"status":{"type":"string","enum":["tentative","confirmed","cancelled"]},"transp":{"type":"string","enum":["opaque","transparent"]},"description":{"type":"string"},"note":{"type":"string"}},"required":["summary","from"],"additionalProperties":false}"#,
    },
    Tool {
        name: "planner_list",
        description: "List occurrences overlapping an explicit ISO window. Dates and timezone-free datetimes mean UTC; no host-local today/week assumption. Preserves the existing bounded recurrence projection (up to 10000 generated instances per event) and cancellation filtering.",
        input_schema: r#"{"type":"object","properties":{"from":{"type":"string"},"to":{"type":"string"},"include_cancelled":{"type":"boolean","default":false}},"required":["from","to"],"additionalProperties":false}"#,
    },
    Tool {
        name: "planner_next",
        description: "Find the next noncancelled occurrence using existing RRULE/RDATE/EXDATE treatment, through the 2100-01-01 horizon. after is ISO/UTC; omit it to capture the current time once.",
        input_schema: r#"{"type":"object","properties":{"after":{"type":"string"}},"additionalProperties":false}"#,
    },
    Tool {
        name: "planner_note",
        description: "Attach an immutable literal note to an event ID or unambiguous prefix. @file and @- are ordinary text.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string","minLength":1},"text":{"type":"string"}},"required":["id","text"],"additionalProperties":false}"#,
    },
    Tool {
        name: "planner_show",
        description: "Show the selected event, its cancellation state, UID, description and notes from one frozen authorized observation.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string","minLength":1}},"required":["id"],"additionalProperties":false}"#,
    },
    Tool {
        name: "planner_cancel",
        description: "Idempotently assert monotone cancellation. Baseline event fields are not overwritten and exact repeats publish nothing.",
        input_schema: r#"{"type":"object","properties":{"id":{"type":"string","minLength":1}},"required":["id"],"additionalProperties":false}"#,
    },
    Tool {
        name: "planner_resolve",
        description: "Resolve an event ID or unambiguous hexadecimal prefix.",
        input_schema: r#"{"type":"object","properties":{"prefix":{"type":"string","minLength":1}},"required":["prefix"],"additionalProperties":false}"#,
    },
    Tool {
        name: "planner_ingest",
        description: "Ingest resident iCalendar text documents, staging the full batch before one publication. Names are diagnostics, not host paths. Exact duplicate UID definitions are skipped; differing immutable fields reject the whole batch, not replaced by SEQUENCE/revision order. Preserves the current parser subset: date/floating times are UTC and TZID is not applied; this is not a general timezone-aware RFC5545 importer.",
        input_schema: r#"{"type":"object","properties":{"documents":{"type":"array","minItems":1,"items":{"type":"object","properties":{"name":{"type":"string","minLength":1},"text":{"type":"string"}},"required":["name","text"],"additionalProperties":false}}},"required":["documents"],"additionalProperties":false}"#,
    },
];
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Tentative,
    Confirmed,
    Cancelled,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Transparency {
    Opaque,
    Transparent,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Add {
    summary: String,
    from: String,
    to: Option<String>,
    rrule: Option<String>,
    location: Option<String>,
    status: Option<Status>,
    transp: Option<Transparency>,
    description: Option<String>,
    note: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    from: String,
    to: String,
    #[serde(default)]
    include_cancelled: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Next {
    after: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Note {
    id: String,
    text: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prefix {
    prefix: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Calendar {
    name: String,
    text: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ingest {
    #[serde(deserialize_with = "crate::mcp::object::vec")]
    documents: Vec<Calendar>,
}
fn selector(value: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() || value.len() > 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_arguments(
            "event selector must be a nonempty hexadecimal ID or prefix, at most 32 characters",
        ));
    }
    Ok(())
}
impl Faculty for Planner {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "planner_add" => {
                let args: Add = decode_arguments(arguments)?;
                let window = super::event_window(&args.from, args.to.as_deref())
                    .map_err(invalid_arguments)?;
                let mut options = AddOptions::new(args.summary, window);
                options.rrule = args.rrule;
                options.location = args.location;
                options.description = args.description;
                options.note = args.note;
                options.status = match args.status {
                    Some(Status::Tentative) => super::STATUS_TENTATIVE,
                    Some(Status::Cancelled) => super::STATUS_CANCELLED,
                    Some(Status::Confirmed) | None => super::STATUS_CONFIRMED,
                }
                .to_owned();
                options.transp = match args.transp {
                    Some(Transparency::Transparent) => super::TRANSP_TRANSPARENT,
                    Some(Transparency::Opaque) | None => super::TRANSP_OPAQUE,
                }
                .to_owned();
                options.validate().map_err(invalid_arguments)?;
                presentation::added(&self.operations.add(&options)?, out)
            }
            "planner_list" => {
                let args: List = decode_arguments(arguments)?;
                let window =
                    super::event_window(&args.from, Some(&args.to)).map_err(invalid_arguments)?;
                presentation::occurrences(
                    &self.operations.list(window, args.include_cancelled)?,
                    out,
                )
            }
            "planner_next" => {
                let args: Next = decode_arguments(arguments)?;
                let after = args
                    .after
                    .as_deref()
                    .map(super::parse_iso8601)
                    .transpose()
                    .map_err(invalid_arguments)?
                    .map(super::chrono_to_epoch);
                let next = self.operations.next(after)?;
                presentation::occurrences(next.as_ref().map_or(&[], std::slice::from_ref), out)
            }
            "planner_note" => {
                let args: Note = decode_arguments(arguments)?;
                selector(&args.id)?;
                presentation::noted(&self.operations.note(&args.id, &args.text)?, out)
            }
            "planner_show" => {
                let args: Event = decode_arguments(arguments)?;
                selector(&args.id)?;
                presentation::show(&self.operations.show(&args.id)?, out)
            }
            "planner_cancel" => {
                let args: Event = decode_arguments(arguments)?;
                selector(&args.id)?;
                presentation::cancelled(&self.operations.cancel(&args.id)?, out)
            }
            "planner_resolve" => {
                let args: Prefix = decode_arguments(arguments)?;
                selector(&args.prefix)?;
                out.line(format!("{:x}", self.operations.resolve(&args.prefix)?))
            }
            "planner_ingest" => {
                let args: Ingest = decode_arguments(arguments)?;
                let documents = args
                    .documents
                    .iter()
                    .map(|document| CalendarInput {
                        name: &document.name,
                        text: &document.text,
                    })
                    .collect::<Vec<_>>();
                super::validate_calendars(&documents).map_err(invalid_arguments)?;
                presentation::ingested(&self.operations.ingest(&documents)?, out)
            }
            _ => bail!("unknown Planner tool '{name}'"),
        }
    }
}
