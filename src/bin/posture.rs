//! `posture` — find candidate redaction points in a corpus.
//!
//! Points it at a directory and it reports material that may identify someone:
//! the author field on a document nobody opens, GPS on a field photograph,
//! speaker notes invisible during the presentation, a sheet marked hidden.
//!
//! Two things it deliberately does NOT do.
//!
//! It does not redact. It surfaces candidates and a human decides — so the
//! tuning is for recall, and a false positive costs one click. That is why
//! findings are *grouped* rather than filtered: dismissing four thousand
//! identical hits should be one decision, but they still have to be shown,
//! because silently excluding a category is how material survives a scrub.
//!
//! It does not say "clean". Every scan records the modalities it applied AND
//! the ones it did not (`unchecked` facts), because a redaction tool that
//! certifies safety manufactures precisely the confidence that gets a source
//! burned. `posture coverage <scan>` prints the gaps.
//!
//! This build implements the deterministic tier only — structure and metadata,
//! no inference. That is where the real disasters live and it needs no model.
//!
//! Commands:
//!   posture scan <path>        — walk a path, extract, record findings
//!   posture list [--scan ID]   — findings, grouped by modality
//!   decide ... --about <finding>   — durable judgement of one finding
//!   posture coverage <scan>    — what that scan did NOT look at
//!   posture scans              — recent scans

// In the query DSL `(expression)` means "this bound Rust value", while
// `?name` introduces a query variable. Rust's ordinary-expression lint cannot
// see that macro grammar and incorrectly suggests deleting the parentheses.
#![allow(unused_parens)]

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::storage::{discover_target, load_signer, open_pile_strict};
use faculties::decide::{self, Resolution};
use faculties::schemas::decide::DEFAULT_SCOPE_ID as DEFAULT_DECIDE_SCOPE_ID;
use faculties::schemas::embeddings::{self, Embedding768};
use faculties::posture_finding::{
    commit_message_location, finding_entity, finding_id, git_probe, Carrier, GitObjects, Location,
};
#[cfg(test)]
use faculties::posture_finding::Inner;
use faculties::schemas::posture::{
    modality, posture, CARRIER_CONTAINER_MEMBER, CARRIER_GIT_BLOB, CARRIER_GIT_COMMIT,
    DEFAULT_POLICY_SCOPE_ID, DEFAULT_SCAN_SCOPE_ID, DOC_UNSUPPORTED, EXEMPLAR_PROTECTED,
    KIND_CHANNEL, KIND_DOCUMENT, KIND_FINDING, KIND_LEGACY_BRIDGE, KIND_OMISSION,
    KIND_POLICY_REVISION, KIND_SCAN, KIND_SIGHTING, KIND_TERM, OUTCOME_EXAMINED,
    OUTCOME_PARSE_FAILED,
};
#[cfg(any(feature = "local-embed", test))]
use faculties::schemas::posture::{EXEMPLAR_BENIGN, KIND_EXEMPLAR};
use hifitime::Epoch;
use lopdf::{Dictionary, Document, Object};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::Blob;
use triblespace::core::collection::{Collection, CollectionCommit};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::*;
use faculties::legacy_hint::open_scope;

type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "posture",
          about = "Find candidate redaction points in a corpus")]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Walk a path and record candidate redaction points
    Scan {
        /// File or directory to examine
        path: PathBuf,
        /// Print findings without writing them to the pile
        #[arg(long)]
        dry_run: bool,
    },
    /// Show findings, grouped by modality
    List {
        /// Restrict to one scan (hex id)
        #[arg(long)]
        scan: Option<String>,
        /// Show at most this many examples per group
        #[arg(long, default_value_t = 3)]
        examples: usize,
        /// Include findings classified benign by a resolved Decide decision.
        #[arg(long)]
        all: bool,
        /// Print the content-located finding ids `decide propose --about` names.
        #[arg(long)]
        ids: bool,
    },
    /// What a scan did NOT examine — read this before trusting a quiet result
    Coverage {
        /// Scan id (hex); defaults to the most recent
        scan: Option<String>,
    },
    /// Recent scans
    Scans,
    /// Install git hooks so the audit runs without being remembered
    Hook {
        /// Repository to install into
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Channel to audit against
        #[arg(long, default_value = "github-public")]
        channel: String,
        /// Only audit pushes whose remote URL contains this substring. A
        /// channel describes a DESTINATION, so auditing every remote against
        /// one channel is a category error — it blocked a push to a private
        /// archive using the public vocabulary. Omit to audit every remote,
        /// which is the fail-closed default. Applies to the pre-push gate
        /// only: a commit has no destination yet.
        #[arg(long)]
        remote_match: Option<String>,
        /// Install only the pre-push GATE, which refuses a push.
        #[arg(long)]
        pre_push: bool,
        /// Install only the post-commit SMOKE ALARM, which refuses nothing and
        /// tells you while `git commit --amend` is still cheap.
        #[arg(long)]
        post_commit: bool,
    },
    /// Store a passage of protected material, embedded, for the semantic tier
    Exemplar {
        /// The passage. Use @path for a file or @- for stdin.
        text: String,
        #[arg(long, default_value = "github-public")]
        channel: String,
        /// Mark as ORDINARY material for this channel, to be subtracted rather
        /// than matched. Without a benign set the score measures register
        /// ("thoughtful prose") instead of content.
        #[arg(long)]
        benign: bool,
    },
    /// Scan text files for material that RESEMBLES an exemplar, spelling none
    /// of the protected terms. This is the tier that reaches the case lexical
    /// matching structurally cannot.
    Semantic {
        path: PathBuf,
        #[arg(long, default_value = "github-public")]
        channel: String,
        /// Cosine floor for reporting. Chunks, not documents, are scored.
        #[arg(long, default_value_t = 0.55)]
        threshold: f32,
    },
    /// Audit every git repo under a directory whose remote is reachable by a
    /// channel. Answers "which repositories can leak, and do they" in one pass.
    Sweep {
        #[arg(default_value = ".")]
        root: PathBuf,
        #[arg(long, default_value = "github-public")]
        channel: String,
        /// Audit every repo, not only those whose remote `gh` reports PUBLIC.
        #[arg(long)]
        all: bool,
        /// Audit each repo's WHOLE reachable history, not only what is ahead
        /// of its remote. A leak is a leak whether it landed today or a year
        /// ago; the push gate can only block what is still preventable, so
        /// this is where "existing or not" is actually checked.
        #[arg(long)]
        history: bool,
    },
    /// Manage the protected vocabulary, scoped to a channel
    Vocab {
        #[command(subcommand)]
        command: VocabCommand,
    },
    /// Audit a git commit range before it leaves for a channel.
    ///
    /// Checks what a file scan cannot: commit MESSAGES. A message is the one
    /// part of a commit that is not in the commit's own diff, so it gets no
    /// review by the normal mechanism — and it is written in the register you
    /// use for your own notes, moments after the work, to a reader you imagine
    /// as yourself. That combination is how internal vocabulary reaches a public
    /// remote. It also checks added and removed Rust lines for changes to
    /// literal-pinned `unsafe as` attribute declarations, independently of
    /// channel vocabulary.
    Git {
        /// Revision arguments, passed to `git log` as written. Usually a range
        /// (`origin/main..HEAD`), but any git revision selection works — and
        /// for a branch the remote has never seen there IS no two-dot range,
        /// so `HEAD --not --remotes=origin` is the honest expression of "what
        /// this push adds". Named options must come BEFORE these.
        #[arg(required = true, num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
        range: Vec<String>,
        /// Channel whose vocabulary to apply
        #[arg(long, default_value = "github-public")]
        channel: String,
        /// Repository path
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
}

#[derive(Subcommand)]
enum VocabCommand {
    /// Protect a term from a channel
    Add {
        term: String,
        #[arg(long, default_value = "github-public")]
        channel: String,
        /// Why this is protected. Recorded because a wordlist without reasons
        /// rots: nobody dares delete an entry nobody can justify.
        #[arg(long)]
        why: Option<String>,
    },
    /// List protected terms
    List {
        #[arg(long)]
        channel: Option<String>,
    },
}

// ── where a finding lives ───────────────────────────────────────────────────
//
// A finding is located by CONTENT, and its id is `(modality, carrier, inner
// locator)`. It used to be `(modality, path, commit:path:line, value)`, which
// commit surgery destroyed: a rebase, cherry-pick, amend or history scrub
// gives the same material a new `commit:path:line`, hence a new id, so every
// Decide resolution silently stopped applying and the finding re-blocked.
//
// The coordinate is MODALITY-DEPENDENT on purpose. Source material has a git
// blob and blobs survive commit surgery byte-identical; a byte range into an
// OOXML zip or a PDF means nothing, so a container's carrier is the member
// posture extracted, hashed by posture; and a commit message has no blob at
// all, so its carrier is the commit.

// ── the extractors ──────────────────────────────────────────────────────────
// Each returns located material. No judgement, no ranking — extraction and
// adjudication are separate stages on purpose.

#[derive(Clone, Debug)]
struct Found {
    modality: Id,
    /// Content-addressed identity coordinate.
    location: Location,
    /// The coordinate exactly as observed, for a human reading the report.
    evidence: String,
    /// The material itself. Evidence, never identity.
    value: String,
    /// The commit this sighting came from, when there was one. The rebuildable
    /// locator cache, not a coordinate.
    seen_in: Option<String>,
}

/// Material inside a container member posture extracted, at a named coordinate
/// within it.
fn member_found(
    modality: Id,
    carrier: Carrier,
    field: impl Into<String>,
    value: impl Into<String>,
) -> Found {
    let field = field.into();
    Found {
        modality,
        location: Location::field(carrier, field.clone()),
        evidence: field,
        value: value.into(),
        seen_in: None,
    }
}

/// Pull the text content of every occurrence of `tag` out of an XML part.
fn xml_tag_texts(xml: &[u8], tag: &str) -> Vec<String> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut out = Vec::new();
    let mut buf = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if local_name(e.name().as_ref()) == tag.as_bytes() {
                    depth += 1;
                    current.clear();
                }
            }
            Ok(Event::Text(t)) if depth > 0 => {
                if let Ok(s) = t.unescape() {
                    current.push_str(&s);
                }
            }
            Ok(Event::End(e)) => {
                if local_name(e.name().as_ref()) == tag.as_bytes() && depth > 0 {
                    depth -= 1;
                    let s = current.trim();
                    if !s.is_empty() {
                        out.push(s.to_string());
                    }
                    current.clear();
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

/// Attribute values for `attr` on every `tag` element.
fn xml_attrs(xml: &[u8], tag: &str, attr: &str) -> Vec<(String, String)> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_reader(xml);
    let mut out = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if local_name(e.name().as_ref()) == tag.as_bytes() {
                    let mut name = String::new();
                    let mut hit: Option<String> = None;
                    for a in e.attributes().flatten() {
                        let k = local_name(a.key.as_ref()).to_vec();
                        let v = String::from_utf8_lossy(&a.value).to_string();
                        if k == b"name" {
                            name = v.clone();
                        }
                        if k == attr.as_bytes() {
                            hit = Some(v);
                        }
                    }
                    if let Some(v) = hit {
                        out.push((name, v));
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

/// XML namespaces mean `w:author` and `author` are the same element to us.
fn local_name(qname: &[u8]) -> &[u8] {
    match qname.iter().position(|b| *b == b':') {
        Some(i) => &qname[i + 1..],
        None => qname,
    }
}

/// OOXML — .docx / .xlsx / .pptx are zips of XML, and most real leaks are in
/// the parts nobody renders.
fn extract_ooxml(path: &Path) -> Result<Vec<Found>> {
    let file = std::fs::File::open(path)?;
    let mut zip = zip::ZipArchive::new(file)?;
    let mut out = Vec::new();

    let names: Vec<String> = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|f| f.name().to_string()))
        .collect();

    let read = |zip: &mut zip::ZipArchive<std::fs::File>, name: &str| -> Option<Vec<u8>> {
        let mut e = zip.by_name(name).ok()?;
        let mut v = Vec::new();
        e.read_to_end(&mut v).ok()?;
        Some(v)
    };

    // core properties — creator / lastModifiedBy / revision are the classic
    // "we sent it out under the wrong name" leak.
    if let Some(xml) = read(&mut zip, "docProps/core.xml") {
        let carrier = Carrier::member(&xml);
        for tag in ["creator", "lastModifiedBy", "revision", "lastPrinted"] {
            for v in xml_tag_texts(&xml, tag) {
                out.push(member_found(
                    modality::OOXML_CORE_PROPS,
                    carrier.clone(),
                    format!("docProps/core.xml:{tag}"),
                    v,
                ));
            }
        }
    }
    if let Some(xml) = read(&mut zip, "docProps/app.xml") {
        let carrier = Carrier::member(&xml);
        for tag in ["Company", "Manager"] {
            for v in xml_tag_texts(&xml, tag) {
                out.push(member_found(
                    modality::OOXML_CORE_PROPS,
                    carrier.clone(),
                    format!("docProps/app.xml:{tag}"),
                    v,
                ));
            }
        }
    }

    for name in &names {
        // comments — every Office app has them, nobody checks before sending
        if name.contains("comments") && name.ends_with(".xml") {
            if let Some(xml) = read(&mut zip, name) {
                let carrier = Carrier::member(&xml);
                for (_, author) in xml_attrs(&xml, "comment", "author") {
                    out.push(member_found(
                        modality::OOXML_COMMENTS,
                        carrier.clone(),
                        format!("{name}:author"),
                        author,
                    ));
                }
                for t in xml_tag_texts(&xml, "t") {
                    out.push(member_found(
                        modality::OOXML_COMMENTS,
                        carrier.clone(),
                        format!("{name}:text"),
                        t,
                    ));
                }
            }
        }
        // speaker notes — invisible while presenting, fully present in the file
        if name.starts_with("ppt/notesSlides/") && name.ends_with(".xml") {
            if let Some(xml) = read(&mut zip, name) {
                let text = xml_tag_texts(&xml, "t").join(" ");
                if !text.trim().is_empty() {
                    out.push(member_found(
                        modality::OOXML_SPEAKER_NOTES,
                        Carrier::member(&xml),
                        name.clone(),
                        text,
                    ));
                }
            }
        }
    }

    // tracked changes still in the body — the deleted paragraph is still there
    if let Some(xml) = read(&mut zip, "word/document.xml") {
        let carrier = Carrier::member(&xml);
        for (tag, kind) in [("ins", "insertion"), ("del", "deletion")] {
            for (_, author) in xml_attrs(&xml, tag, "author") {
                out.push(member_found(
                    modality::OOXML_TRACKED_CHANGES,
                    carrier.clone(),
                    format!("word/document.xml:{kind}@author"),
                    author,
                ));
            }
        }
        for t in xml_tag_texts(&xml, "delText") {
            out.push(member_found(
                modality::OOXML_TRACKED_CHANGES,
                carrier.clone(),
                "word/document.xml:deleted-text",
                t,
            ));
        }
    }

    // hidden / veryHidden sheets
    if let Some(xml) = read(&mut zip, "xl/workbook.xml") {
        let carrier = Carrier::member(&xml);
        for (name, state) in xml_attrs(&xml, "sheet", "state") {
            if state == "hidden" || state == "veryHidden" {
                out.push(member_found(
                    modality::OOXML_HIDDEN_SHEET,
                    carrier.clone(),
                    format!("xl/workbook.xml:{name}"),
                    format!("state={state}"),
                ));
            }
        }
    }

    Ok(out)
}

/// EXIF — GPS on a field photograph is the shortest path from a published
/// image to somebody's front door.
fn extract_exif(path: &Path) -> Result<Vec<Found>> {
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    // "no EXIF here" is a CLEAN result, not a failure. Reporting it as a parse
    // error would cry wolf on every PNG in the corpus, and a tool that cries
    // wolf gets ignored — which costs far more recall than it ever buys.
    let exif = match exif::Reader::new().read_from_container(&mut reader) {
        Ok(e) => e,
        Err(exif::Error::NotFound(_)) | Err(exif::Error::BlankValue(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    // The extracted member is the TIFF block the tags were decoded from. The
    // decoded values (a GPS coordinate, a rational, a MakerNote) are nowhere in
    // those bytes verbatim, so the coordinate is the tag and the member's hash
    // carries the content.
    let carrier = Carrier::member(exif.buf());
    for field in exif.fields() {
        let tag = field.tag;
        let interesting = matches!(
            tag,
            exif::Tag::GPSLatitude
                | exif::Tag::GPSLongitude
                | exif::Tag::GPSAltitude
                | exif::Tag::GPSDateStamp
                | exif::Tag::BodySerialNumber
                | exif::Tag::LensSerialNumber
                | exif::Tag::CameraOwnerName
                | exif::Tag::Artist
                | exif::Tag::Copyright
                | exif::Tag::Software
                | exif::Tag::DateTimeOriginal
                | exif::Tag::ImageDescription
                | exif::Tag::MakerNote
        );
        if interesting {
            let v = field.display_value().with_unit(&exif).to_string();
            let v = if v.len() > 400 {
                format!("{}…", &v[..400])
            } else {
                v
            };
            out.push(member_found(
                modality::EXIF,
                carrier.clone(),
                format!("EXIF:{tag}"),
                v,
            ));
        }
    }
    Ok(out)
}

// ── PDF ─────────────────────────────────────────────────────────────────────
// One parse serves both PDF modalities; opening the file twice is an expensive
// way to learn the same thing.
//
// The information dictionary is the easy half. The other half is the failure
// this whole faculty exists for: a black box drawn over a name in a PDF hides
// nothing. The rectangle is ink laid on top — the text underneath is still in
// the content stream, still selectable, still in every copy-paste, and it is
// invisible to anyone who checks the document by *looking* at it. That is the
// combination that has burned sources: the check passes and the leak ships.
//
// Detection is z-order plus geometry. Walk each page's content stream carrying
// the current transformation matrix and clipping region; remember every opaque
// filled rectangle and every glyph box in device space, each stamped with the
// order it was painted; then report glyphs that a *later* rectangle covers.
// Order is what keeps this quiet on ordinary documents — table shading,
// highlight bars and page furniture are painted before the text that sits on
// them, so they never match, while a redaction box is by construction painted
// after.
//
// What it deliberately does not treat as a cover, because none of them hide
// anything from the reader: a translucent fill (`/ca` below 1), a non-Normal
// blend mode (which is what a flattened highlighter looks like), a stroked or
// clip-only path, and anything the clipping region crops away.
//
// What it cannot see, and so cannot report: text covered by an image or by a
// non-rectangular vector shape, and text hidden by a rectangle that is rotated
// far enough that its axis-aligned hull stops describing it. Those are gaps in
// this modality, not clean results — see the module header on why the
// difference matters.

/// Cap on any single decompressed stream. The corpus is by definition material
/// somebody else produced, so it is treated as hostile input.
const PDF_STREAM_LIMIT: usize = 64 << 20;
/// Per-page glyph cap, so one pathological page cannot eat the machine.
const PDF_MAX_GLYPHS: usize = 400_000;
/// Slack, in points, on the "glyph box sits inside the fill" test. Glyph
/// extents come from font metrics plus a nominal ascent/descent, so demanding
/// exact containment would drop real hits over a fraction of a point.
const PDF_COVER_TOL: f32 = 1.0;
/// How deep to follow form XObjects invoked by `Do`. Deep enough for real
/// documents, bounded so a cyclic one cannot spin forever.
const PDF_MAX_FORM_DEPTH: usize = 6;
/// How many boxes a clipping region keeps before collapsing to its hull.
const PDF_CLIP_PARTS: usize = 8;

/// PDF's affine transform `[a b c d e f]`, row-vector convention: a point is
/// `(x y 1) × M`, so `m.then(n)` reads as "apply m, then n".
#[derive(Clone, Copy)]
struct Mat([f32; 6]);

impl Mat {
    const ID: Mat = Mat([1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);

    fn translate(x: f32, y: f32) -> Mat {
        Mat([1.0, 0.0, 0.0, 1.0, x, y])
    }

    fn then(self, m: Mat) -> Mat {
        let (a, b) = (self.0, m.0);
        Mat([
            a[0] * b[0] + a[1] * b[2],
            a[0] * b[1] + a[1] * b[3],
            a[2] * b[0] + a[3] * b[2],
            a[2] * b[1] + a[3] * b[3],
            a[4] * b[0] + a[5] * b[2] + b[4],
            a[4] * b[1] + a[5] * b[3] + b[5],
        ])
    }

    fn apply(self, x: f32, y: f32) -> (f32, f32) {
        let a = self.0;
        (a[0] * x + a[2] * y + a[4], a[1] * x + a[3] * y + a[5])
    }
}

#[derive(Clone, Copy)]
struct Rect {
    x0: f32,
    y0: f32,
    x1: f32,
    y1: f32,
}

impl Rect {
    /// Axis-aligned hull of already-transformed points. Under a rotated matrix
    /// this is a superset of the real shape, which cuts both ways: a rotated
    /// fill looks larger (a hair more likely to seem covering) and a rotated
    /// text run looks larger (a hair less likely to seem covered). Rotated
    /// content is therefore approximate in both directions — see the header
    /// note on limitations rather than trusting it silently.
    fn hull(pts: &[(f32, f32)]) -> Rect {
        let mut r = Rect {
            x0: f32::MAX,
            y0: f32::MAX,
            x1: f32::MIN,
            y1: f32::MIN,
        };
        for (x, y) in pts {
            r.x0 = r.x0.min(*x);
            r.y0 = r.y0.min(*y);
            r.x1 = r.x1.max(*x);
            r.y1 = r.y1.max(*y);
        }
        r
    }

    /// Everything, for a clipping path that has not been narrowed yet.
    const UNBOUNDED: Rect = Rect {
        x0: -1.0e7,
        y0: -1.0e7,
        x1: 1.0e7,
        y1: 1.0e7,
    };

    fn covers(&self, o: &Rect) -> bool {
        o.x0 >= self.x0 - PDF_COVER_TOL
            && o.x1 <= self.x1 + PDF_COVER_TOL
            && o.y0 >= self.y0 - PDF_COVER_TOL
            && o.y1 <= self.y1 + PDF_COVER_TOL
    }

    fn meet(self, o: Rect) -> Rect {
        Rect {
            x0: self.x0.max(o.x0),
            y0: self.y0.max(o.y0),
            x1: self.x1.min(o.x1),
            y1: self.y1.min(o.y1),
        }
    }

    fn join(self, o: Rect) -> Rect {
        Rect {
            x0: self.x0.min(o.x0),
            y0: self.y0.min(o.y0),
            x1: self.x1.max(o.x1),
            y1: self.y1.max(o.y1),
        }
    }

    fn is_finite(&self) -> bool {
        self.x0.is_finite() && self.y0.is_finite() && self.x1.is_finite() && self.y1.is_finite()
    }

    fn is_empty(&self) -> bool {
        self.x1 <= self.x0 || self.y1 <= self.y0
    }
}

/// A clipping region, as a union of axis-aligned boxes.
///
/// One box is the common case, and it would be tempting to keep only that —
/// but the two-box case is precisely what a word processor emits when it shades
/// a table cell *around* the line of text in it: clip to the strips above and
/// below the baseline, then fill the whole cell. Collapsing that to a single
/// bounding box makes an ordinary shaded table cell look exactly like a box
/// drawn over its own text, and it was the largest remaining source of false
/// positives on a real corpus once plain clipping was honoured at all.
#[derive(Clone, Copy)]
struct Clip {
    parts: [Rect; PDF_CLIP_PARTS],
    len: usize,
}

impl Clip {
    const UNBOUNDED: Clip = Clip {
        parts: [Rect::UNBOUNDED; PDF_CLIP_PARTS],
        len: 1,
    };

    fn parts(&self) -> &[Rect] {
        &self.parts[..self.len]
    }

    /// Intersect with another union of boxes. The intersection of two unions is
    /// the union of the pairwise intersections; past the cap it collapses to the
    /// hull, which is a superset — so precision degrades but nothing is hidden.
    fn meet(self, other: &[Rect]) -> Clip {
        let mut found: Vec<Rect> = Vec::new();
        for a in self.parts() {
            for b in other {
                let m = a.meet(*b);
                if m.is_finite() && !m.is_empty() {
                    found.push(m);
                }
            }
        }
        let mut clip = Clip {
            parts: [Rect::UNBOUNDED; PDF_CLIP_PARTS],
            len: 0,
        };
        if found.len() > PDF_CLIP_PARTS {
            let hull = found.iter().copied().reduce(Rect::join).expect("non-empty");
            found = vec![hull];
        }
        for (slot, r) in clip.parts.iter_mut().zip(found) {
            *slot = r;
            clip.len += 1;
        }
        clip
    }
}

/// The subset of the graphics state that decides whether a fill hides anything.
#[derive(Clone, Copy)]
struct GState {
    ctm: Mat,
    /// `/ca` from an ExtGState. A translucent fill does not hide the text under
    /// it — the reader can see it — so it is not a redaction failure.
    fill_alpha: f32,
    /// Whether the blend mode is Normal. Multiply/darken fills are how flattened
    /// highlighter annotations look, and those are meant to be seen through.
    plain_blend: bool,
    /// The current clipping region. Ink outside it never reaches the page, and
    /// ignoring that was the single largest source of false positives measured
    /// on a real corpus: layout tools routinely draw an oversized background
    /// inside a small clip, which looks — to anyone not tracking the clip —
    /// exactly like a box drawn over the whole page.
    clip: Clip,
}

struct Cover {
    rect: Rect,
    order: usize,
}

struct Glyph {
    bbox: Rect,
    order: usize,
    size: f32,
    text: String,
}

/// What a walker needs to turn a character code into a position and a character.
struct FontInfo<'a> {
    /// Bytes per character code: 2 for Type0/CID composites, 1 otherwise.
    code_bytes: usize,
    /// Advances in glyph space (1/1000 em), keyed by code.
    widths: BTreeMap<u32, f32>,
    default_width: f32,
    /// lopdf's decoder, which understands ToUnicode CMaps, WinAnsi and
    /// `/Differences`. `None` when the font declares an encoding it cannot read
    /// — the glyph still counts as covered, it just reports as U+FFFD.
    encoding: Option<lopdf::Encoding<'a>>,
}

impl FontInfo<'_> {
    fn width(&self, code: u32) -> f32 {
        self.widths
            .get(&code)
            .copied()
            .unwrap_or(self.default_width)
    }
}

/// The `/Font`, `/XObject` and `/ExtGState` a content stream can name. Kept as
/// lists because a page inherits `/Resources` from its parent nodes and any
/// level of the chain may hold part of the answer.
struct Res<'a> {
    fonts: BTreeMap<Vec<u8>, FontInfo<'a>>,
    xobjects: Vec<&'a Dictionary>,
    extgstates: Vec<&'a Dictionary>,
}

fn deref<'a>(doc: &'a Document, obj: &'a Object) -> &'a Object {
    doc.dereference(obj).map(|(_, o)| o).unwrap_or(obj)
}

fn subdicts<'a>(doc: &'a Document, chain: &[&'a Dictionary], key: &[u8]) -> Vec<&'a Dictionary> {
    chain
        .iter()
        .filter_map(|d| d.get(key).ok())
        .filter_map(|o| deref(doc, o).as_dict().ok())
        .collect()
}

fn lookup<'a>(dicts: &[&'a Dictionary], name: &[u8]) -> Option<&'a Object> {
    dicts.iter().find_map(|d| d.get(name).ok())
}

/// Glyph advances for one font. Simple fonts carry `/Widths`; composites keep
/// theirs on the descendant CIDFont in the `/W` run-length form.
fn font_widths(doc: &Document, font: &Dictionary, composite: bool) -> (BTreeMap<u32, f32>, f32) {
    let mut widths = BTreeMap::new();
    if composite {
        let desc = font
            .get(b"DescendantFonts")
            .ok()
            .map(|o| deref(doc, o))
            .and_then(|o| o.as_array().ok())
            .and_then(|a| a.first())
            .map(|o| deref(doc, o))
            .and_then(|o| o.as_dict().ok());
        let Some(desc) = desc else {
            return (widths, 1000.0);
        };
        let default = desc
            .get(b"DW")
            .ok()
            .and_then(|o| o.as_float().ok())
            .unwrap_or(1000.0);
        if let Some(w) = desc
            .get(b"W")
            .ok()
            .map(|o| deref(doc, o))
            .and_then(|o| o.as_array().ok())
        {
            // `/W` alternates two shapes: `c [w …]` and `cFirst cLast w`.
            let mut i = 0usize;
            while i < w.len() {
                let Ok(first) = w[i].as_float() else { break };
                match w.get(i + 1).map(|o| deref(doc, o)) {
                    Some(Object::Array(list)) => {
                        for (k, item) in list.iter().enumerate() {
                            if let Ok(v) = item.as_float() {
                                widths.insert(first as u32 + k as u32, v);
                            }
                        }
                        i += 2;
                    }
                    Some(_) => {
                        let last = w[i + 1].as_float().unwrap_or(first);
                        let v = w
                            .get(i + 2)
                            .and_then(|o| o.as_float().ok())
                            .unwrap_or(default);
                        // guard against a corrupt range asking for a huge map
                        let last = last.min(first + 65_535.0);
                        let mut c = first as u32;
                        while c <= last as u32 {
                            widths.insert(c, v);
                            c += 1;
                        }
                        i += 3;
                    }
                    None => break,
                }
            }
        }
        return (widths, default);
    }

    let first = font
        .get(b"FirstChar")
        .ok()
        .and_then(|o| o.as_i64().ok())
        .unwrap_or(0);
    if let Some(list) = font
        .get(b"Widths")
        .ok()
        .map(|o| deref(doc, o))
        .and_then(|o| o.as_array().ok())
    {
        for (k, item) in list.iter().enumerate() {
            if let Ok(v) = deref(doc, item).as_float() {
                widths.insert((first + k as i64).max(0) as u32, v);
            }
        }
    }
    let missing = font
        .get(b"FontDescriptor")
        .ok()
        .map(|o| deref(doc, o))
        .and_then(|o| o.as_dict().ok())
        .and_then(|d| d.get(b"MissingWidth").ok())
        .and_then(|o| o.as_float().ok())
        // 500/1000 em is a middling Latin glyph: wrong, but wrong by a little
        // in both directions rather than systematically short.
        .unwrap_or(500.0);
    (widths, missing)
}

fn build_res<'a>(doc: &'a Document, chain: &[&'a Dictionary]) -> Res<'a> {
    let mut fonts: BTreeMap<Vec<u8>, FontInfo<'a>> = BTreeMap::new();
    for fdict in subdicts(doc, chain, b"Font") {
        for (name, value) in fdict.iter() {
            if fonts.contains_key(name) {
                continue;
            }
            let Ok(font) = deref(doc, value).as_dict() else {
                continue;
            };
            let composite = font
                .get(b"Subtype")
                .and_then(|o| o.as_name())
                .map(|n| n == b"Type0")
                .unwrap_or(false);
            let (widths, default_width) = font_widths(doc, font, composite);
            fonts.insert(
                name.clone(),
                FontInfo {
                    code_bytes: if composite { 2 } else { 1 },
                    widths,
                    default_width,
                    encoding: font
                        .get_font_encoding_with_limit(doc, PDF_STREAM_LIMIT)
                        .ok(),
                },
            );
        }
    }
    Res {
        fonts,
        xobjects: subdicts(doc, chain, b"XObject"),
        extgstates: subdicts(doc, chain, b"ExtGState"),
    }
}

fn opnum(op: &lopdf::content::Operation, i: usize) -> f32 {
    op.operands
        .get(i)
        .and_then(|o| o.as_float().ok())
        .unwrap_or(0.0)
}

fn opmat(op: &lopdf::content::Operation) -> Mat {
    Mat([
        opnum(op, 0),
        opnum(op, 1),
        opnum(op, 2),
        opnum(op, 3),
        opnum(op, 4),
        opnum(op, 5),
    ])
}

/// Everything inside a `BT`/`ET` block that decides where a shown string lands.
/// `tm` is the text matrix, `tlm` the text-line matrix it is re-based from.
#[derive(Clone, Copy)]
struct TState<'r, 'a> {
    tm: Mat,
    tlm: Mat,
    font: Option<&'r FontInfo<'a>>,
    size: f32,
    /// character spacing
    tc: f32,
    /// word spacing — applies to single-byte code 32 only
    tw: f32,
    /// horizontal scale, as a factor rather than the operator's percent
    th: f32,
    /// leading
    tl: f32,
    /// rise
    ts: f32,
}

impl TState<'_, '_> {
    fn new() -> Self {
        TState {
            tm: Mat::ID,
            tlm: Mat::ID,
            font: None,
            size: 0.0,
            tc: 0.0,
            tw: 0.0,
            th: 1.0,
            tl: 0.0,
            ts: 0.0,
        }
    }

    fn line(&mut self, tx: f32, ty: f32) {
        self.tlm = Mat::translate(tx, ty).then(self.tlm);
        self.tm = self.tlm;
    }
}

struct PageScan<'a> {
    doc: &'a Document,
    order: usize,
    covers: Vec<Cover>,
    glyphs: Vec<Glyph>,
}

impl<'a> PageScan<'a> {
    /// Interpret one content stream, appending to `covers` and `glyphs`.
    fn stream(&mut self, content: &[u8], res: &Res<'a>, base: GState, depth: usize) -> Result<()> {
        let doc = self.doc;
        let ops = lopdf::content::Content::decode(content)
            .map_err(|e| anyhow!("content stream undecodable: {e}"))?
            .operations;

        let mut gs = base;
        let mut stack: Vec<(GState, TState)> = Vec::new();

        // Current path in device space. `boxes` holds the parts we can treat as
        // covering rectangles; `pts` holds every point of the whole path, which
        // bounds it for clipping purposes (a Bézier stays inside the hull of its
        // control points, so including those keeps the bound honest).
        let mut boxes: Vec<Rect> = Vec::new();
        let mut pts: Vec<(f32, f32)> = Vec::new();
        let mut sub: Vec<(f32, f32)> = Vec::new();
        let mut sub_curved = false;
        // set when a subpath was not a box, which means `boxes` no longer
        // describes the whole path and only its hull can be trusted
        let mut irregular = false;
        let mut pending_clip = false;

        let mut t = TState::new();

        for op in &ops {
            self.order += 1;
            match op.operator.as_str() {
                "q" => stack.push((gs, t)),
                "Q" => {
                    if let Some((saved_gs, saved_t)) = stack.pop() {
                        gs = saved_gs;
                        // Text state *parameters* live in the graphics state and
                        // come back with it; the text matrices do not, and are
                        // owned by the enclosing `BT` block.
                        let (tm, tlm) = (t.tm, t.tlm);
                        t = saved_t;
                        t.tm = tm;
                        t.tlm = tlm;
                    }
                }
                "cm" => gs.ctm = opmat(op).then(gs.ctm),
                "gs" => {
                    let named = op
                        .operands
                        .first()
                        .and_then(|o| o.as_name().ok())
                        .and_then(|n| lookup(&res.extgstates, n))
                        .map(|o| deref(doc, o))
                        .and_then(|o| o.as_dict().ok());
                    if let Some(d) = named {
                        if let Some(ca) = d.get(b"ca").ok().and_then(|o| o.as_float().ok()) {
                            gs.fill_alpha = ca;
                        }
                        if let Ok(bm) = d.get(b"BM") {
                            let name = match deref(doc, bm) {
                                Object::Name(n) => n.clone(),
                                Object::Array(a) => a
                                    .first()
                                    .and_then(|o| o.as_name().ok())
                                    .map(|n| n.to_vec())
                                    .unwrap_or_default(),
                                _ => Vec::new(),
                            };
                            gs.plain_blend =
                                name.is_empty() || name == b"Normal" || name == b"Compatible";
                        }
                    }
                }

                // ── path construction ──
                "re" => {
                    let (x, y, w, h) = (opnum(op, 0), opnum(op, 1), opnum(op, 2), opnum(op, 3));
                    let corners = [
                        gs.ctm.apply(x, y),
                        gs.ctm.apply(x + w, y),
                        gs.ctm.apply(x, y + h),
                        gs.ctm.apply(x + w, y + h),
                    ];
                    boxes.push(Rect::hull(&corners));
                    pts.extend_from_slice(&corners);
                }
                "m" => {
                    irregular |= !flush_subpath(&mut sub, &mut sub_curved, &mut boxes);
                    let p = gs.ctm.apply(opnum(op, 0), opnum(op, 1));
                    sub.push(p);
                    pts.push(p);
                }
                "l" => {
                    let p = gs.ctm.apply(opnum(op, 0), opnum(op, 1));
                    sub.push(p);
                    pts.push(p);
                }
                "c" | "v" | "y" => {
                    sub_curved = true;
                    for i in (0..op.operands.len().saturating_sub(1)).step_by(2) {
                        let p = gs.ctm.apply(opnum(op, i), opnum(op, i + 1));
                        pts.push(p);
                        // Feed the control points into the subpath too, not only
                        // the page-wide point set. A Bézier lies inside the hull
                        // of its control points, so this over-approximates the
                        // outline — which is what lets `flush_subpath` recognise
                        // a rounded rectangle instead of discarding it.
                        sub.push(p);
                    }
                }
                "h" => {}
                "W" | "W*" => pending_clip = true,

                // ── path painting ──
                "f" | "F" | "f*" | "b" | "b*" | "B" | "B*" | "S" | "s" | "n" => {
                    irregular |= !flush_subpath(&mut sub, &mut sub_curved, &mut boxes);
                    let fills = !matches!(op.operator.as_str(), "S" | "s" | "n");
                    if fills && gs.fill_alpha >= 0.99 && gs.plain_blend {
                        for r in &boxes {
                            // The painting happens under the clip in force
                            // *before* this path's own `W`, per §8.5.4.
                            for part in gs.clip.parts() {
                                let r = r.meet(*part);
                                if r.is_finite() && !r.is_empty() {
                                    self.covers.push(Cover {
                                        rect: r,
                                        order: self.order,
                                    });
                                }
                            }
                        }
                    }
                    if pending_clip && !pts.is_empty() {
                        // Boxes describe the path exactly when every subpath was
                        // one; otherwise only the hull is safe, and a too-large
                        // clip can only cost precision, never a missed hit.
                        let hull = [Rect::hull(&pts)];
                        let region: &[Rect] = if irregular || boxes.is_empty() {
                            &hull
                        } else {
                            &boxes
                        };
                        gs.clip = gs.clip.meet(region);
                    }
                    boxes.clear();
                    pts.clear();
                    sub.clear();
                    sub_curved = false;
                    irregular = false;
                    pending_clip = false;
                }

                // ── text ──
                "BT" => {
                    t.tm = Mat::ID;
                    t.tlm = Mat::ID;
                }
                "Tf" => {
                    t.font = op
                        .operands
                        .first()
                        .and_then(|o| o.as_name().ok())
                        .and_then(|n| res.fonts.get(n));
                    t.size = opnum(op, 1);
                }
                "Td" => t.line(opnum(op, 0), opnum(op, 1)),
                "TD" => {
                    t.tl = -opnum(op, 1);
                    t.line(opnum(op, 0), opnum(op, 1));
                }
                "Tm" => {
                    t.tlm = opmat(op);
                    t.tm = t.tlm;
                }
                "T*" => t.line(0.0, -t.tl),
                "TL" => t.tl = opnum(op, 0),
                "Tc" => t.tc = opnum(op, 0),
                "Tw" => t.tw = opnum(op, 0),
                "Tz" => t.th = opnum(op, 0) / 100.0,
                "Ts" => t.ts = opnum(op, 0),
                "Tj" => {
                    if let Some(bytes) = op.operands.first().and_then(|o| o.as_str().ok()) {
                        self.show(bytes, &mut t, gs.ctm);
                    }
                }
                // `'` is `T* Tj`, and `"` is `aw Tw ac Tc T* Tj`
                "'" | "\"" => {
                    let bytes = if op.operator == "\"" {
                        t.tw = opnum(op, 0);
                        t.tc = opnum(op, 1);
                        op.operands.get(2)
                    } else {
                        op.operands.first()
                    };
                    t.line(0.0, -t.tl);
                    if let Some(bytes) = bytes.and_then(|o| o.as_str().ok()) {
                        self.show(bytes, &mut t, gs.ctm);
                    }
                }
                "TJ" => {
                    let items = op.operands.first().and_then(|o| o.as_array().ok());
                    for item in items.into_iter().flatten() {
                        match item {
                            Object::String(bytes, _) => self.show(bytes, &mut t, gs.ctm),
                            // a number is a kerning adjustment, in thousandths
                            // of the font size, subtracted from the pen
                            _ => {
                                if let Ok(n) = item.as_float() {
                                    t.tm =
                                        Mat::translate(-n / 1000.0 * t.size * t.th, 0.0).then(t.tm);
                                }
                            }
                        }
                    }
                }

                // ── form XObjects: their contents paint into this page, in
                // this position in the z-order, so they have to be walked too.
                "Do" if depth < PDF_MAX_FORM_DEPTH => {
                    let stream = op
                        .operands
                        .first()
                        .and_then(|o| o.as_name().ok())
                        .and_then(|n| lookup(&res.xobjects, n))
                        .map(|o| deref(doc, o))
                        .and_then(|o| o.as_stream().ok());
                    let Some(stream) = stream else { continue };
                    if stream.dict.get(b"Subtype").and_then(|o| o.as_name()).ok() != Some(b"Form") {
                        continue;
                    }
                    let Ok(inner) = stream.get_plain_content_with_limit(PDF_STREAM_LIMIT) else {
                        continue;
                    };
                    let matrix = stream
                        .dict
                        .get(b"Matrix")
                        .ok()
                        .and_then(|o| o.as_array().ok())
                        .filter(|a| a.len() == 6)
                        .map(|a| {
                            let mut m = [0.0f32; 6];
                            for (k, slot) in m.iter_mut().enumerate() {
                                *slot = a[k].as_float().unwrap_or(if k == 0 || k == 3 {
                                    1.0
                                } else {
                                    0.0
                                });
                            }
                            Mat(m)
                        })
                        .unwrap_or(Mat::ID);
                    let ctm = matrix.then(gs.ctm);
                    // `/BBox` clips the form's contents, and layout tools lean on
                    // it hard — a form whose body paints a full-page rectangle is
                    // routine when the BBox crops it to a footer strip.
                    let bbox = stream
                        .dict
                        .get(b"BBox")
                        .ok()
                        .and_then(|o| deref(doc, o).as_array().ok())
                        .filter(|a| a.len() == 4)
                        .map(|a| {
                            let v: Vec<f32> =
                                a.iter().map(|o| o.as_float().unwrap_or(0.0)).collect();
                            Rect::hull(&[
                                ctm.apply(v[0], v[1]),
                                ctm.apply(v[2], v[1]),
                                ctm.apply(v[0], v[3]),
                                ctm.apply(v[2], v[3]),
                            ])
                        })
                        .unwrap_or(Rect::UNBOUNDED);
                    let inner_gs = GState {
                        ctm,
                        clip: gs.clip.meet(&[bbox]),
                        ..gs
                    };
                    let own = stream
                        .dict
                        .get(b"Resources")
                        .ok()
                        .map(|o| deref(doc, o))
                        .and_then(|o| o.as_dict().ok());
                    match own {
                        Some(d) => {
                            let inner_res = build_res(doc, &[d]);
                            self.stream(&inner, &inner_res, inner_gs, depth + 1)?;
                        }
                        // no `/Resources` of its own: the spec lets it inherit
                        // the page's, and plenty of real generators rely on it
                        None => self.stream(&inner, res, inner_gs, depth + 1)?,
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Lay out one shown string, recording a box per glyph and advancing the pen.
    fn show(&mut self, bytes: &[u8], t: &mut TState, ctm: Mat) {
        let Some(font) = t.font else {
            // No `/Tf` we could resolve. These glyphs cannot be placed, but the
            // pen can be kept roughly honest so later runs are not thrown off.
            t.tm = Mat::translate(bytes.len() as f32 * 0.5 * t.size * t.th, 0.0).then(t.tm);
            return;
        };
        // Nominal ascent/descent as a fraction of the em. Real face metrics
        // vary, but a box drawn to hide a line of text is drawn with margin,
        // and per-glyph bounding boxes from the embedded font would cost a full
        // font parser for a fraction of a point.
        let (up, down) = (0.70 * t.size, 0.20 * t.size);
        for chunk in bytes.chunks(font.code_bytes) {
            let mut code = 0u32;
            for b in chunk {
                code = code * 256 + *b as u32;
            }
            let w = font.width(code) / 1000.0 * t.size * t.th;
            if self.glyphs.len() < PDF_MAX_GLYPHS {
                let trm = t.tm.then(ctm);
                let bbox = Rect::hull(&[
                    trm.apply(0.0, t.ts - down),
                    trm.apply(w, t.ts - down),
                    trm.apply(0.0, t.ts + up),
                    trm.apply(w, t.ts + up),
                ]);
                let text = font
                    .encoding
                    .as_ref()
                    .and_then(|e| e.bytes_to_string(chunk).ok())
                    // Undecodable is still *present*: report the glyph as
                    // U+FFFD rather than pretend the box covers nothing.
                    .unwrap_or_else(|| "\u{FFFD}".to_string());
                if bbox.is_finite() && !text.is_empty() {
                    self.glyphs.push(Glyph {
                        bbox,
                        order: self.order,
                        size: t.size,
                        text,
                    });
                }
            }
            let word = if font.code_bytes == 1 && code == 32 {
                t.tw
            } else {
                0.0
            };
            t.tm = Mat::translate(
                (font.width(code) / 1000.0 * t.size + t.tc + word) * t.th,
                0.0,
            )
            .then(t.tm);
        }
    }

    /// Emit one finding per fill that has extractable text under it.
    fn report(&self, page: u32, carrier: &Carrier, out: &mut Vec<Found>) {
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for cover in &self.covers {
            let mut text = String::new();
            let mut prev: Option<&Glyph> = None;
            for g in self
                .glyphs
                .iter()
                .filter(|g| g.order < cover.order && cover.rect.covers(&g.bbox))
            {
                // PDF writers routinely omit space glyphs and express the gap
                // as kerning instead, so word and line breaks have to be
                // reconstructed from geometry or the report reads as one word.
                if let Some(p) = prev {
                    let newline = (g.bbox.y0 - p.bbox.y0).abs() > 0.5 * g.size;
                    if (newline || g.bbox.x0 - p.bbox.x1 > 0.18 * g.size) && !text.ends_with(' ') {
                        text.push(' ');
                    }
                }
                text.push_str(&g.text);
                prev = Some(g);
            }
            let text = text.trim();
            if text.is_empty() {
                continue;
            }
            let r = &cover.rect;
            let locator = format!(
                "page {page}:box({:.0},{:.0} {:.0}x{:.0})",
                r.x0,
                r.y0,
                r.x1 - r.x0,
                r.y1 - r.y0
            );
            // A box painted twice, or nested boxes over the same words, is one
            // problem — a human should not have to dismiss it repeatedly.
            if !seen.insert(format!("{locator}\u{0}{text}")) {
                continue;
            }
            let value = if text.chars().count() > 1000 {
                format!("{}…", text.chars().take(1000).collect::<String>())
            } else {
                text.to_string()
            };
            out.push(member_found(
                modality::PDF_REDACTION_RECT,
                carrier.clone(),
                locator,
                value,
            ));
        }
    }
}

/// A closed subpath of straight segments is a rectangle often enough to be
/// worth recognising — a good number of writers emit `m l l l h` where the spec
/// would let them say `re`, and the black box looks identical either way.
///
/// Returns whether the subpath was consumed as a box; `false` means the caller
/// is left with only the path's hull to reason about.
/// The bounding box of `pts`, but only if the closed polygon through them fills
/// at least `min_ratio` of that box. Shoelace area against the box area — the
/// cheap test for "this shape is box-shaped", which is what distinguishes a
/// rounded redaction rectangle from an arrow or a wedge.
fn polygon_fills_its_bbox(pts: &[(f32, f32)], min_ratio: f32) -> Option<Rect> {
    if pts.len() < 3 {
        return None;
    }
    let hull = Rect::hull(pts);
    let box_area = (hull.x1 - hull.x0) * (hull.y1 - hull.y0);
    // A degenerate box has no interior to cover, so nothing can hide in it.
    if !box_area.is_finite() || box_area <= 0.0 {
        return None;
    }
    let mut twice = 0.0f32;
    for i in 0..pts.len() {
        let (x0, y0) = pts[i];
        let (x1, y1) = pts[(i + 1) % pts.len()];
        twice += x0 * y1 - x1 * y0;
    }
    let area = (twice * 0.5).abs();
    (area / box_area >= min_ratio).then_some(hull)
}

fn flush_subpath(sub: &mut Vec<(f32, f32)>, curved: &mut bool, boxes: &mut Vec<Rect>) -> bool {
    let pts = std::mem::take(sub);
    let was_curved = std::mem::replace(curved, false);
    if pts.is_empty() {
        return true;
    }
    if was_curved {
        // A curved subpath is usually not a cover — but a ROUNDED RECTANGLE is,
        // and it is what several annotation tools draw when a person reaches for
        // the redaction box. Discarding every curve outright left a recall hole
        // in the one case this modality exists for.
        //
        // The discriminator is how much of its own bounding box the shape fills,
        // measured on the control-point polygon (a Bézier lies inside its control
        // hull, so this over-approximates the outline). A rounded rectangle scores
        // ~0.99 because its corner control points reach the sharp corners; a
        // circle drawn as four Béziers scores ~0.90, since its eight control
        // points form an octagon; a triangle ~0.5.
        //
        // 0.97 is measured, not guessed. Against a 625-PDF corpus, with curves
        // rejected outright as the baseline (319 findings / 38 documents):
        //   0.85 -> 577 / 55    0.92 -> 482 / 49    0.97 -> 448 / 49
        // All three still catch the rounded box and still reject the triangle, so
        // 0.97 buys the same recall for 11 extra documents of review rather than
        // 17. It also lands cleanly between the rounded-rect and circle scores,
        // which is a boundary with a reason behind it rather than a tuned number.
        //
        // The recorded cover is the bounding box, so a genuinely round shape would
        // over-claim its corners — one reason to sit above the circle score
        // instead of below it.
        return polygon_fills_its_bbox(&pts, 0.97)
            .inspect(|r| boxes.push(*r))
            .is_some();
    }
    let n = if pts.len() == 5 && pts[0] == pts[4] {
        4
    } else {
        pts.len()
    };
    if n != 4 {
        return false;
    }
    let axis_aligned = (0..4).all(|i| {
        let a = pts[i];
        let b = pts[(i + 1) % 4];
        (a.0 - b.0).abs() < 0.01 || (a.1 - b.1).abs() < 0.01
    });
    if axis_aligned {
        boxes.push(Rect::hull(&pts[..4]));
    }
    axis_aligned
}

/// Keys of the information dictionary. `Producer`/`Creator` name the software,
/// which sounds harmless right up until it names an internal build that only
/// one organisation runs.
const PDF_INFO_KEYS: &[&str] = &[
    "Author",
    "Creator",
    "Producer",
    "Title",
    "Subject",
    "Keywords",
    "CreationDate",
    "ModDate",
];

/// XMP fields that carry a person, a machine or a document lineage. Matched by
/// local name, so `dc:creator` and a bare `creator` are the same field.
const PDF_XMP_FIELDS: &[&str] = &[
    "creator",
    "title",
    "description",
    "rights",
    "CreatorTool",
    "CreateDate",
    "ModifyDate",
    "MetadataDate",
    "Producer",
    "Keywords",
    "Company",
    "Author",
    "AuthorsPosition",
    "Credit",
    "Source",
    "DocumentID",
    "InstanceID",
    "OriginalDocumentID",
];

fn pdf_value_text(doc: &Document, obj: &Object) -> Option<String> {
    let obj = deref(doc, obj);
    let s = match obj {
        Object::String(..) => lopdf::decode_text_string(obj).ok()?,
        Object::Name(n) => String::from_utf8_lossy(n).to_string(),
        Object::Integer(i) => i.to_string(),
        Object::Real(r) => r.to_string(),
        Object::Boolean(b) => b.to_string(),
        _ => return None,
    };
    let s = s.trim().to_string();
    // An absent or blank field is a clean result, not a finding.
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// `file` is the carrier for information-dictionary findings: lopdf hands back
/// decoded objects, not the byte range they were parsed from, so the smallest
/// honest unit posture can name for them is the document it read. XMP findings
/// do have their own extracted packet and use it.
fn extract_pdf_metadata(doc: &Document, file: &Carrier, out: &mut Vec<Found>) {
    if let Some(info) = doc
        .trailer
        .get(b"Info")
        .ok()
        .map(|o| deref(doc, o))
        .and_then(|o| o.as_dict().ok())
    {
        for key in PDF_INFO_KEYS {
            if let Some(v) = info
                .get(key.as_bytes())
                .ok()
                .and_then(|o| pdf_value_text(doc, o))
            {
                out.push(member_found(
                    modality::PDF_METADATA,
                    file.clone(),
                    format!("Info:{key}"),
                    v,
                ));
            }
        }
        // Custom keys are where workflow tools stash things like an internal
        // matter number or the name of the reviewer, so they are reported too.
        for (name, value) in info.iter() {
            let name = String::from_utf8_lossy(name).to_string();
            if PDF_INFO_KEYS.contains(&name.as_str()) || name == "Trapped" {
                continue;
            }
            if let Some(v) = pdf_value_text(doc, value) {
                out.push(member_found(
                    modality::PDF_METADATA,
                    file.clone(),
                    format!("Info:{name}"),
                    v,
                ));
            }
        }
    }

    // The XMP packet is a second, independent copy of much of the above, and
    // scrubbing tools have a long history of clearing one and not the other.
    let xmp = doc
        .catalog()
        .ok()
        .and_then(|c| c.get(b"Metadata").ok())
        .map(|o| deref(doc, o))
        .and_then(|o| o.as_stream().ok())
        .and_then(|s| s.get_plain_content_with_limit(PDF_STREAM_LIMIT).ok());
    let Some(xmp) = xmp else { return };
    let packet = Carrier::member(&xmp);
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for field in PDF_XMP_FIELDS {
        let mut values = xml_tag_texts(&xmp, field);
        // XMP's compact form puts the same properties on rdf:Description as
        // attributes instead of child elements; both are in the wild.
        values.extend(
            xml_attrs(&xmp, "Description", field)
                .into_iter()
                .map(|(_, v)| v),
        );
        for v in values {
            let v = v.trim().to_string();
            if v.is_empty() || !seen.insert(format!("{field}\u{0}{v}")) {
                continue;
            }
            let v = if v.chars().count() > 400 {
                format!("{}…", v.chars().take(400).collect::<String>())
            } else {
                v
            };
            out.push(member_found(
                modality::PDF_METADATA,
                packet.clone(),
                format!("XMP:{field}"),
                v,
            ));
        }
    }
}

/// PDF — document metadata, and the text a drawn box only appears to remove.
fn extract_pdf(path: &Path) -> Result<Vec<Found>> {
    let doc = Document::load_with_options(
        path,
        lopdf::LoadOptions {
            max_decompressed_size: Some(PDF_STREAM_LIMIT),
            ..Default::default()
        },
    )
    .map_err(|e| anyhow!("load pdf: {e}"))?;

    let mut out = Vec::new();
    let file = Carrier::Member(
        blake3::Hasher::new()
            .update_reader(std::fs::File::open(path)?)
            .map_err(|error| anyhow!("hash pdf: {error}"))?
            .finalize()
            .to_hex()
            .to_string(),
    );
    // A PDF with no `/Info` and no XMP leaves this empty, which is the honest
    // answer: nothing found, not a failure to look.
    extract_pdf_metadata(&doc, &file, &mut out);

    for (page_no, page_id) in doc.get_pages() {
        let content = doc
            .get_page_content_with_limit(page_id, PDF_STREAM_LIMIT)
            // A page we cannot read is not a clean page. Failing the whole file
            // costs the metadata findings above, and that is the right trade:
            // the file lands in the scan's "failed to parse — unexamined" list,
            // where a human opens it, instead of passing as quietly checked.
            .map_err(|e| anyhow!("page {page_no}: content unreadable ({e}) — page NOT examined"))?;
        let chain = resource_chain(&doc, page_id);
        let res = build_res(&doc, &chain);
        let mut scan = PageScan {
            doc: &doc,
            order: 0,
            covers: Vec::new(),
            glyphs: Vec::new(),
        };
        // Page rotation and a shifted MediaBox move covers and glyphs together,
        // so containment is unaffected and the identity is the right base.
        let base = GState {
            ctm: Mat::ID,
            fill_alpha: 1.0,
            plain_blend: true,
            clip: Clip::UNBOUNDED,
        };
        scan.stream(&content, &res, base, 0)
            .map_err(|e| anyhow!("page {page_no}: {e}"))?;
        scan.report(page_no, &Carrier::member(&content), &mut out);
    }
    Ok(out)
}

/// The resource dictionaries in scope for a page, nearest first.
fn resource_chain<'a>(doc: &'a Document, page_id: lopdf::ObjectId) -> Vec<&'a Dictionary> {
    let mut chain = Vec::new();
    if let Ok((direct, inherited)) = doc.get_page_resources(page_id) {
        if let Some(d) = direct {
            chain.push(d);
        }
        for id in inherited {
            if let Ok(d) = doc.get_dictionary(id) {
                chain.push(d);
            }
        }
    }
    chain
}

/// Which extractor, if any, understands this file.
fn dispatch(path: &Path) -> Result<Option<fn(&Path) -> Result<Vec<Found>>>> {
    // CONTENT FIRST. An extension is a claim the filename makes; magic bytes are
    // what the file actually is. A real .pptx renamed `archive.dat` and a real
    // .pdf renamed `report.bin` were both walked past until this sniffed
    // instead. Disclosing them as "never opened" was honest, but a tool tuned
    // for recall should not need the filename's cooperation — and a file someone
    // wanted overlooked is precisely the one that will not cooperate.
    let sniffed = sniff(path);
    // Extension as fallback: an unreadable or truncated header should not
    // downgrade a file we would otherwise have tried.
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let fallback = match ext.as_str() {
        "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" => Some(extract_ooxml as _),
        "jpg" | "jpeg" | "tif" | "tiff" | "heic" | "heif" | "png" | "webp" => {
            Some(extract_exif as _)
        }
        "pdf" => Some(extract_pdf as _),
        _ => None,
    };
    match sniffed {
        Ok(Some(extractor)) => Ok(Some(extractor)),
        Ok(None) => Ok(fallback),
        // A useful extension still lets the actual extractor produce the most
        // specific error. Otherwise an unreadable header is a parse failure,
        // never an unsupported (and therefore apparently harmless) file.
        Err(_) if fallback.is_some() => Ok(fallback),
        Err(error) => Err(error),
    }
}

/// Identify by leading bytes. One short read per file.
fn sniff(path: &Path) -> Result<Option<fn(&Path) -> Result<Vec<Found>>>> {
    use std::io::Read;
    let mut head = [0u8; 12];
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("open {} for type detection", path.display()))?;
    let n = file
        .read(&mut head)
        .with_context(|| format!("read {} for type detection", path.display()))?;
    let h = &head[..n];
    if h.starts_with(b"%PDF") {
        return Ok(Some(extract_pdf));
    }
    // OOXML is a zip. A plain zip simply yields no findings, which is correct.
    if h.starts_with(b"PK\x03\x04") || h.starts_with(b"PK\x05\x06") {
        return Ok(Some(extract_ooxml));
    }
    let heif = h.len() >= 12 && &h[4..8] == b"ftyp";
    if h.starts_with(&[0xFF, 0xD8, 0xFF])
        || h.starts_with(&[0x89, b'P', b'N', b'G'])
        || h.starts_with(b"II*\0")
        || h.starts_with(b"MM\0*")
        || heif
    {
        return Ok(Some(extract_exif));
    }
    Ok(None)
}

/// The modalities this build actually applies.
const IMPLEMENTED: &[Id] = &[
    modality::OOXML_CORE_PROPS,
    modality::OOXML_COMMENTS,
    modality::OOXML_TRACKED_CHANGES,
    modality::OOXML_SPEAKER_NOTES,
    modality::OOXML_HIDDEN_SHEET,
    modality::EXIF,
    modality::PDF_METADATA,
    modality::PDF_REDACTION_RECT,
];

/// Collect files under `root`, counting the directory symlinks NOT followed.
///
/// Directory symlinks are deliberately not traversed. A loop back to an ancestor
/// made a one-file directory report 34 files — the OS's symlink-resolution limit
/// stopped it, not this code — and a link to `/` would have walked the entire
/// filesystem. Symlinked FILES are still scanned; only directory traversal
/// stops, and the count is reported so the omission is visible rather than
/// assumed.
#[derive(Clone, Debug)]
struct WalkOmission {
    path: PathBuf,
    detail: String,
}

fn walk(root: &Path, out: &mut Vec<PathBuf>, omissions: &mut Vec<WalkOmission>) {
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) => {
            omissions.push(WalkOmission {
                path: root.to_path_buf(),
                detail: format!("metadata failed: {error}"),
            });
            return;
        }
    };
    if metadata.file_type().is_symlink() {
        if root.is_file() {
            out.push(root.to_path_buf());
        } else {
            omissions.push(WalkOmission {
                path: root.to_path_buf(),
                detail: "symlinked directory not followed".to_owned(),
            });
        }
        return;
    }
    if metadata.is_file() {
        out.push(root.to_path_buf());
        return;
    }
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) => {
            omissions.push(WalkOmission {
                path: root.to_path_buf(),
                detail: format!("directory read failed: {error}"),
            });
            return;
        }
    };
    for entry in entries {
        let e = match entry {
            Ok(entry) => entry,
            Err(error) => {
                omissions.push(WalkOmission {
                    path: root.to_path_buf(),
                    detail: format!("directory entry read failed: {error}"),
                });
                continue;
            }
        };
        let p = e.path();
        // skip VCS internals; they are not the corpus
        if p.file_name().and_then(|n| n.to_str()) == Some(".git") {
            continue;
        }
        // `symlink_metadata` does not follow the link, so this asks what the
        // entry IS rather than what it points at.
        walk(&p, out, omissions);
    }
}

// ── collection plumbing ─────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct PostureStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

#[derive(Debug)]
struct CollectionView {
    facts: TribleSet,
    reader: PileReader,
}

impl PostureStorage<'_> {
    fn load_scope(&self, scope: Id, label: &str) -> Result<CollectionView> {
        // Authority is loaded before storage is touched. Ordinary reads and
        // writes never mint an identity or substitute an ephemeral signer.
        let signer = load_signer(self.pile, self.key)?;
        let pile = open_pile_strict(self.pile)?;
        let author = signer.verifying_key().to_bytes();
        let mut collection = open_scope(pile, scope, signer);
        let result = (|| {
            let (facts, _) = materialize_stable(&mut collection, scope, author, label)?;
            let reader = collection
                .storage_mut()
                .reader()
                .with_context(|| format!("open Posture {label} blob reader"))?;
            Ok(CollectionView { facts, reader })
        })();
        finish_pile(collection.into_storage(), result)
    }

    /// The signed COMMITs this key authored in `scope`. Tests use it to check
    /// that one scan is one atomic COMMIT; ordinary reads never need it.
    #[cfg(test)]
    fn authored_commits(&self, scope: Id, label: &str) -> Result<Vec<CollectionCommit>> {
        let signer = load_signer(self.pile, self.key)?;
        let pile = open_pile_strict(self.pile)?;
        let author = signer.verifying_key().to_bytes();
        let mut collection = open_scope(pile, scope, signer);
        let result = (|| Ok(materialize_stable(&mut collection, scope, author, label)?.1))();
        finish_pile(collection.into_storage(), result)
    }

    fn policy_view(&self) -> Result<CollectionView> {
        let view = self.load_scope(DEFAULT_POLICY_SCOPE_ID, "policy")?;
        validate_policy_view(&view)?;
        Ok(view)
    }

    /// Reads do not validate. See [`validate_scan_commits`].
    fn scan_view(&self) -> Result<CollectionView> {
        self.load_scope(DEFAULT_SCAN_SCOPE_ID, "scan")
    }

    fn decide_view(&self) -> Result<CollectionView> {
        let view = self.load_scope(DEFAULT_DECIDE_SCOPE_ID, "Decide")?;
        decide::validate_catalog(&view.reader, &view.facts)
            .context("validate authored Decide collection")?;
        Ok(view)
    }

    fn publish_policy(
        &self,
        mut fragment: Fragment,
        description: &str,
    ) -> Result<CollectionCommit> {
        self.with_collection(
            DEFAULT_POLICY_SCOPE_ID,
            "policy",
            |collection, current, reader, _| {
                faculties::posture_policy::validate_policy_catalog_union(reader, current, &fragment)?;
                fragment.describe_with(entity! { metadata::description: description.to_owned() });
                collection
                    .commit(fragment)
                    .context("commit authored Posture policy fragment")
            },
        )
    }

    fn publish_scan(&self, mut fragment: Fragment, description: &str) -> Result<CollectionCommit> {
        self.with_collection(
            DEFAULT_SCAN_SCOPE_ID,
            "scan",
            |collection, _current, reader, commits| {
                let scan = validate_scan_commit_fragment(fragment.facts())?;
                validate_scan_commits(reader, commits, scan)?;
                let mut staged_blobs = fragment.blobs().clone();
                let staged = staged_blobs
                    .reader()
                    .context("snapshot staged Posture scan payloads")?;
                // Only the fragment being written is validated. The accumulated
                // past is not re-judged against today's schema.
                validate_scan_catalog_with(reader, Some(&staged), fragment.facts())?;
                fragment.describe_with(entity! { metadata::description: description.to_owned() });
                collection
                    .commit(fragment)
                    .context("commit authored Posture scan fragment")
            },
        )
    }

    fn with_collection<T>(
        &self,
        scope: Id,
        label: &str,
        operation: impl FnOnce(
            &mut Collection<Pile>,
            &TribleSet,
            &PileReader,
            &[CollectionCommit],
        ) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let pile = open_pile_strict(self.pile)?;
        let author = signer.verifying_key().to_bytes();
        let mut collection = open_scope(pile, scope, signer);
        let result = (|| {
            let (facts, commits) = materialize_stable(&mut collection, scope, author, label)?;
            let reader = collection
                .storage_mut()
                .reader()
                .with_context(|| format!("open Posture {label} blob reader"))?;
            operation(&mut collection, &facts, &reader, &commits)
        })();
        finish_pile(collection.into_storage(), result)
    }
}

/// The team an already-open collection belongs to.
fn collection_team(collection: &Collection<Pile>) -> Result<ed25519_dalek::VerifyingKey> {
    triblespace::core::collection::descriptor::team(collection.descriptor().facts())
        .ok_or_else(|| anyhow!("a Posture root descriptor names the team it belongs to"))?
        .map_err(|error| anyhow!("decode the team on the Posture root descriptor: {error}"))
}

fn materialize_stable(
    collection: &mut Collection<Pile>,
    scope: Id,
    author: [u8; 32],
    label: &str,
) -> Result<(TribleSet, Vec<CollectionCommit>)> {
    // The team is read back off the collection we already hold rather than
    // passed in beside it: it is a property of that collection, and a second
    // copy travelling alongside is a second thing that can disagree.
    let team = collection_team(collection)?;
    loop {
        let before = discover_target(collection.storage_mut(), scope, team)
            .with_context(|| format!("discover fixed Posture {label} descriptor"))?;
        let before = before
            .commits()
            .iter()
            .copied()
            .filter(|commit| commit.public_key().raw == author)
            .collect::<Vec<_>>();
        let facts = collection
            .materialize()
            .with_context(|| format!("materialize authored Posture {label} collection"))?;
        let after = discover_target(collection.storage_mut(), scope, team)
            .with_context(|| format!("rediscover fixed Posture {label} descriptor"))?;
        let after = after
            .commits()
            .iter()
            .copied()
            .filter(|commit| commit.public_key().raw == author)
            .collect::<Vec<_>>();
        if before == after {
            return Ok((facts, after));
        }
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Posture pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Posture pile also failed: {close_error}")))
        }
    }
}

fn read_text(reader: &PileReader, handle: TextHandle, field: &str) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Posture {field} payload"))?;
    Ok(value.to_string())
}

fn now_epoch() -> Result<Epoch> {
    Epoch::now().map_err(|error| anyhow!("read current time: {error:?}"))
}

fn point_interval(epoch: Epoch) -> IntervalValue {
    (epoch, epoch)
        .try_to_inline()
        .expect("valid point interval")
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval
        .try_from_inline()
        .expect("valid Posture timestamp interval");
    lower
}

fn one_required<T>(values: BTreeSet<T>, field: &str) -> Result<T>
where
    T: Ord + Copy,
{
    if values.len() != 1 {
        bail!("{field} has {} values; expected exactly one", values.len());
    }
    Ok(*values.iter().next().expect("one value"))
}

fn one_optional<T>(values: BTreeSet<T>, field: &str) -> Result<Option<T>>
where
    T: Ord + Copy,
{
    if values.len() > 1 {
        bail!("{field} has {} values; expected at most one", values.len());
    }
    Ok(values.iter().next().copied())
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// Write one observation of a finding. Sightings are annotations: which
/// document and commit a scan met the material in, and the material itself as
/// evidence. Losing one costs a re-walk, never a resolution.
fn sighting_entity(fragment: &mut Fragment, finding: Id, document: Id, found: &Found) -> Id {
    let value: TextHandle = fragment.put(found.value.clone());
    let evidence: TextHandle = fragment.put(found.evidence.clone());
    let seen_in: Option<TextHandle> = found
        .seen_in
        .as_ref()
        .map(|commit| fragment.put(commit.clone()));
    let sighting = entity! {
        metadata::tag: KIND_SIGHTING,
        posture::sighting_of: finding,
        posture::document: document,
        posture::value: value,
        posture::evidence: evidence,
        posture::seen_in?: seen_in,
    };
    let id = sighting.root().expect("intrinsic sighting has one root");
    *fragment += sighting;
    id
}

fn entity_attributes(facts: &TribleSet, entity: Id) -> BTreeSet<Id> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity)
        .map(|fact| *fact.a())
        .collect()
}

fn require_attributes(
    facts: &TribleSet,
    entity: Id,
    allowed: impl IntoIterator<Item = Id>,
    kind: &str,
) -> Result<()> {
    let actual = entity_attributes(facts, entity);
    let allowed = allowed.into_iter().collect::<BTreeSet<_>>();
    if !actual.is_subset(&allowed) {
        let unexpected = actual.difference(&allowed).copied().collect::<Vec<_>>();
        bail!(
            "{kind} {} has unexpected attribute(s): {}",
            fmt_id(entity),
            unexpected
                .iter()
                .map(|attribute| fmt_id(*attribute))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

fn entity_tags(facts: &TribleSet, entity: Id) -> BTreeSet<Id> {
    find!(
        tag: Id,
        pattern!(facts, [{ (entity) @ metadata::tag: ?tag }])
    )
    .collect()
}

fn inline_u256_to_u128(value: Inline<inlineencodings::U256BE>) -> Result<u128> {
    if value.raw[..16].iter().any(|byte| *byte != 0) {
        bail!("Posture count exceeds u128");
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&value.raw[16..]);
    Ok(u128::from_be_bytes(bytes))
}

fn text_attribute_ids() -> HashSet<Id> {
    [
        posture::channel_name.id(),
        posture::term.id(),
        posture::why.id(),
        posture::path.id(),
        posture::locator.id(),
        posture::value.id(),
        posture::carrier.id(),
        posture::evidence.id(),
        posture::seen_in.id(),
        posture::target.id(),
        posture::detail.id(),
    ]
    .into_iter()
    .collect()
}

fn read_text_with<R>(
    reader: &PileReader,
    staged: Option<&R>,
    handle: TextHandle,
    field: &str,
) -> Result<String>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    if let Some(staged) = staged {
        if staged
            .metadata(handle)
            .with_context(|| format!("inspect staged Posture {field} payload"))?
            .is_some()
        {
            let value: View<str> = staged
                .get(handle)
                .with_context(|| format!("decode staged Posture {field} payload"))?;
            return Ok(value.to_string());
        }
    }
    read_text(reader, handle, field)
}

fn validate_known_payloads_with<R>(
    reader: &PileReader,
    staged: Option<&R>,
    facts: &TribleSet,
) -> Result<()>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    let text_attributes = text_attribute_ids();
    for fact in facts {
        if text_attributes.contains(fact.a()) {
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::UTF8String>>();
            read_text_with(reader, staged, handle, "text")
                .with_context(|| format!("read Posture text payload for {}", fmt_id(*fact.e())))?;
        } else if fact.a() == &embeddings::attr::embedding.id() {
            let handle = *fact.v::<inlineencodings::Handle<Embedding768>>();
            if let Some(staged) = staged {
                if staged
                    .metadata(handle)
                    .context("inspect staged Posture embedding")?
                    .is_some()
                {
                    let _: View<[f32]> = staged.get(handle).with_context(|| {
                        format!("decode staged Posture embedding for {}", fmt_id(*fact.e()))
                    })?;
                    continue;
                }
            }
            let _: View<[f32]> = reader.get(handle).with_context(|| {
                format!("read existing Posture embedding for {}", fmt_id(*fact.e()))
            })?;
        }
    }
    Ok(())
}

fn validate_policy_view(view: &CollectionView) -> Result<()> {
    faculties::posture_policy::validate_policy_catalog(&view.reader, &view.facts)
}
/// Check that every signed COMMIT about to be joined by a new one is exactly
/// one atomic scan. This runs on the WRITE path only.
///
/// It used to run inside `scan_view()`, which meant every read validated all
/// history against the *current* schema and so guaranteed that any schema
/// change broke the reader — which is exactly what happened. In an append-only
/// store the past was valid when it was written; validation belongs in
/// migrations and at the moment of writing, never on a read path.
fn validate_scan_commits(
    reader: &PileReader,
    commits: &[CollectionCommit],
    writing: Id,
) -> Result<()> {
    let mut scan_commits = BTreeMap::<Id, usize>::new();
    for commit in commits {
        let handle = inlineencodings::Handle::<SimpleArchive>::from_hash(commit.data());
        let blob: Blob<SimpleArchive> = reader
            .get(handle)
            .with_context(|| format!("read Posture scan COMMIT {}", fmt_id(commit.id())))?;
        let facts = TribleSet::try_from_blob(blob)
            .with_context(|| format!("decode Posture scan COMMIT {}", fmt_id(commit.id())))?;
        let scan = find!(
            scan: Id,
            pattern!(&facts, [{ ?scan @ metadata::tag: (&KIND_SCAN) }])
        )
        .collect::<BTreeSet<_>>();
        let Ok(scan) = one_required(scan, "scan COMMIT root") else {
            // A COMMIT with no scan root predates this shape entirely. It is
            // history, not a fault to relitigate on every write.
            continue;
        };
        *scan_commits.entry(scan).or_default() += 1;
    }
    if let Some((scan, count)) = scan_commits.iter().find(|(_, count)| **count != 1) {
        bail!(
            "scan {} is spread across {count} signed COMMITs; scans must be atomic",
            fmt_id(*scan)
        );
    }
    if scan_commits.contains_key(&writing) {
        bail!(
            "scan {} already has a signed COMMIT; scans must be atomic",
            fmt_id(writing)
        );
    }
    Ok(())
}

fn validate_scan_commit_fragment(facts: &TribleSet) -> Result<Id> {
    let scans = find!(
        scan: Id,
        pattern!(facts, [{ ?scan @ metadata::tag: (&KIND_SCAN) }])
    )
    .collect::<BTreeSet<_>>();
    let scan = one_required(scans, "scan COMMIT root")?;
    validate_scan_structure(facts)?;
    let mut expected_subjects = BTreeSet::from([scan]);
    expected_subjects.extend(find!(
        value: Id,
        pattern!(facts, [{ (scan) @ posture::scan_document: ?value }])
    ));
    let sightings = find!(
        value: Id,
        pattern!(facts, [{ (scan) @ posture::scan_sighting: ?value }])
    )
    .collect::<BTreeSet<_>>();
    // Findings enter the Merkle root through the sightings that name them, so
    // the scan never carries a separate list of them.
    for sighting in &sightings {
        expected_subjects.extend(find!(
            value: Id,
            pattern!(facts, [{ (*sighting) @ posture::sighting_of: ?value }])
        ));
    }
    expected_subjects.extend(sightings);
    expected_subjects.extend(find!(
        value: Id,
        pattern!(facts, [{ (scan) @ posture::scan_omission: ?value }])
    ));
    let actual_subjects = facts.iter().map(|fact| *fact.e()).collect::<BTreeSet<_>>();
    if actual_subjects != expected_subjects {
        bail!("scan COMMIT must contain exactly its Merkle-rooted observation");
    }
    Ok(scan)
}

fn validate_scan_catalog_with<R>(
    reader: &PileReader,
    staged: Option<&R>,
    facts: &TribleSet,
) -> Result<()>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    validate_known_payloads_with(reader, staged, facts)?;
    validate_scan_structure(facts)?;
    Ok(())
}

fn validate_scan_structure(facts: &TribleSet) -> Result<()> {
    let scans = find!(
        scan: Id,
        pattern!(facts, [{ ?scan @ metadata::tag: (&KIND_SCAN) }])
    )
    .collect::<BTreeSet<_>>();
    let documents = find!(
        document: Id,
        pattern!(facts, [{ ?document @ metadata::tag: (&KIND_DOCUMENT) }])
    )
    .collect::<BTreeSet<_>>();
    let findings = find!(
        finding: Id,
        pattern!(facts, [{ ?finding @ metadata::tag: (&KIND_FINDING) }])
    )
    .collect::<BTreeSet<_>>();
    let sightings = find!(
        sighting: Id,
        pattern!(facts, [{ ?sighting @ metadata::tag: (&KIND_SIGHTING) }])
    )
    .collect::<BTreeSet<_>>();
    let omissions = find!(
        omission: Id,
        pattern!(facts, [{ ?omission @ metadata::tag: (&KIND_OMISSION) }])
    )
    .collect::<BTreeSet<_>>();
    let mut known = scans.clone();
    known.extend(documents.iter().copied());
    known.extend(findings.iter().copied());
    known.extend(sightings.iter().copied());
    known.extend(omissions.iter().copied());
    let actual = facts.iter().map(|fact| *fact.e()).collect::<BTreeSet<_>>();
    if actual != known {
        bail!("Posture scan collection contains unrecognized entities");
    }

    let coverage_modalities = modality::ALL
        .iter()
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>();
    let known_modalities = modality::ALL
        .iter()
        .chain(modality::GIT_ONLY)
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>();
    for scan in &scans {
        require_attributes(
            facts,
            *scan,
            [
                metadata::tag.id(),
                metadata::created_at.id(),
                posture::target.id(),
                posture::file_count.id(),
                posture::checked.id(),
                posture::unchecked.id(),
                posture::scan_channel.id(),
                posture::scan_document.id(),
                posture::scan_sighting.id(),
                posture::scan_omission.id(),
            ],
            "scan",
        )?;
        if entity_tags(facts, *scan) != BTreeSet::from([KIND_SCAN]) {
            bail!("scan {} has invalid tags", fmt_id(*scan));
        }
        let created_at = one_required(
            find!(
                value: IntervalValue,
                pattern!(facts, [{ (*scan) @ metadata::created_at: ?value }])
            )
            .collect(),
            "scan created_at",
        )?;
        let target = one_required(
            find!(value: TextHandle, pattern!(facts, [{ (*scan) @ posture::target: ?value }]))
                .collect(),
            "scan target",
        )?;
        let file_count = one_required(
            find!(
                value: Inline<inlineencodings::U256BE>,
                pattern!(facts, [{ (*scan) @ posture::file_count: ?value }])
            )
            .collect(),
            "scan file count",
        )?;
        let checked = find!(
            value: Id,
            pattern!(facts, [{ (*scan) @ posture::checked: ?value }])
        )
        .collect::<BTreeSet<_>>();
        let unchecked = find!(
            value: Id,
            pattern!(facts, [{ (*scan) @ posture::unchecked: ?value }])
        )
        .collect::<BTreeSet<_>>();
        let channel = one_optional(
            find!(value: Id, pattern!(facts, [{ (*scan) @ posture::scan_channel: ?value }]))
                .collect(),
            "scan channel",
        )?;
        let scan_documents = find!(
            value: Id,
            pattern!(facts, [{ (*scan) @ posture::scan_document: ?value }])
        )
        .collect::<BTreeSet<_>>();
        let scan_sightings = find!(
            value: Id,
            pattern!(facts, [{ (*scan) @ posture::scan_sighting: ?value }])
        )
        .collect::<BTreeSet<_>>();
        let scan_omissions = find!(
            value: Id,
            pattern!(facts, [{ (*scan) @ posture::scan_omission: ?value }])
        )
        .collect::<BTreeSet<_>>();
        if !scan_documents.is_subset(&documents)
            || !scan_sightings.is_subset(&sightings)
            || !scan_omissions.is_subset(&omissions)
        {
            bail!(
                "scan {} references a missing or mistyped child",
                fmt_id(*scan)
            );
        }
        let checked_coverage = checked
            .intersection(&coverage_modalities)
            .copied()
            .collect::<BTreeSet<_>>();
        let covered = checked_coverage
            .union(&unchecked)
            .copied()
            .collect::<BTreeSet<_>>();
        if !checked.is_disjoint(&unchecked)
            || !checked.is_subset(&known_modalities)
            || !unchecked.is_subset(&coverage_modalities)
            || covered != coverage_modalities
        {
            bail!(
                "scan {} does not partition every file-scan coverage modality into checked or unchecked",
                fmt_id(*scan)
            );
        }
        let actual_files = scan_documents.len() as u128;
        let expected = entity! {
            metadata::tag: KIND_SCAN,
            metadata::created_at: created_at,
            posture::target: target,
            posture::file_count: file_count,
            posture::checked*: checked,
            posture::unchecked*: unchecked,
            posture::scan_channel?: channel,
            posture::scan_document*: scan_documents,
            posture::scan_sighting*: scan_sightings,
            posture::scan_omission*: scan_omissions,
        }
        .root()
        .expect("scan identity has one root");
        if expected != *scan {
            bail!("scan {} is not intrinsic", fmt_id(*scan));
        }
        if inline_u256_to_u128(file_count)? != actual_files {
            bail!(
                "scan {} file_count does not match its documents",
                fmt_id(*scan)
            );
        }
    }

    let mut document_paths = BTreeSet::new();
    for document in &documents {
        require_attributes(
            facts,
            *document,
            [
                metadata::tag.id(),
                posture::path.id(),
                posture::outcome.id(),
                posture::detail.id(),
            ],
            "document",
        )?;
        if entity_tags(facts, *document) != BTreeSet::from([KIND_DOCUMENT]) {
            bail!("document {} has invalid tags", fmt_id(*document));
        }
        let owners = find!(
            scan: Id,
            pattern!(facts, [{ ?scan @ posture::scan_document: (*document) }])
        )
        .collect::<BTreeSet<_>>();
        if owners.is_empty() || !owners.is_subset(&scans) {
            bail!("document {} is not owned by a scan", fmt_id(*document));
        }
        let path = one_required(
            find!(value: TextHandle, pattern!(facts, [{ (*document) @ posture::path: ?value }]))
                .collect(),
            "document path",
        )?;
        for scan in owners {
            if !document_paths.insert((scan, path)) {
                bail!("scan {} has multiple outcomes for one path", fmt_id(scan));
            }
        }
        let outcome = one_required(
            find!(value: Id, pattern!(facts, [{ (*document) @ posture::outcome: ?value }]))
                .collect(),
            "document outcome",
        )?;
        if ![OUTCOME_EXAMINED, DOC_UNSUPPORTED, OUTCOME_PARSE_FAILED].contains(&outcome) {
            bail!("document {} has an unknown outcome", fmt_id(*document));
        }
        let detail = one_optional(
            find!(value: TextHandle, pattern!(facts, [{ (*document) @ posture::detail: ?value }]))
                .collect(),
            "document detail",
        )?;
        if (outcome == OUTCOME_PARSE_FAILED) != detail.is_some() {
            bail!(
                "document {} has inconsistent parse-failure detail",
                fmt_id(*document)
            );
        }
        let expected = entity! {
            metadata::tag: KIND_DOCUMENT,
            posture::path: path,
            posture::outcome: outcome,
            posture::detail?: detail,
        }
        .root()
        .expect("document identity has one root");
        if expected != *document {
            bail!("document {} is not intrinsic", fmt_id(*document));
        }
    }

    for finding in &findings {
        require_attributes(
            facts,
            *finding,
            [
                metadata::tag.id(),
                posture::carrier_kind.id(),
                posture::carrier.id(),
                posture::locator.id(),
                posture::span_start.id(),
                posture::span_end.id(),
            ],
            "finding",
        )?;
        let tags = entity_tags(facts, *finding);
        let modalities = tags
            .intersection(&known_modalities)
            .copied()
            .collect::<BTreeSet<_>>();
        let modality = one_required(modalities, "finding modality")?;
        if tags != BTreeSet::from([KIND_FINDING, modality]) {
            bail!("finding {} has invalid tags", fmt_id(*finding));
        }
        let observers = find!(
            sighting: Id,
            pattern!(facts, [{ ?sighting @ posture::sighting_of: (*finding) }])
        )
        .collect::<BTreeSet<_>>();
        if observers.is_empty() || !observers.is_subset(&sightings) {
            bail!("finding {} was never sighted", fmt_id(*finding));
        }
        let carrier_kind = one_required(
            find!(
                value: Id,
                pattern!(facts, [{ (*finding) @ posture::carrier_kind: ?value }])
            )
            .collect(),
            "finding carrier kind",
        )?;
        if ![
            CARRIER_GIT_BLOB,
            CARRIER_CONTAINER_MEMBER,
            CARRIER_GIT_COMMIT,
        ]
        .contains(&carrier_kind)
        {
            bail!("finding {} has an unknown carrier kind", fmt_id(*finding));
        }
        let carrier = one_required(
            find!(
                value: TextHandle,
                pattern!(facts, [{ (*finding) @ posture::carrier: ?value }])
            )
            .collect(),
            "finding carrier",
        )?;
        let field = one_optional(
            find!(
                value: TextHandle,
                pattern!(facts, [{ (*finding) @ posture::locator: ?value }])
            )
            .collect(),
            "finding inner locator",
        )?;
        let span_start = one_optional(
            find!(
                value: Inline<inlineencodings::U256BE>,
                pattern!(facts, [{ (*finding) @ posture::span_start: ?value }])
            )
            .collect(),
            "finding span start",
        )?;
        let span_end = one_optional(
            find!(
                value: Inline<inlineencodings::U256BE>,
                pattern!(facts, [{ (*finding) @ posture::span_end: ?value }])
            )
            .collect(),
            "finding span end",
        )?;
        // A byte range where the carrier's bytes spell the material, a named
        // coordinate where they do not. Both at once would let the two
        // disagree about where the material is.
        match (field, span_start, span_end) {
            (Some(_), None, None) => {}
            (None, Some(start), Some(end)) => {
                if inline_u256_to_u128(start)? > inline_u256_to_u128(end)? {
                    bail!("finding {} has an inverted byte range", fmt_id(*finding));
                }
            }
            _ => bail!(
                "finding {} must carry exactly one of a byte range or a named coordinate",
                fmt_id(*finding)
            ),
        }
        let expected = entity! {
            metadata::tag: KIND_FINDING,
            metadata::tag: modality,
            posture::carrier_kind: carrier_kind,
            posture::carrier: carrier,
            posture::locator?: field,
            posture::span_start?: span_start,
            posture::span_end?: span_end,
        }
        .root()
        .expect("finding identity has one root");
        if expected != *finding {
            bail!("finding {} is not content-located", fmt_id(*finding));
        }
    }

    for sighting in &sightings {
        require_attributes(
            facts,
            *sighting,
            [
                metadata::tag.id(),
                posture::sighting_of.id(),
                posture::document.id(),
                posture::value.id(),
                posture::evidence.id(),
                posture::seen_in.id(),
            ],
            "sighting",
        )?;
        if entity_tags(facts, *sighting) != BTreeSet::from([KIND_SIGHTING]) {
            bail!("sighting {} has invalid tags", fmt_id(*sighting));
        }
        let owners = find!(
            scan: Id,
            pattern!(facts, [{ ?scan @ posture::scan_sighting: (*sighting) }])
        )
        .collect::<BTreeSet<_>>();
        if owners.is_empty() || !owners.is_subset(&scans) {
            bail!("sighting {} is not owned by a scan", fmt_id(*sighting));
        }
        let finding = one_required(
            find!(
                value: Id,
                pattern!(facts, [{ (*sighting) @ posture::sighting_of: ?value }])
            )
            .collect(),
            "sighting finding",
        )?;
        if !findings.contains(&finding) {
            bail!("sighting {} names a missing finding", fmt_id(*sighting));
        }
        let modality = one_required(
            entity_tags(facts, finding)
                .intersection(&known_modalities)
                .copied()
                .collect(),
            "sighted finding modality",
        )?;
        let document = one_required(
            find!(
                value: Id,
                pattern!(facts, [{ (*sighting) @ posture::document: ?value }])
            )
            .collect(),
            "sighting document",
        )?;
        if !documents.contains(&document) {
            bail!("sighting {} references a missing document", fmt_id(*sighting));
        }
        for scan in &owners {
            if !exists!(pattern!(facts, [{ (*scan) @ posture::scan_document: (document) }])) {
                bail!(
                    "sighting {} references a document outside scan {}",
                    fmt_id(*sighting),
                    fmt_id(*scan)
                );
            }
            if !exists!(pattern!(facts, [{ (*scan) @ posture::checked: (modality) }])) {
                bail!(
                    "sighting {} uses a modality scan {} did not mark checked",
                    fmt_id(*sighting),
                    fmt_id(*scan)
                );
            }
        }
        let document_outcome = one_required(
            find!(
                value: Id,
                pattern!(facts, [{ (document) @ posture::outcome: ?value }])
            )
            .collect(),
            "sighting document outcome",
        )?;
        if document_outcome != OUTCOME_EXAMINED {
            bail!(
                "sighting {} belongs to a document that was not examined",
                fmt_id(*sighting)
            );
        }
        let value = one_required(
            find!(
                value: TextHandle,
                pattern!(facts, [{ (*sighting) @ posture::value: ?value }])
            )
            .collect(),
            "sighting value",
        )?;
        let evidence = one_required(
            find!(
                value: TextHandle,
                pattern!(facts, [{ (*sighting) @ posture::evidence: ?value }])
            )
            .collect(),
            "sighting evidence",
        )?;
        let seen_in = one_optional(
            find!(
                value: TextHandle,
                pattern!(facts, [{ (*sighting) @ posture::seen_in: ?value }])
            )
            .collect(),
            "sighting commit",
        )?;
        let expected = entity! {
            metadata::tag: KIND_SIGHTING,
            posture::sighting_of: finding,
            posture::document: document,
            posture::value: value,
            posture::evidence: evidence,
            posture::seen_in?: seen_in,
        }
        .root()
        .expect("sighting identity has one root");
        if expected != *sighting {
            bail!("sighting {} is not intrinsic", fmt_id(*sighting));
        }
    }

    for omission in &omissions {
        require_attributes(
            facts,
            *omission,
            [metadata::tag.id(), posture::path.id(), posture::detail.id()],
            "omission",
        )?;
        if entity_tags(facts, *omission) != BTreeSet::from([KIND_OMISSION]) {
            bail!("omission {} has invalid tags", fmt_id(*omission));
        }
        let owners = find!(
            scan: Id,
            pattern!(facts, [{ ?scan @ posture::scan_omission: (*omission) }])
        )
        .collect::<BTreeSet<_>>();
        if owners.is_empty() || !owners.is_subset(&scans) {
            bail!("omission {} is not owned by a scan", fmt_id(*omission));
        }
        let path = one_required(
            find!(value: TextHandle, pattern!(facts, [{ (*omission) @ posture::path: ?value }]))
                .collect(),
            "omission path",
        )?;
        let detail = one_required(
            find!(value: TextHandle, pattern!(facts, [{ (*omission) @ posture::detail: ?value }]))
                .collect(),
            "omission detail",
        )?;
        let expected = entity! {
            metadata::tag: KIND_OMISSION,
            posture::path: path,
            posture::detail: detail,
        }
        .root()
        .expect("omission identity has one root");
        if expected != *omission {
            bail!("omission {} is not intrinsic", fmt_id(*omission));
        }
    }

    Ok(())
}

// ── commands ────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum FileOutcome {
    Examined,
    Unsupported,
    ParseFailed(String),
}

#[derive(Debug)]
struct ScannedFile {
    path: PathBuf,
    outcome: FileOutcome,
    findings: Vec<Found>,
}

fn unchecked_modalities() -> BTreeSet<Id> {
    modality::ALL
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| !IMPLEMENTED.contains(id))
        .collect()
}

fn build_scan_fragment(
    target: &Path,
    files: &[ScannedFile],
    omissions: &[WalkOmission],
    created_at: IntervalValue,
    channel: Option<Id>,
    checked: BTreeSet<Id>,
) -> (Fragment, Id) {
    let mut fragment = Fragment::empty();
    let target_handle: TextHandle = fragment.put(target.display().to_string());
    let unchecked = modality::ALL
        .iter()
        .map(|(id, _)| *id)
        .filter(|id| !checked.contains(id))
        .collect::<BTreeSet<_>>();
    let mut documents = BTreeSet::new();
    let mut sightings = BTreeSet::new();
    let mut omitted_paths = BTreeSet::new();

    for file in files {
        let path: TextHandle = fragment.put(file.path.display().to_string());
        let (outcome, detail) = match &file.outcome {
            FileOutcome::Examined => (OUTCOME_EXAMINED, None),
            FileOutcome::Unsupported => (DOC_UNSUPPORTED, None),
            FileOutcome::ParseFailed(error) => {
                let detail: TextHandle = fragment.put(error.clone());
                (OUTCOME_PARSE_FAILED, Some(detail))
            }
        };
        let document = entity! {
            metadata::tag: KIND_DOCUMENT,
            posture::path: path,
            posture::outcome: outcome,
            posture::detail?: detail,
        };
        let document_id = document.root().expect("intrinsic document has one root");
        documents.insert(document_id);
        fragment += document;

        for found in &file.findings {
            let finding = finding_entity(&mut fragment, found.modality, &found.location);
            sightings.insert(sighting_entity(&mut fragment, finding, document_id, found));
        }
    }

    for omitted in omissions {
        let path: TextHandle = fragment.put(omitted.path.display().to_string());
        let detail: TextHandle = fragment.put(omitted.detail.clone());
        let omission = entity! {
            metadata::tag: KIND_OMISSION,
            posture::path: path,
            posture::detail: detail,
        };
        omitted_paths.insert(omission.root().expect("intrinsic omission has one root"));
        fragment += omission;
    }

    // The root names every child identity. A changed outcome, sighting, or
    // omission therefore changes the scan id; an exact retry derives the same
    // id without a random nonce. Findings hang under their sightings, so the
    // root covers them transitively rather than listing them twice.
    let scan = entity! {
        metadata::tag: KIND_SCAN,
        metadata::created_at: created_at,
        posture::target: target_handle,
        posture::file_count: files.len() as u64,
        posture::checked*: checked,
        posture::unchecked*: unchecked,
        posture::scan_channel?: channel,
        posture::scan_document*: documents,
        posture::scan_sighting*: sightings,
        posture::scan_omission*: omitted_paths,
    };
    let scan_id = scan.root().expect("intrinsic scan has one Merkle root");
    fragment += scan;

    (fragment, scan_id)
}

fn cmd_scan(storage: PostureStorage<'_>, target: &Path, dry_run: bool) -> Result<()> {
    let mut paths = Vec::new();
    let mut omissions = Vec::new();
    walk(target, &mut paths, &mut omissions);
    paths.sort();
    omissions.sort_by(|left, right| (&left.path, &left.detail).cmp(&(&right.path, &right.detail)));

    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let (outcome, findings) = match dispatch(&path) {
            Ok(Some(extractor)) => match extractor(&path) {
                Ok(findings) => (FileOutcome::Examined, findings),
                Err(error) => (FileOutcome::ParseFailed(error.to_string()), Vec::new()),
            },
            Ok(None) => (FileOutcome::Unsupported, Vec::new()),
            Err(error) => (FileOutcome::ParseFailed(error.to_string()), Vec::new()),
        };
        files.push(ScannedFile {
            path,
            outcome,
            findings,
        });
    }

    let examined = files
        .iter()
        .filter(|file| matches!(file.outcome, FileOutcome::Examined))
        .count();
    let unsupported = files
        .iter()
        .filter(|file| matches!(file.outcome, FileOutcome::Unsupported))
        .count();
    let failed = files
        .iter()
        .filter(|file| matches!(file.outcome, FileOutcome::ParseFailed(_)))
        .count();
    let finding_count: usize = files.iter().map(|file| file.findings.len()).sum();

    println!(
        "scanned  : {} files under {}",
        files.len(),
        target.display()
    );
    println!("examined : {examined} ({unsupported} unsupported, {failed} failed to parse)");
    println!("findings : {finding_count}\n");

    let mut by_modality: BTreeMap<&str, Vec<(&Path, &Found)>> = BTreeMap::new();
    for file in &files {
        for found in &file.findings {
            by_modality
                .entry(modality::name(found.modality))
                .or_default()
                .push((&file.path, found));
        }
    }
    for (name, items) in &by_modality {
        let documents = items.iter().map(|(path, _)| *path).collect::<BTreeSet<_>>();
        println!(
            "  {name}  ({} findings across {} document(s))",
            items.len(),
            documents.len()
        );
        for (path, found) in items.iter().take(3) {
            let value = found.value.replace('\n', " ");
            let value: String = value.chars().take(90).collect();
            println!(
                "    {}  {}  {value}",
                path.display(),
                found.location.display()
            );
        }
        if items.len() > 3 {
            println!("    … {} more", items.len() - 3);
        }
    }
    if failed > 0 {
        println!("\n  parse failures (NOT clean — unexamined):");
        for file in files
            .iter()
            .filter(|file| matches!(file.outcome, FileOutcome::ParseFailed(_)))
            .take(5)
        {
            let FileOutcome::ParseFailed(error) = &file.outcome else {
                unreachable!()
            };
            println!("    {}  {error}", file.path.display());
        }
    }

    println!("\nNOT CHECKED by this scan — do not read silence here as safety:");
    for id in unchecked_modalities() {
        println!("  - {}", modality::name(id));
    }
    if unsupported > 0 {
        println!("  - {unsupported} file(s) no extractor understands");
    }
    for omitted in omissions.iter().take(8) {
        println!("  - {} ({})", omitted.path.display(), omitted.detail);
    }
    if omissions.len() > 8 {
        println!("  - … {} more persisted omission(s)", omissions.len() - 8);
    }

    if dry_run {
        println!("\n(dry run — nothing written)");
        return Ok(());
    }

    let (fragment, scan_id) = build_scan_fragment(
        target,
        &files,
        &omissions,
        point_interval(now_epoch()?),
        None,
        IMPLEMENTED.iter().copied().collect(),
    );
    storage.publish_scan(fragment, "posture complete scan")?;
    println!("\nscan {}", fmt_id(scan_id));
    Ok(())
}

fn parse_scan_id(raw: Option<&str>) -> Result<Option<Id>> {
    raw.map(|value| Id::from_hex(value.trim()).ok_or_else(|| anyhow!("invalid scan id '{value}'")))
        .transpose()
}

fn all_scan_ids(space: &TribleSet) -> BTreeSet<Id> {
    find!(
        scan: Id,
        pattern!(space, [{ ?scan @ metadata::tag: (&KIND_SCAN) }])
    )
    .collect()
}

fn select_scan(space: &TribleSet, requested: Option<&str>) -> Result<Option<Id>> {
    if let Some(scan) = parse_scan_id(requested)? {
        if !exists!(pattern!(space, [{ (scan) @ metadata::tag: (&KIND_SCAN) }])) {
            bail!(
                "scan {} is not present in the authorized scan collection",
                fmt_id(scan)
            );
        }
        return Ok(Some(scan));
    }
    let mut newest: Option<(i128, Id)> = None;
    let mut tied = Vec::new();
    for scan in all_scan_ids(space) {
        let created_at = one_required(
            find!(
                value: IntervalValue,
                pattern!(space, [{ (scan) @ metadata::created_at: ?value }])
            )
            .collect(),
            "scan created_at",
        )?;
        let key = interval_key(created_at);
        match newest {
            None => {
                newest = Some((key, scan));
                tied = vec![scan];
            }
            Some((current, _)) if key > current => {
                newest = Some((key, scan));
                tied = vec![scan];
            }
            Some((current, _)) if key == current => tied.push(scan),
            _ => {}
        }
    }
    if tied.len() > 1 {
        bail!(
            "{} scans share the newest timestamp; pass an explicit scan id",
            tied.len()
        );
    }
    Ok(newest.map(|(_, scan)| scan))
}

/// The prose a resolution had to spell EXACTLY, before a resolution could
/// carry a machine-readable result.
///
/// It is still read, and deliberately so. A Decide resolution is an intrinsic,
/// content-addressed, immutable event and an already-resolved decision cannot
/// be resolved again, so no edit can re-stamp the historical clearances with
/// `decide::RESULT_BENIGN` — migrating them would mean forging a second
/// resolution head nobody authored. Dropping the legacy read would silently
/// re-block every finding a human already cleared. New clearances use the
/// tag; this is a read path only.
const LEGACY_BENIGN_OUTCOME: &str = "benign";

#[derive(Default)]
struct FindingDecisionState {
    benign: bool,
    justified_benign: bool,
    disputed: bool,
}

/// Which findings a resolved Decide outcome takes off the board.
///
/// `bridges` carries the pre-2026-08-18 occurrence ids a migration proved to
/// be the same material, so a judgement made under the old identity keeps
/// applying to the content-located finding it turned out to be.
struct Settled {
    ordinary: BTreeSet<Id>,
    justified: BTreeSet<Id>,
    bridges: BTreeMap<Id, BTreeSet<Id>>,
}

impl Settled {
    fn hides(&self, modality: Id, finding: Id) -> bool {
        let settled = if modality == modality::UNSAFE_ATTRIBUTE_ID {
            &self.justified
        } else {
            &self.ordinary
        };
        settled.contains(&finding)
            || self
                .bridges
                .get(&finding)
                .is_some_and(|legacy| legacy.iter().any(|id| settled.contains(id)))
    }
}

/// The legacy occurrence ids a migration bridged onto each finding.
fn legacy_bridges(facts: &TribleSet) -> BTreeMap<Id, BTreeSet<Id>> {
    let mut bridges = BTreeMap::<Id, BTreeSet<Id>>::new();
    for (finding, legacy) in find!(
        (finding: Id, legacy: Id),
        pattern!(facts, [{
            _?bridge @
            metadata::tag: (&KIND_LEGACY_BRIDGE),
            posture::sighting_of: ?finding,
            posture::occurrence: ?legacy
        }])
    ) {
        bridges.entry(finding).or_default().insert(legacy);
    }
    bridges
}

/// Occurrences classified benign by the native Decide collection.
///
/// The outcome is an exact protocol value, as Mail's Decide authorization uses
/// exact `send`: merely finishing a deliberation must not turn a negative or
/// unrelated free-form outcome into clearance. Missing decisions contribute
/// nothing. A fork or a second resolved decision with another outcome keeps
/// the finding visible; set union therefore exposes disagreement instead of
/// choosing a winner by time or iteration order.
fn settled_findings(
    reader: &PileReader,
    facts: &TribleSet,
    bridges: BTreeMap<Id, BTreeSet<Id>>,
) -> Result<Settled> {
    let mut states = BTreeMap::<Id, FindingDecisionState>::new();
    for decision in decide::decision_anchors(facts) {
        let genesis = decide::genesis_for_decision(facts, decision)?
            .ok_or_else(|| anyhow!("Decide decision {} has no genesis", fmt_id(decision)))?;
        let Some(about) = genesis.about else {
            continue;
        };
        let state = states.entry(about).or_default();
        let snapshot = match decide::resolution(facts, decision) {
            Resolution::Missing => continue,
            Resolution::Unique(snapshot) => snapshot,
            Resolution::Agreed(snapshots) => snapshots.into_iter().next().ok_or_else(|| {
                anyhow!("Decide decision {} has empty agreement", fmt_id(decision))
            })?,
            Resolution::Forked(_) => {
                state.disputed = true;
                continue;
            }
            Resolution::Invalid(error) => {
                bail!("Decide decision {} is invalid: {error}", fmt_id(decision));
            }
        };
        // The machine-readable result is authoritative. Only when a
        // resolution carries none does the legacy exact-prose form decide,
        // which is what keeps pre-tag clearances applying. The outcome text
        // is otherwise free prose: it exists so a human can say WHY, and a
        // gate that reads it byte-for-byte takes that field away from them.
        let benign = match snapshot.result {
            Some(result) => result == decide::RESULT_BENIGN,
            None => decide::read_text(reader, snapshot.outcome)? == LEGACY_BENIGN_OUTCOME,
        };
        if benign {
            state.benign = true;
            if let Some(context) = genesis.context {
                // Decide validates proposal context as canonical required text;
                // read it anyway so missing/corrupt justification cannot grant
                // clearance merely because a handle is present.
                if !decide::read_text(reader, context)?.trim().is_empty() {
                    state.justified_benign = true;
                }
            }
        } else {
            state.disputed = true;
        }
    }
    let ordinary = states
        .iter()
        .filter_map(|(finding, state)| (state.benign && !state.disputed).then_some(*finding))
        .collect();
    let justified = states
        .into_iter()
        .filter_map(|(finding, state)| (state.justified_benign && !state.disputed).then_some(finding))
        .collect();
    Ok(Settled {
        ordinary,
        justified,
        bridges,
    })
}

#[cfg(test)]
fn benign_occurrences(reader: &PileReader, facts: &TribleSet) -> Result<BTreeSet<Id>> {
    Ok(settled_findings(reader, facts, BTreeMap::new())?.ordinary)
}

fn cmd_list(
    storage: PostureStorage<'_>,
    scan: Option<String>,
    examples: usize,
    all: bool,
    ids: bool,
) -> Result<()> {
    let view = storage.scan_view()?;
    let decisions = storage.decide_view()?;
    let want = parse_scan_id(scan.as_deref())?;
    if let Some(scan) = want {
        if !all_scan_ids(&view.facts).contains(&scan) {
            bail!(
                "scan {} is not present in the authorized scan collection",
                fmt_id(scan)
            );
        }
    }
    let settled = settled_findings(
        &decisions.reader,
        &decisions.facts,
        legacy_bridges(&view.facts),
    )?;
    // Content-located sightings, and — because the store is append-only and
    // those observations really happened — the pre-2026-08-18 findings beside
    // them, under the occurrence id Decide named. Dropping them from the report
    // would be the tool telling a comfortable half-truth about what it holds.
    // (scan, the id Decide names, the entity carrying the modality tag,
    // evidence, value). For a content-located finding the first two are the
    // same entity; for a legacy record the id is its derived occurrence.
    let mut all_rows = find!(
        (scan: Id, finding: Id, evidence: TextHandle, value: TextHandle),
        pattern!(&view.facts, [{
            ?scan @ posture::scan_sighting: _?sighting,
        }, {
            _?sighting @
            metadata::tag: (&KIND_SIGHTING),
            posture::sighting_of: ?finding,
            posture::evidence: ?evidence,
            posture::value: ?value
        }])
    )
    .map(|(scan, finding, evidence, value)| (scan, finding, finding, evidence, value))
    .collect::<Vec<_>>();
    all_rows.extend(
        find!(
            (scan: Id, finding: Id, occurrence: Id, locator: TextHandle, value: TextHandle),
            pattern!(&view.facts, [{
                ?scan @ posture::scan_finding: ?finding,
            }, {
                ?finding @
                metadata::tag: (&KIND_FINDING),
                posture::occurrence: ?occurrence,
                posture::locator: ?locator,
                posture::value: ?value
            }])
        )
        .map(|(scan, finding, occurrence, locator, value)| {
            (scan, occurrence, finding, locator, value)
        }),
    );
    let all_rows = all_rows
        .into_iter()
        .filter(|(scan, _, _, _, _)| want.is_none_or(|wanted| *scan == wanted))
        .map(|(scan, id, tagged, evidence, value)| {
            let modality = find!(
                tag: Id,
                pattern!(&view.facts, [{ (tagged) @ metadata::tag: ?tag }])
            )
            .find(|tag| modality::is_known(*tag))
            .expect("a finding carries one known modality");
            (scan, id, evidence, value, modality)
        })
        .collect::<Vec<_>>();
    let hidden = all_rows
        .iter()
        .filter(|(_, finding, _, _, modality)| settled.hides(*modality, *finding))
        .count();
    let rows = all_rows
        .into_iter()
        .filter(|(_, finding, _, _, modality)| all || !settled.hides(*modality, *finding))
        .collect::<Vec<_>>();

    let mut groups: BTreeMap<&str, Vec<(Id, TextHandle, TextHandle)>> = BTreeMap::new();
    for (_, finding, evidence, value, modality) in &rows {
        groups
            .entry(modality::name(*modality))
            .or_default()
            .push((*finding, *evidence, *value));
    }
    if hidden > 0 && !all {
        println!(
            "{hidden} finding(s) hidden by a resolved Decide decision with result \"benign\" \
             — pass --all to include them"
        );
    }
    if groups.is_empty() {
        println!(
            "no findings{}",
            if want.is_some() { " for that scan" } else { "" }
        );
        println!("(this is NOT a clean bill of health — see posture coverage)");
        return Ok(());
    }
    for (name, items) in &groups {
        println!("{name}  ({})", items.len());
        for (finding, evidence, value) in items.iter().take(examples) {
            let evidence = read_text(&view.reader, *evidence, "finding evidence")?;
            let value = read_text(&view.reader, *value, "finding value")?.replace('\n', " ");
            let value: String = value.chars().take(90).collect();
            if ids {
                println!("  {}  {evidence}  {value}", fmt_id(*finding));
            } else {
                println!("  {evidence}  {value}");
            }
        }
        if items.len() > examples {
            println!("  … {} more", items.len() - examples);
        }
    }
    Ok(())
}

fn cmd_coverage(storage: PostureStorage<'_>, scan: Option<String>) -> Result<()> {
    let view = storage.scan_view()?;
    let Some(scan) = select_scan(&view.facts, scan.as_deref())? else {
        println!("no scans recorded");
        return Ok(());
    };
    let target = one_required(
        find!(
            value: TextHandle,
            pattern!(&view.facts, [{ (scan) @ posture::target: ?value }])
        )
        .collect(),
        "scan target",
    )?;
    println!(
        "scan {} over {}\n",
        fmt_id(scan),
        read_text(&view.reader, target, "scan target")?
    );

    let checked = find!(
        modality: Id,
        pattern!(&view.facts, [{ (scan) @ posture::checked: ?modality }])
    )
    .collect::<BTreeSet<_>>();
    let unchecked = find!(
        modality: Id,
        pattern!(&view.facts, [{ (scan) @ posture::unchecked: ?modality }])
    )
    .collect::<BTreeSet<_>>();
    println!("checked:");
    for modality in checked {
        println!("  + {}", modality::name(modality));
    }
    println!("\nNOT checked — silence here is not evidence of absence:");
    for modality in unchecked {
        println!("  - {}", modality::name(modality));
    }

    let mut outcomes = BTreeMap::<Id, usize>::new();
    for outcome in find!(
        outcome: Id,
        pattern!(&view.facts, [{
            (scan) @ posture::scan_document: _?document,
        }, {
            _?document @
            metadata::tag: (&KIND_DOCUMENT),
            posture::outcome: ?outcome
        }])
    ) {
        *outcomes.entry(outcome).or_default() += 1;
    }
    println!(
        "\nfiles: {} examined, {} unsupported, {} parse-failed",
        outcomes.get(&OUTCOME_EXAMINED).copied().unwrap_or(0),
        outcomes.get(&DOC_UNSUPPORTED).copied().unwrap_or(0),
        outcomes.get(&OUTCOME_PARSE_FAILED).copied().unwrap_or(0)
    );

    let omissions = find!(
        (path: TextHandle, detail: TextHandle),
        pattern!(&view.facts, [{
            (scan) @ posture::scan_omission: _?omission,
        }, {
            _?omission @
            metadata::tag: (&KIND_OMISSION),
            posture::path: ?path,
            posture::detail: ?detail
        }])
    )
    .collect::<Vec<_>>();
    if !omissions.is_empty() {
        println!("\npersisted traversal omissions:");
        for (path, detail) in omissions {
            println!(
                "  - {} ({})",
                read_text(&view.reader, path, "omission path")?,
                read_text(&view.reader, detail, "omission detail")?
            );
        }
    }
    Ok(())
}

fn cmd_scans(storage: PostureStorage<'_>) -> Result<()> {
    let view = storage.scan_view()?;
    let mut scans = Vec::new();
    for scan in all_scan_ids(&view.facts) {
        let target = one_required(
            find!(
                value: TextHandle,
                pattern!(&view.facts, [{ (scan) @ posture::target: ?value }])
            )
            .collect(),
            "scan target",
        )?;
        let created_at = one_required(
            find!(
                value: IntervalValue,
                pattern!(&view.facts, [{ (scan) @ metadata::created_at: ?value }])
            )
            .collect(),
            "scan created_at",
        )?;
        let findings = find!(
            sighting: Id,
            pattern!(&view.facts, [{
                (scan) @ posture::scan_sighting: ?sighting,
            }, {
                ?sighting @ metadata::tag: (&KIND_SIGHTING)
            }])
        )
        .count()
            + find!(
                finding: Id,
                pattern!(&view.facts, [{
                    (scan) @ posture::scan_finding: ?finding,
                }, {
                    ?finding @ metadata::tag: (&KIND_FINDING)
                }])
            )
            .count();
        scans.push((
            interval_key(created_at),
            scan,
            findings,
            read_text(&view.reader, target, "scan target")?,
        ));
    }
    scans.sort_by(|left, right| right.cmp(left));
    if scans.is_empty() {
        println!("no scans recorded");
    }
    for (_, scan, findings, target) in scans {
        println!("{}  {findings:>5} findings  {target}", fmt_id(scan));
    }
    Ok(())
}

// ── channels and the git audit ──────────────────────────────────────────────

fn canonical_channel(raw: &str) -> Result<String> {
    let channel = raw.trim().to_lowercase();
    if channel.is_empty() {
        bail!("channel name cannot be empty");
    }
    Ok(channel)
}

fn canonical_term(raw: &str) -> Result<String> {
    let term = raw.trim().to_lowercase();
    if term.is_empty() {
        bail!("protected term cannot be empty");
    }
    Ok(term)
}

#[cfg(any(feature = "local-embed", test))]
fn canonical_exemplar(raw: &str) -> String {
    raw.replace("\r\n", "\n")
        .replace('\r', "\n")
        .trim()
        .to_owned()
}

fn append_channel(fragment: &mut Fragment, name: &str) -> Id {
    let name: TextHandle = fragment.put(name.to_owned());
    let channel = entity! {
        metadata::tag: KIND_CHANNEL,
        posture::channel_name: name,
    };
    let id = channel.root().expect("intrinsic channel has one root");
    *fragment += channel;
    id
}

fn channel_by_name(reader: &PileReader, space: &TribleSet, raw: &str) -> Result<Option<Id>> {
    let wanted = canonical_channel(raw)?;
    let mut matches = Vec::new();
    for (channel, name) in find!(
        (channel: Id, name: TextHandle),
        pattern!(space, [{
            ?channel @ metadata::tag: (&KIND_CHANNEL), posture::channel_name: ?name
        }])
    ) {
        let expected = entity! {
            metadata::tag: KIND_CHANNEL,
            posture::channel_name: name,
        }
        .root()
        .expect("canonical channel has one root");
        if channel != expected {
            continue;
        }
        if read_text(reader, name, "channel name")? == wanted {
            matches.push(channel);
        }
    }
    matches.sort_unstable();
    matches.dedup();
    match matches.as_slice() {
        [] => Ok(None),
        [channel] => Ok(Some(*channel)),
        _ => bail!(
            "channel {wanted:?} resolves to {} identities; policy catalog is invalid",
            matches.len()
        ),
    }
}

#[derive(Debug)]
enum PolicyHead {
    Missing,
    Unique { revision: Id, members: BTreeSet<Id> },
    Forked(Vec<Id>),
}

fn resolve_policy_head(space: &TribleSet, channel: Id) -> Result<PolicyHead> {
    let revisions = find!(
        revision: Id,
        pattern!(space, [{
            ?revision @
            metadata::tag: (&KIND_POLICY_REVISION),
            posture::in_channel: (channel)
        }])
    )
    .collect::<BTreeSet<_>>();
    if revisions.is_empty() {
        return Ok(PolicyHead::Missing);
    }
    let superseded = revisions
        .iter()
        .flat_map(|revision| {
            find!(
                predecessor: Id,
                pattern!(space, [{ *revision @ metadata::supersedes: ?predecessor }])
            )
        })
        .collect::<BTreeSet<_>>();
    let heads = revisions
        .difference(&superseded)
        .copied()
        .collect::<Vec<_>>();
    match heads.as_slice() {
        [revision] => {
            let members = find!(
                member: Id,
                pattern!(space, [{ (*revision) @ posture::policy_member: ?member }])
            )
            .collect();
            Ok(PolicyHead::Unique {
                revision: *revision,
                members,
            })
        }
        _ => Ok(PolicyHead::Forked(heads)),
    }
}

fn append_policy_revision(
    fragment: &mut Fragment,
    channel: Id,
    members: &BTreeSet<Id>,
    predecessors: &BTreeSet<Id>,
) -> Id {
    let revision = entity! {
        metadata::tag: KIND_POLICY_REVISION,
        posture::in_channel: channel,
        posture::policy_member*: members.clone(),
        metadata::supersedes*: predecessors.clone(),
    };
    let id = revision
        .root()
        .expect("intrinsic policy revision has one root");
    *fragment += revision;
    id
}

fn policy_members(space: &TribleSet, channel: Id) -> Result<(Option<Id>, BTreeSet<Id>)> {
    match resolve_policy_head(space, channel)? {
        PolicyHead::Missing => Ok((None, BTreeSet::new())),
        PolicyHead::Unique { revision, members } => Ok((Some(revision), members)),
        PolicyHead::Forked(heads) => bail!(
            "channel {} is FORKED across {} policy heads ({}); reconcile explicitly before use",
            fmt_id(channel),
            heads.len(),
            heads
                .iter()
                .map(|head| fmt_id(*head))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Remove every active exemplar whose canonical passage equals `body`.
///
/// Role is deliberately not part of this logical key. A protected and a benign
/// reading of the same passage would otherwise both enter the discriminative
/// score and cancel one another. The immutable entity ids still retain both
/// historical assertions; only the next policy snapshot chooses one role.
#[cfg(any(feature = "local-embed", test))]
fn take_exemplars_with_body(
    reader: &PileReader,
    space: &TribleSet,
    members: &mut BTreeSet<Id>,
    body: &str,
) -> Result<BTreeSet<Id>> {
    let mut replaced = BTreeSet::new();
    for member in members.iter().copied() {
        if !exists!(pattern!(space, [{
            (member) @ metadata::tag: (&KIND_EXEMPLAR)
        }])) {
            continue;
        }
        let handle = one_required(
            find!(
                value: TextHandle,
                pattern!(space, [{ (member) @ posture::term: ?value }])
            )
            .collect(),
            "exemplar text",
        )?;
        if read_text(reader, handle, "exemplar text")? == body {
            replaced.insert(member);
        }
    }
    members.retain(|member| !replaced.contains(member));
    Ok(replaced)
}

fn channel_terms(
    reader: &PileReader,
    space: &TribleSet,
    channel: Id,
) -> Result<Vec<(String, String)>> {
    let (_, members) = policy_members(space, channel)?;
    let mut terms = Vec::new();
    for member in members {
        if !exists!(pattern!(space, [{ (member) @ metadata::tag: (&KIND_TERM) }])) {
            continue;
        }
        let term = one_required(
            find!(
                value: TextHandle,
                pattern!(space, [{ (member) @ posture::term: ?value }])
            )
            .collect(),
            "term text",
        )?;
        let why = one_optional(
            find!(
                value: TextHandle,
                pattern!(space, [{ (member) @ posture::why: ?value }])
            )
            .collect(),
            "term rationale",
        )?;
        terms.push((
            read_text(reader, term, "term text")?,
            why.map(|handle| read_text(reader, handle, "term rationale"))
                .transpose()?
                .unwrap_or_default(),
        ));
    }
    terms.sort();
    Ok(terms)
}

fn cmd_vocab_add(
    storage: PostureStorage<'_>,
    term: &str,
    channel: &str,
    why: Option<&str>,
) -> Result<()> {
    let channel_name = canonical_channel(channel)?;
    let term_text = canonical_term(term)?;
    let why_text = why.map(str::trim).filter(|text| !text.is_empty());
    let view = storage.policy_view()?;

    let mut fragment = Fragment::empty();
    let channel_id = append_channel(&mut fragment, &channel_name);
    if let Some(existing) = channel_by_name(&view.reader, &view.facts, &channel_name)? {
        if existing != channel_id {
            bail!("canonical channel identity disagrees with stored channel");
        }
    }
    let (head, mut members) = policy_members(&view.facts, channel_id)?;

    let mut replaced = BTreeSet::new();
    for member in &members {
        if !exists!(pattern!(&view.facts, [{ (*member) @ metadata::tag: (&KIND_TERM) }])) {
            continue;
        }
        let handle = one_required(
            find!(
                value: TextHandle,
                pattern!(&view.facts, [{ (*member) @ posture::term: ?value }])
            )
            .collect(),
            "term text",
        )?;
        if read_text(&view.reader, handle, "term text")? == term_text {
            replaced.insert(*member);
        }
    }
    for member in &replaced {
        members.remove(member);
    }

    let term_handle: TextHandle = fragment.put(term_text.clone());
    let why_handle: Option<TextHandle> = why_text.map(|text| fragment.put(text.to_owned()));
    let term = entity! {
        metadata::tag: KIND_TERM,
        posture::in_channel: channel_id,
        posture::term: term_handle,
        posture::role: EXEMPLAR_PROTECTED,
        posture::why?: why_handle,
    };
    let term_id = term.root().expect("intrinsic term has one root");
    fragment += term;
    members.insert(term_id);

    if replaced == BTreeSet::from([term_id]) {
        println!("already protecting {term_text:?} from channel {channel_name:?}");
        return Ok(());
    }
    let predecessors = head.into_iter().collect();
    append_policy_revision(&mut fragment, channel_id, &members, &predecessors);
    storage.publish_policy(fragment, "posture policy term")?;
    println!("protecting {term_text:?} from channel {channel_name:?}");
    Ok(())
}

fn cmd_vocab_list(storage: PostureStorage<'_>, channel: Option<&str>) -> Result<()> {
    let view = storage.policy_view()?;
    let wanted = channel.map(canonical_channel).transpose()?;
    let mut channels = Vec::new();
    for (id, handle) in find!(
        (channel: Id, name: TextHandle),
        pattern!(&view.facts, [{
            ?channel @ metadata::tag: (&KIND_CHANNEL), posture::channel_name: ?name
        }])
    ) {
        let expected = entity! {
            metadata::tag: KIND_CHANNEL,
            posture::channel_name: handle,
        }
        .root()
        .expect("canonical channel has one root");
        if id != expected {
            continue;
        }
        channels.push((read_text(&view.reader, handle, "channel name")?, id));
    }
    channels.sort();
    channels.dedup();
    if channels.is_empty() {
        println!("no channels defined (add one with posture vocab add <term> --channel <name>)");
    }
    let mut forks = 0usize;
    for (name, channel_id) in channels {
        if wanted.as_ref().is_some_and(|wanted| wanted != &name) {
            continue;
        }
        match resolve_policy_head(&view.facts, channel_id)? {
            PolicyHead::Missing => println!("{name}  (!! no policy revision)"),
            PolicyHead::Forked(heads) => {
                forks += 1;
                println!("{name}  (!! FORKED across {} policy heads)", heads.len());
                for head in heads {
                    println!("  {}", fmt_id(head));
                }
            }
            PolicyHead::Unique { .. } => {
                let terms = channel_terms(&view.reader, &view.facts, channel_id)?;
                println!("{name}  ({} term(s))", terms.len());
                for (term, why) in terms {
                    if why.is_empty() {
                        println!("  {term}");
                    } else {
                        println!("  {term}  — {why}");
                    }
                }
            }
        }
    }
    if forks > 0 {
        bail!("{forks} channel policy fork(s) require explicit reconciliation");
    }
    Ok(())
}

/// Collect every protected-term hit in a commit range: messages, file paths,
/// and per-commit patches. The returned repository root and every locator are
/// canonical identity coordinates; abbreviated hashes exist only in display.
///
/// ONE implementation, used by both `posture git` and `posture sweep`. Two
/// copies of a security check drift, and the copy that drifts is the one that
/// quietly stops looking.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum UnsafeAttributeChange {
    Added,
    Removed,
}

impl UnsafeAttributeChange {
    fn label(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct GitHit {
    /// Content-addressed identity coordinate.
    location: Location,
    /// The coordinate exactly as observed, kept as evidence on the sighting.
    evidence: String,
    /// The commit the material was seen in — the rebuildable locator cache.
    seen_in: String,
    display: String,
    /// Unsafe-attribute hits only: the pin claim without its direction, so an
    /// add/remove pair that leaves the claim unchanged cancels.
    claim: Option<(UnsafeAttributeChange, String)>,
}

fn canonical_git_root(repo_path: &Path) -> Result<PathBuf> {
    let root = git_required(repo_path, &["rev-parse", "--show-toplevel"])?;
    let root = PathBuf::from(root.trim());
    std::fs::canonicalize(&root)
        .with_context(|| format!("canonicalize git repository root {}", root.display()))
}

#[derive(Debug)]
struct GitAudit {
    /// Physical repository root the audit ran against, regardless of how the
    /// caller spelled `--repo`. Identity no longer depends on it.
    repo_root: PathBuf,
    hits: BTreeMap<String, Vec<GitHit>>,
    unsafe_attribute_hits: Vec<GitHit>,
    commits: usize,
    added_lines: usize,
    removed_lines: usize,
}

const UNSAFE_ATTRIBUTE_FINDING: &str =
    "literal-pinned attribute identity (`unsafe as`) change requires justification";

fn abbreviated_object_id(object_id: &str) -> &str {
    &object_id[..object_id.len().min(8)]
}

fn git_hit(
    kind: &str,
    location: Location,
    sha: &str,
    position: impl std::fmt::Display,
    text: &str,
) -> GitHit {
    let position = position.to_string();
    GitHit {
        location,
        evidence: format!("{kind} {sha}:{position}  {}", text.trim()),
        seen_in: sha.to_owned(),
        display: format!(
            "{kind} {}:{position}  {}",
            abbreviated_object_id(sha),
            text.trim()
        ),
        claim: None,
    }
}

/// Unlike a protected-text hit, the policy judgement here belongs to the
/// source DECLARATION — its pinned id, name and encoding — not to a byte range
/// in one blob. So the carrier is the declaration posture normalized out of
/// the source, hashed by posture, and a reformat that leaves the claim intact
/// keeps its justification while a rebase or amend changes only the display.
/// Moving the declaration to another source path or changing its text is a new
/// finding and needs its own justification.
fn unsafe_attribute_hit(
    object_id: &str,
    position: &str,
    source_path: &str,
    change: UnsafeAttributeChange,
    declaration: &UnsafeAttributeDeclaration,
) -> GitHit {
    let carrier = Carrier::member(declaration.text.as_bytes());
    let claim = format!(
        "{}\u{0}{source_path}#{}",
        carrier.address(),
        declaration.same_text_ordinal
    );
    let coordinate = format!(
        "{} {source_path}#{}",
        change.label(),
        declaration.same_text_ordinal
    );
    GitHit {
        location: Location::field(carrier, coordinate),
        evidence: format!(
            "rust-attribute-{} {source_path}#{}  {}",
            change.label(),
            declaration.same_text_ordinal,
            declaration.text
        ),
        seen_in: object_id.to_owned(),
        display: format!(
            "unsafe-attribute-{} {}:{position}  {}",
            change.label(),
            abbreviated_object_id(object_id),
            declaration.text.trim()
        ),
        claim: Some((change, claim)),
    }
}

#[derive(Debug, Eq, PartialEq)]
struct UnsafeAttributeDeclaration {
    /// One-based inclusive source-line span.
    start_line: u64,
    end_line: u64,
    /// Whitespace-normalized complete declaration through its semicolon. The
    /// encoding remains part of this text when rustfmt wraps it.
    text: String,
    /// Distinguish repeated identical declarations without making ordinary
    /// source-line movement part of identity.
    same_text_ordinal: usize,
}

fn unsafe_attribute_declarations(source: &str) -> Vec<UnsafeAttributeDeclaration> {
    // Token-tree whitespace and comments may separate every part of the macro
    // arm, including the id literal from `unsafe as`. Match through the first
    // semicolon so the complete name and encoding participate in identity.
    let comments = r"(?:(?://[^\n]*\n)|(?:/\*.*?\*/)|\s)*";
    let pattern = format!(r#"(?ms)^[ \t]*"[0-9A-Fa-f]{{32}}"{comments}unsafe{comments}as\b"#);
    let declaration_start =
        Regex::new(&pattern).expect("unsafe attribute declaration regex is valid");
    let mut declarations = Vec::new();
    let mut text_counts = BTreeMap::<String, usize>::new();
    for matched in declaration_start.find_iter(source) {
        let Some(end) = rust_declaration_end(source, matched.end()) else {
            continue;
        };
        let matched_text = &source[matched.start()..end];
        let text = matched_text
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let same_text_ordinal = *text_counts
            .entry(text.clone())
            .and_modify(|count| *count += 1)
            .or_insert(1);
        declarations.push(UnsafeAttributeDeclaration {
            start_line: source[..matched.start()]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count() as u64
                + 1,
            end_line: source[..end].bytes().filter(|byte| *byte == b'\n').count() as u64 + 1,
            text,
            same_text_ordinal,
        });
    }
    declarations
}

/// Find the arm-terminating semicolon while ignoring semicolons inside Rust
/// comments and literals. This is intentionally a small lexer rather than
/// `[^;]*`: compatibility comments quite reasonably contain prose punctuation,
/// and truncating there would omit the encoding from the reviewed claim.
fn rust_declaration_end(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut index = start;
    let mut block_depth = 0usize;
    let mut line_comment = false;
    let mut string = false;
    let mut character = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        if line_comment {
            if byte == b'\n' {
                line_comment = false;
            }
            index += 1;
            continue;
        }
        if block_depth > 0 {
            if byte == b'/' && next == Some(b'*') {
                block_depth += 1;
                index += 2;
            } else if byte == b'*' && next == Some(b'/') {
                block_depth -= 1;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if string || character {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if (string && byte == b'"') || (character && byte == b'\'') {
                string = false;
                character = false;
            }
            index += 1;
            continue;
        }
        match (byte, next) {
            (b'/', Some(b'/')) => {
                line_comment = true;
                index += 2;
            }
            (b'/', Some(b'*')) => {
                block_depth = 1;
                index += 2;
            }
            (b'"', _) => {
                string = true;
                index += 1;
            }
            // Treat only a visibly closed short character literal as such;
            // ordinary Rust lifetimes should remain normal tokens.
            (b'\'', _) if bytes[index + 1..bytes.len().min(index + 8)].contains(&b'\'') => {
                character = true;
                index += 1;
            }
            (b';', _) => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}

fn hunk_start(line: &str, prefix: char) -> Option<u64> {
    line.split_whitespace().find_map(|field| {
        field
            .strip_prefix(prefix)
            .and_then(|range| range.split(',').next())
            .and_then(|start| start.parse::<u64>().ok())
    })
}

fn append_changed_unsafe_attributes(
    repo_root: &Path,
    display_commit: &str,
    treeish: &str,
    change: UnsafeAttributeChange,
    changed_lines: BTreeMap<String, BTreeSet<u64>>,
    hits: &mut Vec<GitHit>,
) -> Result<()> {
    for (patch_path, changed_lines) in changed_lines {
        if patch_path == "/dev/null" {
            continue;
        }
        let source_path = patch_path
            .strip_prefix("a/")
            .or_else(|| patch_path.strip_prefix("b/"))
            .unwrap_or(&patch_path);
        let object = format!("{treeish}:{source_path}");
        let source = git_required(repo_root, &["show", &object])?;
        for declaration in unsafe_attribute_declarations(&source) {
            if !(declaration.start_line..=declaration.end_line)
                .any(|line| changed_lines.contains(&line))
            {
                continue;
            }
            let position = if declaration.start_line == declaration.end_line {
                format!("{source_path}:{}", declaration.start_line)
            } else {
                format!(
                    "{source_path}:{}-{}",
                    declaration.start_line, declaration.end_line
                )
            };
            hits.push(unsafe_attribute_hit(
                display_commit,
                &position,
                source_path,
                change,
                &declaration,
            ));
        }
    }
    Ok(())
}

fn unsafe_attribute_claims(
    hits: &[GitHit],
    direction: UnsafeAttributeChange,
) -> BTreeSet<String> {
    hits.iter()
        .filter_map(|hit| hit.claim.as_ref())
        .filter(|(change, _)| *change == direction)
        .map(|(_, claim)| claim.clone())
        .collect()
}

fn cancel_unchanged_unsafe_attributes(hits: &mut Vec<GitHit>) {
    let added = unsafe_attribute_claims(hits, UnsafeAttributeChange::Added);
    let removed = unsafe_attribute_claims(hits, UnsafeAttributeChange::Removed);
    let unchanged = added
        .intersection(&removed)
        .cloned()
        .collect::<BTreeSet<_>>();
    hits.retain(|hit| {
        hit.claim
            .as_ref()
            .is_none_or(|(_, claim)| !unchanged.contains(claim))
    });
}

/// Audit one ordinary two-way commit edge. Merge commits are deliberately
/// expanded into one edge per parent: combined-diff syntax has one old
/// coordinate and prefix column per parent and cannot be parsed as a unified
/// diff without silently losing parent-specific removals.
fn collect_parent_unsafe_hits(
    repo_root: &Path,
    sha: &str,
    parent: Option<&str>,
    unsafe_attribute_hits: &mut Vec<GitHit>,
) -> Result<usize> {
    let patch = match parent {
        Some(parent) => git_required(
            repo_root,
            &[
                "diff",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--diff-algorithm=myers",
                "--unified=0",
                parent,
                sha,
            ],
        )?,
        None => git_required(
            repo_root,
            &[
                "show",
                "--format=",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--diff-algorithm=myers",
                "--unified=0",
                sha,
            ],
        )?,
    };

    let mut added_rust_lines = BTreeMap::<String, BTreeSet<u64>>::new();
    let mut removed_rust_lines = BTreeMap::<String, BTreeSet<u64>>::new();
    let mut old_patch_path = "?";
    let mut new_patch_path = "?";
    let mut next_old_line = None;
    let mut next_new_line = None;
    let mut n_removed = 0usize;
    for line in patch.lines() {
        if line.starts_with("diff --git ") {
            old_patch_path = "?";
            new_patch_path = "?";
            next_old_line = None;
            next_new_line = None;
            continue;
        }
        if let Some(path) = line.strip_prefix("--- ") {
            old_patch_path = path;
            next_old_line = None;
            continue;
        }
        if let Some(path) = line.strip_prefix("+++ ") {
            new_patch_path = path;
            next_new_line = None;
            continue;
        }
        if line.starts_with("@@") {
            next_old_line = hunk_start(line, '-');
            next_new_line = hunk_start(line, '+');
            continue;
        }
        if line.starts_with('-') && !line.starts_with("---") {
            n_removed += 1;
            if old_patch_path.ends_with(".rs") {
                if let Some(source_line) = next_old_line {
                    removed_rust_lines
                        .entry(old_patch_path.to_owned())
                        .or_default()
                        .insert(source_line);
                }
            }
            next_old_line = next_old_line.map(|line| line + 1);
            continue;
        }
        if !line.starts_with('+') || line.starts_with("+++") {
            if !line.starts_with('\\') {
                next_old_line = next_old_line.map(|line| line + 1);
                next_new_line = next_new_line.map(|line| line + 1);
            }
            continue;
        }
        let added_line = next_new_line;
        next_new_line = next_new_line.map(|line| line + 1);
        if new_patch_path.ends_with(".rs") {
            if let Some(line) = added_line {
                added_rust_lines
                    .entry(new_patch_path.to_owned())
                    .or_default()
                    .insert(line);
            }
        }
    }

    let mut edge_unsafe_hits = Vec::new();
    append_changed_unsafe_attributes(
        repo_root,
        sha,
        sha,
        UnsafeAttributeChange::Added,
        added_rust_lines,
        &mut edge_unsafe_hits,
    )?;
    if !removed_rust_lines.is_empty() {
        let parent =
            parent.ok_or_else(|| anyhow!("root commit {sha} unexpectedly removes source lines"))?;
        append_changed_unsafe_attributes(
            repo_root,
            sha,
            parent,
            UnsafeAttributeChange::Removed,
            removed_rust_lines,
            &mut edge_unsafe_hits,
        )?;
    }
    // A formatter may remove and add differently-spaced source lines while
    // leaving the normalized path/name/encoding claim unchanged. That is not a
    // pin lifecycle event and must retain its existing justification.
    cancel_unchanged_unsafe_attributes(&mut edge_unsafe_hits);
    unsafe_attribute_hits.extend(edge_unsafe_hits);
    Ok(n_removed)
}

/// Preserve the original protected-term semantics: one combined patch per
/// commit catches conflict-resolution text introduced relative to every parent
/// without treating ordinary content inherited from one side as newly
/// published again at the merge commit.
fn collect_commit_patch_term_hits(
    repo_root: &Path,
    sha: &str,
    terms: &[(String, String)],
    objects: &mut GitObjects,
    hits: &mut BTreeMap<String, Vec<GitHit>>,
) -> Result<usize> {
    let patch = git_required(
        repo_root,
        &[
            "show",
            "--format=",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--diff-algorithm=myers",
            "--unified=0",
            sha,
        ],
    )?;
    let mut patch_path = "?";
    let mut next_new_line = None;
    let mut n_added = 0usize;
    for (diff_line_index, line) in patch.lines().enumerate() {
        if let Some(path) = line.strip_prefix("+++ ") {
            patch_path = path;
            next_new_line = None;
            continue;
        }
        if line.starts_with("@@") {
            next_new_line = hunk_start(line, '+');
            continue;
        }
        if !line.starts_with('+') || line.starts_with("+++") {
            if next_new_line.is_some() && !line.starts_with('-') && !line.starts_with('\\') {
                next_new_line = next_new_line.map(|line| line + 1);
            }
            continue;
        }
        n_added += 1;
        let added_line = next_new_line;
        let position = match added_line {
            Some(new_line) => format!("{patch_path}:{new_line}:diff-{}", diff_line_index + 1),
            None => format!("{patch_path}:diff-{}", diff_line_index + 1),
        };
        next_new_line = next_new_line.map(|line| line + 1);
        let source_path = patch_path
            .strip_prefix("a/")
            .or_else(|| patch_path.strip_prefix("b/"))
            .unwrap_or(patch_path);
        let lower = line.to_lowercase();
        for (term, _) in terms {
            if !lower.contains(&term.to_lowercase()) {
                continue;
            }
            // The material is a line of the new file version, so it lives in
            // that file's blob — content-addressed, and untouched by the
            // rebase that used to re-identify it.
            let location = match added_line {
                Some(new_line) => objects.locate(repo_root, sha, source_path, new_line, term)?,
                None => Location::field(Carrier::Commit(sha.to_owned()), position.clone()),
            };
            hits.entry(term.clone())
                .or_default()
                .push(git_hit("patch", location, sha, &position, line));
        }
    }
    Ok(n_added)
}

fn collect_hits(
    repo_path: &Path,
    revisions: &[String],
    terms: &[(String, String)],
) -> Result<GitAudit> {
    let repo_root = canonical_git_root(repo_path)?;
    let mut objects = GitObjects::default();
    let mut hits: BTreeMap<String, Vec<GitHit>> = BTreeMap::new();
    let mut unsafe_attribute_hits = Vec::new();
    let mut n_commits = 0usize;
    let mut n_added = 0usize;
    let mut n_removed = 0usize;

    // Commit messages, one record per commit so a hit can name its commit.
    // %x1e separates sha from body, %x1f terminates the record — control
    // characters, so a message can never forge a record boundary.
    let log = git_required(&repo_root, &git_log_args(revisions, "--format=%H%x1e%B%x1f"))?;
    for rec in log.split('\u{1f}') {
        // `git log` writes a newline after each custom-format record. Remove
        // only that framing; line numbers within the message body are identity.
        let rec = rec.trim_start_matches('\n');
        if rec.is_empty() {
            continue;
        }
        n_commits += 1;
        let (sha, body) = rec.split_once('\u{1e}').unwrap_or(("?", rec));
        let sha = sha.trim();
        // A commit message has no blob, so the carrier is the commit and the
        // range is into its message. This is the one modality commit surgery
        // still moves; there is nothing content-addressed to hold it still.
        let mut offset = 0usize;
        for (line_index, raw) in body.split_inclusive('\n').enumerate() {
            let line = raw.trim_end_matches(['\n', '\r']);
            let lower = line.to_lowercase();
            for (t, _) in terms {
                if !lower.contains(&t.to_lowercase()) {
                    continue;
                }
                let location = commit_message_location(sha, offset, line, line_index, t);
                hits.entry(t.clone()).or_default().push(git_hit(
                    "message",
                    location,
                    sha,
                    line_index + 1,
                    line,
                ));
            }
            offset += raw.len();
        }
    }

    let shas: Vec<String> = git_required(&repo_root, &git_log_args(revisions, "--format=%H"))?
        .lines()
        .map(str::to_string)
        .collect();
    for sha in &shas {
        // FILE PATHS are published content too. A file at
        // a file whose PATH spells a protected term while its contents do not
        // in its path, and the patch body never mentions either — the `+++ b/`
        // header is the only place the name appears and it is skipped.
        for (path_index, path) in git_required(
            &repo_root,
            &["show", "--format=", "--name-only", "--no-renames", sha],
        )?
        .lines()
        .filter(|path| !path.is_empty())
        .enumerate()
        {
            let lower = path.to_lowercase();
            // A path is a tree entry, not bytes inside a blob. The blob it
            // names is still the content-addressed anchor: a rebase preserves
            // both the blob and the name it is stored under.
            let carrier = match objects.blob_at(&repo_root, sha, path)? {
                Some(oid) => Carrier::GitBlob(oid),
                None => Carrier::Commit(sha.to_owned()),
            };
            for (t, _) in terms {
                if lower.contains(&t.to_lowercase()) {
                    hits.entry(t.clone()).or_default().push(git_hit(
                        "path",
                        Location::field(carrier.clone(), path.to_owned()),
                        sha,
                        format!("{}:{path}", path_index + 1),
                        path,
                    ));
                }
            }
        }
        let lineage = git_required(&repo_root, &["rev-list", "--parents", "-n", "1", sha])?;
        let parents = lineage.split_whitespace().skip(1).collect::<Vec<_>>();
        if parents.is_empty() {
            let removed =
                collect_parent_unsafe_hits(&repo_root, sha, None, &mut unsafe_attribute_hits)?;
            n_removed += removed;
        } else {
            for parent in parents {
                let removed = collect_parent_unsafe_hits(
                    &repo_root,
                    sha,
                    Some(parent),
                    &mut unsafe_attribute_hits,
                )?;
                n_removed += removed;
            }
        }
        n_added += collect_commit_patch_term_hits(&repo_root, sha, terms, &mut objects, &mut hits)?;
    }
    // One sighting per (location, commit): the same material seen in two
    // commits is one finding with two sightings, never two findings.
    for term_hits in hits.values_mut() {
        term_hits.sort();
        term_hits.dedup();
    }
    unsafe_attribute_hits.sort();
    unsafe_attribute_hits.dedup();
    Ok(GitAudit {
        repo_root,
        hits,
        unsafe_attribute_hits,
        commits: n_commits,
        added_lines: n_added,
        removed_lines: n_removed,
    })
}

/// `git log <revisions...> <format>`. The revisions go in verbatim: git owns
/// that grammar, and re-parsing it here would only teach posture a worse
/// version of it.
fn git_log_args<'a>(revisions: &'a [String], format: &'a str) -> Vec<&'a str> {
    let mut args = vec!["log"];
    args.extend(revisions.iter().map(String::as_str));
    args.push(format);
    args
}

fn git_required(repo_path: &Path, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new("git")
        .env("LC_ALL", "C")
        .arg("-C")
        .arg(repo_path)
        .args(args)
        .output()
        .with_context(|| format!("run git -C {} {}", repo_path.display(), args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        bail!(
            "git -C {} {} failed{}",
            repo_path.display(),
            args.join(" "),
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// The protected terms for a channel, loaded once so a sweep does not reopen the
/// pile per repository.
fn load_channel_terms(
    storage: PostureStorage<'_>,
    channel: &str,
) -> Result<Option<(Id, Vec<(String, String)>)>> {
    let view = storage.policy_view()?;
    let Some(channel) = channel_by_name(&view.reader, &view.facts, channel)? else {
        return Ok(None);
    };
    Ok(Some((
        channel,
        channel_terms(&view.reader, &view.facts, channel)?,
    )))
}

fn load_terms(storage: PostureStorage<'_>, channel: &str) -> Result<Vec<(String, String)>> {
    Ok(load_channel_terms(storage, channel)?
        .map(|(_, terms)| terms)
        .unwrap_or_default())
}

fn git_audit_must_fail(
    lexical_checked: bool,
    protected_hits: usize,
    unsafe_attribute_hits: usize,
) -> bool {
    !lexical_checked || protected_hits > 0 || unsafe_attribute_hits > 0
}

fn cmd_git(
    storage: PostureStorage<'_>,
    revisions: &[String],
    channel: &str,
    repo_path: &Path,
) -> Result<()> {
    // A named option swallowed into the revision list would silently audit
    // against the DEFAULT channel — a gate quietly checking the wrong
    // vocabulary is worse than one that refuses.
    if let Some(bad) = revisions
        .iter()
        .find(|rev| rev.starts_with("--channel") || rev.starts_with("--repo"))
    {
        bail!(
            "{bad} was read as a revision, not an option; put --channel/--repo before the revisions"
        );
    }
    let range = revisions.join(" ");
    let policy = load_channel_terms(storage, channel)?;
    let (channel_id, terms) = match policy {
        Some((channel_id, terms)) => (Some(channel_id), terms),
        None => (None, Vec::new()),
    };
    let lexical_checked = !terms.is_empty();

    let GitAudit {
        repo_root,
        hits,
        unsafe_attribute_hits,
        commits: n_commits,
        added_lines: n_added,
        removed_lines: n_removed,
    } = collect_hits(repo_path, revisions, &terms)?;

    // Persist the complete audit before rendering or deciding the exit code.
    // This gives Decide a content-located finding to name and records a
    // genuinely empty audit differently from an audit never run.
    let decisions = storage.decide_view()?;
    let settled = settled_findings(
        &decisions.reader,
        &decisions.facts,
        legacy_bridges(&storage.scan_view()?.facts),
    )?;
    let findings = hits
        .iter()
        .flat_map(|(term, term_hits)| {
            term_hits.iter().map(move |hit| Found {
                modality: modality::PROTECTED_TERM,
                location: hit.location.clone(),
                evidence: hit.evidence.clone(),
                value: term.clone(),
                seen_in: Some(hit.seen_in.clone()),
            })
        })
        .chain(unsafe_attribute_hits.iter().map(|hit| Found {
            modality: modality::UNSAFE_ATTRIBUTE_ID,
            location: hit.location.clone(),
            evidence: hit.evidence.clone(),
            value: UNSAFE_ATTRIBUTE_FINDING.to_owned(),
            seen_in: Some(hit.seen_in.clone()),
        }))
        .collect::<Vec<_>>();
    let files = [ScannedFile {
        path: repo_root.clone(),
        outcome: FileOutcome::Examined,
        findings,
    }];
    let target = PathBuf::from(format!("git:{} {range}", repo_root.display()));
    let (fragment, _) = build_scan_fragment(
        &target,
        &files,
        &[],
        point_interval(now_epoch()?),
        channel_id,
        if lexical_checked {
            BTreeSet::from([modality::PROTECTED_TERM, modality::UNSAFE_ATTRIBUTE_ID])
        } else {
            BTreeSet::from([modality::UNSAFE_ATTRIBUTE_ID])
        },
    );
    storage.publish_scan(fragment, "posture git audit")?;

    let found = hits.values().map(Vec::len).sum::<usize>();
    let hits = hits
        .into_iter()
        .filter_map(|(term, term_hits)| {
            let kept = term_hits
                .into_iter()
                .filter(|hit| {
                    !settled.hides(
                        modality::PROTECTED_TERM,
                        finding_id(modality::PROTECTED_TERM, &hit.location),
                    )
                })
                .collect::<Vec<_>>();
            (!kept.is_empty()).then_some((term, kept))
        })
        .collect::<BTreeMap<_, _>>();
    let remaining = hits.values().map(Vec::len).sum::<usize>();
    let unsafe_found = unsafe_attribute_hits.len();
    let unsafe_attribute_hits = unsafe_attribute_hits
        .into_iter()
        .filter(|hit| {
            !settled.hides(
                modality::UNSAFE_ATTRIBUTE_ID,
                finding_id(modality::UNSAFE_ATTRIBUTE_ID, &hit.location),
            )
        })
        .collect::<Vec<_>>();
    let unsafe_remaining = unsafe_attribute_hits.len();
    let hidden = (found - remaining) + (unsafe_found - unsafe_remaining);

    println!("channel  : {channel} ({} protected term(s))", terms.len());
    if !lexical_checked {
        println!("lexical  : NOT CHECKED — channel has no protected-term vocabulary");
    }
    println!("range    : {range}");
    println!("examined : {n_commits} commit message(s), {n_added} added and {n_removed} removed line(s) across {n_commits} commit patch(es)\n");

    if hidden > 0 {
        println!(
            "{hidden} finding(s) hidden by a resolved Decide decision with result \"benign\"."
        );
    }
    if !hits.is_empty() {
        let total: usize = hits.values().map(|v| v.len()).sum();
        println!("{total} hit(s) across {} term(s):\n", hits.len());
        for (term, term_hits) in &hits {
            println!("  {term}  ({} hit(s))", term_hits.len());
            for hit in term_hits.iter().take(4) {
                let finding = finding_id(modality::PROTECTED_TERM, &hit.location);
                println!("    {}  {}", fmt_id(finding), hit.display);
            }
            if term_hits.len() > 4 {
                println!("    … {} more", term_hits.len() - 4);
            }
        }
    }
    if !unsafe_attribute_hits.is_empty() {
        println!(
            "{} literal-pinned Rust attribute declaration change(s) require justification:\n",
            unsafe_attribute_hits.len()
        );
        for hit in &unsafe_attribute_hits {
            println!(
                "    {}  {}",
                fmt_id(finding_id(modality::UNSAFE_ATTRIBUTE_ID, &hit.location)),
                hit.display
            );
        }
    }
    if hits.is_empty() && unsafe_attribute_hits.is_empty() {
        println!("no unresolved Posture finding remains in this range.");
    } else {
        println!(
            "\nA finding stops blocking only after a Decide decision about its exact id \
             resolves with `--result benign`; the outcome text is free prose and stays yours \
             to write. An unsafe-attribute change additionally requires a nonempty \
             `decide propose --context` justification."
        );
    }

    // Never a clean bill of health.
    println!("\nNOT CHECKED — this audit is narrow by construction:");
    println!("  - file contents outside this range's added lines");
    println!(
        "  - removed-line protected terms (literal-pinned attribute declarations ARE checked)"
    );
    println!("  - author names, emails and commit dates");
    println!("  - binary files, and anything a term does not literally spell");
    println!(
        "  - thematic material carrying no protected term (the 2026-07-22 leak was exactly this)"
    );

    if !lexical_checked {
        eprintln!(
            "posture: refusing a clean result because channel {channel:?} has no \
             protected-term vocabulary; the unsafe-attribute invariant was still checked."
        );
    }
    if git_audit_must_fail(
        lexical_checked,
        hits.values().map(Vec::len).sum(),
        unsafe_attribute_hits.len(),
    ) {
        std::process::exit(1);
    }
    Ok(())
}

/// Write the git hooks that run the audit without anyone having to remember it.
///
/// This is the point of the whole thing. A check you have to remember to run is
/// not a check — yesterday's near-miss was caught because I happened to look at
/// the remote first, which is luck, not process. Git already knows when content
/// is about to cross into a channel; the audit should be a side effect of that
/// moment rather than a separate obligation.
///
/// TWO moments, doing different jobs.
///
/// `pre-push` is the GATE. It refuses, because a push is the last moment the
/// material is still preventable.
///
/// `post-commit` is the SMOKE ALARM. By push time a leak is already in history
/// and the remedy is a rewrite; one commit earlier the remedy is
/// `git commit --amend`, which costs nothing. So it audits the commit that just
/// happened and SAYS so. It never fails: the commit already exists, a non-zero
/// exit from post-commit changes nothing git does, and a hook that produces
/// only noise gets deleted.
///
/// Both are installed by default because they are two halves of one habit;
/// `--pre-push` or `--post-commit` installs just that one.
fn cmd_hook(
    storage: PostureStorage<'_>,
    repo: &Path,
    channel: &str,
    remote_match: Option<&str>,
    pre_push: bool,
    post_commit: bool,
) -> Result<()> {
    // Neither flag means "set this repo up", which is both. Naming one is a
    // deliberate restriction, never an accidental one.
    let (want_pre_push, want_post_commit) = match (pre_push, post_commit) {
        (false, false) => (true, true),
        pair => pair,
    };
    let git_dir = {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["rev-parse", "--git-dir"])
            .output()
            .map_err(|e| anyhow!("run git: {e}"))?;
        if !out.status.success() {
            anyhow::bail!("{} is not a git repository", repo.display());
        }
        let rel = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let p = PathBuf::from(&rel);
        if p.is_absolute() {
            p
        } else {
            repo.join(p)
        }
    };
    let hooks = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks).map_err(|e| anyhow!("create {}: {e}", hooks.display()))?;

    let exe = std::env::current_exe()
        .map_err(|e| anyhow!("locate posture binary: {e}"))?
        .display()
        .to_string();
    let pile = storage.pile.display().to_string();
    let key = storage
        .key
        .map(Path::display)
        .map(|path| path.to_string())
        .unwrap_or_default();

    // Shared by both hooks so they cannot drift apart on the one thing that
    // matters most: what happens when the tooling is missing. `verdict` is the
    // word for what this particular hook does about it, because the pre-push
    // gate refuses the push and the post-commit alarm cannot refuse anything.
    let missing_tooling = |verdict: &str, on_missing_exit: &str| {
        format!(
            r#"# Fail LEGIBLY. If the binary has been rebuilt away or the pile has moved,
# "command not found" gives no clue why. A safety tool that gets in the way
# without explaining itself gets deleted in irritation, which is the worst
# possible outcome for it.
if [ ! -x "$POSTURE" ]; then
    echo "posture: hook installed but the binary is missing at:" >&2
    echo "           $POSTURE" >&2
    echo "         Rebuild it, or remove this hook with:" >&2
    echo "           rm \"$0\"" >&2
    echo "         {verdict}" >&2
    exit {on_missing_exit}
fi
if [ ! -f "$PILE" ]; then
    echo "posture: hook installed but the pile is missing at:" >&2
    echo "           $PILE" >&2
    echo "         The protected vocabulary lives there, so nothing can be checked." >&2
    echo "         {verdict}" >&2
    exit {on_missing_exit}
fi"#
        )
    };

    // The pre-push protocol feeds us "<local ref> <local sha> <remote ref>
    // <remote sha>" per line. An all-zero remote sha means the remote has no
    // such ref yet — a brand-new branch.
    let pre_push_script = format!(
        r#"#!/bin/sh
# Installed by `posture hook`. Audits what is about to cross into a channel.
# Bypass with --no-verify, but read what it says first.
set -e
POSTURE="{exe}"
PILE="{pile}"
KEY="{key}"
CHANNEL="{channel}"
ZERO=0000000000000000000000000000000000000000
REMOTE_MATCH="{remote_match}"

# git passes the remote NAME as $1 and its URL as $2. A channel describes a
# destination, so a push to a remote this channel does not cover must be skipped
# — auditing a private archive against the public vocabulary is a category
# error, and it blocked a legitimate backup push once. Skipping is announced,
# never silent.
if [ -n "$REMOTE_MATCH" ]; then
    case "$2$1" in
        *"$REMOTE_MATCH"*) : ;;
        *)
            echo "posture: remote '$1' does not match '$REMOTE_MATCH' for channel '$CHANNEL' — not audited."
            exit 0
            ;;
    esac
fi

{missing}

status=0
# What is already at the remote is not preventable, so the gate does not read
# it. It reads what this push ADDS. For a new branch that is NOT its whole
# history — the branch is new, the commits behind it are mostly not — so the
# selection is "reachable from the pushed ref, not from anything this remote
# already has". Auditing the whole history here made a two-file push demand
# justification for 291 commits and 347k lines of other people's work, and a
# gate nobody can pass is a gate that gets --no-verify'd. History is audited by
# `posture sweep --history`, where it can be worked through rather than
# blocking a push.
if git remote | grep -qx -- "$1"; then
    already_there="--remotes=$1"
else
    # Pushing to a bare URL: no remote-tracking refs name it, so fall back to
    # every remote. Over-auditing here is the safe direction.
    already_there="--remotes"
fi

while read -r _local_ref local_sha _remote_ref remote_sha; do
    [ "$local_sha" = "$ZERO" ] && continue          # branch deletion
    if [ "$remote_sha" = "$ZERO" ]; then
        # New branch. Deliberately unquoted below: these are shas and ref
        # globs, and they have to reach git as separate arguments.
        revisions="$local_sha --not $already_there"
    else
        revisions="$remote_sha..$local_sha"
    fi
    if [ -n "$KEY" ]; then
        PILE="$PILE" TRIBLESPACE_KEY="$KEY" \
            "$POSTURE" git --channel "$CHANNEL" $revisions || status=1
    else
        PILE="$PILE" "$POSTURE" git --channel "$CHANNEL" $revisions || status=1
    fi
done

if [ "$status" != 0 ]; then
    echo ""
    echo "posture: refusing the push. Fix, or re-run with --no-verify if these are"
    echo "         genuinely fine for the '$CHANNEL' channel."
fi
exit $status
"#,
        exe = exe,
        pile = pile,
        key = key,
        channel = channel,
        remote_match = remote_match.unwrap_or(""),
        missing = missing_tooling(
            "Refusing the push rather than passing an unchecked one.",
            "1"
        ),
    );

    // ADVISORY, and every line below follows from that. The commit already
    // exists; there is no verdict to hand back, only news to deliver early
    // enough to be worth having.
    //
    // DETACHED, and that follows from advisory too. The audit costs one pile
    // open, which on a real pile is not small: 142s of CPU to read a one-line
    // commit, measured. A commit that pauses for two minutes is a commit
    // nobody makes, and this hook would be deleted within the day. Since there
    // is no verdict to wait for, nothing is gained by making anyone wait —
    // `git commit --amend` stays cheap until the push, not for the next two
    // minutes. So git returns immediately and the report arrives when it does,
    // in the terminal and in a log beside the hook so it cannot be lost.
    let post_commit_script = format!(
        r#"#!/bin/sh
# Installed by `posture hook`. Audits the commit that just happened, so a leak
# is news while `git commit --amend` is still the whole remedy.
#
# ADVISORY. It never fails a commit — the commit already exists, so a non-zero
# exit would change nothing git does and would only train you to ignore it.
# The gate that actually refuses is the pre-push hook.
#
# It does NOT consult a remote-match: a commit has no destination yet, so it
# always audits against '{channel}'. Erring toward telling you is the right
# error for something that cannot block.
POSTURE="{exe}"
PILE="{pile}"
KEY="{key}"
CHANNEL="{channel}"

{missing}

GIT_DIR_PATH=$(git rev-parse --git-dir)
LOG="$GIT_DIR_PATH/posture-post-commit.log"
LOCK="$GIT_DIR_PATH/posture-post-commit.lock"

# Just the commit that was made. `HEAD^@` is all of HEAD's parents, so on a
# merge this is the merge commit alone rather than the entire branch it brought
# in — those commits were news when they were made, and re-announcing them on
# every merge is how an alarm becomes wallpaper. A root commit has no parent to
# subtract.
if git rev-parse --verify --quiet HEAD^1 >/dev/null 2>&1; then
    revisions="HEAD --not HEAD^@"
else
    revisions="HEAD"
fi
head_sha=$(git rev-parse HEAD)

# `mkdir` is the atomic test-and-set every shell has. Two audits of one pile at
# once would only make both slower; the one already running is announced rather
# than silently dropped, because a smoke alarm that quietly does nothing is
# worse than no smoke alarm.
if ! mkdir "$LOCK" 2>/dev/null; then
    echo "posture: an audit of an earlier commit is still running, so $(git rev-parse --short HEAD) was NOT checked."
    echo "         Re-run it yourself with:  posture git HEAD --not HEAD^@ --channel $CHANNEL"
    echo "         (or remove a stale lock:  rmdir \"$LOCK\")"
    exit 0
fi

# Detached. Deliberately unquoted revisions: they are revision arguments and
# must reach git separately.
{{
    if [ -n "$KEY" ]; then
        report=$(PILE="$PILE" TRIBLESPACE_KEY="$KEY" \
            "$POSTURE" git --channel "$CHANNEL" $revisions 2>&1)
    else
        report=$(PILE="$PILE" "$POSTURE" git --channel "$CHANNEL" $revisions 2>&1)
    fi
    found=$?
    rmdir "$LOCK" 2>/dev/null

    if [ "$found" = 0 ]; then
        # Quiet on a clean commit. The full coverage report after every single
        # commit is noise, and noise is how this hook gets removed.
        echo ""
        echo "posture: nothing flagged in $(git rev-parse --short "$head_sha" 2>/dev/null) for '$CHANNEL' (narrow by"
        echo "         construction — \`posture git HEAD --not HEAD^@\` prints what it did not check)."
        exit 0
    fi

    echo ""
    echo "posture: COMMIT $(git rev-parse --short "$head_sha" 2>/dev/null) carries something the '$CHANNEL' channel protects."
    echo ""
    printf '%s\n' "$report" | sed 's/^/  /'
    echo ""
    echo "  It is not pushed yet, so the whole remedy is still cheap:"
    echo "    git commit --amend        (fix the content, keep the commit)"
    echo "  or, if the material is genuinely fine for this channel:"
    echo "    decide propose \"<what this is>\" --context \"<why it is fine>\" --about <finding id>"
    echo "    decide resolve <decision> \"<the reasoning>\" --result benign"
    echo ""
    echo "  Nothing is blocked. The pre-push hook is what will refuse."
}} 2>&1 | tee -a "$LOG" &

# Advisory to the end: never non-zero, and never a wait.
exit 0
"#,
        exe = exe,
        pile = pile,
        key = key,
        channel = channel,
        missing = missing_tooling(
            "Reporting nothing rather than pretending this commit was checked.",
            "0"
        ),
    );

    let mut wanted = Vec::new();
    if want_pre_push {
        wanted.push(("pre-push", &pre_push_script));
    }
    if want_post_commit {
        wanted.push(("post-commit", &post_commit_script));
    }

    // Refuse the whole install before writing ANY of it. Half-installing and
    // then erroring would leave a repo whose hooks disagree about which
    // moments are audited, which is worse than the clean refusal.
    for (name, _) in &wanted {
        refuse_foreign_hook(&hooks, name)?;
    }
    for (name, script) in &wanted {
        println!("installed {}", write_hook(&hooks, name, script)?.display());
    }
    println!("  channel : {channel}");
    match remote_match {
        Some(m) => println!("  remotes : only those matching {m:?} (pre-push only)"),
        None => println!("  remotes : ALL (pass --remote-match to scope by destination)"),
    }
    println!("  pile    : {}", storage.pile.display());
    if want_pre_push {
        println!("\npre-push is the GATE. It runs on every push and exits non-zero on a hit,");
        println!("and also when the channel has no vocabulary — a hook that passes because");
        println!("it checked nothing is worse than no hook. It audits what the push ADDS,");
        println!("never what the remote already holds; for existing history run");
        println!("`posture sweep --history`.");
    }
    if want_post_commit {
        println!("\npost-commit is the SMOKE ALARM. It audits the commit that just happened");
        println!("and never refuses anything — by push time a leak is history and the remedy");
        println!("is a rewrite; one commit earlier it is `git commit --amend`. It runs");
        println!("DETACHED, so the commit returns at once and the report follows a little");
        println!("later, in the terminal and in .git/posture-post-commit.log.");
    }
    Ok(())
}

/// Never clobber someone else's hook silently — that would be a destructive
/// side effect of a command that reads like a setup step.
fn refuse_foreign_hook(hooks: &Path, name: &str) -> Result<()> {
    let path = hooks.join(name);
    if path.exists() {
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        if !existing.contains("Installed by `posture hook`") {
            anyhow::bail!(
                "{} already exists and was not written by posture; refusing to overwrite it",
                path.display()
            );
        }
    }
    Ok(())
}

/// Write one hook, executable.
fn write_hook(hooks: &Path, name: &str, script: &str) -> Result<PathBuf> {
    let path = hooks.join(name);
    std::fs::write(&path, script).map_err(|e| anyhow!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| anyhow!("chmod {}: {e}", path.display()))?;
    }
    Ok(path)
}

// ── the semantic tier ────────────────────────────────────────────────────────
//
// Lexical matching cannot reach the case that has actually leaked. On
// 2026-07-22 an entire private narrative shipped in a public repository as a
// semantic-search test corpus, and a proper-noun grep returned clean because
// none of those documents contained the proper nouns.
//
// CHUNKED, and this is the whole design rather than an implementation detail. A
// whole-document embedding is dominated by the document's dominant topic, so one
// sensitive paragraph inside a long technical file is diluted away — measured:
// querying the shared space with a paraphrase of a single passage failed to
// surface the fragment containing it, while near-verbatim text scored 0.737. A
// document-level scanner would therefore miss precisely the shape of leak this
// tier exists for. So chunks are scored, and a document takes its MAXIMUM.

#[cfg(feature = "local-embed")]
use faculties::nomic::load_text_embedder;

/// Unit vectors, so a dot product is the cosine.
#[cfg(feature = "local-embed")]
fn l2(mut v: Vec<f32>) -> Vec<f32> {
    let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 {
        for x in &mut v {
            *x /= n;
        }
    }
    v
}

/// Overlapping windows of whole lines. Overlap matters: a passage that straddles
/// a boundary would otherwise be split into two halves, each too diluted to
/// score, which is the same dilution failure one level down.
#[cfg(feature = "local-embed")]
fn chunks(text: &str, lines_per: usize, stride: usize) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let end = (i + lines_per).min(lines.len());
        let body = lines[i..end].join("\n");
        // Skip chunks with too little prose to mean anything; an embedding of
        // three lines of punctuation is noise that will happily score 0.4.
        if body.split_whitespace().count() >= 12 {
            out.push((i + 1, body));
        }
        if end == lines.len() {
            break;
        }
        i += stride;
    }
    out
}

#[cfg(feature = "local-embed")]
fn cmd_exemplar(
    storage: PostureStorage<'_>,
    text: &str,
    channel: &str,
    benign: bool,
) -> Result<()> {
    let body = canonical_exemplar(&read_arg(text)?);
    if body.split_whitespace().count() < 12 {
        bail!(
            "exemplar is too short to embed meaningfully ({} words)",
            body.split_whitespace().count()
        );
    }
    let channel_name = canonical_channel(channel)?;
    eprintln!("posture: loading nomic-embed-text (once)…");
    let embedder = load_text_embedder()?;
    let vector = l2(embedder
        .embed_query(&body)
        .map_err(|error| anyhow!("embed exemplar: {error:?}"))?);

    let view = storage.policy_view()?;
    let mut fragment = Fragment::empty();
    let channel_id = append_channel(&mut fragment, &channel_name);
    let (head, mut members) = policy_members(&view.facts, channel_id)?;
    let replaced = take_exemplars_with_body(&view.reader, &view.facts, &mut members, &body)?;
    let text_handle: TextHandle = fragment.put(body.clone());
    let role = if benign {
        EXEMPLAR_BENIGN
    } else {
        EXEMPLAR_PROTECTED
    };
    let exemplar = entity! {
        metadata::tag: KIND_EXEMPLAR,
        posture::term: text_handle,
        posture::in_channel: channel_id,
        posture::role: role,
    };
    let exemplar_id = exemplar.root().expect("intrinsic exemplar has one root");
    fragment += exemplar;

    // The vector is reproducible exhaust attached after deriving the semantic
    // identity. Model/backend improvements therefore never rename the policy
    // member or fork its snapshot.
    let vector_handle = fragment.put(vector);
    fragment += entity! {
        ExclusiveId::force_ref(&exemplar_id) @
        embeddings::attr::embedding: vector_handle
    };

    members.insert(exemplar_id);
    if replaced != BTreeSet::from([exemplar_id]) {
        let predecessors = head.into_iter().collect();
        append_policy_revision(&mut fragment, channel_id, &members, &predecessors);
    }
    if fragment.facts().difference(&view.facts).is_empty() {
        println!(
            "already stored {} exemplar for channel {channel_name:?}",
            if benign { "BENIGN" } else { "protected" }
        );
        return Ok(());
    }
    storage.publish_policy(fragment, "posture policy exemplar")?;
    println!(
        "stored {} exemplar ({} words) for channel {channel_name:?}",
        if benign { "BENIGN" } else { "protected" },
        body.split_whitespace().count()
    );
    Ok(())
}

#[cfg(feature = "local-embed")]
fn cmd_semantic(
    storage: PostureStorage<'_>,
    root: &Path,
    channel: &str,
    threshold: f32,
) -> Result<()> {
    // Load the exact current policy snapshot first: no point loading a model to
    // compare against zero, and a fork is invalid rather than arbitrated.
    let view = storage.policy_view()?;
    let Some(channel_id) = channel_by_name(&view.reader, &view.facts, channel)? else {
        bail!("channel {channel:?} has no policy");
    };
    let (_, members) = policy_members(&view.facts, channel_id)?;
    let mut exemplars: Vec<(bool, String, Vec<f32>)> = Vec::new();
    let mut n_protected = 0usize;
    let mut n_benign = 0usize;
    for exemplar in members {
        if !exists!(pattern!(&view.facts, [{
            (exemplar) @ metadata::tag: (&KIND_EXEMPLAR)
        }])) {
            continue;
        }
        let text = one_required(
            find!(
                value: TextHandle,
                pattern!(&view.facts, [{ (exemplar) @ posture::term: ?value }])
            )
            .collect(),
            "exemplar text",
        )?;
        let role = one_required(
            find!(
                value: Id,
                pattern!(&view.facts, [{ (exemplar) @ posture::role: ?value }])
            )
            .collect(),
            "exemplar role",
        )?;
        let benign = match role {
            EXEMPLAR_BENIGN => {
                n_benign += 1;
                true
            }
            EXEMPLAR_PROTECTED => {
                n_protected += 1;
                false
            }
            _ => bail!(
                "exemplar {} has unknown role {}",
                fmt_id(exemplar),
                fmt_id(role)
            ),
        };
        let vectors = find!(
            value: Inline<inlineencodings::Handle<Embedding768>>,
            pattern!(&view.facts, [{
                (exemplar) @ embeddings::attr::embedding: ?value
            }])
        )
        .collect::<BTreeSet<_>>();
        if vectors.is_empty() {
            bail!(
                "exemplar {} has no embedding exhaust; semantic scan cannot examine it",
                fmt_id(exemplar)
            );
        }
        let text = read_text(&view.reader, text, "exemplar text")?;
        for vector in vectors {
            let vector: View<[f32]> = view
                .reader
                .get(vector)
                .with_context(|| format!("read embedding for exemplar {}", fmt_id(exemplar)))?;
            exemplars.push((benign, text.clone(), vector.to_vec()));
        }
    }
    if n_protected == 0 {
        // Same rule as the lexical tier: a scan with nothing to compare against
        // would report clean while checking nothing.
        anyhow::bail!(
            "channel {channel:?} has no protected exemplars — a semantic scan against none \
             would report clean while comparing nothing. Add one with \
             `posture exemplar @file --channel {channel}`"
        );
    }

    let mut files = Vec::new();
    let mut omissions = Vec::new();
    walk(root, &mut files, &mut omissions);
    files.sort();
    // NO EXTENSION WHITELIST. An earlier version filtered to a known list of
    // text extensions, and three files of pure protected narrative named .rst,
    // .org and .adoc produced "examined: 0 files" and a clean result — the exact
    // vacuous green this tool exists to refuse, built in by a performance
    // shortcut. Files are now excluded by MEASURED properties (too large, not
    // valid UTF-8), never by their name, and every exclusion is counted and
    // reported.
    const MAX_BYTES: u64 = 4 * 1024 * 1024;
    let mut too_big = 0usize;
    let mut texty = Vec::new();
    for path in files {
        match std::fs::metadata(&path) {
            Ok(m) if m.len() > MAX_BYTES => {
                too_big += 1;
            }
            Ok(_) => texty.push(path),
            Err(error) => omissions.push(WalkOmission {
                path,
                detail: format!("metadata failed before semantic scan: {error}"),
            }),
        }
    }

    eprintln!("posture: loading nomic-embed-text (once)…");
    let emb = load_text_embedder()?;

    let mut hits: Vec<(f32, PathBuf, usize, String)> = Vec::new();
    let mut n_chunks = 0usize;
    let mut skipped = 0usize;
    for p in &texty {
        let Ok(text) = std::fs::read_to_string(p) else {
            skipped += 1;
            continue;
        };
        let mut best: Option<(f32, usize, String)> = None;
        for (line, body) in chunks(&text, 12, 8) {
            n_chunks += 1;
            let v = emb
                .embed_query(&body)
                .map_err(|error| anyhow!("embed {}:{line}: {error:?}", p.display()))?;
            let v = l2(v);
            // DISCRIMINATIVE, not absolute. Nearest protected exemplar minus
            // nearest benign one, so whatever the two have in common — being
            // careful explanatory English, mostly — cancels out. With no benign
            // set this degrades to the absolute score, which measured register
            // rather than content and flagged 98 of 103 real source files.
            let nearest = |want_benign: bool| {
                exemplars
                    .iter()
                    .filter(|(b, _, _)| *b == want_benign)
                    .map(|(_, _, e)| e.iter().zip(&v).map(|(a, b)| a * b).sum::<f32>())
                    .fold(f32::NEG_INFINITY, f32::max)
            };
            let protected = nearest(false);
            let benign = nearest(true);
            let score = if benign.is_finite() {
                protected - benign
            } else {
                protected
            };
            if best.as_ref().is_none_or(|(b, _, _)| score > *b) {
                // The most prose-like line in the chunk, not the first one. A
                // finding whose evidence reads "}" is a finding the reviewer
                // dismisses without looking, which wastes the whole detection.
                let snippet = body
                    .lines()
                    .map(str::trim)
                    .max_by_key(|l| {
                        l.split_whitespace()
                            .filter(|w| w.chars().any(char::is_alphabetic))
                            .count()
                    })
                    .unwrap_or("")
                    .to_string();
                best = Some((score, line, snippet));
            }
        }
        // A document takes its best chunk, never an average — averaging is the
        // dilution this tier exists to defeat.
        if let Some((score, line, snip)) = best {
            if score >= threshold {
                hits.push((score, p.clone(), line, snip));
            }
        }
    }
    hits.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    println!("channel  : {channel} ({n_protected} protected, {n_benign} benign exemplar(s))");
    if n_benign == 0 {
        println!("  !! no benign exemplars: scores are ABSOLUTE and will track prose register");
        println!("     rather than content. Add contrast with `posture exemplar ... --benign`.");
    }
    println!(
        "examined : {} of {} file(s), {n_chunks} chunk(s), threshold {threshold}",
        texty.len() - skipped,
        texty.len() + too_big
    );
    println!();
    if hits.is_empty() {
        println!("no chunk resembles an exemplar above {threshold}.");
    } else {
        println!("{} document(s) with a resembling chunk:\n", hits.len());
        for (score, p, line, snip) in hits.iter().take(40) {
            let s: String = snip.chars().take(80).collect();
            println!("  {score:.3}  {}:{line}  {s}", p.display());
        }
        if hits.len() > 40 {
            println!("  … {} more", hits.len() - 40);
        }
    }
    println!("\nNOT CHECKED:");
    // Counted, not asserted. A coverage line that states a policy instead of a
    // measurement is how "0 files examined" once read as a clean bill of health.
    println!("  - {skipped} file(s) that are not valid UTF-8 (binaries, PDFs, office documents — use `posture scan`)");
    println!("  - {too_big} file(s) over {} MiB", MAX_BYTES / 1024 / 1024);
    for omission in &omissions {
        println!("  - {} ({})", omission.path.display(), omission.detail);
    }
    println!("  - anything an exemplar does not resemble — this tier is only as");
    println!("    broad as the exemplars given to it, and cosine similarity is a");
    println!("    proxy for 'about the same thing', not a proof of it");
    println!();
    println!("  READ THIS BEFORE TRUSTING THE RANKING. Measured 2026-08-05 on this");
    println!("  project: the tier DETECTS but does not RANK. Inserting a narrative");
    println!("  paragraph moved its own file 0.017 -> 0.039, yet two innocent files");
    println!("  scored higher (0.081, 0.076) — ordinary doc comments about memory and");
    println!("  identity. This codebase IMPLEMENTS the concepts the protected material");
    println!("  DESCRIBES, so both occupy the same semantic region and no absolute");
    println!("  threshold separates them. That is structural, not a tuning problem.");
    println!("  Use it on a DIFF, where a file is its own baseline, not as a filter");
    println!("  over a tree. Corpora whose subject matter differs from the protected");
    println!("  material should behave far better.");
    Ok(())
}

#[cfg(not(feature = "local-embed"))]
fn cmd_exemplar(_: PostureStorage<'_>, _: &str, _: &str, _: bool) -> Result<()> {
    anyhow::bail!("built without the `local-embed` feature; the semantic tier is unavailable")
}

#[cfg(not(feature = "local-embed"))]
fn cmd_semantic(_: PostureStorage<'_>, _: &Path, _: &str, _: f32) -> Result<()> {
    anyhow::bail!("built without the `local-embed` feature; the semantic tier is unavailable")
}

/// `@path` reads a file, `@-` reads stdin, anything else is the literal text —
/// the same convention the other faculties use for prose arguments.
#[cfg(feature = "local-embed")]
fn read_arg(arg: &str) -> Result<String> {
    match arg {
        "@-" => {
            use std::io::Read;
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| anyhow!("read stdin: {e}"))?;
            Ok(s)
        }
        a if a.starts_with('@') => {
            std::fs::read_to_string(&a[1..]).map_err(|e| anyhow!("read {}: {e}", &a[1..]))
        }
        a => Ok(a.to_string()),
    }
}

/// One pass over every repository under `root`: which have a remote that reaches
/// this channel, which are ahead of it, and which of those carry protected
/// material.
///
/// Written after finding, by luck during an unrelated hygiene check, a private
/// full-history archive whose only remote was the public repository it had been
/// created to be separated from. "Which repos can leak" should not depend on
/// somebody happening to look.
fn cmd_sweep(
    storage: PostureStorage<'_>,
    root: &Path,
    channel: &str,
    all: bool,
    history: bool,
) -> Result<()> {
    let terms = load_terms(storage, channel)?;
    let lexical_checked = !terms.is_empty();
    let decisions = storage.decide_view()?;
    let settled = settled_findings(
        &decisions.reader,
        &decisions.facts,
        legacy_bridges(&storage.scan_view()?.facts),
    )?;

    let mut repos = Vec::new();
    for entry in
        std::fs::read_dir(root).with_context(|| format!("read sweep root {}", root.display()))?
    {
        let path = entry
            .with_context(|| format!("read directory entry under {}", root.display()))?
            .path();
        if path.join(".git").exists() {
            repos.push(path);
        }
    }
    repos.sort();

    let have_gh = std::process::Command::new("gh")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);

    println!("channel  : {channel} ({} protected term(s))", terms.len());
    if !lexical_checked {
        println!("lexical  : NOT CHECKED — channel has no protected-term vocabulary");
    }
    println!("root     : {}", root.display());
    println!("repos    : {}\n", repos.len());
    if !have_gh && !all {
        println!("  !! gh is unavailable: visibility is unknown, so EVERY repo with a");
        println!("     remote is audited rather than silently skipped.\n");
    }

    let mut flagged = 0usize;
    let mut skipped_private = 0usize;
    let mut no_remote = 0usize;
    for repo in &repos {
        let Some(origin) = git_probe(repo, &["remote", "get-url", "origin"], &[2])? else {
            no_remote += 1;
            continue;
        };
        let slug = origin
            .rsplit_once(':')
            .map(|(_, suffix)| suffix)
            .unwrap_or(&origin)
            .trim_end_matches(".git")
            .rsplitn(3, '/')
            .take(2)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("/");
        let visibility = if have_gh {
            std::process::Command::new("gh")
                .args([
                    "repo",
                    "view",
                    &slug,
                    "--json",
                    "visibility",
                    "-q",
                    ".visibility",
                ])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
                .unwrap_or_else(|| "UNKNOWN".to_owned())
        } else {
            "UNKNOWN".to_owned()
        };
        if visibility == "PRIVATE" && !all {
            skipped_private += 1;
            continue;
        }

        // Prefer the remote mainline. With no remote mainline or upstream, scan
        // all of HEAD; an absent comparison base must never turn into zero work.
        let base = if history {
            None
        } else if git_probe(
            repo,
            &["rev-parse", "--verify", "--quiet", "origin/main"],
            &[1],
        )?
        .is_some()
        {
            Some("origin/main")
        } else if git_probe(
            repo,
            &["rev-parse", "--verify", "--quiet", "origin/master"],
            &[1],
        )?
        .is_some()
        {
            Some("origin/master")
        } else if git_probe(repo, &["rev-parse", "--verify", "--quiet", "@{u}"], &[1])?.is_some() {
            Some("@{u}")
        } else {
            None
        };
        let range = base
            .map(|base| format!("{base}..HEAD"))
            .unwrap_or_else(|| "HEAD".to_owned());
        let revisions = vec![range.clone()];
        // `ahead` is the honest word for the default range and a lie for
        // --history, where the same number counts the whole reachable history.
        let scope = if history { "reach" } else { "ahead" };
        let ahead = git_required(repo, &["log", "--oneline", &range])?
            .lines()
            .filter(|line| !line.is_empty())
            .count();
        if ahead == 0 {
            continue;
        }
        let GitAudit {
            hits,
            unsafe_attribute_hits,
            ..
        } = collect_hits(repo, &revisions, &terms)?;
        let hits = hits
            .into_iter()
            .filter_map(|(term, term_hits)| {
                let kept = term_hits
                    .into_iter()
                    .filter(|hit| {
                        !settled.hides(
                            modality::PROTECTED_TERM,
                            finding_id(modality::PROTECTED_TERM, &hit.location),
                        )
                    })
                    .collect::<Vec<_>>();
                (!kept.is_empty()).then_some((term, kept))
            })
            .collect::<BTreeMap<_, _>>();
        let unsafe_attribute_hits = unsafe_attribute_hits
            .into_iter()
            .filter(|hit| {
                !settled.hides(
                    modality::UNSAFE_ATTRIBUTE_ID,
                    finding_id(modality::UNSAFE_ATTRIBUTE_ID, &hit.location),
                )
            })
            .collect::<Vec<_>>();
        let count: usize = hits.values().map(Vec::len).sum::<usize>() + unsafe_attribute_hits.len();
        if count > 0 {
            flagged += 1;
            let classes = hits.len() + usize::from(!unsafe_attribute_hits.is_empty());
            println!(
                "  {:<24} {:<28} {visibility:<8} {scope}={ahead:<5} {count} finding(s) across {classes} class(es)",
                repo.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("?"),
                slug,
            );
            println!("      (range {range})");
            for (term, lines) in &hits {
                println!("      {term}  ({} hit(s))", lines.len());
            }
            if !unsafe_attribute_hits.is_empty() {
                println!(
                    "      unsafe-attribute-id  ({} finding(s))",
                    unsafe_attribute_hits.len()
                );
            }
        } else {
            println!(
                "  {:<24} {:<28} {visibility:<8} {scope}={ahead:<5} clean",
                repo.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("?"),
                slug
            );
        }
    }

    println!(
        "\n{flagged} repositor(y/ies) carry unresolved Posture findings {}.",
        if history {
            "anywhere in their reachable history"
        } else {
            "ahead of their remote"
        }
    );
    println!("\nNOT CHECKED:");
    println!("  - {skipped_private} repo(s) whose remote gh reports PRIVATE (re-run with --all)");
    println!("  - {no_remote} repo(s) with no origin remote");
    println!("  - repos nested deeper than one level under the root");
    println!("  - OTHER BRANCHES of a scanned repo: only the checked-out HEAD is audited");
    if !history {
        println!(
            "  - HISTORY already on the remote: only work ahead of it was read (pass --history)"
        );
    }
    println!("  - uncommitted work, which cannot be pushed but can be committed later");
    println!("  - everything posture git does not check (see its own coverage note)");

    if !lexical_checked {
        eprintln!(
            "posture: sweep cannot issue a clean result because channel {channel:?} has no \
             protected-term vocabulary; unsafe-attribute invariants were still checked."
        );
    }
    if flagged > 0 || !lexical_checked {
        std::process::exit(1);
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = PostureStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };
    match cli.command {
        // no subcommand still links the schema, so the attributes stay discoverable
        None => {
            Cli::command().print_help().ok();
            println!();
            Ok(())
        }
        Some(Command::Scan { path, dry_run }) => cmd_scan(storage, &path, dry_run),
        Some(Command::List {
            scan,
            examples,
            all,
            ids,
        }) => cmd_list(storage, scan, examples, all, ids),
        Some(Command::Coverage { scan }) => cmd_coverage(storage, scan),
        Some(Command::Scans) => cmd_scans(storage),
        Some(Command::Hook {
            repo,
            channel,
            remote_match,
            pre_push,
            post_commit,
        }) => cmd_hook(
            storage,
            &repo,
            &channel,
            remote_match.as_deref(),
            pre_push,
            post_commit,
        ),
        Some(Command::Sweep {
            root,
            channel,
            all,
            history,
        }) => cmd_sweep(storage, &root, &channel, all, history),
        Some(Command::Exemplar {
            text,
            channel,
            benign,
        }) => cmd_exemplar(storage, &text, &channel, benign),
        Some(Command::Semantic {
            path,
            channel,
            threshold,
        }) => cmd_semantic(storage, &path, &channel, threshold),
        Some(Command::Vocab { command }) => match command {
            VocabCommand::Add { term, channel, why } => {
                cmd_vocab_add(storage, &term, &channel, why.as_deref())
            }
            VocabCommand::List { channel } => cmd_vocab_list(storage, channel.as_deref()),
        },
        Some(Command::Git {
            range,
            channel,
            repo,
        }) => cmd_git(storage, &range, &channel, &repo),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    /// A revision selection as `git log` would receive it.
    fn revs(spec: &str) -> Vec<String> {
        spec.split_whitespace().map(str::to_owned).collect()
    }

    struct TestStore {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
    }

    impl TestStore {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("posture-test.pile");
            let key = directory.path().join("posture-test.key");
            File::create(&pile).unwrap();
            faculties::storage::initialize_signer(&pile, Some(&key)).unwrap();
            Self {
                _directory: directory,
                pile,
                key,
            }
        }

        fn storage(&self) -> PostureStorage<'_> {
            PostureStorage {
                pile: &self.pile,
                key: Some(&self.key),
            }
        }

        fn publish_raw(&self, scope: Id, mut fragment: Fragment, description: &str) {
            fragment.describe_with(entity! { metadata::description: description.to_owned() });
            faculties::storage::publish_fragment(
                &self.pile,
                Some(&self.key),
                scope,
                fragment,
            )
            .unwrap();
        }
    }

    fn git_fixture(repo: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .env("LC_ALL", "C")
            .env("GIT_AUTHOR_NAME", "Posture Fixture")
            .env("GIT_AUTHOR_EMAIL", "posture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Posture Fixture")
            .env("GIT_COMMITTER_EMAIL", "posture@example.invalid")
            .arg("-C")
            .arg(repo)
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git -C {} {} failed: {}",
            repo.display(),
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn git_audit_fixture() -> tempfile::TempDir {
        // Creating the fixture below the test process's cwd gives us both a
        // genuinely relative spelling and an absolute spelling of one repo.
        let directory = tempfile::Builder::new()
            .prefix("posture-git-")
            .tempdir_in(".")
            .unwrap();
        git_fixture(directory.path(), &["init", "--quiet"]);
        std::fs::write(
            directory.path().join("fixture.txt"),
            "project-sunrise\nproject-sunrise\n",
        )
        .unwrap();
        git_fixture(directory.path(), &["add", "fixture.txt"]);
        git_fixture(
            directory.path(),
            &[
                "commit",
                "--quiet",
                "-m",
                "fixture",
                "-m",
                "project-sunrise\nproject-sunrise",
            ],
        );
        directory
    }

    fn git_unsafe_attribute_fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        git_fixture(directory.path(), &["init", "--quiet"]);
        std::fs::write(
            directory.path().join("schema.rs"),
            concat!(
                "attributes! {\n",
                "    \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" unsafe as legacy: ShortString;\n",
                "}\n",
            ),
        )
        .unwrap();
        git_fixture(directory.path(), &["add", "schema.rs"]);
        git_fixture(
            directory.path(),
            &["commit", "--quiet", "-m", "legacy fixture"],
        );

        std::fs::write(
            directory.path().join("schema.rs"),
            concat!(
                "attributes! {\n",
                "    \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" unsafe as legacy: ShortString;\n",
                "    \"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\" as safe: ShortString;\n",
                "    \"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\" unsafe as pub migrated:\n",
                "        ShortString;\n",
                "    // \"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\" unsafe as prose: ShortString;\n",
                "}\n",
                "const EXPLANATION: &str = \"unsafe as is exceptional\";\n",
            ),
        )
        .unwrap();
        std::fs::write(
            directory.path().join("notes.txt"),
            "\"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE\" unsafe as not_rust: ShortString;\n",
        )
        .unwrap();
        git_fixture(directory.path(), &["add", "schema.rs", "notes.txt"]);
        git_fixture(
            directory.path(),
            &["commit", "--quiet", "-m", "new declarations"],
        );
        directory
    }

    fn append_test_term(fragment: &mut Fragment, channel: Id, raw: &str, why: Option<&str>) -> Id {
        let text: TextHandle = fragment.put(canonical_term(raw).unwrap());
        let why: Option<TextHandle> = why.map(|value| fragment.put(value.trim().to_owned()));
        let term = entity! {
            metadata::tag: KIND_TERM,
            posture::in_channel: channel,
            posture::term: text,
            posture::role: EXEMPLAR_PROTECTED,
            posture::why?: why,
        };
        let id = term.root().unwrap();
        *fragment += term;
        id
    }

    fn append_test_exemplar(
        fragment: &mut Fragment,
        channel: Id,
        raw: &str,
        role: Id,
        vector: Vec<f32>,
    ) -> Id {
        let text: TextHandle = fragment.put(canonical_exemplar(raw));
        let exemplar = entity! {
            metadata::tag: KIND_EXEMPLAR,
            posture::in_channel: channel,
            posture::term: text,
            posture::role: role,
        };
        let id = exemplar.root().unwrap();
        *fragment += exemplar;
        let embedding = fragment.put(vector);
        *fragment += entity! {
            ExclusiveId::force_ref(&id) @ embeddings::attr::embedding: embedding
        };
        id
    }

    /// A container-member finding for fixtures. The member is the coordinate's
    /// own bytes, which is enough to give each fixture finding a distinct
    /// carrier without carrying a real document around.
    fn f(modality: Id, field: &str, value: &str) -> Found {
        member_found(modality, Carrier::member(field.as_bytes()), field, value)
    }

    fn sample_scan_inputs() -> (Vec<ScannedFile>, Vec<WalkOmission>) {
        (
            vec![
                ScannedFile {
                    path: PathBuf::from("examined.png"),
                    outcome: FileOutcome::Examined,
                    findings: vec![f(modality::EXIF, "EXIF:Artist", "Example Author")],
                },
                ScannedFile {
                    path: PathBuf::from("unsupported.bin"),
                    outcome: FileOutcome::Unsupported,
                    findings: Vec::new(),
                },
                ScannedFile {
                    path: PathBuf::from("broken.pdf"),
                    outcome: FileOutcome::ParseFailed("malformed fixture".to_owned()),
                    findings: Vec::new(),
                },
            ],
            vec![WalkOmission {
                path: PathBuf::from("linked-directory"),
                detail: "directory symlink deliberately not followed".to_owned(),
            }],
        )
    }

    #[test]
    fn canonical_policy_write_is_idempotent_and_reads_are_pure() {
        let store = TestStore::new();
        let storage = store.storage();

        cmd_vocab_add(
            storage,
            "  Project-Sunrise  ",
            "  Public-Release ",
            Some("  example fixture  "),
        )
        .unwrap();
        let view = storage.policy_view().unwrap();
        assert_eq!(
            storage
                .authored_commits(DEFAULT_POLICY_SCOPE_ID, "policy")
                .unwrap()
                .len(),
            1
        );
        let channel = channel_by_name(&view.reader, &view.facts, "PUBLIC-RELEASE")
            .unwrap()
            .unwrap();
        assert_eq!(
            channel_terms(&view.reader, &view.facts, channel).unwrap(),
            vec![("project-sunrise".to_owned(), "example fixture".to_owned())]
        );
        drop(view);

        let after_first_write = std::fs::metadata(&store.pile).unwrap().len();
        cmd_vocab_add(
            storage,
            "PROJECT-SUNRISE",
            "public-release",
            Some("example fixture"),
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(&store.pile).unwrap().len(),
            after_first_write,
            "an idempotent policy write must not append another COMMIT"
        );

        storage.policy_view().unwrap();
        storage.scan_view().unwrap();
        assert_eq!(
            std::fs::metadata(&store.pile).unwrap().len(),
            after_first_write,
            "materializing either collection must not mutate the pile"
        );

        let missing_key = store._directory.path().join("missing.key");
        let unavailable = PostureStorage {
            key: Some(&missing_key),
            ..storage
        };
        assert!(unavailable.policy_view().is_err());
        assert!(!missing_key.exists(), "a read must never mint a signer");
        assert_eq!(
            std::fs::metadata(&store.pile).unwrap().len(),
            after_first_write
        );
    }

    #[test]
    fn sibling_policy_revisions_remain_visible_and_block_consumers() {
        let store = TestStore::new();
        let mut fragment = Fragment::empty();
        let channel = append_channel(&mut fragment, "public-release");
        let left_term = append_test_term(&mut fragment, channel, "alpha", None);
        let right_term = append_test_term(&mut fragment, channel, "beta", None);
        let base =
            append_policy_revision(&mut fragment, channel, &BTreeSet::new(), &BTreeSet::new());
        append_policy_revision(
            &mut fragment,
            channel,
            &BTreeSet::from([left_term]),
            &BTreeSet::from([base]),
        );
        append_policy_revision(
            &mut fragment,
            channel,
            &BTreeSet::from([right_term]),
            &BTreeSet::from([base]),
        );
        store.publish_raw(DEFAULT_POLICY_SCOPE_ID, fragment, "forked policy fixture");

        let view = store.storage().policy_view().unwrap();
        match resolve_policy_head(&view.facts, channel).unwrap() {
            PolicyHead::Forked(heads) => assert_eq!(heads.len(), 2),
            other => panic!("expected visible policy fork, got {other:?}"),
        }
        drop(view);
        let error = load_terms(store.storage(), "public-release").unwrap_err();
        assert!(error.to_string().contains("FORKED"));
    }

    #[test]
    fn one_revision_cannot_name_two_versions_of_the_same_term() {
        let store = TestStore::new();
        let mut fragment = Fragment::empty();
        let channel = append_channel(&mut fragment, "public-release");
        let old = append_test_term(&mut fragment, channel, "alpha", Some("old rationale"));
        let new = append_test_term(&mut fragment, channel, "alpha", Some("new rationale"));
        append_policy_revision(
            &mut fragment,
            channel,
            &BTreeSet::from([old, new]),
            &BTreeSet::new(),
        );
        store.publish_raw(
            DEFAULT_POLICY_SCOPE_ID,
            fragment,
            "ambiguous policy fixture",
        );

        let error = store.storage().policy_view().unwrap_err();
        assert!(error
            .to_string()
            .contains("two identities for canonical term"));
    }

    #[test]
    fn exemplar_identity_excludes_embedding_exhaust_and_role_changes_replace_membership() {
        let store = TestStore::new();
        let mut first = Fragment::empty();
        let channel = append_channel(&mut first, "public-release");
        let exemplar = append_test_exemplar(
            &mut first,
            channel,
            "A generic protected example passage.",
            EXEMPLAR_PROTECTED,
            vec![0.0; 768],
        );
        append_policy_revision(
            &mut first,
            channel,
            &BTreeSet::from([exemplar]),
            &BTreeSet::new(),
        );
        store.publish_raw(DEFAULT_POLICY_SCOPE_ID, first, "first exemplar exhaust");

        let mut second = Fragment::empty();
        let second_channel = append_channel(&mut second, "public-release");
        let same_exemplar = append_test_exemplar(
            &mut second,
            second_channel,
            "A generic protected example passage.",
            EXEMPLAR_PROTECTED,
            vec![1.0; 768],
        );
        assert_eq!(channel, second_channel);
        assert_eq!(exemplar, same_exemplar);
        store.publish_raw(
            DEFAULT_POLICY_SCOPE_ID,
            second,
            "replacement exemplar exhaust",
        );

        let view = store.storage().policy_view().unwrap();
        let roles = find!(
            role: Id,
            pattern!(&view.facts, [{ (exemplar) @ posture::role: ?role }])
        )
        .collect::<BTreeSet<_>>();
        assert_eq!(roles, BTreeSet::from([EXEMPLAR_PROTECTED]));
        let vectors = find!(
            vector: Inline<inlineencodings::Handle<Embedding768>>,
            pattern!(&view.facts, [{
                (exemplar) @ embeddings::attr::embedding: ?vector
            }])
        )
        .collect::<BTreeSet<_>>();
        assert_eq!(
            vectors.len(),
            2,
            "embedding versions are retained as exhaust"
        );

        let (head, mut members) = policy_members(&view.facts, channel).unwrap();
        let removed = take_exemplars_with_body(
            &view.reader,
            &view.facts,
            &mut members,
            "A generic protected example passage.",
        )
        .unwrap();
        assert_eq!(removed, BTreeSet::from([exemplar]));
        assert!(!members.contains(&exemplar));
        drop(view);

        let mut role_change = Fragment::empty();
        let role_channel = append_channel(&mut role_change, "public-release");
        let benign = append_test_exemplar(
            &mut role_change,
            role_channel,
            "A generic protected example passage.",
            EXEMPLAR_BENIGN,
            vec![0.5; 768],
        );
        members.insert(benign);
        append_policy_revision(
            &mut role_change,
            role_channel,
            &members,
            &head.into_iter().collect(),
        );
        store.publish_raw(DEFAULT_POLICY_SCOPE_ID, role_change, "exemplar role change");
        let view = store.storage().policy_view().unwrap();
        let (_, current) = policy_members(&view.facts, channel).unwrap();
        assert!(current.contains(&benign));
        assert!(!current.contains(&exemplar));

        let invalid = TestStore::new();
        let mut ambiguous = Fragment::empty();
        let channel = append_channel(&mut ambiguous, "public-release");
        let protected = append_test_exemplar(
            &mut ambiguous,
            channel,
            "One passage cannot occupy both policy roles.",
            EXEMPLAR_PROTECTED,
            vec![0.0; 768],
        );
        let benign = append_test_exemplar(
            &mut ambiguous,
            channel,
            "One passage cannot occupy both policy roles.",
            EXEMPLAR_BENIGN,
            vec![1.0; 768],
        );
        append_policy_revision(
            &mut ambiguous,
            channel,
            &BTreeSet::from([protected, benign]),
            &BTreeSet::new(),
        );
        invalid.publish_raw(
            DEFAULT_POLICY_SCOPE_ID,
            ambiguous,
            "ambiguous exemplar roles",
        );
        assert!(invalid
            .storage()
            .policy_view()
            .unwrap_err()
            .to_string()
            .contains("two identities for canonical exemplar"));
    }

    #[test]
    fn complete_scan_is_one_atomic_commit_with_explicit_outcomes_and_omissions() {
        let store = TestStore::new();
        let created_at = point_interval(Epoch::from_unix_seconds(1_234.0));
        let (files, omissions) = sample_scan_inputs();
        let (fragment, scan) = build_scan_fragment(
            Path::new("fixture-corpus"),
            &files,
            &omissions,
            created_at,
            None,
            IMPLEMENTED.iter().copied().collect(),
        );
        assert_eq!(
            validate_scan_commit_fragment(fragment.facts()).unwrap(),
            scan
        );
        store
            .storage()
            .publish_scan(fragment, "complete scan fixture")
            .unwrap();

        let view = store.storage().scan_view().unwrap();
        assert_eq!(
            store
                .storage()
                .authored_commits(DEFAULT_SCAN_SCOPE_ID, "scan")
                .unwrap()
                .len(),
            1
        );
        let outcomes = find!(
            outcome: Id,
            pattern!(&view.facts, [{
                _?document @ metadata::tag: (&KIND_DOCUMENT), posture::outcome: ?outcome
            }])
        )
        .collect::<BTreeSet<_>>();
        assert_eq!(
            outcomes,
            BTreeSet::from([OUTCOME_EXAMINED, DOC_UNSUPPORTED, OUTCOME_PARSE_FAILED])
        );
        assert_eq!(
            find!(
                omission: Id,
                pattern!(&view.facts, [{ ?omission @ metadata::tag: (&KIND_OMISSION) }])
            )
            .count(),
            1
        );
        drop(view);

        // The same observation signed twice is not two scans. It is one scan
        // spread over two COMMITs, which the atomicity rule rejects.
        let (files, omissions) = sample_scan_inputs();
        let (duplicate, duplicate_scan) = build_scan_fragment(
            Path::new("fixture-corpus"),
            &files,
            &omissions,
            created_at,
            None,
            IMPLEMENTED.iter().copied().collect(),
        );
        assert_eq!(scan, duplicate_scan);

        let (mut changed_files, omissions) = sample_scan_inputs();
        changed_files[0].findings[0].value = "Different Author".to_owned();
        let (_, changed_scan) = build_scan_fragment(
            Path::new("fixture-corpus"),
            &changed_files,
            &omissions,
            created_at,
            None,
            IMPLEMENTED.iter().copied().collect(),
        );
        assert_ne!(
            scan, changed_scan,
            "changing evidence under an otherwise identical header must change the Merkle root"
        );

        let error = store
            .storage()
            .publish_scan(duplicate, "duplicate scan fixture")
            .unwrap_err();
        assert!(error.to_string().contains("scans must be atomic"));
    }

    #[test]
    fn git_only_modality_preserves_historical_file_scan_coverage() {
        let created_at = point_interval(Epoch::from_unix_seconds(1_500.0));
        let (files, omissions) = sample_scan_inputs();
        let (historical, historical_scan) = build_scan_fragment(
            Path::new("historical-file-scan"),
            &files,
            &omissions,
            created_at,
            None,
            IMPLEMENTED.iter().copied().collect(),
        );
        assert_eq!(
            validate_scan_commit_fragment(historical.facts()).unwrap(),
            historical_scan
        );
        assert!(!exists!(pattern!(historical.facts(), [{
            (historical_scan) @ posture::unchecked: (&modality::UNSAFE_ATTRIBUTE_ID)
        }])));

        let files = [ScannedFile {
            path: PathBuf::from("repository"),
            outcome: FileOutcome::Examined,
            findings: vec![f(
                modality::UNSAFE_ATTRIBUTE_ID,
                "rust-attribute-added src/schema.rs#1",
                UNSAFE_ATTRIBUTE_FINDING,
            )],
        }];
        let (git, git_scan) = build_scan_fragment(
            Path::new("git:repository HEAD"),
            &files,
            &[],
            point_interval(Epoch::from_unix_seconds(1_501.0)),
            None,
            BTreeSet::from([modality::PROTECTED_TERM, modality::UNSAFE_ATTRIBUTE_ID]),
        );
        assert_eq!(
            validate_scan_commit_fragment(git.facts()).unwrap(),
            git_scan
        );
        assert!(exists!(pattern!(git.facts(), [{
            _?finding @ metadata::tag: (&KIND_FINDING), metadata::tag: (&modality::UNSAFE_ATTRIBUTE_ID)
        }])));
    }

    #[test]
    fn scan_structure_rejects_incomplete_and_semantically_inconsistent_records() {
        let target = Path::new("fixture-corpus");
        let created_at = point_interval(Epoch::from_unix_seconds(2_345.0));

        let mut missing_coverage = Fragment::empty();
        let target_handle: TextHandle = missing_coverage.put(target.display().to_string());
        missing_coverage += entity! {
            metadata::tag: KIND_SCAN,
            metadata::created_at: created_at,
            posture::target: target_handle,
            posture::file_count: 0_u64,
            posture::checked*: BTreeSet::from([modality::EXIF]),
            posture::unchecked*: BTreeSet::<Id>::new(),
        };
        assert!(validate_scan_commit_fragment(missing_coverage.facts())
            .unwrap_err()
            .to_string()
            .contains("partition every file-scan coverage modality"));

        let mut missing_document = Fragment::empty();
        let target_handle: TextHandle = missing_document.put(target.display().to_string());
        missing_document += entity! {
            metadata::tag: KIND_SCAN,
            metadata::created_at: created_at,
            posture::target: target_handle,
            posture::file_count: 1_u64,
            posture::checked*: IMPLEMENTED.iter().copied().collect::<BTreeSet<_>>(),
            posture::unchecked*: unchecked_modalities(),
        };
        assert!(validate_scan_commit_fragment(missing_document.facts())
            .unwrap_err()
            .to_string()
            .contains("file_count"));

        let mut no_detail = Fragment::empty();
        let target_handle: TextHandle = no_detail.put(target.display().to_string());
        let path: TextHandle = no_detail.put("broken.pdf".to_owned());
        let document = entity! {
            metadata::tag: KIND_DOCUMENT,
            posture::path: path,
            posture::outcome: OUTCOME_PARSE_FAILED,
        };
        let document_id = document.root().unwrap();
        let scan_entity = entity! {
            metadata::tag: KIND_SCAN,
            metadata::created_at: created_at,
            posture::target: target_handle,
            posture::file_count: 1_u64,
            posture::checked*: IMPLEMENTED.iter().copied().collect::<BTreeSet<_>>(),
            posture::unchecked*: unchecked_modalities(),
            posture::scan_document*: BTreeSet::from([document_id]),
        };
        no_detail += document;
        no_detail += scan_entity;
        assert!(validate_scan_commit_fragment(no_detail.facts())
            .unwrap_err()
            .to_string()
            .contains("parse-failure detail"));

        let files = vec![ScannedFile {
            path: PathBuf::from("examined.png"),
            outcome: FileOutcome::Examined,
            findings: vec![f(modality::EXIF, "EXIF:Artist", "Example Author")],
        }];
        let (left, _) = build_scan_fragment(
            target,
            &files,
            &[],
            created_at,
            None,
            IMPLEMENTED.iter().copied().collect(),
        );
        let files = vec![ScannedFile {
            path: PathBuf::from("examined.png"),
            outcome: FileOutcome::Examined,
            findings: Vec::new(),
        }];
        let (right, _) = build_scan_fragment(
            target,
            &files,
            &[],
            point_interval(Epoch::from_unix_seconds(2_346.0)),
            None,
            IMPLEMENTED.iter().copied().collect(),
        );
        let mut mixed = left.into_facts();
        mixed += right.into_facts();
        assert!(validate_scan_commit_fragment(&mixed)
            .unwrap_err()
            .to_string()
            .contains("scan COMMIT root"));
    }

    #[test]
    fn semantic_occurrences_are_settled_directly_by_exact_decide_outcomes() {
        let store = TestStore::new();
        let storage = store.storage();
        let (files, omissions) = sample_scan_inputs();
        let (first, first_scan) = build_scan_fragment(
            Path::new("fixture-corpus"),
            &files,
            &omissions,
            point_interval(Epoch::from_unix_seconds(3_000.0)),
            None,
            IMPLEMENTED.iter().copied().collect(),
        );
        let occurrence = one_required(
            find!(
                finding: Id,
                pattern!(first.facts(), [{ ?finding @ metadata::tag: (&KIND_FINDING) }])
            )
            .collect(),
            "fixture finding",
        )
        .unwrap();
        storage.publish_scan(first, "first semantic scan").unwrap();

        let (second, second_scan) = build_scan_fragment(
            Path::new("fixture-corpus"),
            &files,
            &omissions,
            point_interval(Epoch::from_unix_seconds(3_001.0)),
            None,
            IMPLEMENTED.iter().copied().collect(),
        );
        assert_ne!(first_scan, second_scan);
        // The same material, observed again: one finding, two sightings.
        assert!(exists!(pattern!(second.facts(), [{
            (occurrence) @ metadata::tag: (&KIND_FINDING)
        }])));
        storage
            .publish_scan(second, "second semantic scan")
            .unwrap();

        let decision = genid().id;
        let proposed = decide::decision_fragment(
            decision,
            "Classify this Posture occurrence",
            None,
            Some(occurrence),
            point_interval(Epoch::from_unix_seconds(3_002.0)),
        )
        .unwrap()
        .0;
        store.publish_raw(
            DEFAULT_DECIDE_SCOPE_ID,
            proposed,
            "unresolved fixture decision",
        );
        let view = storage.decide_view().unwrap();
        assert!(!benign_occurrences(&view.reader, &view.facts)
            .unwrap()
            .contains(&occurrence));

        let benign = decide::resolution_fragment(
            decision,
            "benign, and here is a whole sentence of reasoning about why",
            Some(decide::RESULT_BENIGN),
            true,
            &[],
            &[],
            point_interval(Epoch::from_unix_seconds(3_003.0)),
        )
        .unwrap()
        .0;
        store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, benign, "benign fixture decision");
        let view = storage.decide_view().unwrap();
        assert!(benign_occurrences(&view.reader, &view.facts)
            .unwrap()
            .contains(&occurrence));

        let disagreement = genid().id;
        let proposed = decide::decision_fragment(
            disagreement,
            "Reconsider this Posture occurrence",
            None,
            Some(occurrence),
            point_interval(Epoch::from_unix_seconds(3_004.0)),
        )
        .unwrap()
        .0;
        store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, proposed, "second fixture decision");
        let other = decide::resolution_fragment(
            disagreement,
            "sensitive",
            None,
            true,
            &[],
            &[],
            point_interval(Epoch::from_unix_seconds(3_005.0)),
        )
        .unwrap()
        .0;
        store.publish_raw(
            DEFAULT_DECIDE_SCOPE_ID,
            other,
            "disagreeing fixture decision",
        );
        let view = storage.decide_view().unwrap();
        assert!(!benign_occurrences(&view.reader, &view.facts)
            .unwrap()
            .contains(&occurrence));
    }

    #[test]
    fn agreed_benign_heads_settle_but_a_fork_does_not() {
        let store = TestStore::new();
        let decision = genid().id;
        let occurrence = genid().id;
        store.publish_raw(
            DEFAULT_DECIDE_SCOPE_ID,
            decide::decision_fragment(
                decision,
                "Classify occurrence",
                None,
                Some(occurrence),
                point_interval(Epoch::from_unix_seconds(4_000.0)),
            )
            .unwrap()
            .0,
            "fixture decision",
        );
        store.publish_raw(
            DEFAULT_DECIDE_SCOPE_ID,
            decide::resolution_fragment(
                decision,
                "benign, and here is a whole sentence of reasoning about why",
                Some(decide::RESULT_BENIGN),
                true,
                &[],
                &[],
                point_interval(Epoch::from_unix_seconds(4_001.0)),
            )
            .unwrap()
            .0,
            "first benign head",
        );
        store.publish_raw(
            DEFAULT_DECIDE_SCOPE_ID,
            decide::resolution_fragment(
                decision,
                "benign, and here is a whole sentence of reasoning about why",
                Some(decide::RESULT_BENIGN),
                true,
                &[],
                &[],
                point_interval(Epoch::from_unix_seconds(4_002.0)),
            )
            .unwrap()
            .0,
            "second benign head",
        );
        let view = store.storage().decide_view().unwrap();
        assert!(matches!(
            decide::resolution(&view.facts, decision),
            Resolution::Agreed(_)
        ));
        assert!(benign_occurrences(&view.reader, &view.facts)
            .unwrap()
            .contains(&occurrence));

        store.publish_raw(
            DEFAULT_DECIDE_SCOPE_ID,
            decide::resolution_fragment(
                decision,
                "reject",
                None,
                true,
                &[],
                &[],
                point_interval(Epoch::from_unix_seconds(4_003.0)),
            )
            .unwrap()
            .0,
            "rejecting head",
        );
        let view = store.storage().decide_view().unwrap();
        assert!(matches!(
            decide::resolution(&view.facts, decision),
            Resolution::Forked(_)
        ));
        assert!(!benign_occurrences(&view.reader, &view.facts)
            .unwrap()
            .contains(&occurrence));
    }

    /// The two hooks do different jobs, and the difference has to be real in
    /// the generated scripts, not only in the documentation.
    #[test]
    fn the_gate_refuses_and_the_smoke_alarm_never_does() {
        let store = TestStore::new();
        let repo = git_audit_fixture();
        let hooks = repo.path().join(".git").join("hooks");

        cmd_hook(
            store.storage(),
            repo.path(),
            "github-public",
            Some("example"),
            false,
            false,
        )
        .unwrap();

        let pre_push = std::fs::read_to_string(hooks.join("pre-push")).unwrap();
        let post_commit = std::fs::read_to_string(hooks.join("post-commit")).unwrap();

        // Neither flag installs both: they are two halves of one habit.
        assert!(pre_push.contains("Installed by `posture hook`"));
        assert!(post_commit.contains("Installed by `posture hook`"));

        // The gate reads what the push ADDS, and refuses.
        assert!(pre_push.contains("--not $already_there"));
        assert!(pre_push.contains("exit $status"));
        assert!(pre_push.contains("Refusing the push"));

        // The alarm reads the commit that just happened, and cannot refuse:
        // every exit it can reach is zero, including the one where its own
        // tooling is missing.
        assert!(post_commit.contains("HEAD --not HEAD^@"));
        // It must not make anyone WAIT either: one pile open is 142s of CPU,
        // and a commit that pauses for two minutes is a commit nobody makes.
        assert!(
            post_commit.contains("| tee -a \"$LOG\" &"),
            "the audit has to run detached or the hook is unusable on a real pile"
        );
        assert!(post_commit.contains("mkdir \"$LOCK\""));
        assert!(
            !post_commit.contains("exit 1"),
            "a post-commit hook that exits non-zero changes nothing git does and \
             only trains the reader to ignore it"
        );
        // A destination it cannot know must not silently narrow what it reads.
        assert!(!post_commit.contains("REMOTE_MATCH"));

        // Naming one hook is a deliberate restriction. Install into a second
        // repo so this is not confused with the pair written above.
        let single = git_audit_fixture();
        cmd_hook(
            store.storage(),
            single.path(),
            "github-public",
            None,
            false,
            true,
        )
        .unwrap();
        let single_hooks = single.path().join(".git").join("hooks");
        assert!(single_hooks.join("post-commit").exists());
        assert!(!single_hooks.join("pre-push").exists());
    }

    /// A hook someone else wrote is not ours to overwrite, and that has to hold
    /// for every hook posture installs, not only the first one it learned.
    #[test]
    fn a_foreign_hook_of_either_name_is_never_clobbered() {
        let store = TestStore::new();
        for name in ["pre-push", "post-commit"] {
            let repo = git_audit_fixture();
            let hooks = repo.path().join(".git").join("hooks");
            std::fs::create_dir_all(&hooks).unwrap();
            std::fs::write(hooks.join(name), "#!/bin/sh\n# someone else's\n").unwrap();
            let error = cmd_hook(
                store.storage(),
                repo.path(),
                "github-public",
                None,
                false,
                false,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("not written by posture"),
                "{name}: {error}"
            );
            assert_eq!(
                std::fs::read_to_string(hooks.join(name)).unwrap(),
                "#!/bin/sh\n# someone else's\n"
            );
        }
    }

    #[test]
    fn posture_cli_has_no_parallel_verdict_commands() {
        let command = Cli::command();
        for retired in ["accept", "defer", "revoke"] {
            assert!(command.find_subcommand(retired).is_none());
        }
    }

    #[test]
    fn foreign_signer_cannot_introduce_scan_membership_and_descriptor_is_fixed() {
        let store = TestStore::new();
        let (files, omissions) = sample_scan_inputs();
        let (fragment, _) = build_scan_fragment(
            Path::new("foreign-corpus"),
            &files,
            &omissions,
            point_interval(Epoch::from_unix_seconds(4_000.0)),
            None,
            IMPLEMENTED.iter().copied().collect(),
        );
        let pile = open_pile_strict(&store.pile).unwrap();
        // `Collection::new` directly, NOT the team-of-one opener: the whole
        // point is a signer that is not the team. The foreign key must address
        // the SAME collection — same name, same team — or this proves only that
        // two different collections do not see each other, which is trivial.
        let team = faculties::storage::load_signer(&store.pile, Some(&store.key))
            .unwrap()
            .verifying_key();
        let mut foreign = Collection::new(
            pile,
            &faculties::collection_names::require_name(DEFAULT_SCAN_SCOPE_ID),
            team,
            ed25519_dalek::SigningKey::from_bytes(&[0x91; 32]),
            faculties::collection_names::require_reach(DEFAULT_SCAN_SCOPE_ID),
        );
        foreign.commit(fragment).unwrap();
        foreign.into_storage().close().unwrap();

        let view = store.storage().scan_view().unwrap();
        assert!(view.facts.is_empty());
        assert!(store
            .storage()
            .authored_commits(DEFAULT_SCAN_SCOPE_ID, "scan")
            .unwrap()
            .is_empty());

        let mut pile = open_pile_strict(&store.pile).unwrap();
        let target = discover_target(&mut pile, DEFAULT_SCAN_SCOPE_ID, team).unwrap();
        assert_eq!(
            target.descriptor().facts(),
            faculties::collection_names::root_descriptor(DEFAULT_SCAN_SCOPE_ID, team).facts()
        );
        assert_eq!(target.commits().len(), 1);
        pile.close().unwrap();
    }

    #[test]
    fn additive_legacy_policy_facts_are_inert_beside_canonical_shadows() {
        let store = TestStore::new();
        let mut fragment = Fragment::empty();
        let old_channel = ExclusiveId::force(Id::new([0x92; 16]).unwrap());
        let name: TextHandle = fragment.put("public-release".to_owned());
        fragment += entity! { &old_channel @
            metadata::tag: KIND_CHANNEL,
            posture::channel_name: name,
        };
        let old_term = ExclusiveId::force(Id::new([0x93; 16]).unwrap());
        let text: TextHandle = fragment.put("legacy-term".to_owned());
        fragment += entity! { &old_term @
            metadata::tag: KIND_TERM,
            posture::in_channel: &old_channel,
            posture::term: text,
        };

        let channel = append_channel(&mut fragment, "public-release");
        let term = append_test_term(&mut fragment, channel, "legacy-term", None);
        append_policy_revision(
            &mut fragment,
            channel,
            &BTreeSet::from([term]),
            &BTreeSet::new(),
        );
        store.publish_raw(DEFAULT_POLICY_SCOPE_ID, fragment, "additive policy fixture");

        let view = store.storage().policy_view().unwrap();
        assert_eq!(
            channel_by_name(&view.reader, &view.facts, "public-release").unwrap(),
            Some(channel)
        );
        assert_ne!(*old_channel, channel);
        assert!(view.facts.iter().any(|fact| fact.e() == &*old_term));
        assert_eq!(
            channel_terms(&view.reader, &view.facts, channel).unwrap(),
            vec![("legacy-term".to_owned(), String::new())]
        );
        drop(view);

        let unknown = entity! { metadata::tag: genid().id };
        store.publish_raw(
            DEFAULT_POLICY_SCOPE_ID,
            unknown,
            "unrecognized policy fixture",
        );
        assert!(store
            .storage()
            .policy_view()
            .unwrap_err()
            .to_string()
            .contains("unrecognized entity"));
    }

    #[test]
    fn git_occurrences_are_independent_of_repo_path_spelling() {
        let directory = git_audit_fixture();
        let relative = PathBuf::from(directory.path().file_name().unwrap());
        assert!(relative.is_relative());
        let absolute = std::fs::canonicalize(directory.path()).unwrap();
        let terms = vec![("project-sunrise".to_owned(), "fixture".to_owned())];

        let from_relative = collect_hits(&relative, &revs("HEAD"), &terms).unwrap();
        let from_absolute = collect_hits(&absolute, &revs("HEAD"), &terms).unwrap();

        assert_eq!(from_relative.repo_root, absolute);
        assert_eq!(from_absolute.repo_root, absolute);
        assert_eq!(from_relative.hits, from_absolute.hits);
        let relative_ids = from_relative.hits["project-sunrise"]
            .iter()
            .map(|hit| finding_id(modality::PROTECTED_TERM, &hit.location))
            .collect::<Vec<_>>();
        let absolute_ids = from_absolute.hits["project-sunrise"]
            .iter()
            .map(|hit| finding_id(modality::PROTECTED_TERM, &hit.location))
            .collect::<Vec<_>>();
        assert_eq!(relative_ids, absolute_ids);
    }

    #[test]
    fn git_unsafe_attribute_rule_checks_only_new_literal_pins_in_rust() {
        let directory = git_unsafe_attribute_fixture();
        let audit = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();

        assert!(audit.hits.is_empty());
        assert_eq!(audit.unsafe_attribute_hits.len(), 1);
        let hit = &audit.unsafe_attribute_hits[0];
        assert!(hit.evidence.contains("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"));
        assert!(hit.evidence.contains("ShortString;"));
        assert!(hit.evidence.contains("schema.rs"));

        let whole_history = collect_hits(directory.path(), &revs("HEAD"), &[]).unwrap();
        assert_eq!(
            whole_history.unsafe_attribute_hits.len(),
            2,
            "the old literal pin is visible only when its introducing commit is in range"
        );
    }

    #[test]
    fn git_unsafe_attribute_invariant_runs_but_a_missing_lexical_channel_fails_closed() {
        let store = TestStore::new();
        assert!(load_channel_terms(store.storage(), "undefined-channel")
            .unwrap()
            .is_none());

        let directory = git_unsafe_attribute_fixture();
        let audit = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
        assert!(audit.hits.is_empty());
        assert_eq!(audit.unsafe_attribute_hits.len(), 1);
        assert!(git_audit_must_fail(
            false,
            0,
            audit.unsafe_attribute_hits.len()
        ));
        assert!(
            git_audit_must_fail(false, 0, 0),
            "a quiet invariant scan must not disguise missing lexical coverage"
        );
    }

    #[test]
    fn unsafe_attribute_parser_accepts_token_tree_header_wrapping_and_comments() {
        let declarations = unsafe_attribute_declarations(concat!(
            "attributes! {\n",
            "    \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n",
            "    /* compatibility arm */ unsafe\n",
            "    // macro keyword follows\n",
            "    as legacy:\n",
            "        inlineencodings::GenId;\n",
            "}\n",
        ));
        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].start_line, 2);
        assert_eq!(declarations[0].end_line, 6);
        assert!(declarations[0].text.contains("inlineencodings::GenId;"));

        let after_as_comment = unsafe_attribute_declarations(concat!(
            "attributes! {\n",
            "    \"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\" unsafe as value:\n",
            "        /* preserved for compatibility; do not change */\n",
            "        inlineencodings::GenId;\n",
            "}\n",
        ));
        assert_eq!(after_as_comment.len(), 1);
        assert!(after_as_comment[0]
            .text
            .contains("compatibility; do not change"));
        assert!(after_as_comment[0].text.contains("inlineencodings::GenId;"));
    }

    #[test]
    fn multiline_encoding_only_change_is_a_new_unsafe_attribute_occurrence() {
        let directory = git_unsafe_attribute_fixture();
        let before = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
        assert_eq!(before.unsafe_attribute_hits.len(), 1);
        let before_id =
            finding_id(
            modality::UNSAFE_ATTRIBUTE_ID,
            &before.unsafe_attribute_hits[0].location,
        );

        let path = directory.path().join("schema.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            source.replace("        ShortString;", "        inlineencodings::GenId;"),
        )
        .unwrap();
        git_fixture(directory.path(), &["add", "schema.rs"]);
        git_fixture(
            directory.path(),
            &["commit", "--quiet", "-m", "change pinned encoding"],
        );

        let after = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
        assert_eq!(after.unsafe_attribute_hits.len(), 2);
        let added = after
            .unsafe_attribute_hits
            .iter()
            .find(|hit| hit.evidence.starts_with("rust-attribute-added"))
            .unwrap();
        let removed = after
            .unsafe_attribute_hits
            .iter()
            .find(|hit| hit.evidence.starts_with("rust-attribute-removed"))
            .unwrap();
        assert!(added.evidence.contains("inlineencodings::GenId;"));
        assert!(removed.evidence.contains("ShortString;"));
        assert_ne!(
            before_id,
            finding_id(modality::UNSAFE_ATTRIBUTE_ID, &added.location),
            "the encoding is part of the exact compatibility claim"
        );
    }

    #[test]
    fn unsafe_attribute_removal_unpinning_and_renaming_are_reviewed() {
        let unpinned = git_unsafe_attribute_fixture();
        let path = unpinned.path().join("schema.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            source.replace("unsafe as pub migrated", "as pub migrated"),
        )
        .unwrap();
        git_fixture(unpinned.path(), &["add", "schema.rs"]);
        git_fixture(
            unpinned.path(),
            &["commit", "--quiet", "-m", "use safe attribute anchor"],
        );
        let audit = collect_hits(unpinned.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
        assert_eq!(audit.unsafe_attribute_hits.len(), 1);
        assert!(audit.unsafe_attribute_hits[0]
            .evidence
            .starts_with("rust-attribute-removed"));
        assert!(audit.unsafe_attribute_hits[0]
            .evidence
            .contains("pub migrated"));

        let renamed = git_unsafe_attribute_fixture();
        let path = renamed.path().join("schema.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, source.replace("pub migrated", "pub renamed")).unwrap();
        git_fixture(renamed.path(), &["add", "schema.rs"]);
        git_fixture(
            renamed.path(),
            &["commit", "--quiet", "-m", "rename pinned attribute"],
        );
        let audit = collect_hits(renamed.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
        assert_eq!(audit.unsafe_attribute_hits.len(), 2);
        assert!(audit
            .unsafe_attribute_hits
            .iter()
            .any(|hit| hit.evidence.starts_with("rust-attribute-added")
                && hit.evidence.contains("pub renamed")));
        assert!(audit
            .unsafe_attribute_hits
            .iter()
            .any(|hit| hit.evidence.starts_with("rust-attribute-removed")
                && hit.evidence.contains("pub migrated")));
    }

    #[test]
    fn whitespace_only_unsafe_attribute_rewrite_reuses_justification() {
        let directory = git_unsafe_attribute_fixture();
        let path = directory.path().join("schema.rs");
        let source = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            source.replace(
                "\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\" unsafe as pub migrated:\n        ShortString;",
                "\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\" unsafe as pub migrated: ShortString;",
            ),
        )
        .unwrap();
        git_fixture(directory.path(), &["add", "schema.rs"]);
        git_fixture(
            directory.path(),
            &["commit", "--quiet", "-m", "format schema"],
        );
        let audit = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
        assert!(
            audit.unsafe_attribute_hits.is_empty(),
            "a source-only rewrite of the same path/name/encoding claim keeps its decision"
        );
    }

    #[test]
    fn merge_audits_removal_relative_only_to_non_first_parent() {
        let directory = tempfile::tempdir().unwrap();
        git_fixture(directory.path(), &["init", "--quiet"]);
        std::fs::write(directory.path().join("schema.rs"), "attributes! {}\n").unwrap();
        git_fixture(directory.path(), &["add", "schema.rs"]);
        git_fixture(directory.path(), &["commit", "--quiet", "-m", "base"]);
        let main_branch = git_fixture(directory.path(), &["branch", "--show-current"]);

        git_fixture(directory.path(), &["checkout", "--quiet", "-b", "side"]);
        std::fs::write(
            directory.path().join("schema.rs"),
            concat!(
                "attributes! {\n",
                "    \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" unsafe as side_pin: ShortString;\n",
                "}\n",
            ),
        )
        .unwrap();
        git_fixture(directory.path(), &["add", "schema.rs"]);
        git_fixture(
            directory.path(),
            &["commit", "--quiet", "-m", "side adds pin"],
        );

        git_fixture(directory.path(), &["checkout", "--quiet", &main_branch]);
        std::fs::write(directory.path().join("main.txt"), "main work\n").unwrap();
        git_fixture(directory.path(), &["add", "main.txt"]);
        git_fixture(directory.path(), &["commit", "--quiet", "-m", "main work"]);
        git_fixture(
            directory.path(),
            &[
                "merge",
                "--quiet",
                "--no-ff",
                "-s",
                "ours",
                "side",
                "-m",
                "merge without side pin",
            ],
        );

        let merge = git_fixture(directory.path(), &["rev-parse", "HEAD"]);
        let lineage = git_fixture(
            directory.path(),
            &["rev-list", "--parents", "-n", "1", &merge],
        );
        let parents = lineage.split_whitespace().skip(1).collect::<Vec<_>>();
        assert_eq!(parents.len(), 2);
        let mut unsafe_hits = Vec::new();
        collect_parent_unsafe_hits(directory.path(), &merge, Some(parents[1]), &mut unsafe_hits)
            .unwrap();
        assert_eq!(unsafe_hits.len(), 1);
        let hit = &unsafe_hits[0];
        assert!(hit.evidence.starts_with("rust-attribute-removed"));
        assert!(hit.evidence.contains("side_pin: ShortString;"));
    }

    #[test]
    fn merge_deduplicates_one_new_claim_seen_against_both_parents() {
        let directory = tempfile::tempdir().unwrap();
        git_fixture(directory.path(), &["init", "--quiet"]);
        std::fs::write(directory.path().join("schema.rs"), "attributes! {}\n").unwrap();
        git_fixture(directory.path(), &["add", "schema.rs"]);
        git_fixture(directory.path(), &["commit", "--quiet", "-m", "base"]);
        let main_branch = git_fixture(directory.path(), &["branch", "--show-current"]);

        git_fixture(directory.path(), &["checkout", "--quiet", "-b", "side"]);
        std::fs::write(directory.path().join("side.txt"), "side\n").unwrap();
        git_fixture(directory.path(), &["add", "side.txt"]);
        git_fixture(directory.path(), &["commit", "--quiet", "-m", "side"]);
        git_fixture(directory.path(), &["checkout", "--quiet", &main_branch]);
        std::fs::write(directory.path().join("main.txt"), "main\n").unwrap();
        git_fixture(directory.path(), &["add", "main.txt"]);
        git_fixture(directory.path(), &["commit", "--quiet", "-m", "main"]);
        git_fixture(
            directory.path(),
            &["merge", "--quiet", "--no-ff", "--no-commit", "side"],
        );
        std::fs::write(
            directory.path().join("schema.rs"),
            concat!(
                "attributes! {\n",
                "    \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\" unsafe as merge_pin: ShortString;\n",
                "}\n",
            ),
        )
        .unwrap();
        git_fixture(directory.path(), &["add", "schema.rs"]);
        git_fixture(
            directory.path(),
            &["commit", "--quiet", "-m", "merge adds pin"],
        );

        let audit = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
        assert_eq!(
            audit.unsafe_attribute_hits.len(),
            1,
            "one semantic claim compared with two parents is one review occurrence"
        );
        assert!(audit.unsafe_attribute_hits[0]
            .evidence
            .starts_with("rust-attribute-added"));
    }

    #[test]
    fn unsafe_attribute_findings_have_exact_decide_occurrences() {
        let directory = git_unsafe_attribute_fixture();
        let audit = collect_hits(directory.path(), &revs("HEAD^..HEAD"), &[]).unwrap();
        let hit = &audit.unsafe_attribute_hits[0];
        let occurrence = finding_id(modality::UNSAFE_ATTRIBUTE_ID, &hit.location);

        // Same declaration, rewritten commit: identity is the declaration's own
        // hash, so a rebase changes only the evidence.
        let rebased = GitHit {
            seen_in: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_owned(),
            display: "unsafe-attribute deadbeef:b/schema.rs:99  rewritten commit".to_owned(),
            ..hit.clone()
        };
        assert_eq!(
            occurrence,
            finding_id(modality::UNSAFE_ATTRIBUTE_ID, &rebased.location),
            "rewriting the introducing commit must not discard its declaration justification"
        );

        let Inner::Field(coordinate) = &hit.location.inner else {
            panic!("an unsafe-attribute claim is a named coordinate, not a byte range");
        };
        let changed = Location::field(
            hit.location.carrier.clone(),
            coordinate.replace("schema.rs", "other.rs"),
        );
        let changed_occurrence = finding_id(modality::UNSAFE_ATTRIBUTE_ID, &changed);
        assert_ne!(
            occurrence, changed_occurrence,
            "moving or changing the declaration is a new occurrence"
        );

        let store = TestStore::new();
        let decision = genid().id;
        let proposed = decide::decision_fragment(
            decision,
            "Justify this literal-pinned attribute identity",
            Some("It preserves rows written under this already-published byte id".to_owned()),
            Some(occurrence),
            point_interval(Epoch::from_unix_seconds(6_000.0)),
        )
        .unwrap()
        .0;
        store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, proposed, "attribute justification");
        let resolved = decide::resolution_fragment(
            decision,
            "benign, and here is a whole sentence of reasoning about why",
            Some(decide::RESULT_BENIGN),
            true,
            &[],
            &[],
            point_interval(Epoch::from_unix_seconds(6_001.0)),
        )
        .unwrap()
        .0;
        store.publish_raw(
            DEFAULT_DECIDE_SCOPE_ID,
            resolved,
            "attribute classification",
        );
        let view = store.storage().decide_view().unwrap();
        let benign = settled_findings(&view.reader, &view.facts, BTreeMap::new()).unwrap();
        assert!(benign.justified.contains(&occurrence));
        assert!(!benign.justified.contains(&changed_occurrence));
    }

    #[test]
    fn unsafe_attribute_clearance_requires_decide_proposal_context() {
        let store = TestStore::new();
        let occurrence = genid().id;

        let decision = genid().id;
        let proposal = decide::decision_fragment(
            decision,
            "Classify literal-pinned attribute",
            None,
            Some(occurrence),
            point_interval(Epoch::from_unix_seconds(6_100.0)),
        )
        .unwrap()
        .0;
        store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, proposal, "unexplained proposal");
        let resolution = decide::resolution_fragment(
            decision,
            "benign, and here is a whole sentence of reasoning about why",
            Some(decide::RESULT_BENIGN),
            true,
            &[],
            &[],
            point_interval(Epoch::from_unix_seconds(6_101.0)),
        )
        .unwrap()
        .0;
        store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, resolution, "unexplained benign");

        let view = store.storage().decide_view().unwrap();
        let benign = settled_findings(&view.reader, &view.facts, BTreeMap::new()).unwrap();
        assert!(benign.ordinary.contains(&occurrence));
        assert!(!benign.justified.contains(&occurrence));
        assert!(benign.hides(modality::PROTECTED_TERM, occurrence));
        assert!(!benign.hides(modality::UNSAFE_ATTRIBUTE_ID, occurrence));
        drop(view);

        let explained = genid().id;
        let proposal = decide::decision_fragment(
            explained,
            "Classify literal-pinned attribute",
            Some("This exact byte id and encoding preserve already-published rows".to_owned()),
            Some(occurrence),
            point_interval(Epoch::from_unix_seconds(6_102.0)),
        )
        .unwrap()
        .0;
        store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, proposal, "explained proposal");
        let resolution = decide::resolution_fragment(
            explained,
            "benign, and here is a whole sentence of reasoning about why",
            Some(decide::RESULT_BENIGN),
            true,
            &[],
            &[],
            point_interval(Epoch::from_unix_seconds(6_103.0)),
        )
        .unwrap()
        .0;
        store.publish_raw(DEFAULT_DECIDE_SCOPE_ID, resolution, "explained benign");
        let view = store.storage().decide_view().unwrap();
        let benign = settled_findings(&view.reader, &view.facts, BTreeMap::new()).unwrap();
        assert!(benign.hides(modality::UNSAFE_ATTRIBUTE_ID, occurrence));
    }

    /// A resolution's PROSE is for a human. Only the result tag clears a
    /// finding — except for the pre-tag resolutions, which had nothing else,
    /// and are read exactly as they always were.
    #[test]
    fn only_a_result_tag_clears_a_finding_and_legacy_prose_still_does() {
        let store = TestStore::new();

        let mut cleared = |title: &'static str, outcome: &'static str, result: Option<Id>, at: f64| {
            let finding = genid().id;
            let decision = genid().id;
            store.publish_raw(
                DEFAULT_DECIDE_SCOPE_ID,
                decide::decision_fragment(
                    decision,
                    title,
                    Some("justified".to_owned()),
                    Some(finding),
                    point_interval(Epoch::from_unix_seconds(at)),
                )
                .unwrap()
                .0,
                "clearance proposal",
            );
            store.publish_raw(
                DEFAULT_DECIDE_SCOPE_ID,
                decide::resolution_fragment(
                    decision,
                    outcome,
                    result,
                    true,
                    &[],
                    &[],
                    point_interval(Epoch::from_unix_seconds(at + 1.0)),
                )
                .unwrap()
                .0,
                "clearance resolution",
            );
            let view = store.storage().decide_view().unwrap();
            let settled = settled_findings(&view.reader, &view.facts, BTreeMap::new()).unwrap();
            settled.hides(modality::PROTECTED_TERM, finding)
        };

        // The tag clears, and the prose is free to be an actual explanation.
        assert!(cleared(
            "tagged",
            "benign - it is a BPE vocabulary, so it spells most of the lexicon",
            Some(decide::RESULT_BENIGN),
            7_000.0
        ));
        // Pre-tag clearances carried the exact word and nothing else.
        assert!(cleared("legacy prose", LEGACY_BENIGN_OUTCOME, None, 7_100.0));
        // Everything else is prose a program must not read as clearance.
        assert!(!cleared("near miss", "Benign.", None, 7_200.0));
        assert!(!cleared("reasoned but untagged", "benign, because X", None, 7_300.0));
    }

    #[test]
    fn identical_git_lines_are_distinct_exact_occurrences() {
        let directory = git_audit_fixture();
        let terms = vec![("project-sunrise".to_owned(), "fixture".to_owned())];
        let audit = collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap();
        let object_id = git_fixture(directory.path(), &["rev-parse", "HEAD"]);
        let term_hits = &audit.hits["project-sunrise"];

        let patch_hits = term_hits
            .iter()
            .filter(|hit| hit.evidence.starts_with("patch "))
            .collect::<Vec<_>>();
        assert_eq!(patch_hits.len(), 2);
        assert_ne!(patch_hits[0].location, patch_hits[1].location);
        assert!(patch_hits
            .iter()
            .all(|hit| hit.evidence.contains(&object_id)));
        assert_ne!(
            finding_id(modality::PROTECTED_TERM, &patch_hits[0].location),
            finding_id(modality::PROTECTED_TERM, &patch_hits[1].location)
        );

        let message_hits = term_hits
            .iter()
            .filter(|hit| hit.evidence.starts_with("message "))
            .collect::<Vec<_>>();
        assert_eq!(message_hits.len(), 2);
        assert_ne!(message_hits[0].location, message_hits[1].location);
    }

    #[test]
    fn full_object_ids_not_display_prefixes_define_git_occurrences() {
        let first_object_id = format!("12345678{}", "0".repeat(32));
        let second_object_id = format!("12345678{}", "1".repeat(32));
        let first = git_hit(
            "patch",
            Location::span(Carrier::GitBlob(first_object_id.clone()), 0, 15),
            &first_object_id,
            "b/fixture.txt:1:diff-7",
            "+project-sunrise",
        );
        let second = git_hit(
            "patch",
            Location::span(Carrier::GitBlob(second_object_id.clone()), 0, 15),
            &second_object_id,
            "b/fixture.txt:1:diff-7",
            "+project-sunrise",
        );

        assert!(first.display.contains("12345678"));
        assert!(second.display.contains("12345678"));
        assert!(!first.display.contains(&first_object_id));
        assert!(!second.display.contains(&second_object_id));
        assert_ne!(first.location, second.location);

        assert_ne!(
            finding_id(modality::PROTECTED_TERM, &first.location),
            finding_id(modality::PROTECTED_TERM, &second.location)
        );
    }

    /// A repository whose HEAD carries a protected term on one line of one
    /// file, with unrelated lines around it to move it against later.
    fn git_carry_forward_fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        git_fixture(directory.path(), &["init", "--quiet"]);
        std::fs::write(directory.path().join("base.txt"), "unrelated\n").unwrap();
        git_fixture(directory.path(), &["add", "base.txt"]);
        git_fixture(directory.path(), &["commit", "--quiet", "-m", "base"]);
        std::fs::write(
            directory.path().join("notes.md"),
            "intro\nproject-sunrise appears here\ntail\n",
        )
        .unwrap();
        git_fixture(directory.path(), &["add", "notes.md"]);
        git_fixture(directory.path(), &["commit", "--quiet", "-m", "add notes"]);
        directory
    }

    fn fixture_terms() -> Vec<(String, String)> {
        vec![("project-sunrise".to_owned(), "fixture".to_owned())]
    }

    /// Finding ids for one term, restricted to a kind of sighting ("patch",
    /// "message", "path").
    fn finding_ids(audit: &GitAudit, term: &str, kind: &str) -> BTreeSet<Id> {
        audit
            .hits
            .get(term)
            .into_iter()
            .flatten()
            .filter(|hit| hit.evidence.starts_with(&format!("{kind} ")))
            .map(|hit| finding_id(modality::PROTECTED_TERM, &hit.location))
            .collect()
    }

    /// THE property the redesign exists for. Commit surgery rewrites commits
    /// and leaves blobs byte-identical, so the material keeps its id and every
    /// Decide resolution about it keeps applying.
    #[test]
    fn commit_surgery_that_preserves_the_blob_preserves_the_finding_id() {
        let directory = git_carry_forward_fixture();
        let terms = fixture_terms();
        let before = collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap();
        let before_ids = finding_ids(&before, "project-sunrise", "patch");
        assert_eq!(before_ids.len(), 1, "one protected line, one finding");
        let head_before = git_fixture(directory.path(), &["rev-parse", "HEAD"]);
        let blob_before = git_fixture(directory.path(), &["rev-parse", "HEAD:notes.md"]);

        // Amend and then rebase the whole history: new commit ids throughout.
        git_fixture(
            directory.path(),
            &[
                "commit",
                "--amend",
                "--quiet",
                "--no-edit",
                "--date=2001-02-03T04:05:06",
            ],
        );
        git_fixture(
            directory.path(),
            &["rebase", "--quiet", "--force-rebase", "--root"],
        );
        let head_after = git_fixture(directory.path(), &["rev-parse", "HEAD"]);
        let blob_after = git_fixture(directory.path(), &["rev-parse", "HEAD:notes.md"]);
        assert_ne!(head_before, head_after, "the fixture must actually rewrite");
        assert_eq!(blob_before, blob_after, "a rebase does not touch blobs");

        let after = collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap();
        assert_eq!(
            before_ids,
            finding_ids(&after, "project-sunrise", "patch"),
            "the same material at a new commit is the same finding"
        );
        let commits = after.hits["project-sunrise"]
            .iter()
            .filter(|hit| hit.evidence.starts_with("patch "))
            .map(|hit| hit.seen_in.clone())
            .collect::<BTreeSet<_>>();
        assert!(
            !commits.contains(&head_before),
            "the locator cache follows the rewrite even though identity does not"
        );
    }

    /// git decides what moved. A line lifted into another file inside a commit
    /// that also edits it is not new material, and `blame -M -C` is the thing
    /// that knows so — which is why posture asks instead of matching for
    /// itself.
    #[test]
    fn moved_material_is_carried_forward_and_new_material_is_not() {
        let directory = git_carry_forward_fixture();
        let terms = fixture_terms();
        let introduced = finding_ids(
            &collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap(),
            "project-sunrise",
            "patch",
        );
        assert_eq!(introduced.len(), 1);

        // Move the file AND change it, so the new path's blob is genuinely a
        // different object from the one the material was introduced in.
        git_fixture(directory.path(), &["mv", "notes.md", "docs.md"]);
        let moved = directory.path().join("docs.md");
        let body = std::fs::read_to_string(&moved).unwrap();
        std::fs::write(&moved, format!("{body}extra unrelated line\n")).unwrap();
        git_fixture(directory.path(), &["add", "-A"]);
        git_fixture(
            directory.path(),
            &["commit", "--quiet", "-m", "move and extend notes"],
        );
        assert_ne!(
            git_fixture(directory.path(), &["rev-parse", "HEAD:docs.md"]),
            git_fixture(directory.path(), &["rev-parse", "HEAD~1:notes.md"]),
            "the moved file must have a new blob for this test to mean anything"
        );

        let after_move = finding_ids(
            &collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap(),
            "project-sunrise",
            "patch",
        );
        assert_eq!(
            introduced, after_move,
            "material git reports as moved must not be re-created as a new finding"
        );

        // Negative control: a genuinely new instance of the same term, in
        // another file, is a DIFFERENT finding — every instance is judged, and
        // the equality above is not everything collapsing into one id.
        std::fs::write(
            directory.path().join("other.md"),
            "project-sunrise elsewhere\n",
        )
        .unwrap();
        git_fixture(directory.path(), &["add", "other.md"]);
        git_fixture(
            directory.path(),
            &["commit", "--quiet", "-m", "second instance"],
        );
        let after_new = finding_ids(
            &collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap(),
            "project-sunrise",
            "patch",
        );
        assert_eq!(
            after_new.len(),
            2,
            "the same string in a second place is a second judgement"
        );
        assert!(after_new.is_superset(&introduced));
    }

    /// The honest exception, asserted rather than assumed: a commit message has
    /// no blob, so its carrier is the commit, and commit surgery DOES move it.
    /// A reworded or rebased message re-blocks and needs a fresh decision.
    #[test]
    fn a_commit_message_finding_does_not_survive_commit_surgery() {
        let directory = tempfile::tempdir().unwrap();
        git_fixture(directory.path(), &["init", "--quiet"]);
        std::fs::write(directory.path().join("base.txt"), "unrelated\n").unwrap();
        git_fixture(directory.path(), &["add", "base.txt"]);
        git_fixture(
            directory.path(),
            &["commit", "--quiet", "-m", "mentions project-sunrise"],
        );
        let terms = fixture_terms();
        let before = finding_ids(
            &collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap(),
            "project-sunrise",
            "message",
        );
        assert_eq!(before.len(), 1);

        git_fixture(
            directory.path(),
            &[
                "commit",
                "--amend",
                "--quiet",
                "--no-edit",
                "--date=2001-02-03T04:05:06",
            ],
        );
        let after = finding_ids(
            &collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap(),
            "project-sunrise",
            "message",
        );
        assert_eq!(after.len(), 1);
        assert_ne!(
            before, after,
            "there is no content-addressed carrier for a message; say so plainly"
        );
    }

    #[test]
    fn git_subprocess_errors_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let terms = vec![("project-sunrise".to_owned(), "fixture".to_owned())];
        let error = collect_hits(directory.path(), &revs("HEAD"), &terms).unwrap_err();
        assert!(error.to_string().contains("git -C"));

        let error =
            git_probe(directory.path(), &["remote", "get-url", "origin"], &[2]).unwrap_err();
        assert!(error.to_string().contains("git -C"));
    }
}
