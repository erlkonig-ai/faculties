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
//!   posture coverage <scan>    — what that scan did NOT look at
//!   posture scans              — recent scans

// In the query DSL `(expression)` means "this bound Rust value", while
// `?name` introduces a query variable. Rust's ordinary-expression lint cannot
// see that macro grammar and incorrectly suggests deleting the parentheses.
#![allow(unused_parens)]

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::collection_access::{self, CollectionSnapshot, CollectionView};
use faculties::schemas::embeddings::{self, Embedding768};
use faculties::schemas::posture::{
    modality, posture, DEFAULT_POLICY_SCOPE_ID, DEFAULT_SCAN_SCOPE_ID, DOC_UNSUPPORTED,
    EXEMPLAR_BENIGN, EXEMPLAR_PROTECTED, KIND_CHANNEL, KIND_DOCUMENT, KIND_EXEMPLAR, KIND_FINDING,
    KIND_OMISSION, KIND_POLICY_REVISION, KIND_SCAN, KIND_TERM, OUTCOME_EXAMINED,
    OUTCOME_PARSE_FAILED,
};
use hifitime::Epoch;
use lopdf::{Dictionary, Document, Object};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::Blob;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::{BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::*;

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
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
    /// Extrinsic scope for channels, vocabulary, and exemplars.
    #[arg(long, env = "POSTURE_POLICY_SCOPE", value_parser = parse_id_arg)]
    policy_scope: Option<Id>,
    /// Extrinsic scope for complete scan observations.
    #[arg(long, env = "POSTURE_SCAN_SCOPE", value_parser = parse_id_arg)]
    scan_scope: Option<Id>,
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
    },
    /// What a scan did NOT examine — read this before trusting a quiet result
    Coverage {
        /// Scan id (hex); defaults to the most recent
        scan: Option<String>,
    },
    /// Recent scans
    Scans,
    /// Install a pre-push hook so the audit runs without being remembered
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
        /// which is the fail-closed default.
        #[arg(long)]
        remote_match: Option<String>,
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
    /// remote.
    Git {
        /// Commit range, e.g. origin/main..HEAD
        range: String,
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

// ── the extractors ──────────────────────────────────────────────────────────
// Each returns (modality, locator, value) triples. No judgement, no ranking —
// extraction and adjudication are separate stages on purpose.

#[derive(Debug)]
struct Found {
    modality: Id,
    locator: String,
    value: String,
}

fn f(modality: Id, locator: impl Into<String>, value: impl Into<String>) -> Found {
    Found {
        modality,
        locator: locator.into(),
        value: value.into(),
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
        for tag in ["creator", "lastModifiedBy", "revision", "lastPrinted"] {
            for v in xml_tag_texts(&xml, tag) {
                out.push(f(
                    modality::OOXML_CORE_PROPS,
                    format!("docProps/core.xml:{tag}"),
                    v,
                ));
            }
        }
    }
    if let Some(xml) = read(&mut zip, "docProps/app.xml") {
        for tag in ["Company", "Manager"] {
            for v in xml_tag_texts(&xml, tag) {
                out.push(f(
                    modality::OOXML_CORE_PROPS,
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
                for (_, author) in xml_attrs(&xml, "comment", "author") {
                    out.push(f(
                        modality::OOXML_COMMENTS,
                        format!("{name}:author"),
                        author,
                    ));
                }
                for t in xml_tag_texts(&xml, "t") {
                    out.push(f(modality::OOXML_COMMENTS, format!("{name}:text"), t));
                }
            }
        }
        // speaker notes — invisible while presenting, fully present in the file
        if name.starts_with("ppt/notesSlides/") && name.ends_with(".xml") {
            if let Some(xml) = read(&mut zip, name) {
                let text = xml_tag_texts(&xml, "t").join(" ");
                if !text.trim().is_empty() {
                    out.push(f(modality::OOXML_SPEAKER_NOTES, name.clone(), text));
                }
            }
        }
    }

    // tracked changes still in the body — the deleted paragraph is still there
    if let Some(xml) = read(&mut zip, "word/document.xml") {
        for (tag, kind) in [("ins", "insertion"), ("del", "deletion")] {
            for (_, author) in xml_attrs(&xml, tag, "author") {
                out.push(f(
                    modality::OOXML_TRACKED_CHANGES,
                    format!("word/document.xml:{kind}@author"),
                    author,
                ));
            }
        }
        for t in xml_tag_texts(&xml, "delText") {
            out.push(f(
                modality::OOXML_TRACKED_CHANGES,
                "word/document.xml:deleted-text",
                t,
            ));
        }
    }

    // hidden / veryHidden sheets
    if let Some(xml) = read(&mut zip, "xl/workbook.xml") {
        for (name, state) in xml_attrs(&xml, "sheet", "state") {
            if state == "hidden" || state == "veryHidden" {
                out.push(f(
                    modality::OOXML_HIDDEN_SHEET,
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
            out.push(f(modality::EXIF, format!("EXIF:{tag}"), v));
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
    fn report(&self, page: u32, out: &mut Vec<Found>) {
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
            out.push(f(modality::PDF_REDACTION_RECT, locator, value));
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

fn extract_pdf_metadata(doc: &Document, out: &mut Vec<Found>) {
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
                out.push(f(modality::PDF_METADATA, format!("Info:{key}"), v));
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
                out.push(f(modality::PDF_METADATA, format!("Info:{name}"), v));
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
            out.push(f(modality::PDF_METADATA, format!("XMP:{field}"), v));
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
    // A PDF with no `/Info` and no XMP leaves this empty, which is the honest
    // answer: nothing found, not a failure to look.
    extract_pdf_metadata(&doc, &mut out);

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
        scan.report(page_no, &mut out);
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
    policy_scope: Id,
    scan_scope: Id,
}

impl PostureStorage<'_> {
    fn allowed_signers(&self) -> Result<HashSet<ed25519_dalek::VerifyingKey>> {
        let signer = collection_access::load_signer(self.pile, self.key)?;
        Ok(HashSet::from([signer.verifying_key()]))
    }

    fn policy_view(&self) -> Result<CollectionView> {
        let allowed = self.allowed_signers()?;
        let view = CollectionSnapshot::open(self.pile)?
            .materialize_scope(self.policy_scope, &allowed)
            .context("materialize Posture policy collection")?;
        validate_policy_view(&view)?;
        Ok(view)
    }

    fn scan_view(&self) -> Result<CollectionView> {
        let allowed = self.allowed_signers()?;
        let view = CollectionSnapshot::open(self.pile)?
            .materialize_scope(self.scan_scope, &allowed)
            .context("materialize Posture scan collection")?;
        validate_scan_view(&view)?;
        Ok(view)
    }

    fn publish_policy(&self, fragment: Fragment, description: &str) -> Result<CollectionCommit> {
        let current = self.policy_view()?;
        let mut staged_blobs = fragment.blobs().clone();
        let staged = staged_blobs
            .reader()
            .context("snapshot staged Posture policy payloads")?;
        let mut union = current.facts.clone();
        union += fragment.facts().clone();
        validate_policy_catalog_with(&current.reader, Some(&staged), &union)?;
        publish_fragment(
            self.pile,
            self.key,
            self.policy_scope,
            fragment,
            description,
        )
    }

    fn publish_scan(&self, fragment: Fragment, description: &str) -> Result<CollectionCommit> {
        let current = self.scan_view()?;
        validate_scan_commit_fragment(fragment.facts())?;
        let mut staged_blobs = fragment.blobs().clone();
        let staged = staged_blobs
            .reader()
            .context("snapshot staged Posture scan payloads")?;
        let mut union = current.facts.clone();
        union += fragment.facts().clone();
        validate_scan_catalog_with(&current.reader, Some(&staged), &union)?;
        publish_fragment(self.pile, self.key, self.scan_scope, fragment, description)
    }
}

fn publish_fragment(
    pile: &Path,
    key: Option<&Path>,
    scope: Id,
    content: Fragment,
    description: &str,
) -> Result<CollectionCommit> {
    let mut commit_metadata = Fragment::empty();
    let description: TextHandle = commit_metadata.put(description.to_owned());
    commit_metadata += entity! { metadata::description: description };
    collection_access::publish_fragment(pile, key, scope, content, commit_metadata)
}

fn read_text(reader: &PileReader, handle: TextHandle, field: &str) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Posture {field} payload"))?;
    Ok(value.to_string())
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
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
            let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
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
    validate_policy_catalog(&view.reader, &view.facts)
}

fn validate_policy_catalog(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    validate_policy_catalog_with::<PileReader>(reader, None, facts)
}

fn validate_policy_catalog_with<R>(
    reader: &PileReader,
    staged: Option<&R>,
    facts: &TribleSet,
) -> Result<()>
where
    R: BlobStoreGet + BlobStoreMeta,
{
    validate_known_payloads_with(reader, staged, facts)?;
    let channels = find!(
        channel: Id,
        pattern!(facts, [{ ?channel @ metadata::tag: (&KIND_CHANNEL) }])
    )
    .collect::<BTreeSet<_>>();
    let terms = find!(
        term: Id,
        pattern!(facts, [{ ?term @ metadata::tag: (&KIND_TERM) }])
    )
    .collect::<BTreeSet<_>>();
    let exemplars = find!(
        exemplar: Id,
        pattern!(facts, [{ ?exemplar @ metadata::tag: (&KIND_EXEMPLAR) }])
    )
    .collect::<BTreeSet<_>>();
    let revisions = find!(
        revision: Id,
        pattern!(facts, [{ ?revision @ metadata::tag: (&KIND_POLICY_REVISION) }])
    )
    .collect::<BTreeSet<_>>();
    let mut known = channels.clone();
    known.extend(terms.iter().copied());
    known.extend(exemplars.iter().copied());
    known.extend(revisions.iter().copied());
    let actual = facts.iter().map(|fact| *fact.e()).collect::<BTreeSet<_>>();
    if actual != known {
        let unknown = actual.difference(&known).copied().collect::<Vec<_>>();
        bail!(
            "Posture policy collection contains {} unrecognized entity/entities ({})",
            unknown.len(),
            unknown
                .iter()
                .map(|entity| fmt_id(*entity))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    for channel in &channels {
        require_attributes(
            facts,
            *channel,
            [metadata::tag.id(), posture::channel_name.id()],
            "channel",
        )?;
        if entity_tags(facts, *channel) != BTreeSet::from([KIND_CHANNEL]) {
            bail!("channel {} has invalid tags", fmt_id(*channel));
        }
        let name = one_required(
            find!(
                value: TextHandle,
                pattern!(facts, [{ (*channel) @ posture::channel_name: ?value }])
            )
            .collect(),
            "channel name",
        )?;
        let text = read_text_with(reader, staged, name, "channel name")?;
        if canonical_channel(&text)? != text {
            bail!("channel {} has a non-canonical name", fmt_id(*channel));
        }
        let expected = entity! {
            metadata::tag: KIND_CHANNEL,
            posture::channel_name: name,
        }
        .root()
        .expect("channel identity has one root");
        if expected != *channel {
            bail!("channel {} is not intrinsic", fmt_id(*channel));
        }
    }

    for term in &terms {
        require_attributes(
            facts,
            *term,
            [
                metadata::tag.id(),
                posture::in_channel.id(),
                posture::term.id(),
                posture::role.id(),
                posture::why.id(),
            ],
            "term",
        )?;
        if entity_tags(facts, *term) != BTreeSet::from([KIND_TERM]) {
            bail!("term {} has invalid tags", fmt_id(*term));
        }
        let channel = one_required(
            find!(value: Id, pattern!(facts, [{ (*term) @ posture::in_channel: ?value }]))
                .collect(),
            "term channel",
        )?;
        if !channels.contains(&channel) {
            bail!("term {} references a missing channel", fmt_id(*term));
        }
        let text = one_required(
            find!(value: TextHandle, pattern!(facts, [{ (*term) @ posture::term: ?value }]))
                .collect(),
            "term text",
        )?;
        let role = one_required(
            find!(value: Id, pattern!(facts, [{ (*term) @ posture::role: ?value }])).collect(),
            "term role",
        )?;
        if role != EXEMPLAR_PROTECTED {
            bail!("term {} is not explicitly protected", fmt_id(*term));
        }
        if canonical_term(&read_text_with(reader, staged, text, "term text")?)?
            != read_text_with(reader, staged, text, "term text")?
        {
            bail!("term {} has non-canonical text", fmt_id(*term));
        }
        let why = one_optional(
            find!(value: TextHandle, pattern!(facts, [{ (*term) @ posture::why: ?value }]))
                .collect(),
            "term rationale",
        )?;
        if let Some(why) = why {
            let text = read_text_with(reader, staged, why, "term rationale")?;
            if text.is_empty() || text.trim() != text {
                bail!("term {} has a non-canonical rationale", fmt_id(*term));
            }
        }
        let expected = entity! {
            metadata::tag: KIND_TERM,
            posture::in_channel: channel,
            posture::term: text,
            posture::role: role,
            posture::why?: why,
        }
        .root()
        .expect("term identity has one root");
        if expected != *term {
            bail!("term {} is not intrinsic", fmt_id(*term));
        }
    }

    for exemplar in &exemplars {
        require_attributes(
            facts,
            *exemplar,
            [
                metadata::tag.id(),
                posture::in_channel.id(),
                posture::term.id(),
                posture::role.id(),
                embeddings::attr::embedding.id(),
            ],
            "exemplar",
        )?;
        if entity_tags(facts, *exemplar) != BTreeSet::from([KIND_EXEMPLAR]) {
            bail!("exemplar {} has invalid tags", fmt_id(*exemplar));
        }
        let channel = one_required(
            find!(
                value: Id,
                pattern!(facts, [{ (*exemplar) @ posture::in_channel: ?value }])
            )
            .collect(),
            "exemplar channel",
        )?;
        if !channels.contains(&channel) {
            bail!(
                "exemplar {} references a missing channel",
                fmt_id(*exemplar)
            );
        }
        let text = one_required(
            find!(
                value: TextHandle,
                pattern!(facts, [{ (*exemplar) @ posture::term: ?value }])
            )
            .collect(),
            "exemplar text",
        )?;
        let body = read_text_with(reader, staged, text, "exemplar text")?;
        if body.is_empty() || canonical_exemplar(&body) != body {
            bail!("exemplar {} has non-canonical text", fmt_id(*exemplar));
        }
        let role = one_required(
            find!(
                value: Id,
                pattern!(facts, [{ (*exemplar) @ posture::role: ?value }])
            )
            .collect(),
            "exemplar role",
        )?;
        if role != EXEMPLAR_BENIGN && role != EXEMPLAR_PROTECTED {
            bail!("exemplar {} has an invalid role", fmt_id(*exemplar));
        }
        let expected = entity! {
            metadata::tag: KIND_EXEMPLAR,
            posture::term: text,
            posture::in_channel: channel,
            posture::role: role,
        }
        .root()
        .expect("exemplar identity has one root");
        if expected != *exemplar {
            bail!("exemplar {} is not intrinsic", fmt_id(*exemplar));
        }
    }

    for revision in &revisions {
        require_attributes(
            facts,
            *revision,
            [
                metadata::tag.id(),
                posture::in_channel.id(),
                posture::policy_member.id(),
                metadata::supersedes.id(),
            ],
            "policy revision",
        )?;
        if entity_tags(facts, *revision) != BTreeSet::from([KIND_POLICY_REVISION]) {
            bail!("policy revision {} has invalid tags", fmt_id(*revision));
        }
        let channel = one_required(
            find!(
                value: Id,
                pattern!(facts, [{ (*revision) @ posture::in_channel: ?value }])
            )
            .collect(),
            "policy revision channel",
        )?;
        if !channels.contains(&channel) {
            bail!(
                "policy revision {} references a missing channel",
                fmt_id(*revision)
            );
        }
        let members = find!(
            value: Id,
            pattern!(facts, [{ (*revision) @ posture::policy_member: ?value }])
        )
        .collect::<BTreeSet<_>>();
        let mut term_keys = BTreeMap::<String, Id>::new();
        let mut exemplar_keys = BTreeMap::<String, Id>::new();
        for member in &members {
            if !terms.contains(member) && !exemplars.contains(member) {
                bail!(
                    "policy revision {} references missing member {}",
                    fmt_id(*revision),
                    fmt_id(*member)
                );
            }
            let member_channel = one_required(
                find!(
                    value: Id,
                    pattern!(facts, [{ (*member) @ posture::in_channel: ?value }])
                )
                .collect(),
                "policy member channel",
            )?;
            if member_channel != channel {
                bail!(
                    "policy revision {} contains a cross-channel member",
                    fmt_id(*revision)
                );
            }
            // A term's rationale is deliberately part of its immutable
            // identity, so editing the rationale creates a new entity.  One
            // policy snapshot may nevertheless contain only one entity for a
            // canonical term: otherwise the active policy is ambiguous even
            // though every individual member is structurally valid.
            if terms.contains(member) {
                let handle = one_required(
                    find!(
                        value: TextHandle,
                        pattern!(facts, [{ (*member) @ posture::term: ?value }])
                    )
                    .collect(),
                    "policy term text",
                )?;
                let key = read_text_with(reader, staged, handle, "policy term text")?;
                if let Some(other) = term_keys.insert(key.clone(), *member) {
                    bail!(
                        "policy revision {} contains two identities for canonical term {:?} ({}, {})",
                        fmt_id(*revision),
                        key,
                        fmt_id(other),
                        fmt_id(*member)
                    );
                }
            } else {
                let handle = one_required(
                    find!(
                        value: TextHandle,
                        pattern!(facts, [{ (*member) @ posture::term: ?value }])
                    )
                    .collect(),
                    "policy exemplar text",
                )?;
                let key = read_text_with(reader, staged, handle, "policy exemplar text")?;
                if let Some(other) = exemplar_keys.insert(key.clone(), *member) {
                    bail!(
                        "policy revision {} contains two identities for canonical exemplar {:?} ({}, {})",
                        fmt_id(*revision),
                        key,
                        fmt_id(other),
                        fmt_id(*member)
                    );
                }
            }
        }
        let predecessors = find!(
            value: Id,
            pattern!(facts, [{ (*revision) @ metadata::supersedes: ?value }])
        )
        .collect::<BTreeSet<_>>();
        for predecessor in &predecessors {
            if predecessor == revision || !revisions.contains(predecessor) {
                bail!(
                    "policy revision {} has an invalid predecessor",
                    fmt_id(*revision)
                );
            }
            let predecessor_channel = one_required(
                find!(
                    value: Id,
                    pattern!(facts, [{ (*predecessor) @ posture::in_channel: ?value }])
                )
                .collect(),
                "predecessor policy channel",
            )?;
            if predecessor_channel != channel {
                bail!(
                    "policy revision {} crosses channel histories",
                    fmt_id(*revision)
                );
            }
        }
        let expected = entity! {
            metadata::tag: KIND_POLICY_REVISION,
            posture::in_channel: channel,
            posture::policy_member*: members,
            metadata::supersedes*: predecessors,
        }
        .root()
        .expect("policy revision identity has one root");
        if expected != *revision {
            bail!("policy revision {} is not intrinsic", fmt_id(*revision));
        }
    }
    Ok(())
}

fn validate_scan_view(view: &CollectionView) -> Result<()> {
    let mut scan_commits = BTreeMap::<Id, usize>::new();
    for commit in &view.commits {
        let handle = inlineencodings::Handle::<SimpleArchive>::from_hash(commit.data());
        let blob: Blob<SimpleArchive> = view
            .reader
            .get(handle)
            .with_context(|| format!("read Posture scan COMMIT {}", fmt_id(commit.id())))?;
        let facts = TribleSet::try_from_blob(blob)
            .with_context(|| format!("decode Posture scan COMMIT {}", fmt_id(commit.id())))?;
        let scan = validate_scan_commit_fragment(&facts)
            .with_context(|| format!("validate Posture scan COMMIT {}", fmt_id(commit.id())))?;
        *scan_commits.entry(scan).or_default() += 1;
    }
    if let Some((scan, count)) = scan_commits.iter().find(|(_, count)| **count != 1) {
        bail!(
            "scan {} is spread across {count} signed COMMITs; scans must be atomic",
            fmt_id(*scan)
        );
    }
    validate_scan_catalog(&view.reader, &view.facts)
}

fn validate_scan_commit_fragment(facts: &TribleSet) -> Result<Id> {
    let scans = find!(
        scan: Id,
        pattern!(facts, [{ ?scan @ metadata::tag: (&KIND_SCAN) }])
    )
    .collect::<BTreeSet<_>>();
    let scan = one_required(scans, "scan COMMIT root")?;
    validate_scan_structure(facts)?;
    for entity in facts.iter().map(|fact| *fact.e()).collect::<BTreeSet<_>>() {
        if entity == scan {
            continue;
        }
        let owner = one_required(
            find!(value: Id, pattern!(facts, [{ (entity) @ posture::scan: ?value }])).collect(),
            "scan COMMIT entity owner",
        )?;
        if owner != scan {
            bail!("scan COMMIT contains an entity belonging to another scan");
        }
    }
    Ok(scan)
}

fn validate_scan_catalog(reader: &PileReader, facts: &TribleSet) -> Result<()> {
    validate_scan_catalog_with::<PileReader>(reader, None, facts)
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
    validate_scan_structure(facts)
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
    let omissions = find!(
        omission: Id,
        pattern!(facts, [{ ?omission @ metadata::tag: (&KIND_OMISSION) }])
    )
    .collect::<BTreeSet<_>>();
    let mut known = scans.clone();
    known.extend(documents.iter().copied());
    known.extend(findings.iter().copied());
    known.extend(omissions.iter().copied());
    let actual = facts.iter().map(|fact| *fact.e()).collect::<BTreeSet<_>>();
    if actual != known {
        bail!("Posture scan collection contains unrecognized entities");
    }

    let known_modalities = modality::ALL
        .iter()
        .map(|(id, _)| *id)
        .collect::<BTreeSet<_>>();
    for scan in &scans {
        require_attributes(
            facts,
            *scan,
            [
                metadata::tag.id(),
                metadata::created_at.id(),
                posture::occurrence.id(),
                posture::target.id(),
                posture::file_count.id(),
                posture::checked.id(),
                posture::unchecked.id(),
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
        let occurrence = one_required(
            find!(value: Id, pattern!(facts, [{ (*scan) @ posture::occurrence: ?value }]))
                .collect(),
            "scan occurrence",
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
        let covered = checked.union(&unchecked).copied().collect::<BTreeSet<_>>();
        if !checked.is_disjoint(&unchecked)
            || !checked.is_subset(&known_modalities)
            || !unchecked.is_subset(&known_modalities)
            || covered != known_modalities
        {
            bail!(
                "scan {} does not partition every known modality into checked or unchecked",
                fmt_id(*scan)
            );
        }
        let expected = entity! {
            metadata::tag: KIND_SCAN,
            metadata::created_at: created_at,
            posture::occurrence: occurrence,
            posture::target: target,
            posture::file_count: file_count,
            posture::checked*: checked,
            posture::unchecked*: unchecked,
        }
        .root()
        .expect("scan identity has one root");
        if expected != *scan {
            bail!("scan {} is not intrinsic", fmt_id(*scan));
        }
        let actual_files = documents
            .iter()
            .filter(|document| {
                exists!(pattern!(facts, [{ (**document) @ posture::scan: (*scan) }]))
            })
            .count() as u128;
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
                posture::scan.id(),
                posture::path.id(),
                posture::outcome.id(),
                posture::detail.id(),
            ],
            "document",
        )?;
        if entity_tags(facts, *document) != BTreeSet::from([KIND_DOCUMENT]) {
            bail!("document {} has invalid tags", fmt_id(*document));
        }
        let scan = one_required(
            find!(value: Id, pattern!(facts, [{ (*document) @ posture::scan: ?value }])).collect(),
            "document scan",
        )?;
        if !scans.contains(&scan) {
            bail!("document {} references a missing scan", fmt_id(*document));
        }
        let path = one_required(
            find!(value: TextHandle, pattern!(facts, [{ (*document) @ posture::path: ?value }]))
                .collect(),
            "document path",
        )?;
        if !document_paths.insert((scan, path)) {
            bail!("scan {} has multiple outcomes for one path", fmt_id(scan));
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
            posture::scan: scan,
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
                posture::scan.id(),
                posture::document.id(),
                posture::locator.id(),
                posture::value.id(),
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
        let scan = one_required(
            find!(value: Id, pattern!(facts, [{ (*finding) @ posture::scan: ?value }])).collect(),
            "finding scan",
        )?;
        let document = one_required(
            find!(
                value: Id,
                pattern!(facts, [{ (*finding) @ posture::document: ?value }])
            )
            .collect(),
            "finding document",
        )?;
        if !documents.contains(&document)
            || !exists!(pattern!(facts, [{ (document) @ posture::scan: (scan) }]))
        {
            bail!(
                "finding {} references a document outside its scan",
                fmt_id(*finding)
            );
        }
        if !exists!(pattern!(facts, [{ (scan) @ posture::checked: (modality) }])) {
            bail!(
                "finding {} uses a modality its scan did not mark checked",
                fmt_id(*finding)
            );
        }
        let document_outcome = one_required(
            find!(
                value: Id,
                pattern!(facts, [{ (document) @ posture::outcome: ?value }])
            )
            .collect(),
            "finding document outcome",
        )?;
        if document_outcome != OUTCOME_EXAMINED {
            bail!(
                "finding {} belongs to a document that was not examined",
                fmt_id(*finding)
            );
        }
        let locator = one_required(
            find!(
                value: TextHandle,
                pattern!(facts, [{ (*finding) @ posture::locator: ?value }])
            )
            .collect(),
            "finding locator",
        )?;
        let value = one_required(
            find!(
                value: TextHandle,
                pattern!(facts, [{ (*finding) @ posture::value: ?value }])
            )
            .collect(),
            "finding value",
        )?;
        let expected = entity! {
            metadata::tag: KIND_FINDING,
            metadata::tag: modality,
            posture::scan: scan,
            posture::document: document,
            posture::locator: locator,
            posture::value: value,
        }
        .root()
        .expect("finding identity has one root");
        if expected != *finding {
            bail!("finding {} is not intrinsic", fmt_id(*finding));
        }
    }

    for omission in &omissions {
        require_attributes(
            facts,
            *omission,
            [
                metadata::tag.id(),
                posture::scan.id(),
                posture::path.id(),
                posture::detail.id(),
            ],
            "omission",
        )?;
        if entity_tags(facts, *omission) != BTreeSet::from([KIND_OMISSION]) {
            bail!("omission {} has invalid tags", fmt_id(*omission));
        }
        let scan = one_required(
            find!(value: Id, pattern!(facts, [{ (*omission) @ posture::scan: ?value }])).collect(),
            "omission scan",
        )?;
        if !scans.contains(&scan) {
            bail!("omission {} references a missing scan", fmt_id(*omission));
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
            posture::scan: scan,
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
    occurrence: Id,
) -> (Fragment, Id) {
    let mut fragment = Fragment::empty();
    let target_handle: TextHandle = fragment.put(target.display().to_string());
    let checked = IMPLEMENTED.iter().copied().collect::<BTreeSet<_>>();
    let unchecked = unchecked_modalities();
    let scan = entity! {
        metadata::tag: KIND_SCAN,
        metadata::created_at: created_at,
        posture::occurrence: occurrence,
        posture::target: target_handle,
        posture::file_count: files.len() as u64,
        posture::checked*: checked,
        posture::unchecked*: unchecked,
    };
    let scan_id = scan.root().expect("intrinsic scan has one root");
    fragment += scan;

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
            posture::scan: scan_id,
            posture::path: path,
            posture::outcome: outcome,
            posture::detail?: detail,
        };
        let document_id = document.root().expect("intrinsic document has one root");
        fragment += document;

        for found in &file.findings {
            let locator: TextHandle = fragment.put(found.locator.clone());
            let value: TextHandle = fragment.put(found.value.clone());
            fragment += entity! {
                metadata::tag: KIND_FINDING,
                metadata::tag: found.modality,
                posture::scan: scan_id,
                posture::document: document_id,
                posture::locator: locator,
                posture::value: value,
            };
        }
    }

    for omitted in omissions {
        let path: TextHandle = fragment.put(omitted.path.display().to_string());
        let detail: TextHandle = fragment.put(omitted.detail.clone());
        fragment += entity! {
            metadata::tag: KIND_OMISSION,
            posture::scan: scan_id,
            posture::path: path,
            posture::detail: detail,
        };
    }

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
            println!("    {}  {}  {value}", path.display(), found.locator);
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

    let occurrence = genid().id;
    let (fragment, scan_id) = build_scan_fragment(
        target,
        &files,
        &omissions,
        point_interval(now_epoch()?),
        occurrence,
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

fn cmd_list(storage: PostureStorage<'_>, scan: Option<String>, examples: usize) -> Result<()> {
    let view = storage.scan_view()?;
    let want = parse_scan_id(scan.as_deref())?;
    if let Some(scan) = want {
        if !all_scan_ids(&view.facts).contains(&scan) {
            bail!(
                "scan {} is not present in the authorized scan collection",
                fmt_id(scan)
            );
        }
    }
    let rows = find!(
        (finding: Id, scan: Id, locator: TextHandle, value: TextHandle),
        pattern!(&view.facts, [{
            ?finding @
            metadata::tag: (&KIND_FINDING),
            posture::scan: ?scan,
            posture::locator: ?locator,
            posture::value: ?value
        }])
    )
    .filter(|(_, scan, _, _)| want.is_none_or(|wanted| *scan == wanted))
    .collect::<Vec<_>>();

    let mut groups: BTreeMap<&str, Vec<(TextHandle, TextHandle)>> = BTreeMap::new();
    for (finding, _, locator, value) in &rows {
        let modality = find!(
            tag: Id,
            pattern!(&view.facts, [{ (*finding) @ metadata::tag: ?tag }])
        )
        .find(|tag| modality::ALL.iter().any(|(known, _)| known == tag));
        groups
            .entry(modality.map(modality::name).unwrap_or("unclassified"))
            .or_default()
            .push((*locator, *value));
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
        for (locator, value) in items.iter().take(examples) {
            let locator = read_text(&view.reader, *locator, "finding locator")?;
            let value = read_text(&view.reader, *value, "finding value")?.replace('\n', " ");
            let value: String = value.chars().take(90).collect();
            println!("  {locator}  {value}");
        }
        if items.len() > examples {
            println!(
                "  … {} more (one decision dismisses the group)",
                items.len() - examples
            );
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
            _?document @
            metadata::tag: (&KIND_DOCUMENT),
            posture::scan: (scan),
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
            _?omission @
            metadata::tag: (&KIND_OMISSION),
            posture::scan: (scan),
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
            finding: Id,
            pattern!(&view.facts, [{
                ?finding @ metadata::tag: (&KIND_FINDING), posture::scan: (scan)
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

/// Collect every protected-term hit in a commit range: messages, file paths, and
/// per-commit patches. Returns (hits, commits scanned, added lines scanned).
///
/// ONE implementation, used by both `posture git` and `posture sweep`. Two
/// copies of a security check drift, and the copy that drifts is the one that
/// quietly stops looking.
fn collect_hits(
    repo_path: &Path,
    range: &str,
    terms: &[(String, String)],
) -> Result<(BTreeMap<String, Vec<String>>, usize, usize)> {
    let mut hits: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut n_commits = 0usize;
    let mut n_added = 0usize;

    // Commit messages, one record per commit so a hit can name its commit.
    // %x1e separates sha from body, %x1f terminates the record — control
    // characters, so a message can never forge a record boundary.
    let log = git_required(repo_path, &["log", range, "--format=%H%x1e%B%x1f"])?;
    for rec in log.split('\u{1f}') {
        let rec = rec.trim();
        if rec.is_empty() {
            continue;
        }
        n_commits += 1;
        let (sha, body) = rec.split_once('\u{1e}').unwrap_or(("?", rec));
        let short = &sha[..sha.len().min(8)];
        for (t, _) in terms {
            let lt = t.to_lowercase();
            for line in body.lines().filter(|l| l.to_lowercase().contains(&lt)) {
                hits.entry(t.clone())
                    .or_default()
                    .push(format!("message {short}  {}", line.trim()));
            }
        }
    }

    let shas: Vec<String> = git_required(repo_path, &["log", range, "--format=%H"])?
        .lines()
        .map(str::to_string)
        .collect();
    for sha in &shas {
        let short = &sha[..sha.len().min(8)];
        // FILE PATHS are published content too. A file at
        // a file whose PATH spells a protected term while its contents do not
        // in its path, and the patch body never mentions either — the `+++ b/`
        // header is the only place the name appears and it is skipped.
        for path in git_required(repo_path, &["show", "--format=", "--name-only", sha])?.lines() {
            let lower = path.to_lowercase();
            for (t, _) in terms {
                if lower.contains(&t.to_lowercase()) {
                    hits.entry(t.clone())
                        .or_default()
                        .push(format!("path  {short}  {path}"));
                }
            }
        }
        // PER-COMMIT patches, not the range's net diff: a file added in one
        // commit and deleted in the next contributes nothing to `git diff A..B`
        // while both commits still push and `git show` recovers it forever.
        //
        // And `git show` per commit rather than one `git log -p`: log -p omits
        // merge diffs by default, so an "evil merge" whose conflict resolution
        // introduces content present in neither parent is invisible to it.
        // Measured: log -p found 0, show found 1. Do not "simplify" this.
        for line in git_required(repo_path, &["show", "--format=", "--unified=0", sha])?.lines() {
            if !line.starts_with('+') || line.starts_with("+++") {
                continue;
            }
            n_added += 1;
            let lower = line.to_lowercase();
            for (t, _) in terms {
                if lower.contains(&t.to_lowercase()) {
                    hits.entry(t.clone())
                        .or_default()
                        .push(format!("patch {short}  {}", line.trim()));
                }
            }
        }
    }
    Ok((hits, n_commits, n_added))
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
fn load_terms(storage: PostureStorage<'_>, channel: &str) -> Result<Vec<(String, String)>> {
    let view = storage.policy_view()?;
    let Some(channel) = channel_by_name(&view.reader, &view.facts, channel)? else {
        return Ok(Vec::new());
    };
    channel_terms(&view.reader, &view.facts, channel)
}

fn cmd_git(
    storage: PostureStorage<'_>,
    range: &str,
    channel: &str,
    repo_path: &Path,
) -> Result<()> {
    let terms = load_terms(storage, channel)?;

    if terms.is_empty() {
        // Refusing to pass silently: an empty vocabulary would otherwise print a
        // clean result, which is the single failure this tool must never have.
        anyhow::bail!(
            "channel {channel:?} has no protected terms — an audit against an empty \
             vocabulary would report clean while checking nothing. Add terms with \
             `posture vocab add <term> --channel {channel}`"
        );
    }

    let (hits, n_commits, n_added) = collect_hits(repo_path, range, &terms)?;

    println!("channel  : {channel} ({} protected term(s))", terms.len());
    println!("range    : {range}");
    println!("examined : {n_commits} commit message(s), {n_added} added line(s) across {n_commits} commit patch(es)\n");

    if hits.is_empty() {
        println!("no protected term appears in this range.");
    } else {
        let total: usize = hits.values().map(|v| v.len()).sum();
        println!("{total} hit(s) across {} term(s):\n", hits.len());
        for (t, lines) in &hits {
            println!("  {t}  ({} hit(s))", lines.len());
            for l in lines.iter().take(4) {
                println!("    {l}");
            }
            if lines.len() > 4 {
                println!(
                    "    … {} more (one decision dismisses the group)",
                    lines.len() - 4
                );
            }
        }
    }

    // Never a clean bill of health.
    println!("\nNOT CHECKED — this audit is narrow by construction:");
    println!("  - file contents outside this range's added lines");
    println!("  - lines this range REMOVES, and anything already on the remote");
    println!("  - author names, emails and commit dates");
    println!("  - binary files, and anything a term does not literally spell");
    println!(
        "  - thematic material carrying no protected term (the 2026-07-22 leak was exactly this)"
    );

    if !hits.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

/// Write a pre-push hook that runs the audit on whatever is about to be pushed.
///
/// This is the point of the whole thing. A check you have to remember to run is
/// not a check — yesterday's near-miss was caught because I happened to look at
/// the remote first, which is luck, not process. Git already knows when content
/// is about to cross into a channel; the audit should be a side effect of that
/// moment rather than a separate obligation.
fn cmd_hook(
    storage: PostureStorage<'_>,
    repo: &Path,
    channel: &str,
    remote_match: Option<&str>,
) -> Result<()> {
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
    let path = hooks.join("pre-push");

    let exe = std::env::current_exe()
        .map_err(|e| anyhow!("locate posture binary: {e}"))?
        .display()
        .to_string();

    // The pre-push protocol feeds us "<local ref> <local sha> <remote ref>
    // <remote sha>" per line. An all-zero remote sha means a brand-new branch,
    // where everything reachable is new to the channel.
    let script = format!(
        r#"#!/bin/sh
# Installed by `posture hook`. Audits what is about to cross into a channel.
# Bypass with --no-verify, but read what it says first.
set -e
POSTURE="{exe}"
PILE="{pile}"
POLICY_SCOPE="{policy_scope}"
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

# Fail CLOSED but legibly. If the binary has been rebuilt away or the pile has
# moved, every push in this repo starts failing, and "command not found" gives
# no clue why. A safety tool that blocks work without explaining itself gets
# deleted in irritation, which is the worst possible outcome for it.
if [ ! -x "$POSTURE" ]; then
    echo "posture: hook installed but the binary is missing at:" >&2
    echo "           $POSTURE" >&2
    echo "         Rebuild it, or remove this hook with:" >&2
    echo "           rm \"$0\"" >&2
    echo "         Refusing the push rather than passing an unchecked one." >&2
    exit 1
fi
if [ ! -f "$PILE" ]; then
    echo "posture: hook installed but the pile is missing at:" >&2
    echo "           $PILE" >&2
    echo "         The protected vocabulary lives there, so nothing can be checked." >&2
    echo "         Refusing the push rather than passing an unchecked one." >&2
    exit 1
fi

status=0
while read -r _local_ref local_sha _remote_ref remote_sha; do
    [ "$local_sha" = "$ZERO" ] && continue          # branch deletion
    if [ "$remote_sha" = "$ZERO" ]; then
        range="$local_sha"                          # new branch: all of it
    else
        range="$remote_sha..$local_sha"
    fi
    if [ -n "$KEY" ]; then
        PILE="$PILE" TRIBLESPACE_KEY="$KEY" POSTURE_POLICY_SCOPE="$POLICY_SCOPE" \
            "$POSTURE" git "$range" --channel "$CHANNEL" || status=1
    else
        PILE="$PILE" POSTURE_POLICY_SCOPE="$POLICY_SCOPE" \
            "$POSTURE" git "$range" --channel "$CHANNEL" || status=1
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
        pile = storage.pile.display(),
        policy_scope = fmt_id(storage.policy_scope),
        key = storage
            .key
            .map(Path::display)
            .map(|path| path.to_string())
            .unwrap_or_default(),
        channel = channel,
        remote_match = remote_match.unwrap_or(""),
    );

    if path.exists() {
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        if !existing.contains("Installed by `posture hook`") {
            // Never clobber someone else's hook silently — that would be a
            // destructive side effect of a command that reads like a setup step.
            anyhow::bail!(
                "{} already exists and was not written by posture; refusing to overwrite it",
                path.display()
            );
        }
    }
    std::fs::write(&path, script).map_err(|e| anyhow!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| anyhow!("chmod {}: {e}", path.display()))?;
    }
    println!("installed {}", path.display());
    println!("  channel : {channel}");
    match remote_match {
        Some(m) => println!("  remotes : only those matching {m:?}"),
        None => println!("  remotes : ALL (pass --remote-match to scope by destination)"),
    }
    println!("  pile    : {}", storage.pile.display());
    println!("\nIt runs on every push. It exits non-zero on a hit, and also when the");
    println!("channel has no vocabulary — a hook that passes because it checked");
    println!("nothing is worse than no hook.");
    Ok(())
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
fn git_probe(repo_path: &Path, args: &[&str], absent_statuses: &[i32]) -> Result<Option<String>> {
    let output = std::process::Command::new("git")
        .env("LC_ALL", "C")
        .arg("-C")
        .arg(repo_path)
        .args(args)
        .output()
        .with_context(|| format!("run git -C {} {}", repo_path.display(), args.join(" ")))?;
    if output.status.success() {
        return Ok(Some(
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        ));
    }
    if output
        .status
        .code()
        .is_some_and(|code| absent_statuses.contains(&code))
    {
        return Ok(None);
    }
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
    )
}

fn cmd_sweep(storage: PostureStorage<'_>, root: &Path, channel: &str, all: bool) -> Result<()> {
    let terms = load_terms(storage, channel)?;
    if terms.is_empty() {
        bail!(
            "channel {channel:?} has no protected terms — a sweep against an empty \
             vocabulary would report every repository clean while checking nothing"
        );
    }

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
        let base = if git_probe(
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
        let ahead = git_required(repo, &["log", "--oneline", &range])?
            .lines()
            .filter(|line| !line.is_empty())
            .count();
        if ahead == 0 {
            continue;
        }
        let (hits, _, _) = collect_hits(repo, &range, &terms)?;
        let count: usize = hits.values().map(Vec::len).sum();
        if count > 0 {
            flagged += 1;
            println!(
                "  {:<24} {:<28} {visibility:<8} ahead={ahead:<5} {count} hit(s) across {} term(s)",
                repo.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("?"),
                slug,
                hits.len()
            );
            println!("      (range {range})");
            for (term, lines) in &hits {
                println!("      {term}  ({} hit(s))", lines.len());
            }
        } else {
            println!(
                "  {:<24} {:<28} {visibility:<8} ahead={ahead:<5} clean",
                repo.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("?"),
                slug
            );
        }
    }

    println!("\n{flagged} repositor(y/ies) carry protected material ahead of their remote.");
    println!("\nNOT CHECKED:");
    println!("  - {skipped_private} repo(s) whose remote gh reports PRIVATE (re-run with --all)");
    println!("  - {no_remote} repo(s) with no origin remote");
    println!("  - repos nested deeper than one level under the root");
    println!("  - OTHER BRANCHES of a scanned repo: only the checked-out HEAD is audited");
    println!("  - uncommitted work, which cannot be pushed but can be committed later");
    println!("  - everything posture git does not check (see its own coverage note)");

    if flagged > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = PostureStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
        policy_scope: cli.policy_scope.unwrap_or(DEFAULT_POLICY_SCOPE_ID),
        scan_scope: cli.scan_scope.unwrap_or(DEFAULT_SCAN_SCOPE_ID),
    };
    match cli.command {
        // no subcommand still links the schema, so the attributes stay discoverable
        None => {
            Cli::command().print_help().ok();
            println!();
            Ok(())
        }
        Some(Command::Scan { path, dry_run }) => cmd_scan(storage, &path, dry_run),
        Some(Command::List { scan, examples }) => cmd_list(storage, scan, examples),
        Some(Command::Coverage { scan }) => cmd_coverage(storage, scan),
        Some(Command::Scans) => cmd_scans(storage),
        Some(Command::Hook {
            repo,
            channel,
            remote_match,
        }) => cmd_hook(storage, &repo, &channel, remote_match.as_deref()),
        Some(Command::Sweep { root, channel, all }) => cmd_sweep(storage, &root, &channel, all),
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

    struct TestStore {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
        policy_scope: Id,
        scan_scope: Id,
    }

    impl TestStore {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("posture-test.pile");
            let key = directory.path().join("posture-test.key");
            File::create(&pile).unwrap();
            collection_access::initialize_signer(&pile, Some(&key)).unwrap();
            Self {
                _directory: directory,
                pile,
                key,
                policy_scope: genid().id,
                scan_scope: genid().id,
            }
        }

        fn storage(&self) -> PostureStorage<'_> {
            PostureStorage {
                pile: &self.pile,
                key: Some(&self.key),
                policy_scope: self.policy_scope,
                scan_scope: self.scan_scope,
            }
        }

        fn publish_raw(&self, scope: Id, fragment: Fragment, description: &str) {
            publish_fragment(&self.pile, Some(&self.key), scope, fragment, description).unwrap();
        }
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
        assert_eq!(view.commits.len(), 1);
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
        store.publish_raw(store.policy_scope, fragment, "forked policy fixture");

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
        store.publish_raw(store.policy_scope, fragment, "ambiguous policy fixture");

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
        store.publish_raw(store.policy_scope, first, "first exemplar exhaust");

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
        store.publish_raw(store.policy_scope, second, "replacement exemplar exhaust");

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
        store.publish_raw(store.policy_scope, role_change, "exemplar role change");
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
        invalid.publish_raw(invalid.policy_scope, ambiguous, "ambiguous exemplar roles");
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
        let occurrence = genid().id;
        let (files, omissions) = sample_scan_inputs();
        let (fragment, scan) = build_scan_fragment(
            Path::new("fixture-corpus"),
            &files,
            &omissions,
            created_at,
            occurrence,
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
        assert_eq!(view.commits.len(), 1);
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
            occurrence,
        );
        assert_eq!(scan, duplicate_scan);
        store.publish_raw(store.scan_scope, duplicate, "duplicate scan fixture");
        let error = store.storage().scan_view().unwrap_err();
        assert!(error.to_string().contains("scans must be atomic"));
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
            posture::occurrence: genid().id,
            posture::target: target_handle,
            posture::file_count: 0_u64,
            posture::checked*: BTreeSet::from([modality::EXIF]),
            posture::unchecked*: BTreeSet::<Id>::new(),
        };
        assert!(validate_scan_commit_fragment(missing_coverage.facts())
            .unwrap_err()
            .to_string()
            .contains("partition every known modality"));

        let mut missing_document = Fragment::empty();
        let target_handle: TextHandle = missing_document.put(target.display().to_string());
        missing_document += entity! {
            metadata::tag: KIND_SCAN,
            metadata::created_at: created_at,
            posture::occurrence: genid().id,
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
        let scan_entity = entity! {
            metadata::tag: KIND_SCAN,
            metadata::created_at: created_at,
            posture::occurrence: genid().id,
            posture::target: target_handle,
            posture::file_count: 1_u64,
            posture::checked*: IMPLEMENTED.iter().copied().collect::<BTreeSet<_>>(),
            posture::unchecked*: unchecked_modalities(),
        };
        let scan = scan_entity.root().unwrap();
        no_detail += scan_entity;
        let path: TextHandle = no_detail.put("broken.pdf".to_owned());
        no_detail += entity! {
            metadata::tag: KIND_DOCUMENT,
            posture::scan: scan,
            posture::path: path,
            posture::outcome: OUTCOME_PARSE_FAILED,
        };
        assert!(validate_scan_commit_fragment(no_detail.facts())
            .unwrap_err()
            .to_string()
            .contains("parse-failure detail"));

        let files = vec![ScannedFile {
            path: PathBuf::from("examined.png"),
            outcome: FileOutcome::Examined,
            findings: vec![f(modality::EXIF, "EXIF:Artist", "Example Author")],
        }];
        let (left, _) = build_scan_fragment(target, &files, &[], created_at, genid().id);
        let files = vec![ScannedFile {
            path: PathBuf::from("examined.png"),
            outcome: FileOutcome::Examined,
            findings: Vec::new(),
        }];
        let (right, _) = build_scan_fragment(target, &files, &[], created_at, genid().id);
        let mut mixed = left.into_facts();
        mixed += right.into_facts();
        assert!(validate_scan_commit_fragment(&mixed)
            .unwrap_err()
            .to_string()
            .contains("scan COMMIT root"));
    }

    #[test]
    fn git_subprocess_errors_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let terms = vec![("project-sunrise".to_owned(), "fixture".to_owned())];
        let error = collect_hits(directory.path(), "HEAD", &terms).unwrap_err();
        assert!(error.to_string().contains("git -C"));

        let error =
            git_probe(directory.path(), &["remote", "get-url", "origin"], &[2]).unwrap_err();
        assert!(error.to_string().contains("git -C"));
    }
}
