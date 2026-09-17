//! The source catalogue: what exists, what uses what, and what is defined where.
//!
//! # What this is for
//!
//! `grep` answers "where does this text appear". It cannot answer "do we
//! already have a GPU graph layout", because the answer does not contain the
//! words you would search for; and it cannot answer "this is absent" with a
//! denominator, because it only ever reports what it found in the tree it was
//! pointed at. Those two are what this faculty exists for. It is not a search
//! engine and it is not a second copy of the source.
//!
//! # Three bright lines against the shadow model
//!
//! A code catalogue is the most tempting possible place to build one, so these
//! are stated rather than assumed, and they are the thing to check in review:
//!
//! 1. **Every relation projection in this module is exactly one `find!`,**
//!    generic over `P: TriblePattern + ?Sized`, returning a `Vec` of tuples or
//!    of a row type that query alone fills. A DISPLAY row
//!    ([`operations::Hit`]) is assembled at the point of use from several of
//!    them — but only for results that already survived a relation query, never
//!    ahead of a question, and never kept.
//! 2. **No value read from the pile may outlive the function that queried it.**
//!    No `OnceLock`, no `lazy_static`, no struct field holding query results, no
//!    `Catalog`. If you find yourself typing `fn load_all_items() -> Vec<Item>`,
//!    stop. The one memo in the codebase is
//!    `operations::Texts`, which caches blob TEXT by content handle for the
//!    length of one command: nothing queries it, nothing joins against it, and
//!    it answers no question the pile was not asked.
//! 3. **[`extract`] may not name a `Pile`, `Storage`, `Collection` or
//!    `TribleSet` in any signature.** It is pure and unit-testable on fixture
//!    strings; its output is one file's parse, consumed into fragments and
//!    dropped.
//!
//! # Identity
//!
//! An ITEM is identified by its normalized token stream alone, so byte-identical
//! code in two files is ONE item with two PLACEMENTs and duplication is exhaust
//! rather than a feature that had to be built. A UNIT is one `(repo, path,
//! content)` triple, so re-ingesting an unchanged file is a no-op and two
//! machines scanning the same commit converge. Everything a judgement produced
//! — kind, name, doc, signature, visibility, mentions — annotates those cores
//! instead of entering them, so a better extractor re-annotates the same
//! entities rather than re-minting the world.
//!
//! Nothing here computes or validates a derived id in order to look something
//! up. Ids come back from [`Fragment::root`] and are treated as opaque. Swap
//! every one of them for a fresh `genid` and only idempotence breaks: duplicates
//! become distinct items with one placement each, re-ingest grows the pile, and
//! nothing else notices.
//!
//! A `Handle<UTF8String>` computed from a query string and used in `pattern!`
//! value position is NOT the hash-join sin. That rule governs derived ENTITY
//! ids. A handle is a content-addressed VALUE, and `pattern!` folds literal
//! values to constants by exactly the same path
//! (`triblespace-core/src/inline.rs:564`).

pub mod cli;
pub mod extract;
pub mod git;
pub mod index;
pub mod ingest;
pub mod mcp;
pub mod operations;
pub mod render;

use anybytes::Bytes;
use triblespace::core::blob::Blob;
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::prelude::blobencodings::RawBytes;
use triblespace::prelude::inlineencodings::LineLocation;
use triblespace::prelude::*;

use crate::schemas::code::{
    attrs, ItemKind, Language, Visibility, EXTRACTOR_RUST_SYN_V1, EXTRACTOR_RUST_SYN_V1_LAW,
    EXTRACTOR_RUST_SYN_V1_NAME, KIND_ITEM, KIND_PLACEMENT, KIND_SCAN, KIND_UNIT,
};

pub use crate::schemas::code::DEFAULT_SCOPE_ID;

/// A content-addressed text value.
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
/// A content-addressed byte value.
pub type BytesHandle = Inline<inlineencodings::Handle<RawBytes>>;
/// `(start line, start column, end line, end column)`, as stored.
pub type SpanValue = Inline<LineLocation>;
/// An observation time.
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

/// The content-addressed handle of one text, without storing it.
///
/// This is how an exact-identifier question becomes a constant term in a
/// pattern: the querier spells the identifier, the handle folds to a value, and
/// the engine answers from an index range rather than by scanning strings.
pub fn text_handle(text: &str) -> TextHandle {
    let blob: Blob<blobencodings::UTF8String> = text.to_owned().to_blob();
    blob.get_handle()
}

/// The content-addressed handle of some bytes, without storing them.
pub fn bytes_handle(bytes: &[u8]) -> BytesHandle {
    let blob: Blob<RawBytes> = Bytes::from_source(bytes.to_vec()).to_blob();
    blob.get_handle()
}

/// Decode a stored span.
pub fn span_parts(span: SpanValue) -> (u64, u64, u64, u64) {
    span.try_from_inline()
        .expect("LineLocation decodes infallibly")
}

// ── fragment constructors ────────────────────────────────────────────────

/// The extraction law, published so a reader holding the pile learns what an
/// item's tokens mean without the code that produced them.
///
/// A changed law gets a NEW id rather than a new meaning for this one, so a
/// normalization change is visible in the pile instead of silently forking
/// every item identity in it.
pub fn law_fragment() -> Fragment {
    let mut fragment = Fragment::empty();
    let law = fragment.put::<blobencodings::UTF8String, _>(EXTRACTOR_RUST_SYN_V1_LAW.to_owned());
    let name = fragment.put::<blobencodings::UTF8String, _>(EXTRACTOR_RUST_SYN_V1_NAME.to_owned());
    fragment += entity! { ExclusiveId::force_ref(&EXTRACTOR_RUST_SYN_V1) @
        metadata::name: name,
        metadata::description: law,
    };
    fragment
}

/// The identity core of one unit: a repo, a repo-relative path, and content.
///
/// Built from precomputed handles and carrying no blobs, because its only job
/// on the fast path is to yield the id that answers "have I already catalogued
/// exactly these bytes at exactly this path?".
pub fn unit_core(repo: TextHandle, path: TextHandle, content: BytesHandle) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_UNIT,
        attrs::repo: repo,
        attrs::path: path,
        crate::schemas::files::file::content: content,
    }
}

/// The identity core of one item: its normalized token stream, and nothing else.
pub fn item_core(tokens: TextHandle) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_ITEM,
        attrs::source_tokens: tokens,
    }
}

/// The identity core of one placement: an item, at a range, in a unit.
pub fn placement_core(unit: Id, item: Id, range: SpanValue) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_PLACEMENT,
        attrs::unit: &unit,
        attrs::item: &item,
        attrs::source_range: range,
    }
}

/// The identity core of one scan: one repository at one commit.
///
/// Deliberately excludes the observation time, so two machines scanning the
/// same commit produce the SAME scan entity carrying two `created_at` values.
/// Putting the clock in the core would make `--at` diverge per machine.
pub fn scan_core(repo: TextHandle, commit: TextHandle) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_SCAN,
        attrs::repo: repo,
        attrs::commit: commit,
    }
}

/// Facts saying a scan observed a unit. Emitted one at a time, so a scan is
/// never accumulated in memory.
pub fn scan_holds(scan: Id, unit: Id) -> Fragment {
    entity! { ExclusiveId::force_ref(&scan) @ attrs::holds: &unit }
}

/// Everything that annotates a scan.
pub fn scan_annotation(scan: Id, observed_at: IntervalValue, mode: &str) -> Fragment {
    let mut fragment = Fragment::empty();
    let mode = fragment.put::<blobencodings::UTF8String, _>(mode.to_owned());
    fragment += entity! { ExclusiveId::force_ref(&scan) @
        metadata::created_at: observed_at,
        metadata::description: mode,
        attrs::extractor: &EXTRACTOR_RUST_SYN_V1,
    };
    fragment
}

/// One unit, its items and their placements, as one independently derivable
/// fragment.
///
/// One fragment per FILE, not per declaration: the writer's idempotence check
/// walks a candidate's facts and stops at the first it has not seen, so a
/// file-sized candidate costs one short-circuited walk rather than one probe per
/// item. The Merkle structure comes free from spreading children into the
/// parent.
///
/// `mentions` handles are deliberately stored WITHOUT their blobs. They are
/// content-addressed values a querier reproduces by spelling the identifier, and
/// the same strings are recoverable from the item's `source_tokens`, which IS
/// stored. Storing three quarters of a million short blobs to re-read text we
/// already hold would be paying a large price for nothing.
pub fn unit_fragment(
    repo: &str,
    path: &str,
    language: Language,
    content: &[u8],
    extracted: &extract::Extracted,
) -> (Fragment, Id) {
    let mut fragment = Fragment::empty();
    let repo_handle = fragment.put::<blobencodings::UTF8String, _>(repo.to_owned());
    let path_handle = fragment.put::<blobencodings::UTF8String, _>(path.to_owned());
    let content_handle = fragment.put::<RawBytes, _>(Bytes::from_source(content.to_vec()));

    let core = unit_core(repo_handle, path_handle, content_handle);
    let unit = core.root().expect("unit core has one intrinsic root");
    fragment += core;

    let doc = extracted
        .doc
        .as_ref()
        .map(|doc| fragment.put::<blobencodings::UTF8String, _>(doc.clone()));
    let parse_error = extracted
        .parse_error
        .as_ref()
        .map(|error| fragment.put::<blobencodings::UTF8String, _>(error.clone()));
    let import_roots: Vec<TextHandle> = extracted
        .import_roots
        .iter()
        .map(|root| fragment.put::<blobencodings::UTF8String, _>(root.clone()))
        .collect();

    fragment += entity! { ExclusiveId::force_ref(&unit) @
        attrs::language: language.name(),
        attrs::doc?: doc,
        attrs::parse_error?: parse_error,
        attrs::import_root*: import_roots,
    };

    // Placement ids, by item index, so a child can name its enclosing
    // placement. Enclosure is location-specific: two byte-identical `fn new`
    // in two impls are one item and differ only here.
    let mut placements: Vec<Option<Id>> = Vec::with_capacity(extracted.items.len());
    for declaration in &extracted.items {
        let tokens = fragment.put::<blobencodings::UTF8String, _>(declaration.tokens.clone());
        let core = item_core(tokens);
        let item = core.root().expect("item core has one intrinsic root");
        fragment += core;

        let name = declaration
            .name
            .as_ref()
            .map(|name| fragment.put::<blobencodings::UTF8String, _>(name.clone()));
        let doc = declaration
            .doc
            .as_ref()
            .map(|doc| fragment.put::<blobencodings::UTF8String, _>(doc.clone()));
        let signature = if declaration.signature.is_empty() {
            None
        } else {
            Some(fragment.put::<blobencodings::UTF8String, _>(declaration.signature.clone()))
        };
        let mentions: Vec<TextHandle> = declaration
            .mentions
            .iter()
            .map(|mention| text_handle(mention))
            .collect();

        fragment += entity! { ExclusiveId::force_ref(&item) @
            attrs::kind: declaration.kind.name(),
            attrs::visibility: declaration.visibility.name(),
            metadata::name?: name,
            attrs::doc?: doc,
            attrs::signature?: signature,
            attrs::mentions*: mentions,
        };

        let range: SpanValue = declaration.span.to_inline();
        let core = placement_core(unit, item, range);
        let placement = core.root().expect("placement core has one intrinsic root");
        fragment += core;
        let within = declaration
            .parent
            .and_then(|parent| placements.get(parent).copied().flatten());
        fragment += entity! { ExclusiveId::force_ref(&placement) @
            attrs::within?: within.as_ref(),
        };
        placements.push(Some(placement));
    }

    (fragment, unit)
}

// ── projections ──────────────────────────────────────────────────────────
//
// Every function below is ONE `find!` over relations queried at the point of
// use. None of them is cached, memoized, or assembled into a catalogue, and a
// row this reader cannot decode does not inhabit the result type — an unknown
// kind string is SKIPPED, never an error, because a typed query is what lets
// two generations of this faculty read one pile.

/// Every scan in the collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanRow {
    pub id: Id,
    pub repo: TextHandle,
    pub commit: TextHandle,
    pub observed_at: IntervalValue,
}

pub fn projected_scans<P>(facts: &P) -> Vec<ScanRow>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (id: Id, repo: TextHandle, commit: TextHandle, observed_at: IntervalValue),
        pattern!(facts, [{ ?id @
            metadata::tag: &KIND_SCAN,
            attrs::repo: ?repo,
            attrs::commit: ?commit,
            metadata::created_at: ?observed_at,
        }])
    )
    .map(|(id, repo, commit, observed_at)| ScanRow {
        id,
        repo,
        commit,
        observed_at,
    })
    .collect()
}

/// One declaration, located.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Located {
    pub item: Id,
    pub placement: Id,
    pub unit: Id,
    pub range: SpanValue,
}

/// Placements, within one scan, of items whose name is exactly `name`.
///
/// The scan is a constraint inside the pattern, not a filter after it: "which
/// revision is this true at" is part of the question, and an answer that cannot
/// say which revision it came from is how three wrong absence claims got made
/// from stale checkouts.
pub fn definitions_in_scan<P>(facts: &P, scan: Id, name: TextHandle) -> Vec<Located>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (item: Id, placement: Id, unit: Id, range: SpanValue),
        pattern!(facts, [
            { scan @ attrs::holds: ?unit },
            { ?item @ metadata::name: name },
            { ?placement @
                attrs::unit: ?unit,
                attrs::item: ?item,
                attrs::source_range: ?range },
        ])
    )
    .map(|(item, placement, unit, range)| Located {
        item,
        placement,
        unit,
        range,
    })
    .collect()
}

/// Placements, within one scan, of items that syntactically name `identifier`.
///
/// `mentions` is unresolved and positionless, so this answer is exactly as
/// trustworthy as the identifier is rare. Callers are expected to say so
/// instead of phrasing a common name as settled — see [`render`].
pub fn usages_in_scan<P>(facts: &P, scan: Id, identifier: TextHandle) -> Vec<Located>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (item: Id, placement: Id, unit: Id, range: SpanValue),
        pattern!(facts, [
            { scan @ attrs::holds: ?unit },
            { ?item @ attrs::mentions: identifier },
            { ?placement @
                attrs::unit: ?unit,
                attrs::item: ?item,
                attrs::source_range: ?range },
        ])
    )
    .map(|(item, placement, unit, range)| Located {
        item,
        placement,
        unit,
        range,
    })
    .collect()
}

/// Every item placed in one scan, for a denominator an absence verdict can cite.
pub fn placement_count_in_scan<P>(facts: &P, scan: Id) -> usize
where
    P: TriblePattern + ?Sized,
{
    find!(
        (placement: Id, unit: Id),
        pattern!(facts, [
            { scan @ attrs::holds: ?unit },
            { ?placement @ attrs::unit: ?unit },
        ])
    )
    .count()
}

/// Units one scan observed.
pub fn units_in_scan<P>(facts: &P, scan: Id) -> Vec<Id>
where
    P: TriblePattern + ?Sized,
{
    find!(unit: Id, pattern!(facts, [{ scan @ attrs::holds: ?unit }])).collect()
}

/// Where one unit is: its repo and its repo-relative path.
pub fn unit_location<P>(facts: &P, unit: Id) -> Vec<(TextHandle, TextHandle)>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (repo: TextHandle, path: TextHandle),
        pattern!(facts, [{ unit @ attrs::repo: ?repo, attrs::path: ?path }])
    )
    .collect()
}

/// A unit's raw content, for `code show --source`.
pub fn unit_content<P>(facts: &P, unit: Id) -> Vec<BytesHandle>
where
    P: TriblePattern + ?Sized,
{
    find!(
        content: BytesHandle,
        pattern!(facts, [{ unit @ crate::schemas::files::file::content: ?content }])
    )
    .collect()
}

/// A unit's `use`-path first segments.
pub fn unit_import_roots<P>(facts: &P, unit: Id) -> Vec<TextHandle>
where
    P: TriblePattern + ?Sized,
{
    find!(
        root: TextHandle,
        pattern!(facts, [{ unit @ attrs::import_root: ?root }])
    )
    .collect()
}

/// How many units in this collection import `root` at all.
///
/// This is how the distinguishing-import evidence line gets its rarity without
/// a corpus-wide frequency table built at startup. One counting query per
/// candidate root — at most a few dozen per invocation, each a constant-folded
/// index range — and nothing is retained between them.
pub fn import_root_frequency<P>(facts: &P, root: TextHandle) -> usize
where
    P: TriblePattern + ?Sized,
{
    find!(
        unit: Id,
        pattern!(facts, [{ ?unit @ attrs::import_root: root }])
    )
    .count()
}

/// What this reader can say about one item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItemRow {
    pub kind: ItemKind,
    pub visibility: Visibility,
}

/// One item's kind and visibility, skipping vocabulary this build does not know.
///
/// A kind string from a newer extractor is not an error here. It simply does not
/// inhabit the result type, which is what lets two generations of this faculty
/// read one pile through a cutover.
pub fn item_row<P>(facts: &P, item: Id) -> Vec<ItemRow>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (kind: String, visibility: String),
        pattern!(facts, [{ item @ attrs::kind: ?kind, attrs::visibility: ?visibility }])
    )
    .filter_map(|(kind, visibility)| {
        Some(ItemRow {
            kind: ItemKind::from_name(&kind)?,
            visibility: Visibility::from_name(&visibility)?,
        })
    })
    .collect()
}

/// One item's display names. Deliberately a set: `metadata::name` is documented
/// as display rather than identity, and nothing forbids two.
pub fn item_names<P>(facts: &P, item: Id) -> Vec<TextHandle>
where
    P: TriblePattern + ?Sized,
{
    find!(
        name: TextHandle,
        pattern!(facts, [{ item @ metadata::name: ?name }])
    )
    .collect()
}

/// One item's prose.
pub fn item_doc<P>(facts: &P, item: Id) -> Vec<TextHandle>
where
    P: TriblePattern + ?Sized,
{
    find!(doc: TextHandle, pattern!(facts, [{ item @ attrs::doc: ?doc }])).collect()
}

/// One item's signature.
pub fn item_signature<P>(facts: &P, item: Id) -> Vec<TextHandle>
where
    P: TriblePattern + ?Sized,
{
    find!(
        signature: TextHandle,
        pattern!(facts, [{ item @ attrs::signature: ?signature }])
    )
    .collect()
}

/// One unit's prose.
pub fn unit_doc<P>(facts: &P, unit: Id) -> Vec<TextHandle>
where
    P: TriblePattern + ?Sized,
{
    find!(doc: TextHandle, pattern!(facts, [{ unit @ attrs::doc: ?doc }])).collect()
}

/// Units that carry a parse error, so the gap is visible rather than silent.
pub fn parse_failures_in_scan<P>(facts: &P, scan: Id) -> Vec<(Id, TextHandle)>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (unit: Id, error: TextHandle),
        pattern!(facts, [
            { scan @ attrs::holds: ?unit },
            { ?unit @ attrs::parse_error: ?error },
        ])
    )
    .collect()
}

/// Items placed more than once, as a self-join on the placement relation.
///
/// Byte-identical code is already ONE item, so the pile's content addressing IS
/// the clone detector: no hash attribute, no hashing pass, no comparison. The
/// caller drops the reflexive pairs and canonicalises pair order, which is
/// bag-to-set presentation, not a filter standing in for a missing constraint.
pub fn duplicate_placements_in_scan<P>(facts: &P, scan: Id) -> Vec<(Id, Id, Id, Id, Id)>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (item: Id, left: Id, right: Id, left_unit: Id, right_unit: Id),
        pattern!(facts, [
            { scan @ attrs::holds: ?left_unit },
            { scan @ attrs::holds: ?right_unit },
            { ?left @ attrs::unit: ?left_unit, attrs::item: ?item },
            { ?right @ attrs::unit: ?right_unit, attrs::item: ?item },
        ])
    )
    .collect()
}

/// Items of one kind placed in one scan, for `code stats` and shape questions.
pub fn items_of_kind_in_scan<P>(facts: &P, scan: Id, kind: &str) -> Vec<Located>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (item: Id, placement: Id, unit: Id, range: SpanValue),
        pattern!(facts, [
            { scan @ attrs::holds: ?unit },
            { ?item @ attrs::kind: kind },
            { ?placement @
                attrs::unit: ?unit,
                attrs::item: ?item,
                attrs::source_range: ?range },
        ])
    )
    .map(|(item, placement, unit, range)| Located {
        item,
        placement,
        unit,
        range,
    })
    .collect()
}

/// Items of one kind that also name `identifier`, within one scan.
///
/// The shape question — "which structs hold owned `String` fields" — is this
/// query, and it is one query rather than a sixteen-agent survey. It is a SHAPE
/// fact, not a dataflow fact: a struct naming `String` in a generic bound is a
/// true row and a false lead, and the renderer says so.
pub fn items_of_kind_mentioning_in_scan<P>(
    facts: &P,
    scan: Id,
    kind: &str,
    identifier: TextHandle,
) -> Vec<Located>
where
    P: TriblePattern + ?Sized,
{
    find!(
        (item: Id, placement: Id, unit: Id, range: SpanValue),
        pattern!(facts, [
            { scan @ attrs::holds: ?unit },
            { ?item @ attrs::kind: kind, attrs::mentions: identifier },
            { ?placement @
                attrs::unit: ?unit,
                attrs::item: ?item,
                attrs::source_range: ?range },
        ])
    )
    .map(|(item, placement, unit, range)| Located {
        item,
        placement,
        unit,
        range,
    })
    .collect()
}

/// Every item id, for prefix resolution in `code show`.
pub fn all_item_ids<P>(facts: &P) -> Vec<Id>
where
    P: TriblePattern + ?Sized,
{
    find!(item: Id, pattern!(facts, [{ ?item @ metadata::tag: &KIND_ITEM }])).collect()
}

#[cfg(test)]
mod tests;
