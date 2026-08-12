//! Files schema: content-addressed file storage with directory trees and
//! import snapshots.
//!
//! Used by `files.rs` (the faculty CLI) and by any downstream consumer
//! that wants to read file entities, directory trees, or import snapshots
//! from a pile.

use triblespace::macros::id_hex;
use triblespace::prelude::*;
use triblespace_search::schemas::Embedding;

// ── branch name ──────────────────────────────────────────────────────────
/// Stable extrinsic scope of the Files `SimpleArchive`-union collection.
///
/// Minted with `trible genid` on 2026-08-07 and recovered from the reviewed
/// collection-cutover lineage:
/// `56002AB0A2A7D56753EE20C61900BFB0`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("56002AB0A2A7D56753EE20C61900BFB0");

/// Exact name of the pre-collection repository branch.
///
/// New collection operations address [`DEFAULT_SCOPE_ID`]; this name is input
/// vocabulary for the one-way stopped-world migration only.
pub const FILES_BRANCH_NAME: &str = "files";

// ── kinds ────────────────────────────────────────────────────────────────
pub const KIND_FILE: Id = id_hex!("1F9C9DCA69504452F318BA11E81D47D1");
/// A normalized IANA media type such as `text/plain` or `image/png`.
///
/// Media-type entities are intrinsic records carrying this marker plus their
/// full normalized name in `metadata::name`. Files point at them through
/// `file::media_type`, so long vendor types remain lossless and equal types
/// converge across every producer.
pub const KIND_MEDIA_TYPE: Id = id_hex!("C0DA01871FCB60E8D7F0B5AC5CF4F960");
pub const KIND_DIRECTORY: Id = id_hex!("58CDFCBA4E4B91979766D50FB18777B5");
pub const KIND_IMPORT: Id = id_hex!("89655D039A90634F09207BFEB5BE65AD");
/// A rasterized PDF page — the retrieval unit for `application/pdf` in the
/// nomic-mm7b space. A page entity carries `page::parent` (the file it came
/// from), `page::index` (1-based page number), and an `embeddings::attr_mm7b`
/// vector (the page image embedded). A PDF isn't an image, so the page is what
/// `files similar --mm7b` actually ranks; a hit resolves back to "file X, page N".
pub const KIND_PAGE: Id = id_hex!("2FD7176842BAB84DF000A094D2685552");

// ── attributes ───────────────────────────────────────────────────────────
pub mod file {
    use super::*;
    attributes! {
        // file leaf: content blob
        "C1E3A12230595280F22ABEB8733D082C" unsafe as content: inlineencodings::Handle<blobencodings::RawBytes>;
        // file/directory: name (filename or dirname)
        "AA6AB6F5E68F3A9D95681251C2B9DAFA" unsafe as name: inlineencodings::Handle<blobencodings::LongString>;
        // file leaf: canonical media-type entity
        "B300DAE46621BF56D11621BAD9C66BA5" unsafe as media_type: inlineencodings::GenId;
        // import timestamp; preserved legacy file provenance outside identity
        "3765160CC1A96BE38302B344718E4C49" unsafe as imported_at: inlineencodings::NsTAIInterval;
        // TODO: migrate to metadata::tag (GenId) — should use canonical tag
        // entities with metadata::name, not inline ShortString. See wiki.rs TagIndex.
        "CDA941A27F86A7551779CF9524DE1D0F" unsafe as tag: inlineencodings::ShortString;
        // directory: children (multi-valued, files or subdirectories)
        "0AC1D962B6E8170FDD73AE3743E16578" unsafe as children: inlineencodings::GenId;
        // import: root directory or file entity
        "7B36A7A304C26C5504EA54F5723FA135" unsafe as root: inlineencodings::GenId;
        // import path; also preserved source provenance on historical files
        "E4B24BB9F469CEC6FD12926C56514E9F" unsafe as source_path: inlineencodings::Handle<blobencodings::LongString>;
        // file leaf: CLIP-512 embedding handle (v0, untyped Embedding) —
        // semantic-search exhaust, set on `add` for image/* files. Being
        // superseded by the shared 768-d nomic space (`schemas::embeddings`,
        // dim-typed `Embedding768`); kept live until the nomic vision tower
        // lands, then a clean break (new attribute, no dimension clash).
        "433BE3AC7F95405872385898AD52FB73" unsafe as embedding: inlineencodings::Handle<Embedding>;
    }
}

/// Rasterized-PDF-page attributes (see [`KIND_PAGE`]). A page entity is the
/// retrieval unit for PDFs in the nomic-mm7b space; the embedding itself lives
/// on the shared `embeddings::attr_mm7b::embedding`.
pub mod page {
    use super::*;
    attributes! {
        // page: the file entity this page was rasterized from
        "2CA50D520D6784D9340851C36EDED209" unsafe as parent: inlineencodings::GenId;
        // page: 1-based page number, decimal text (a display/identity label)
        "1AACF2C318E912C3B74283FB127D3CFE" unsafe as index: inlineencodings::ShortString;
    }
}
