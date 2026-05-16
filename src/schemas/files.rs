//! Files schema: content-addressed file storage with directory trees and
//! import snapshots.
//!
//! Used by `files.rs` (the faculty CLI) and by any downstream consumer
//! that wants to read file entities, directory trees, or import snapshots
//! from a pile.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

// ── branch name ──────────────────────────────────────────────────────────
pub const FILES_BRANCH_NAME: &str = "files";

// ── kinds ────────────────────────────────────────────────────────────────
pub const KIND_FILE: Id = id_hex!("1F9C9DCA69504452F318BA11E81D47D1");
pub const KIND_DIRECTORY: Id = id_hex!("58CDFCBA4E4B91979766D50FB18777B5");
pub const KIND_IMPORT: Id = id_hex!("89655D039A90634F09207BFEB5BE65AD");

// ── attributes ───────────────────────────────────────────────────────────
pub mod file {
    use super::*;
    attributes! {
        // file leaf: content blob
        "C1E3A12230595280F22ABEB8733D082C" as content: inlineencodings::Handle<blobencodings::RawBytes>;
        // file/directory: name (filename or dirname)
        "AA6AB6F5E68F3A9D95681251C2B9DAFA" as name: inlineencodings::Handle<blobencodings::LongString>;
        // file leaf: MIME type
        "BFE2C88ECD13D56F80967C343FC072EE" as mime: inlineencodings::ShortString;
        // import: timestamp
        "3765160CC1A96BE38302B344718E4C49" as imported_at: inlineencodings::NsTAIInterval;
        // TODO: migrate to metadata::tag (GenId) — should use canonical tag
        // entities with metadata::name, not inline ShortString. See wiki.rs TagIndex.
        "CDA941A27F86A7551779CF9524DE1D0F" as tag: inlineencodings::ShortString;
        // directory: children (multi-valued, files or subdirectories)
        "0AC1D962B6E8170FDD73AE3743E16578" as children: inlineencodings::GenId;
        // import: root directory or file entity
        "7B36A7A304C26C5504EA54F5723FA135" as root: inlineencodings::GenId;
        // import: original filesystem path
        "E4B24BB9F469CEC6FD12926C56514E9F" as source_path: inlineencodings::Handle<blobencodings::LongString>;
    }
}
