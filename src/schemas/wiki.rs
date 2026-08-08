//! Wiki schema: fragments, content, links, file references, and tag vocabulary.
//!
//! Used by `wiki.rs` (the faculty CLI) and by viewers that render wiki
//! fragments from a pile (the GORBIE wiki viewer widget, playground
//! dashboard, etc.).

use std::collections::HashMap;
use triblespace::core::inline::encodings::time::Lower;
use triblespace::core::metadata;
use triblespace::core::repo::BlobStoreGet;
use triblespace::macros::{find, id_hex, pattern};
use triblespace::prelude::*;

/// Text handle type for wiki content/title blobs.
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

pub const WIKI_BRANCH_NAME: &str = "wiki";

pub const KIND_VERSION_ID: Id = id_hex!("1AA0310347EDFED7874E8BFECC6438CF");

pub const TAG_ARCHIVED_ID: Id = id_hex!("480CB6A663C709478A26A8B49F366C3F");

pub const TAG_SPECS: [(Id, &str); 9] = [
    (KIND_VERSION_ID, "version"),
    (id_hex!("1A7FB717FBFCA81CA3AA7D3D186ACC8F"), "hypothesis"),
    (id_hex!("72CE6B03E39A8AAC37BC0C4015ED54E2"), "critique"),
    (id_hex!("243AE22C5E020F61EBBC8C0481BF05A4"), "finding"),
    (id_hex!("8871C1709EBFCDD2588369003D3964DE"), "paper"),
    (id_hex!("7D58EBA4E1E4A1EF868C3C4A58AEC22E"), "source"),
    (id_hex!("C86BCF906D270403A0A2083BB95B3552"), "concept"),
    (id_hex!("F8172CC4E495817AB52D2920199EF4BD"), "experiment"),
    (TAG_ARCHIVED_ID, "archived"),
];

pub mod attrs {
    use super::*;
    attributes! {
        "EBFC56D50B748E38A14F5FC768F1B9C1" as fragment: inlineencodings::GenId;
        "6DBBE746B7DD7A4793CA098AB882F553" as content: inlineencodings::Handle<blobencodings::LongString>;
        "78BABEF1792531A2E51A372D96FE5F3E" as title: inlineencodings::Handle<blobencodings::LongString>;
        "DEAFB7E307DF72389AD95A850F24BAA5" as links_to: inlineencodings::GenId;
        // Content-hash reference: `files:<64-char-blake3>` points to file bytes directly.
        "C61CA2F2A70103FD79E97C2F88B854D8" as references_file_content: inlineencodings::Handle<blobencodings::RawBytes>;
        // File-entity reference: `files:<32-char-id>` points to a file entity with metadata.
        "C98FE0EF9151F196D8F7D816ABBBCC49" as references_file: inlineencodings::GenId;
    }
}

// ── read-side query helpers ────────────────────────────────────────────────
// Shared by the `wiki` faculty CLI and by `orient`'s wake-assembler (which
// surfaces `cover`-tagged fragments — ambient principles/beliefs — on wake).

/// Resolve a tag entity id by its `metadata::name` (case-insensitive).
pub fn find_tag_by_name<B: BlobStoreGet>(space: &TribleSet, ws: &B, name: &str) -> Option<Id> {
    for (id, handle) in find!(
        (id: Id, h: TextHandle),
        pattern!(space, [{ ?id @ metadata::name: ?h }])
    ) {
        if let Ok(view) = ws.get::<View<str>, _>(handle) {
            if view.as_ref().eq_ignore_ascii_case(name) {
                return Some(id);
            }
        }
    }
    None
}

/// Tags on a version entity, excluding the `KIND_VERSION` marker itself.
pub fn tags_of(space: &TribleSet, vid: Id) -> Vec<Id> {
    find!(tag: Id, pattern!(space, [{ vid @ metadata::tag: ?tag }]))
        .filter(|t| *t != KIND_VERSION_ID)
        .collect()
}

/// Read the title string of a version entity.
pub fn read_title<B: BlobStoreGet>(space: &TribleSet, ws: &B, vid: Id) -> Option<String> {
    let (h,) = find!((h: TextHandle), pattern!(space, [{ vid @ attrs::title: ?h }])).next()?;
    let view: View<str> = ws.get(h).ok()?;
    Some(view.as_ref().to_string())
}

/// Read the content string of a version entity.
pub fn read_content<B: BlobStoreGet>(space: &TribleSet, ws: &B, vid: Id) -> Option<String> {
    let (h,) = find!((h: TextHandle), pattern!(space, [{ vid @ attrs::content: ?h }])).next()?;
    let view: View<str> = ws.get(h).ok()?;
    Some(view.as_ref().to_string())
}

/// Latest-version-per-fragment as `{fragment -> (version, created_at)}`.
pub fn latest_versions(space: &TribleSet) -> HashMap<Id, (Id, Lower)> {
    let mut latest: HashMap<Id, (Id, Lower)> = HashMap::new();
    for (vid, frag, ts) in find!(
        (vid: Id, frag: Id, ts: Lower),
        pattern!(space, [{
            ?vid @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: ?frag,
            metadata::created_at: ?ts,
        }])
    ) {
        latest
            .entry(frag)
            .and_modify(|e| {
                if ts > e.1 {
                    *e = (vid, ts);
                }
            })
            .or_insert((vid, ts));
    }
    latest
}

/// Every fragment whose *latest* version carries the `cover` tag, as
/// `(title, content)` pairs sorted by title — the ambient set the wake ritual
/// surfaces. Empty if there is no `cover` tag in the pile yet.
pub fn cover_fragments<B: BlobStoreGet>(space: &TribleSet, ws: &B) -> Vec<(String, String)> {
    let cover_tag = match find_tag_by_name(space, ws, "cover") {
        Some(id) => id,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (_frag, (vid, _ts)) in latest_versions(space) {
        if !tags_of(space, vid).contains(&cover_tag) {
            continue;
        }
        let title = read_title(space, ws, vid).unwrap_or_default();
        if let Some(content) = read_content(space, ws, vid) {
            out.push((title, content));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}
