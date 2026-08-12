//! Wiki schema: fragments, content, links, file references, and tag vocabulary.
//!
//! Used by `wiki.rs` (the faculty CLI) and by viewers that render wiki
//! fragments from a pile (the GORBIE wiki viewer widget, playground
//! dashboard, etc.).

use std::collections::HashMap;
use triblespace::core::inline::encodings::time::Lower;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::Workspace;
use triblespace::macros::{find, id_hex, pattern};
use triblespace::prelude::*;

/// Text handle type for wiki content/title blobs.
pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

/// Stable scope of the authored Wiki collection.
///
/// Minted with `trible genid` on 2026-08-09 and retained from the reviewed
/// collection-cutover lineage.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("5E2E291C8CD660400D807E916EDEAF1D");

/// Exact name of the pre-collection repository branch.
pub const LEGACY_BRANCH_NAME: &str = "wiki";

/// Compatibility name for branch-era consumers which have not yet moved to
/// the native Wiki collection. It is migration input vocabulary, not live
/// collection identity.
pub const WIKI_BRANCH_NAME: &str = LEGACY_BRANCH_NAME;

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

/// Kinds for the revision DAG (minted with `trible genid` on 2026-08-09).
///
/// Native revisions are authored artifacts. Legacy versions retain their old
/// ids and facts additively; `metadata::supersedes` connects both identity
/// epochs without introducing an anchor or alias registry. An AUTHORSHIP
/// record keeps author and time independently queryable.
pub const KIND_REVISION: Id = id_hex!("F2442F00FB816AE01EC450AA5FFE806F");
pub const KIND_AUTHORSHIP: Id = id_hex!("46130A9EC858D471273BAB519C6FE01A");

pub mod attrs {
    use super::*;
    attributes! {
        // Revision DAG.
        //
        // `supersedes` is NOT minted here: the canonical `metadata::supersedes`
        // already means exactly this and is what `memory supersede` writes.
        //
        // `author` REUSES the shared relation already declared by memory,
        // archive and blockdag. It is an existing relation with rows under it,
        // so it is PINNED — it must resolve to the same id those already write,
        // and the derived form would not.
        //
        // `revision` is genuinely new with no rows under it, so it takes the
        // anchored form: the literal is a minted ANCHOR and the id derives from
        // (anchor, value_encoding). That coupling is the point — re-typing it
        // would yield a different attribute rather than silently addressing
        // rows written under the old type. Anchor minted 2026-08-09 with
        // `trible genid`.
        "FF2DD2D2E71E8CD4AC45C0667FECAF4A" as revision: inlineencodings::GenId;
        "838CC157FFDD37C6AC7CC5A472E43ADB" unsafe as author: inlineencodings::GenId;
        "EBFC56D50B748E38A14F5FC768F1B9C1" unsafe as fragment: inlineencodings::GenId;
        "6DBBE746B7DD7A4793CA098AB882F553" unsafe as content: inlineencodings::Handle<blobencodings::LongString>;
        "78BABEF1792531A2E51A372D96FE5F3E" unsafe as title: inlineencodings::Handle<blobencodings::LongString>;
        "DEAFB7E307DF72389AD95A850F24BAA5" unsafe as links_to: inlineencodings::GenId;
        // Content-hash reference: `files:<64-char-blake3>` points to file bytes directly.
        "C61CA2F2A70103FD79E97C2F88B854D8" unsafe as references_file_content: inlineencodings::Handle<blobencodings::RawBytes>;
        // File-entity reference: `files:<32-char-id>` points to a file entity with metadata.
        "C98FE0EF9151F196D8F7D816ABBBCC49" unsafe as references_file: inlineencodings::GenId;
    }
}

// ── read-side query helpers ────────────────────────────────────────────────
// Shared by the `wiki` faculty CLI and by `orient`'s wake-assembler (which
// surfaces `cover`-tagged fragments — ambient principles/beliefs — on wake).

/// Resolve a tag entity id by its `metadata::name` (case-insensitive).
pub fn find_tag_by_name(space: &TribleSet, ws: &mut Workspace<Pile>, name: &str) -> Option<Id> {
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
pub fn read_title(space: &TribleSet, ws: &mut Workspace<Pile>, vid: Id) -> Option<String> {
    let (h,) = find!((h: TextHandle), pattern!(space, [{ vid @ attrs::title: ?h }])).next()?;
    let view: View<str> = ws.get(h).ok()?;
    Some(view.as_ref().to_string())
}

/// Read the content string of a version entity.
pub fn read_content(space: &TribleSet, ws: &mut Workspace<Pile>, vid: Id) -> Option<String> {
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
pub fn cover_fragments(space: &TribleSet, ws: &mut Workspace<Pile>) -> Vec<(String, String)> {
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

// ── the revision DAG ───────────────────────────────────────────────────────
//
// A VERSION in the old model was minted from (fragment, title, content) and
// then had its timestamp and tags merged on afterwards, so re-tagging reused
// the id and tag removal could not be represented at all. A REVISION here is
// intrinsic over its whole convergent content state — title, content, tags,
// and the set of revisions it supersedes — so retagging *is* a new revision and
// subtraction never needs representing.
//
// What deliberately stays OUT of identity:
//
// * LINKS. A wiki link graph may be cyclic, so identity-bearing links would
//   require a BLAKE3 fixed point over a cyclic graph. Links are a deterministic
//   projection of content instead.
// * TIME. It is occurrence provenance and remains queryable through an
//   authorship record, while AUTHOR is part of the authored artifact itself.
// * ANCHORS. Legacy ids survive on their original entities and fragment facts;
//   no new alias or component anchor is introduced.

/// One revision: an authored artifact.
///
/// Identity is `(author, title, content, tags, supersedes)`. The AUTHOR is in
/// it deliberately — a wiki is paper publishing in the small, so two people
/// writing the same sentence have published two things and a system that
/// silently merges them is wrong about what happened. An exact retry by the
/// same author converges, which makes re-import idempotent without any token to
/// remember; different authors never collapse.
///
/// The signed COMMIT remains the publication OCCURRENCE, so genuinely repeated
/// publications stay distinguishable there without disturbing artifact
/// identity.
///
/// `author` must be CRYPTOGRAPHICALLY BOUND, never a claimed value carried in
/// content: native admission derives it from the publishing key and requires
/// agreement. Preserved legacy versions remain their original entities and do
/// not synthesize a persona id from an Ed25519 commit key.
///
/// Tags participate: they are mutable, and their ids are content-derived from
/// their normalized names, so identical state still mints an identical revision
/// in every pile and tag removal is representable.
pub fn revision_fragment(
    author: Id,
    title: &str,
    content: &str,
    tags: &[Id],
    supersedes: &[Id],
) -> Fragment {
    // The blobs travel WITH the fragment, so rewritten content cannot become a
    // handle whose bytes live somewhere the plan does not carry.
    let mut fragment = Fragment::empty();
    let title: TextHandle = fragment.put(title.to_owned());
    let content: TextHandle = fragment.put(content.to_owned());
    fragment += revision_fragment_from_handles(author, title, content, tags, supersedes);
    fragment
}

/// Canonical revision facts when the text handles are already available.
///
/// This is the admission-side inverse of [`revision_fragment`]. It deliberately
/// carries no blobs; callers validating persisted rows already have a reader.
pub fn revision_fragment_from_handles(
    author: Id,
    title: TextHandle,
    content: TextHandle,
    tags: &[Id],
    supersedes: &[Id],
) -> Fragment {
    let mut tags: Vec<Id> = tags.to_vec();
    tags.push(KIND_REVISION);
    tags.sort_unstable();
    tags.dedup();
    let mut supersedes: Vec<Id> = supersedes.to_vec();
    supersedes.sort_unstable();
    supersedes.dedup();
    entity! {
        attrs::author: author,
        attrs::title: title,
        attrs::content: content,
        metadata::tag*: tags.iter(),
        metadata::supersedes*: supersedes.iter(),
    }
}

/// Provenance for a revision, omitted entirely when unknown.
///
/// Bootstrap must pass through whatever authored time it has or pass `None`;
/// it must never synthesize `now()`, because that would make a reimport mint a
/// different record for the same historical act.
pub fn authorship_fragment(
    revision: Id,
    author: Option<Id>,
    authored_at: Option<Inline<inlineencodings::NsTAIInterval>>,
) -> Option<Fragment> {
    if author.is_none() && authored_at.is_none() {
        // A record asserting neither who nor when asserts nothing. Emitting it
        // would put an empty provenance claim on the revision and make "has
        // provenance" true where none is known.
        return None;
    }
    Some(entity! {
        attrs::revision: revision,
        attrs::author?: author,
        metadata::created_at?: authored_at,
        metadata::tag: KIND_AUTHORSHIP,
    })
}

#[cfg(test)]
mod revision_tests {
    use super::*;
    use hifitime::Epoch;
    use triblespace::macros::id_hex;

    const TAG_A: Id = id_hex!("D1000000000000000000000000000001");
    const TAG_B: Id = id_hex!("D1000000000000000000000000000002");
    const AUTHOR: Id = id_hex!("D3000000000000000000000000000001");
    const AUTHOR2: Id = id_hex!("D3000000000000000000000000000002");

    const AUTHOR_A: Id = id_hex!("A9000000000000000000000000000001");
    const AUTHOR_B: Id = id_hex!("A9000000000000000000000000000002");

    fn rev(title: &str, content: &str, tags: &[Id], supersedes: &[Id]) -> Id {
        revision_fragment(AUTHOR_A, title, content, tags, supersedes)
            .root()
            .expect("revision is intrinsic, so it always has a root")
    }

    /// Convergence: one author repeating the same authored artifact reaches
    /// the same revision identity.
    #[test]
    fn identical_state_converges() {
        assert_eq!(
            rev("T", "body", &[TAG_A], &[]),
            rev("T", "body", &[TAG_A], &[])
        );
    }

    /// Tag order and duplication are not state.
    #[test]
    fn tags_are_a_set() {
        assert_eq!(
            rev("T", "body", &[TAG_A, TAG_B], &[]),
            rev("T", "body", &[TAG_B, TAG_A, TAG_A], &[])
        );
    }

    /// THE DEFECT THIS MODEL EXISTS TO FIX. Under the old scheme a version id
    /// was minted from (fragment, title, content) with tags merged on
    /// afterwards, so adding or removing a tag reused the id and whole-history
    /// union kept the stale edge forever — tag removal was not removal. Here a
    /// different tag set is simply a different revision.
    #[test]
    fn retagging_is_a_new_revision() {
        let base = rev("T", "body", &[TAG_A], &[]);
        let added = rev("T", "body", &[TAG_A, TAG_B], &[]);
        let removed = rev("T", "body", &[], &[]);
        assert_ne!(base, added);
        assert_ne!(base, removed);
        assert_ne!(added, removed);
    }

    /// A revert restores earlier CONTENT but supersedes the state it undoes, so
    /// it is a distinct revision rather than colliding with the original.
    #[test]
    fn a_revert_does_not_collide_with_what_it_restores() {
        let v1 = rev("T", "first", &[], &[]);
        let v2 = rev("T", "second", &[], &[v1]);
        let reverted = rev("T", "first", &[], &[v2]);
        assert_ne!(
            reverted, v1,
            "same content, different history, different revision"
        );
        assert_ne!(reverted, v2);
    }

    /// Supersedes is a set inside identity. Admission separately requires each
    /// named revision to exist and rejects cycles, which is what makes the
    /// model closed where identity-bearing LINKS would not have been.
    #[test]
    fn supersedes_is_a_set_and_orders_do_not_matter() {
        let a = rev("T", "a", &[], &[]);
        let b = rev("T", "b", &[], &[]);
        assert_eq!(
            rev("T", "merged", &[], &[a, b]),
            rev("T", "merged", &[], &[b, a])
        );
    }
    /// THE AUTHORED-ARTIFACT RULE. Same prose, different author, different
    /// revision — a wiki is paper publishing in the small, so two people writing
    /// the same sentence have published two things.
    #[test]
    fn a_different_author_is_a_different_revision() {
        let a = revision_fragment(AUTHOR_A, "T", "body", &[], &[])
            .root()
            .unwrap();
        let b = revision_fragment(AUTHOR_B, "T", "body", &[], &[])
            .root()
            .unwrap();
        assert_ne!(a, b);
    }

    /// And the property that buys: an exact retry by the SAME author converges,
    /// so re-import is idempotent with no token to remember.
    #[test]
    fn the_same_author_repeating_themselves_converges() {
        let a = revision_fragment(AUTHOR_A, "T", "body", &[], &[])
            .root()
            .unwrap();
        let b = revision_fragment(AUTHOR_A, "T", "body", &[], &[])
            .root()
            .unwrap();
        assert_eq!(a, b);
    }

    /// Queryable provenance is a separate record, so observations at distinct
    /// author ids never collapse even though they refer to one revision.
    #[test]
    fn authorship_is_separate_from_state() {
        let r = rev("T", "body", &[], &[]);
        let e = Epoch::from_tai_seconds(1_000.0);
        let at = (e, e).try_to_inline().expect("TAI interval");
        let a = authorship_fragment(r, Some(AUTHOR), Some(at))
            .unwrap()
            .root()
            .unwrap();
        let b = authorship_fragment(r, Some(AUTHOR2), Some(at))
            .unwrap()
            .root()
            .unwrap();
        assert_ne!(a, b, "different authors, different records");
        assert_eq!(
            r,
            rev("T", "body", &[], &[]),
            "same one revision underneath"
        );
    }

    /// Unknown provenance is OMITTED, never synthesized — and a record with
    /// neither author nor time asserts nothing, so it is not emitted at all.
    /// Bootstrap therefore never has to invent a `now()` it would then bake in.
    #[test]
    fn empty_provenance_emits_no_record() {
        let r = rev("T", "body", &[], &[]);
        assert!(authorship_fragment(r, None, None).is_none());
        assert!(authorship_fragment(r, Some(AUTHOR), None).is_some());
    }
}

// ── links are derived, never asserted ──────────────────────────────────────

/// Wiki link targets appearing in `content`, as raw 32-hex strings, lowercased.
///
/// Content-only and ambient-independent ON PURPOSE. The older extractor
/// consulted the surrounding space and dropped any target that did not already
/// resolve, which makes the extracted edge set depend on what else happens to
/// be present — the same content yields different links in different piles, and
/// a link "repairs itself" when its target is imported later. Parsing is a
/// property of the text alone.
///
/// Because of that, materialized link edges are DERIVED data, reproducible from
/// content by a recipe, and belong in a recipe-versioned derived collection
/// rather than being asserted as facts alongside the revision.
pub fn extract_link_targets(content: &str) -> Vec<String> {
    let re = regex::Regex::new(r#"#link\("wiki:(?:[a-zA-Z_][a-zA-Z0-9_]*:)?([0-9a-fA-F]{32})"\)"#)
        .expect("static regex");
    let mut out: Vec<String> = re
        .captures_iter(content)
        .map(|c| c[1].to_lowercase())
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod link_extraction_tests {
    use super::*;

    /// Parsing depends on the text alone — an empty ambient space yields the
    /// same targets as a populated one, which is what makes link edges derived
    /// data rather than a fact about the pile's contents.
    #[test]
    fn extraction_is_ambient_independent() {
        let content = r#"see #link("wiki:0B7BAAC2A1D34E5F8091A2B3C4D5E6F7") and
                         #link("wiki:cites:AABBCCDDEEFF00112233445566778899")"#;
        let got = extract_link_targets(content);
        assert_eq!(
            got,
            vec![
                "0b7baac2a1d34e5f8091a2b3c4d5e6f7".to_string(),
                "aabbccddeeff00112233445566778899".to_string(),
            ]
        );
    }

    /// Targets that do not exist anywhere are still extracted, so a link never
    /// "repairs itself" when its target is imported later.
    #[test]
    fn unresolvable_targets_are_still_links() {
        let got = extract_link_targets(r#"#link("wiki:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")"#);
        assert_eq!(got, vec!["ffffffffffffffffffffffffffffffff".to_string()]);
    }

    #[test]
    fn repeated_targets_dedupe_and_non_links_are_ignored() {
        let content = r#"#link("wiki:0B7BAAC2A1D34E5F8091A2B3C4D5E6F7")
                         #link("wiki:0b7baac2a1d34e5f8091a2b3c4d5e6f7")
                         wiki:0B7BAAC2A1D34E5F8091A2B3C4D5E6F7 bare, and
                         #link("files:0B7BAAC2A1D34E5F8091A2B3C4D5E6F7")"#;
        assert_eq!(
            extract_link_targets(content),
            vec!["0b7baac2a1d34e5f8091a2b3c4d5e6f7".to_string()]
        );
    }
}
