//! Posture schema: candidate redaction points, and — just as importantly —
//! what was *not* examined.
//!
//! `posture` finds material in a corpus that may identify someone: metadata a
//! document carries without showing it, the author field nobody looks at, GPS
//! on a field photograph. It never decides. It surfaces candidates and a human
//! adjudicates, so the tuning is for recall.
//!
//! The unusual part of this schema is [`posture::unchecked`]. A redaction tool
//! that reports "clean" manufactures exactly the false confidence that gets a
//! source burned — and the failure is not hypothetical: a verification grep
//! reported clean on a repository that still held an entire private narrative,
//! because the narrative contained none of the searched tokens. So a scan
//! records the modalities it applied AND the modalities it did not, as facts.
//! "No OCR was run on the scanned pages" is then queryable, not a footnote
//! someone forgot to write.
//!
//! Documents that no extractor understood are recorded too, tagged
//! [`DOC_UNSUPPORTED`], so "which files did this scan never actually look
//! inside?" has an answer.
//!
//! The original domain ids were minted with `trible genid` on 2026-08-04
//! (compass ceabb6c1). Collection scopes and the immutable policy/scan ids were
//! minted with `trible genid` on 2026-08-08 while porting the faculty.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

/// Stable extrinsic scope of the canonical policy collection.
///
/// Minted with `trible genid` on 2026-08-08:
/// `D61043AF08CB40E904152AE23C939637`.
pub const DEFAULT_POLICY_SCOPE_ID: Id = id_hex!("D61043AF08CB40E904152AE23C939637");

/// Name of the pre-collection Posture branch this scope replaced.
pub const LEGACY_BRANCH_NAME: &str = "posture";

/// Stable extrinsic scope of complete scan observations.
///
/// Minted with `trible genid` on 2026-08-08:
/// `2E5F17C8DE7EB764BAE5745896157BFB`.
pub const DEFAULT_SCAN_SCOPE_ID: Id = id_hex!("2E5F17C8DE7EB764BAE5745896157BFB");

// ── entity kinds ──
pub const KIND_SCAN: Id = id_hex!("2E9956BE4BA2DAF3B0086C31663EBDB7");

/// One judgeable piece of material, located by CONTENT.
///
/// Its identity is `(modality, carrier, inner locator)` — never a commit, a
/// path or a line, because commit surgery (rebase, cherry-pick, amend, scrub)
/// gives the same material a new `commit:path:line` and so silently detached
/// every Decide resolution from the finding it had settled. Blobs are
/// content-addressed and a rebase does not touch them, so the same material
/// keeps the same id across exactly the operations that used to break it.
pub const KIND_FINDING: Id = id_hex!("434B0078816E968CD2E28714E049DECC");
pub const KIND_DOCUMENT: Id = id_hex!("CD1BF38C03DE6DCCC1E8F17E36EE28B1");

/// One observation of a finding: this scan saw that material here, carrying
/// this evidence. Annotations, not identity — a finding's id never depends on
/// which scan met it, and a lost sighting costs a re-walk, never correctness.
///
/// Minted with `trible genid` on 2026-08-18:
/// `94E23A756A38B4247A8291E482BD935A`.
pub const KIND_SIGHTING: Id = id_hex!("94E23A756A38B4247A8291E482BD935A");

/// A migration bridge: a pre-2026-08-18 `(modality, path, locator, value)`
/// occurrence id and the content-located finding it turned out to be. It only
/// exists so an already-resolved Decide outcome keeps applying across the
/// identity change; nothing new is ever written under the legacy id.
///
/// Minted with `trible genid` on 2026-08-18:
/// `B1979991B897CBFA5D76FB17565DE65A`.
pub const KIND_LEGACY_BRIDGE: Id = id_hex!("B1979991B897CBFA5D76FB17565DE65A");

// ── carriers: what content-addresses a finding's material ───────────────────
//
// The coordinate is MODALITY-DEPENDENT by construction. Source material has a
// git blob; a byte range into an OOXML zip or a PDF is meaningless, so a
// container's carrier is the member posture actually extracted, hashed by
// posture; and a commit message has no blob at all, so its carrier is the
// commit. The consequence is stated where it costs something: git can carry a
// blob finding forward across renames and edits (`blame -M -C`), and it cannot
// do that for a posture-hashed member, which relies on the extracted member's
// own bytes being stable.

/// The material is bytes of a git blob, addressed by its object id.
///
/// Minted with `trible genid` on 2026-08-18:
/// `C6BB4C2C6C4C3067316F1A1636F80B39`.
pub const CARRIER_GIT_BLOB: Id = id_hex!("C6BB4C2C6C4C3067316F1A1636F80B39");

/// The material is inside a member posture extracted from a container (an
/// OOXML part, a PDF page content stream, an EXIF/TIFF block), addressed by a
/// BLAKE3 hash posture computes over those exact extracted bytes.
///
/// Minted with `trible genid` on 2026-08-18:
/// `57EAFE825E3A0BFE7DEE22B7F3136C28`.
pub const CARRIER_CONTAINER_MEMBER: Id = id_hex!("57EAFE825E3A0BFE7DEE22B7F3136C28");

/// The material is in a commit itself — a commit message has no blob. This is
/// the one carrier commit surgery still moves, and the honest place to say so:
/// a rebased commit message is a new finding.
///
/// Minted with `trible genid` on 2026-08-18:
/// `06A6BAAF9D4DC2B6A4EACA0B7A15125D`.
pub const CARRIER_GIT_COMMIT: Id = id_hex!("06A6BAAF9D4DC2B6A4EACA0B7A15125D");

/// One complete immutable policy snapshot for a channel. Its members and
/// predecessor snapshots are part of its intrinsic identity. Concurrent
/// children remain visible as multiple DAG heads; consumers never choose one
/// by clock or iterator order.
pub const KIND_POLICY_REVISION: Id = id_hex!("716EFBC6B1E9619F713E3CC839ED00AD");

/// A path the walker deliberately or accidentally could not descend into.
pub const KIND_OMISSION: Id = id_hex!("574FD0AA24F604359C5131D15F709A93");

/// The file was opened by a matching extractor, even when it yielded no
/// findings.
pub const OUTCOME_EXAMINED: Id = id_hex!("CF8ED07E604B4D0BF2712FFAF2FE0DB5");

/// A document no extractor in this build understands. Its presence is the
/// honest form of "we walked past this file without opening it".
pub const DOC_UNSUPPORTED: Id = id_hex!("AA9A5C024090BD5E7AE1A7BFB2036D74");

/// The file matched an extractor (or could not be opened while identifying
/// one), but extraction did not complete. The error is retained in
/// [`posture::detail`].
pub const OUTCOME_PARSE_FAILED: Id = id_hex!("29F0776C30A77822789C3C246DEA1FB2");

/// Modalities — the unit of both "a finding came from here" and "this scan did
/// / did not look here". Shared deliberately: the same vocabulary that
/// classifies a finding also describes coverage, so a modality can never
/// produce findings without appearing in the coverage record.
pub mod modality {
    use super::*;

    // ── implemented ──
    /// OOXML `docProps/core.xml` — creator, lastModifiedBy, revision, dates.
    pub const OOXML_CORE_PROPS: Id = id_hex!("CBA394FA9BB7DDF8F5ADCA383C17A9EF");
    /// Word/Excel/PowerPoint comment parts.
    pub const OOXML_COMMENTS: Id = id_hex!("BE417A427AAEEEC0D271DA077A1CCBCA");
    /// Tracked insertions/deletions still present in the document body.
    pub const OOXML_TRACKED_CHANGES: Id = id_hex!("B659E3308EE19D7CF6543018F439DE8D");
    /// PowerPoint speaker notes — invisible when presenting, present in the file.
    pub const OOXML_SPEAKER_NOTES: Id = id_hex!("41A02119A01F74504434B0F483ED6A6E");
    /// Spreadsheet sheets marked hidden or veryHidden.
    pub const OOXML_HIDDEN_SHEET: Id = id_hex!("0A6088C1BF4D2B14BE4353B0DB992CF7");
    /// Image EXIF/TIFF tags — GPS, body serial, capture time, software.
    pub const EXIF: Id = id_hex!("DDE9C8786F9155CBA7E8571BFD6A8898");

    // ── not applied by `posture scan`. Present so that a scan can state their
    // absence rather than stay silent about it. Some are implemented elsewhere
    // (see below); "unchecked" is a statement about THIS scan, not about the
    // tool's capabilities, and conflating the two is how a coverage report
    // becomes a lie. ──
    /// PDF document information dictionary and XMP packet.
    pub const PDF_METADATA: Id = id_hex!("E09117C39E124F4AC0BCEE8F9B8B2433");
    /// Text still selectable underneath a drawn redaction rectangle.
    pub const PDF_REDACTION_RECT: Id = id_hex!("8E74B2ADB5FF32C0035CDA0D6CCA172C");
    /// Optical character recognition over scanned pages and images.
    pub const OCR: Id = id_hex!("53EAF70EF801BA7D19885E6BD037C341");
    /// Speech-to-text over audio and video tracks.
    pub const AUDIO_TRANSCRIPT: Id = id_hex!("66775E7BA0A9CAD07111028E5AA1CB82");
    /// A protected term found in a git commit message, path, or added line.
    pub const PROTECTED_TERM: Id = id_hex!("433BEC19196D856273D739B023A1085E");
    /// A Rust attribute declaration that pins an already-published byte id with
    /// `unsafe as`. Safe anchored `as` declarations are the default; every new
    /// literal-pinned declaration needs an occurrence-specific justification.
    ///
    /// Minted with `trible genid` on 2026-08-12:
    /// `8EC83CD4107A1BDF9F3C5245AF9C4EE6`.
    pub const UNSAFE_ATTRIBUTE_ID: Id = id_hex!("8EC83CD4107A1BDF9F3C5245AF9C4EE6");
    /// Term matching against a protected-entity vocabulary. Implemented, but by
    /// `posture git`, not by `posture scan` — so a file scan still declares it
    /// unchecked, which is accurate rather than pedantic: scanning a directory
    /// genuinely does not apply it.
    pub const LEXICAL: Id = id_hex!("1352F4EA0D388C5C5446E1EF7C674FED");
    /// Embedding proximity — the thematic case lexical cannot reach. Implemented
    /// by `posture semantic`, likewise not by `posture scan`.
    pub const SEMANTIC: Id = id_hex!("D7BFF6953021AE25A8683A0E749C3ED4");
    /// Image regions cropped in the viewer but still embedded in the file.
    pub const EMBEDDED_CROP: Id = id_hex!("E6117E71FB35A0A0D0E1CE2D695F468D");

    /// The immutable file-scan coverage universe. A file scan diffs its applied
    /// set against this to derive what it must declare unchecked.
    ///
    /// This set is part of the meaning of already-published scan records: adding
    /// a modality here would retroactively make every older coverage partition
    /// incomplete. New command-specific modalities belong in a separate set.
    pub const ALL: &[(Id, &str)] = &[
        (OOXML_CORE_PROPS, "ooxml-core-props"),
        (OOXML_COMMENTS, "ooxml-comments"),
        (OOXML_TRACKED_CHANGES, "ooxml-tracked-changes"),
        (OOXML_SPEAKER_NOTES, "ooxml-speaker-notes"),
        (OOXML_HIDDEN_SHEET, "ooxml-hidden-sheet"),
        (EXIF, "exif"),
        (PDF_METADATA, "pdf-metadata"),
        (PDF_REDACTION_RECT, "pdf-redaction-rect"),
        (OCR, "ocr"),
        (AUDIO_TRANSCRIPT, "audio-transcript"),
        (PROTECTED_TERM, "protected-term"),
        (LEXICAL, "lexical"),
        (SEMANTIC, "semantic"),
        (EMBEDDED_CROP, "embedded-crop"),
    ];

    /// Modalities emitted and checked by `posture git` but not obligations in a
    /// historical file scan's checked/unchecked coverage partition.
    pub const GIT_ONLY: &[(Id, &str)] = &[(UNSAFE_ATTRIBUTE_ID, "unsafe-attribute-id")];

    pub fn is_known(id: Id) -> bool {
        ALL.iter()
            .chain(GIT_ONLY)
            .any(|(candidate, _)| *candidate == id)
    }

    /// Human-readable name for a modality id.
    pub fn name(id: Id) -> &'static str {
        ALL.iter()
            .chain(GIT_ONLY)
            .find(|(i, _)| *i == id)
            .map(|(_, n)| *n)
            .unwrap_or("unknown")
    }
}

// ── channels and the protected vocabulary ──
//
// A CHANNEL is a destination, and it is the primitive the whole tool turns on:
// the same bytes are fine in one place and catastrophic in another. A term that
// is confidential in one repository can be the public API of the next — this was
// not theoretical, an audit run with one vocabulary produced 13 "hits" in a repo
// where every one of those words was a shipped command name.
//
// So terms are scoped to a channel, never global. The vocabulary lives in the
// operator's own pile and is itself the most sensitive artifact here: it is a
// precise index of what is being protected, which is the argument for it never
// leaving the machine.
pub const KIND_CHANNEL: Id = id_hex!("25EEC04882BAFDB8077C692EF069BE5F");
pub const KIND_TERM: Id = id_hex!("8FAB4029F0BC57F2184E8C491631CB88");

/// An EXEMPLAR is a passage of the protected material itself, stored with its
/// embedding, so the semantic tier can match content that spells none of the
/// protected terms. The 2026-07-22 leak was exactly that: an entire private
/// narrative shipped in a public repository as a semantic-search test corpus,
/// past a proper-noun grep that returned clean.
///
/// Reuses `posture::term` for the text and `posture::in_channel` for scope; the
/// vector hangs off the canonical `embeddings::attr::embedding`, in the SAME
/// shared nomic space as wiki fragments and memory chunks, rather than minting a
/// parallel one.
pub const KIND_EXEMPLAR: Id = id_hex!("B1B85A06FD70CD27B6CB598A96D9D4AB");

/// Marks an exemplar as BENIGN — ordinary material for this channel, present to
/// be subtracted rather than matched.
///
/// Without it the tier measures REGISTER, not content. Measured 2026-08-05: a
/// single abstract exemplar flagged 98 of 103 real source files, because
/// well-written doc comments explaining design rationale are abstract
/// explanatory prose and so is any passage about a system's interiority. The
/// embedding is not wrong; "thoughtful English" genuinely is the nearest common
/// feature. The score therefore has to be DISCRIMINATIVE — nearest protected
/// exemplar minus nearest benign one — so that whatever the two share cancels.
pub const EXEMPLAR_BENIGN: Id = id_hex!("D27598B7BC3B3EC28EB1507BC939130B");

/// Explicit protected role for an exemplar. Benign/protected is data, not the
/// presence or absence of a marker.
pub const EXEMPLAR_PROTECTED: Id = id_hex!("032A514DF3C7A0E947E0FA340B329248");

pub mod posture {
    use super::*;
    attributes! {
        /// Channel → its name ("github-public", "client-deliverable").
        "0CB41E9330855B39E59686D54CD091DE" unsafe as channel_name: inlineencodings::Handle<blobencodings::LongString>;
        /// Term → the string to look for. Matched case-insensitively.
        "2618BF2D4418EA1D006815517CA41927" unsafe as term: inlineencodings::Handle<blobencodings::LongString>;
        /// Term → the channel it is protected FROM.
        "6860CCB7DCCEA0BE95BC07A35DCD5CBE" unsafe as in_channel: inlineencodings::GenId;
        /// Term → why it is protected. Carried because a bare wordlist rots:
        /// nobody dares remove an entry whose reason nobody recorded.
        "0B86BA9EB3A1B6FD0C70AC7B75A24E06" unsafe as why: inlineencodings::Handle<blobencodings::LongString>;
        /// Policy revision → one exact term or exemplar member. Repeated.
        ///
        /// Minted with `trible genid` on 2026-08-08:
        /// `245EFCA76A6AAA2A17F512548C87A7E7`.
        "245EFCA76A6AAA2A17F512548C87A7E7" unsafe as policy_member: inlineencodings::GenId;
        /// Term/exemplar → its explicit policy role.
        ///
        /// Minted with `trible genid` on 2026-08-08:
        /// `50DCC5C0FB746CC15772710DEBB65B1E`.
        "50DCC5C0FB746CC15772710DEBB65B1E" unsafe as role: inlineencodings::GenId;
        /// Finding → the scan that produced it.
        "AD904325C9E0EE6A62DA4E9C731E9714" unsafe as scan: inlineencodings::GenId;
        /// Finding → the document it was found in.
        "81AD29AAC2A2E3C60207E433B5BB35D7" unsafe as document: inlineencodings::GenId;
        /// Document → its path as scanned.
        "46DCFC71243F75A716E96933671AF2AD" unsafe as path: inlineencodings::Handle<blobencodings::LongString>;
        /// Finding → the named coordinate inside its carrier, for material the
        /// carrier's bytes do not literally spell ("docProps/core.xml:creator",
        /// a path a blob is stored under). A byte-addressable finding carries
        /// [`posture::span_start`]/[`posture::span_end`] instead, and exactly
        /// one of the two forms is present.
        "8D48ED59152DEC32A8AE9E60816499B1" unsafe as locator: inlineencodings::Handle<blobencodings::LongString>;
        /// Sighting → the material itself. This is the sensitive payload, and
        /// the reason a posture pile is at least as confidential as what it
        /// scanned. Evidence, never identity: for a byte range in a
        /// content-addressed carrier the material IS the bytes, so recording it
        /// twice would only let the two disagree.
        "2DD2823925C7DDA38CE3A5ECA82CAD52" unsafe as value: inlineencodings::Handle<blobencodings::LongString>;
        /// Finding → which content-addressing scheme its carrier uses
        /// ([`CARRIER_GIT_BLOB`], [`CARRIER_CONTAINER_MEMBER`],
        /// [`CARRIER_GIT_COMMIT`]).
        ///
        /// Minted with `trible genid` on 2026-08-18:
        /// `FB9C446537BB030AE735D9A93877557C`.
        "FB9C446537BB030AE735D9A93877557C" as carrier_kind: inlineencodings::GenId;
        /// Finding → the carrier's content address, lowercase hex: a git blob
        /// or commit object id, or posture's BLAKE3 hash of an extracted
        /// container member.
        ///
        /// Minted with `trible genid` on 2026-08-18:
        /// `44D5736640286A9FE38527C1AEF0B7EA`.
        "44D5736640286A9FE38527C1AEF0B7EA" as carrier: inlineencodings::Handle<blobencodings::LongString>;
        /// Finding → first byte of the material inside its carrier, inclusive.
        ///
        /// Minted with `trible genid` on 2026-08-18:
        /// `7BB744E8FC1B7BFF92623AE81C2C6F4A`.
        "7BB744E8FC1B7BFF92623AE81C2C6F4A" as span_start: inlineencodings::U256BE;
        /// Finding → one past the last byte of the material, exclusive. The
        /// span is the material, not its containing line, which is what makes
        /// the content derivable rather than identifying.
        ///
        /// Minted with `trible genid` on 2026-08-18:
        /// `62137C6CE42357E122F52B4D2584F23F`.
        "62137C6CE42357E122F52B4D2584F23F" as span_end: inlineencodings::U256BE;
        /// Sighting → the finding it observed.
        ///
        /// Minted with `trible genid` on 2026-08-18:
        /// `9C842163D0B6B2B05CDA637C79CC0038`.
        "9C842163D0B6B2B05CDA637C79CC0038" as sighting_of: inlineencodings::GenId;
        /// Sighting → the commit the material was seen in. The rebuildable
        /// locator cache: append-only historical fact (this material appeared
        /// in that commit), so it cannot go stale, only be incomplete.
        ///
        /// Minted with `trible genid` on 2026-08-18:
        /// `B44C8144A5118C08D824DDA80B45C8AF`.
        "B44C8144A5118C08D824DDA80B45C8AF" as seen_in: inlineencodings::Handle<blobencodings::LongString>;
        /// Sighting → the human coordinate exactly as observed ("patch
        /// abc1234:src/lib.rs:12"). Display exhaust; nothing reads it back.
        ///
        /// Minted with `trible genid` on 2026-08-18:
        /// `81BAE4F185ABA41A2BC656CFD6827D31`.
        "81BAE4F185ABA41A2BC656CFD6827D31" as evidence: inlineencodings::Handle<blobencodings::LongString>;
        /// Scan → one exact sighting in its Merkle observation set. Findings
        /// enter the root through their sightings, which name them.
        ///
        /// Minted with `trible genid` on 2026-08-18:
        /// `E009BEED48735BF41AE6460E7BAF9B92`.
        "E009BEED48735BF41AE6460E7BAF9B92" as scan_sighting: inlineencodings::GenId;
        /// Scan → the root path it was pointed at.
        "8CAF5292A19C695755E3CBD9E1BD4F2E" unsafe as target: inlineencodings::Handle<blobencodings::LongString>;
        /// Scan → a modality it DID apply.
        "A4E0193BBC1935D183A7447A93CE8B08" unsafe as checked: inlineencodings::GenId;
        /// Scan → a modality it did NOT apply. The anti-"clean" attribute: a
        /// scan is only as trustworthy as the gaps it admits.
        "EAE05B8465E40ABAD9CBDA52DA83B759" unsafe as unchecked: inlineencodings::GenId;
        /// Scan → how many files it walked.
        "4489D34BE64CF6A8D2D923D4859A4399" unsafe as file_count: inlineencodings::U256BE;
        /// Document → exactly one scan outcome (`examined`, `unsupported`, or
        /// `parse-failed`).
        ///
        /// Minted with `trible genid` on 2026-08-08:
        /// `B1D289B991914D06298A45E2D3F828F6`.
        "B1D289B991914D06298A45E2D3F828F6" unsafe as outcome: inlineencodings::GenId;
        /// Historical V3 scan nonce. Native V4 writers never emit it: scan
        /// identity is derived only from the observation itself.
        ///
        /// Minted with `trible genid` on 2026-08-08:
        /// `DFBEBF94BA5910FFE67D9153BA47700E`.
        "DFBEBF94BA5910FFE67D9153BA47700E" unsafe as scan_nonce: inlineencodings::GenId;
        /// Parse failure or walk omission → exact diagnostic text.
        ///
        /// Minted with `trible genid` on 2026-08-08:
        /// `6E46C2DC054717AF129BD0D2CC730D69`.
        "6E46C2DC054717AF129BD0D2CC730D69" unsafe as detail: inlineencodings::Handle<blobencodings::LongString>;
        /// Legacy bridge → the pre-2026-08-18 occurrence id, the deterministic
        /// identity of `(modality, path, locator, value)`. Never written on a
        /// finding again: `commit:path:line` in the locator meant a rebase
        /// silently re-identified the material.
        "8241EAE5A38DBDB6F766637F4F2DE692" unsafe as occurrence: inlineencodings::GenId;
        /// Scan → destination channel used by an audit, when any.
        "71F17B3900B005D6B3720B122B347582" unsafe as scan_channel: inlineencodings::GenId;
        /// Scan → one exact document outcome in its Merkle observation set.
        /// Minted with `trible genid` on 2026-08-11.
        "26F75BC480669978650F99B11480D168" as scan_document: inlineencodings::GenId;
        /// Historical scan → one exact finding in its Merkle observation set.
        /// Superseded by [`posture::scan_sighting`]; read by the findings
        /// migration, never written.
        /// Minted with `trible genid` on 2026-08-11.
        "952559B264EA4F07812CE79D13D70166" as scan_finding: inlineencodings::GenId;
        /// Scan → one exact traversal omission in its Merkle observation set.
        /// Minted with `trible genid` on 2026-08-11.
        "4A79C0B54AF4B8AE50B9D2CEDAA05D48" as scan_omission: inlineencodings::GenId;
    }
}
