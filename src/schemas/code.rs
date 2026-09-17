//! Collection-native source-code catalogue ontology.
//!
//! An ITEM is a declaration identified by its normalized token stream and
//! nothing else, so byte-identical code in two files is ONE item with two
//! PLACEMENTs. A UNIT is one `(repo, path, content)` triple. A SCAN is one
//! observation of one repo at one commit.
//!
//! Everything a judgement produced — kind, name, doc, signature, visibility,
//! mentions — ANNOTATES a core that only the bytes and the grammar determined,
//! so a better extractor re-annotates the same entities instead of re-minting
//! the world, and the two generations union cleanly under `cat`.
//!
//! Duplication is therefore exhaust rather than a feature: a clone is an item
//! with two placements, found by a self-join, with no hash attribute and no
//! hashing pass. Re-ingesting an unchanged tree is a no-op, and two machines
//! scanning the same commit produce the same entities, because nothing
//! machine-local (absolute path, wall clock, iteration order) reaches a core.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

/// Stable extrinsic scope of the authored Code collection.
///
/// Minted with `trible genid` on 2026-09-17:
/// `EB416080F8F2C34CA05598C4FCBA3535`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("EB416080F8F2C34CA05598C4FCBA3535");

/// One `(repo, path, content)` triple: a file as it stood at some revision.
///
/// Minted with `trible genid` on 2026-09-17.
pub const KIND_UNIT: Id = id_hex!("A52225D11B70645750139A3776DD3230");

/// One declaration, identified by its normalized token stream alone.
///
/// Minted with `trible genid` on 2026-09-17.
pub const KIND_ITEM: Id = id_hex!("47F7160C12A15702D5A3DFB5227FE79C");

/// One item occurring in one unit at one byte range.
///
/// Minted with `trible genid` on 2026-09-17.
pub const KIND_PLACEMENT: Id = id_hex!("34E05E4F4155C853CD97C2D58B647CBF");

/// One observation of one repository at one commit.
///
/// Minted with `trible genid` on 2026-09-17.
pub const KIND_SCAN: Id = id_hex!("3213AAE6414EEEAAA712C17ED5CBD308");

/// The extraction law: which declaration nodes become items, how their token
/// stream is normalized, and what counts as a mention.
///
/// Published as a fragment so a reader holding the pile learns what an item's
/// tokens mean without the code that produced them. A changed law gets a NEW
/// id, so the change is visible in the pile instead of silently forking every
/// item identity.
///
/// Minted with `trible genid` on 2026-09-17.
pub const EXTRACTOR_RUST_SYN_V1: Id = id_hex!("603D7068C8F1B92D5D20AA9206ABF467");

/// Human-readable name of the extraction law above.
pub const EXTRACTOR_RUST_SYN_V1_NAME: &str = "rust-syn-v1";

/// The normalization law itself, published verbatim with the law entity.
pub const EXTRACTOR_RUST_SYN_V1_LAW: &str = "\
Rust declarations are located with syn's item visitor over a file whose leading \
`#!` shebang line (not `#![`) has been stripped. Each visited declaration \
becomes one item. Its token stream is normalized by walking the item's tokens \
depth-first, emitting each leaf token's textual spelling, emitting a group's \
delimiters as their literal open and close characters around its contents, and \
joining every emitted piece with a single ASCII space. Whitespace, formatting \
and plain `//` comments therefore do not participate in identity, while `///` \
doc comments do, because they are `#[doc = \"...\"]` tokens. A mention is any \
identifier the declaration syntactically names, including every segment of a \
path, the full `::`-joined spelling of that path, and identifiers and paths \
recovered from inside macro token streams; mentions are unresolved, so they \
witness spelling rather than binding. A file that does not parse yields a unit \
carrying a parse error and no items.";

pub mod attrs {
    use super::*;

    attributes! {
        // ── unit ──────────────────────────────────────────────────────────
        /// Repository directory name, e.g. `faculties`. A value, not an
        /// entity: a repo has no properties this catalogue models, and a
        /// repo-relative name is what makes two machines converge.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "8FBE9F0E3A11E45DBAC45692DDB44514" as repo:
            inlineencodings::Handle<blobencodings::UTF8String>;

        /// Repo-relative path, e.g. `src/widgets/wiki.rs`. Deliberately not
        /// absolute: an absolute path is machine-local and would fork the
        /// identity of every unit per checkout.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "32CDF6DB5C03778BE5EFD193B7421957" as path:
            inlineencodings::Handle<blobencodings::UTF8String>;

        /// Closed vocabulary: `rust`, `toml`, `markdown`, `shell`, `typst`,
        /// `text`. Closed, so `ShortString` cannot overflow.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "35F62EB70939951867305D9D986AE68C" as language: inlineencodings::ShortString;

        /// Human prose about this entity. On a UNIT: `//!` module docs, or the
        /// whole text for prose languages. On an ITEM: its `///` docs plus any
        /// `//` banner comment immediately above it.
        ///
        /// One relation, two entity classes — an attribute is a relation, not
        /// a struct field. This is the attribute the prose BM25 derivation
        /// selects.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "4D5F0C0A0778939732A813D4100149CC" as doc:
            inlineencodings::Handle<blobencodings::UTF8String>;

        /// Why this unit yielded no items. Its presence is not an error; it is
        /// the open-world record that we ingested what we could establish.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "CE2FACA8CFB8FABE1D3C54498D6374E3" as parse_error:
            inlineencodings::Handle<blobencodings::UTF8String>;

        /// First segment of a `use` path in this unit. Repeated. Serves the
        /// distinguishing-import evidence line and `code uses --imports`.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "22CAE18A57BDA43133B65547A6689663" as import_root:
            inlineencodings::Handle<blobencodings::UTF8String>;

        // ── item ──────────────────────────────────────────────────────────
        /// Closed vocabulary: `fn`, `struct`, `enum`, `trait`, `impl`, `mod`,
        /// `use`, `const`, `static`, `type`, `macro`, `union`, `extern`.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "A0ED33675DF3B92867FD68177794BEDD" as kind: inlineencodings::ShortString;

        /// Normalized to a closed vocabulary — `pub`, `crate`, `super`,
        /// `restricted`, `private` — because `pub(in crate::a::b::c)` would
        /// overflow `ShortString`, and overflow is a panic.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "41DAF4F9B5A081674E272996B89D818F" as visibility: inlineencodings::ShortString;

        /// Declaration head, SLICED from the source by byte range rather than
        /// re-printed through `quote`, which mangles spacing. This string is
        /// for a human to read.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "6937C17DB1414657A0578447A8F6EAE3" as signature:
            inlineencodings::Handle<blobencodings::UTF8String>;

        /// An identifier this item syntactically names. Repeated, deduped.
        /// Every path segment AND the full `::`-joined path text, including
        /// paths reconstructed from inside macro token streams.
        ///
        /// This one relation replaces the entire call-edge class. It is
        /// UNRESOLVED and POSITIONLESS, so a usage answer is exactly as
        /// trustworthy as the identifier is rare; readers are expected to say
        /// so rather than phrase a common name as a settled answer.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "9ECEFFBFC44F689A941C1214E0BF4C46" as mentions:
            inlineencodings::Handle<blobencodings::UTF8String>;

        // ── placement ─────────────────────────────────────────────────────
        /// The unit this placement is in.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "7E04326235C8A7A7EB1C3F8CB07C8A7F" as unit: inlineencodings::GenId;

        /// The item this placement places.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "AEE10E1CADC91638D3906B40C3790723" as item: inlineencodings::GenId;

        /// The enclosing PLACEMENT (impl / mod / trait), not the enclosing
        /// item: enclosure is location-specific, so two byte-identical `fn
        /// new` in two impls share an item and differ only here.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "11A6CB6787AB1BFA17B25579239670F2" as within: inlineencodings::GenId;

        // ── scan ──────────────────────────────────────────────────────────
        /// Git commit sha, or `worktree:<blake3 of the sorted
        /// (path, content-handle) list>` for an uncommitted tree.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "D2C9BF2E62C5EAFFA2299BB2B58747DA" as commit:
            inlineencodings::Handle<blobencodings::UTF8String>;

        /// A unit this scan observed. Repeated, and emitted incrementally so
        /// the scan is never accumulated in memory.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "110B07579AB1B8E3E95B7239B82AF1C0" as holds: inlineencodings::GenId;

        /// The extraction law that produced this scan's facts.
        ///
        /// Minted with `trible genid` on 2026-09-17.
        "F7DF8119B5470CF8BF692C5C5B5680B3" as extractor: inlineencodings::GenId;

        // ── re-declared, not minted ───────────────────────────────────────
        // These two byte identities are already published by
        // `triblespace-macros`, whose compile-time instrumentation records
        // `entity!`/`attributes!` invocation sites against exactly them. The
        // literal-pinning form keeps a pile holding both able to join the
        // compiler's record of a macro site with this catalogue's record of
        // the same file. The declared encodings are unchanged.
        /// Byte range of a placement inside its unit, as
        /// `(start line, start column, end line, end column)`.
        "8ED33DA54C226ADEA0FFF7863563DF5F" unsafe as source_range:
            inlineencodings::LineLocation;

        /// The normalized token stream that IS an item's identity.
        "B981AEA9437561F8DB96E7EECBB94BFD" unsafe as source_tokens:
            inlineencodings::Handle<blobencodings::UTF8String>;
    }
}

/// The languages this build can say anything about.
///
/// A file whose extension is not one of these is skipped, never rejected: an
/// unknown extension is something this reader cannot model, and refusing it
/// would put the open world's polarity backwards.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Language {
    Rust,
    Toml,
    Markdown,
    Shell,
    Typst,
    Text,
}

impl Language {
    pub fn name(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Toml => "toml",
            Self::Markdown => "markdown",
            Self::Shell => "shell",
            Self::Typst => "typst",
            Self::Text => "text",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "rust" => Some(Self::Rust),
            "toml" => Some(Self::Toml),
            "markdown" => Some(Self::Markdown),
            "shell" => Some(Self::Shell),
            "typst" => Some(Self::Typst),
            "text" => Some(Self::Text),
            _ => None,
        }
    }

    /// The language of one repo-relative path, or `None` when this build has
    /// nothing to say about it.
    pub fn of_path(path: &str) -> Option<Self> {
        let name = path.rsplit('/').next().unwrap_or(path);
        if let Some(extension) = name.rsplit_once('.').map(|(_, extension)| extension) {
            return match extension {
                "rs" => Some(Self::Rust),
                "toml" => Some(Self::Toml),
                "md" => Some(Self::Markdown),
                "sh" | "bash" | "zsh" => Some(Self::Shell),
                "typ" => Some(Self::Typst),
                "txt" => Some(Self::Text),
                _ => None,
            };
        }
        None
    }
}

/// Declaration kinds this extractor distinguishes.
///
/// A reader that meets a kind string it does not know skips that row rather
/// than failing: the vocabulary is allowed to grow without invalidating piles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ItemKind {
    Fn,
    Struct,
    Enum,
    Union,
    Trait,
    Impl,
    Mod,
    Use,
    Const,
    Static,
    Type,
    Macro,
    Extern,
}

impl ItemKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Fn => "fn",
            Self::Struct => "struct",
            Self::Enum => "enum",
            Self::Union => "union",
            Self::Trait => "trait",
            Self::Impl => "impl",
            Self::Mod => "mod",
            Self::Use => "use",
            Self::Const => "const",
            Self::Static => "static",
            Self::Type => "type",
            Self::Macro => "macro",
            Self::Extern => "extern",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "fn" => Some(Self::Fn),
            "struct" => Some(Self::Struct),
            "enum" => Some(Self::Enum),
            "union" => Some(Self::Union),
            "trait" => Some(Self::Trait),
            "impl" => Some(Self::Impl),
            "mod" => Some(Self::Mod),
            "use" => Some(Self::Use),
            "const" => Some(Self::Const),
            "static" => Some(Self::Static),
            "type" => Some(Self::Type),
            "macro" => Some(Self::Macro),
            "extern" => Some(Self::Extern),
            _ => None,
        }
    }
}

/// Visibility normalized to a closed vocabulary.
///
/// `pub(in crate::a::b::c)` is a real spelling in this corpus and would
/// overflow a 32-byte `ShortString`, which panics the encoder. The exact
/// restriction path stays recoverable from `signature`; what this attribute
/// carries is the part a query can filter on.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Visibility {
    Public,
    Crate,
    Super,
    Restricted,
    Private,
}

impl Visibility {
    pub fn name(self) -> &'static str {
        match self {
            Self::Public => "pub",
            Self::Crate => "crate",
            Self::Super => "super",
            Self::Restricted => "restricted",
            Self::Private => "private",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "pub" => Some(Self::Public),
            "crate" => Some(Self::Crate),
            "super" => Some(Self::Super),
            "restricted" => Some(Self::Restricted),
            "private" => Some(Self::Private),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_closed_vocabulary_value_fits_a_short_string() {
        // ShortString is 32 bytes and overflow panics the encoder, so a closed
        // vocabulary is only safe while it stays closed AND short.
        for name in [
            Language::Rust.name(),
            Language::Toml.name(),
            Language::Markdown.name(),
            Language::Shell.name(),
            Language::Typst.name(),
            Language::Text.name(),
        ] {
            assert!(name.len() <= 32, "{name} overflows ShortString");
        }
        for kind in [
            ItemKind::Fn,
            ItemKind::Struct,
            ItemKind::Enum,
            ItemKind::Union,
            ItemKind::Trait,
            ItemKind::Impl,
            ItemKind::Mod,
            ItemKind::Use,
            ItemKind::Const,
            ItemKind::Static,
            ItemKind::Type,
            ItemKind::Macro,
            ItemKind::Extern,
        ] {
            assert!(
                kind.name().len() <= 32,
                "{} overflows ShortString",
                kind.name()
            );
        }
        for visibility in [
            Visibility::Public,
            Visibility::Crate,
            Visibility::Super,
            Visibility::Restricted,
            Visibility::Private,
        ] {
            assert!(visibility.name().len() <= 32);
        }
    }

    #[test]
    fn a_language_name_round_trips() {
        for language in [
            Language::Rust,
            Language::Toml,
            Language::Markdown,
            Language::Shell,
            Language::Typst,
            Language::Text,
        ] {
            assert_eq!(Language::from_name(language.name()), Some(language));
        }
    }

    #[test]
    fn a_path_this_build_cannot_model_has_no_language() {
        assert_eq!(Language::of_path("src/lib.rs"), Some(Language::Rust));
        assert_eq!(Language::of_path("Cargo.toml"), Some(Language::Toml));
        assert_eq!(
            Language::of_path("book/src/pile.md"),
            Some(Language::Markdown)
        );
        assert_eq!(Language::of_path("scripts/install"), None);
        assert_eq!(Language::of_path("assets/logo.png"), None);
    }
}
