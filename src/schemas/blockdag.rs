//! Block-DAG archive schema — the canonical perception/action format.
//!
//! Every conversation importer (`.claude`, `.codex`, ChatGPT, Gemini, Copilot,
//! …) targets this one shape, replacing the seven bespoke identity schemes of
//! [`super::archive`]. Design locked with JP 2026-07-26; full rationale in
//! wiki:5B7586E438F167509FBE0D1F60E28123 and compass 9d9768c9.
//!
//! # The shape
//!
//! The atom is a **block**, not a message. A conversation is a directed acyclic
//! graph of blocks; a "turn" or "message" is a *derived view* computed by query,
//! never stored. Each block owns one or more **content-facts** (its own
//! content-addressed entities), and every content-fact is flavored by
//! **direction** (`in` = perceived by the being, `out` = produced by it). The
//! direction tag *is* the training loss mask read straight off the structure.
//!
//! # Identity is content, not provenance
//!
//! A block's id is the content-address of its identity core — `{previous?,
//! timestamp, contains-<content_fact ids>}` — so two exports of the same
//! conversation converge on the same entities instead of forking. Everything
//! else (`author`, `experiencer`, provenance, kind tag) is **non-identity** and
//! attaches monotonically without ever re-minting a block.
//!
//! This drives a strict **two-pass `entity!` discipline** in every importer —
//! never hand-roll a content-addressed id, never build a `Trible` directly:
//!
//! ```ignore
//! // pass 1 — identity core only; `_` mints the intrinsic (content-derived) id
//! let cf = entity! { _ @
//!     content_fact::modality:  content_fact::modality::text,
//!     content_fact::direction: content_fact::direction::in_,
//!     content_fact::payload:   text_handle,
//! };
//! // `.root()` yields an `Id`; `entity!{ &id @ … }` wants an `ExclusiveId`
//! // (an `Id` does not `AsRef<ExclusiveId>`), so wrap it — `force` is the
//! // check-free constructor, correct for a deterministic content-derived id.
//! let cf_id = ExclusiveId::force(cf.root().expect("single root id"));
//! change += cf;
//! // pass 2 — non-identity facts on the *same* entity id
//! change += entity! { &cf_id @ metadata::tag: content_fact::KIND };
//!
//! // block: identity core references the derived content-fact id(s)
//! let block = entity! { _ @
//!     block::timestamp: ts,
//!     block::previous:  parent_id,   // omit on a conversation's first block
//!     block::contains:  cf_id,
//! };
//! let block_id = ExclusiveId::force(block.root().expect("single root id"));
//! change += block;
//! change += entity! { &block_id @
//!     metadata::tag:      block::KIND,
//!     block::author:      participant_id,   // relations-roster entity link
//!     block::experiencer: participant_id,
//! };
//! ```
//!
//! # The resolution law
//!
//! Three references point at things not always held at import time:
//! - **tool correlator** (`toolu_…`, `call_…`) — internal & co-present: resolve
//!   to a [`content_fact::responds_to`] edge at import, then *drop the string*.
//! - **asset pointer** — external, bytes arrive later: *keep* the pointer
//!   ([`content_fact::asset_pointer`] + mime/size) as the content-fact; attach
//!   bytes via [`content_fact::resolved_to`] when they come (monotone, never
//!   touches the id).
//! - **author label** — external, participant may be rosterable later: *keep*
//!   the raw label (reuse [`super::archive::import_schema::source_author`]);
//!   attach the [`block::author`] entity link when rosterable.
//!
//! # Open taste-calls flagged for review (JP)
//! - `modality`/`direction` are **reified enum entities** (a `GenId` link to one
//!   of the minted tag ids below), not `ShortString`s — so "all `image` facts"
//!   or "everything `out`" is one edge match, and the tag is part of the
//!   content-address as an axis. (JP wanted direction queryable "as a tag on the
//!   entity".) Alternative would be a `ShortString` enum.
//! - `author`/`experiencer` are **freshly minted** here (target space = the
//!   `relations` roster) rather than reusing [`super::archive::archive::author`]
//!   (whose targets are the old `kind_author` entities), to keep the new
//!   author-space clean during the seven-importer migration.
//! - `metadata::tag` (kind) is applied in the **non-identity** pass: kind is
//!   classification, not content — identity stays "what was said".

use triblespace::macros::id_hex;
use triblespace::prelude::blobencodings::LongString;
pub use triblespace::prelude::blobencodings::RawBytes;
use triblespace::prelude::inlineencodings::{GenId, Handle, NsTAIInterval, ShortString, U256BE};
use triblespace::prelude::*;

/// Block entity: a content-addressed position in the perception/action DAG.
pub mod block {
    use super::*;

    attributes! {
        /// IDENTITY-CORE. The block(s) this one follows — the DAG edge.
        /// Repeated; absent on a conversation's first block. Two regenerations
        /// sharing one `previous` fall out as siblings for free.
        "9B8F693BE959136E90C34CF054F9033F" as pub previous: GenId;
        /// IDENTITY-CORE. Always `NsTAIInterval` (every source normalized), so
        /// equal instants are equal *values* and the engine can join/range-query
        /// on time across every conversation. Required, never optional.
        "695A45C4A57FDA7FDF8A609117878E97" as pub timestamp: NsTAIInterval;
        /// IDENTITY-CORE. A content-fact this block owns (repeated). Linking the
        /// content-derived content-fact ids is what makes the block id depend on
        /// what was said — the Merkle tree.
        "A8A1254C922182ECDF5DC50A21D74493" as pub contains: GenId;

        /// NON-IDENTITY. Who *produced* the block — a typed entity link into the
        /// `relations` roster. On `in` blocks the external participant (JP, sol);
        /// on `out` blocks the producing face (liora-cc, liora-gpt).
        "1237AC01F81B5B5036BF8E9C2F4AF9B2" as pub author: GenId;
        /// NON-IDENTITY. Whose perceive→act loop this block belongs to — which
        /// stream. Invariant (import-time consistency check, direction still
        /// always explicit): `direction = out  ⟺  author == experiencer`.
        "ECD468B693FD08FDFA37AFF91DE050AC" as pub experiencer: GenId;
    }

    /// Kind tag for block entities (applied via `metadata::tag`, non-identity).
    pub const KIND: Id = id_hex!("91B88464F7B5A178DC4FA87DE28CDFA9");
}

/// Content-fact entity: a single perceived-or-produced datum, flavored by
/// direction, nested under its block via [`block::contains`].
pub mod content_fact {
    use super::*;

    attributes! {
        /// IDENTITY-CORE. Reified modality — a link to one of [`modality`]'s tag
        /// entities (`text`/`audio`/`image`/`tool_call`/`tool_result`/`thinking`).
        "9044EA72B7B056F20CB02375ABFB7D87" as pub modality: GenId;
        /// IDENTITY-CORE. Reified direction — a link to [`direction::in_`] or
        /// [`direction::out_`]. Always present; the training loss mask.
        "3A42C2348E452E2C2E98B6C576576947" as pub direction: GenId;
        /// IDENTITY-CORE (when inline). Text payload for `text`/`thinking` and
        /// textual tool args/results. Mutually exclusive with `blob`/`asset_*`.
        "6CA37B269D7900D866824EB5560E747B" as pub payload: Handle<LongString>;
        /// IDENTITY-CORE (when held). Content-addressed media bytes. The same
        /// image seen through two exports (inline base64 vs `file_<id>.dat`)
        /// normalizes to one handle and stores once.
        "EEA16296F288D635B9BA4F603827E109" as pub blob: Handle<RawBytes>;

        /// IDENTITY-CORE (when bytes not held). The asset *reference* — "an
        /// image was here" — is itself the content-fact until bytes arrive.
        "91FB71A7D25EC34E208DA622DD680481" as pub asset_pointer: Handle<LongString>;
        /// IDENTITY-CORE (with `asset_pointer`). Claimed media type.
        "FBDE96ECC5E3CC4D8E96A59AB372C72D" as pub asset_mime: ShortString;
        /// IDENTITY-CORE (with `asset_pointer`). Claimed byte size.
        "2CF092F132FA9110BA10B1B1482831DB" as pub asset_size: U256BE;

        /// NON-IDENTITY, monotone. Bytes that arrived later for a pointer-
        /// identified fact. Recovery never changes a block id.
        "61604A1C2B6AA2A6F1D36541323B0CFE" as pub resolved_to: Handle<RawBytes>;
        /// NON-IDENTITY. `tool_result → tool_use` semantic edge, resolved from
        /// the (then discarded) vendor correlator. Distinct from `previous`: with
        /// parallel tool use the answers-that edge ≠ the follows-that edge.
        "C27311E268EE31956D2852884BDE72C3" as pub responds_to: GenId;
        /// NON-IDENTITY. Claude's `thinking.signature` attestation — provenance,
        /// not content, so it stays out of the identity core.
        "C13B0606C75DAE51EE40F3E4D48E9B78" as pub signature: Handle<LongString>;
    }

    /// Kind tag for content-fact entities (applied via `metadata::tag`).
    pub const KIND: Id = id_hex!("C29DDE04AD573274192D1AB86BA5B0A3");

    /// Reified modality tag entities. A new modality gets both directions for
    /// free — direction is a separate axis, never doubled into the vocabulary.
    pub mod modality {
        use super::*;
        pub const text: Id = id_hex!("AE8DC7E9948F3B2408F86049F1D2C548");
        pub const audio: Id = id_hex!("BD2EF853BA7CC99A10DDDA2E5C25D1A4");
        pub const image: Id = id_hex!("2EEF41445AE93BFABD02423BEDB6ECEF");
        pub const tool_call: Id = id_hex!("A4B7EC585B0906BFFC42464015E2903C");
        pub const tool_result: Id = id_hex!("09A663D69EBDEC15ED329EC5CB7AF445");
        pub const thinking: Id = id_hex!("293748A40FE28BDC888C1AF336F60D5C");
    }

    /// Reified direction tag entities. `(text "ok", in_)` and `(text "ok", out_)`
    /// are distinct content-addresses that never collide.
    pub mod direction {
        use super::*;
        /// Perceived by the being (`user`, `tool_result`, a pasted image).
        pub const in_: Id = id_hex!("1452B759336E0DEF96E78937D6E7F15D");
        /// Produced by the being (its reply, thinking, a tool call).
        pub const out_: Id = id_hex!("39990F231B5FDB6F0FF4DB55616A2939");
    }
}
