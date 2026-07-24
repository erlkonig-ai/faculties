//! Mail schema: RFC 5322-shaped email messages stored as tribles.
//!
//! Used by `mail.rs` (the faculty CLI). Decomposes incoming and
//! outgoing email into individual triblespace attributes so
//! queries are native pile patterns (joins on sender/recipient,
//! range scans on `sent_at`, BM25 search over body/subject,
//! thread walks via `in_reply_to+` and `references` graph edges).
//!
//! Mail entities use **deterministic ids derived from the
//! `Message-Id`** via `entity!`'s intrinsic derivation over the
//! single `message_id` fact (see `entity_id_for_message`) —
//! `in_reply_to` and `references` GenIds point at predicted entity ids, so a
//! thread reference resolves whether or not the referenced
//! message is in our pile yet. When that message arrives later
//! (via a separate fetch, forward, or backup pull), its entity
//! materializes at the predicted id and the link goes live with
//! no patching.
//!
//! Attachments live in the `files` faculty (`KIND_FILE`,
//! `file::content` / `file::name` / `file::mime`); the mail
//! message references them via `mail::attachment: GenId` so
//! attachment dedup (BLAKE3 over file bytes) is automatic
//! across mail and the rest of the pile.
//!
//! Spam is a kind tag (`metadata::tag: &KIND_SPAM`) rather than
//! a boolean attribute — matches the canonical kind-marker
//! convention and lets manual reclassification stay
//! append-only-safe.

use triblespace::macros::id_hex;
use triblespace::prelude::*;

pub const DEFAULT_BRANCH: &str = "mail";

/// Marks an entity as an RFC 5322-shaped mail message.
pub const KIND_MESSAGE: Id = id_hex!("4426CEA53841F34E8D3C0913818F340F");

/// Tag marker applied via `metadata::tag` to messages classified
/// as spam (typically because the inbound mail carried
/// `X-Spam-Status: Yes`). Messages tagged this way are filtered
/// out of `mail list` / `mail today` / etc. by default; pass
/// `--spam` or `--all` to surface them.
pub const KIND_SPAM: Id = id_hex!("809C2F66A336C6D61140ABEFFA49513C");

/// Tag marker for outbound messages that haven't been transmitted
/// yet. `mail draft` mints a KIND_DRAFT entity with all the
/// normal `mail::*` attributes (subject, body, to, cc, bcc); a
/// successful `mail send` adds the KIND_MESSAGE tag and the
/// send-time facts (`sent_at`, `raw`) without dropping
/// KIND_DRAFT — so the history "this used to be a draft, then
/// sent at X" is preserved.
///
/// Send is gated on a linked `decide::KIND_DECISION` (via
/// `decide::about: <draft-id>`) being resolved.
pub const KIND_DRAFT: Id = id_hex!("C6A2C78ADD94CBEC207072FD3931017D");

/// Marks a stored mail-account configuration entity. Lives on the
/// **secrets** branch (written by `secrets mail-account add`, read by
/// `mail`/`orient`). The account's server credentials + hosts/ports are
/// serialized to JSON and password-locked into `mail_account::box`
/// (argon2id-derived key + secretbox, keyed on `FACULTIES_SECRETS_PW`,
/// the same envelope the secrets identity lockbox uses). The account
/// **address** is a cleartext queryable key (`mail_account::address`) so
/// the faculties can list/select accounts without the password.
///
/// Multiple accounts coexist (one entity each, keyed by address); the
/// active one is named by a single latest-wins `KIND_MAIL_ACTIVE`
/// pointer entity (`mail_account::address` = the active address).
pub const KIND_MAIL_ACCOUNT: Id = id_hex!("BC1F0E3D5DB2DC2AD00AE42FCF3AD495");

/// Latest-wins pointer to the active mail account: a small entity whose
/// `mail_account::address` names which `KIND_MAIL_ACCOUNT` is active.
/// `secrets mail-account use <address>` mints a fresh one; the newest by
/// `metadata::created_at` wins (append-only-safe re-selection).
pub const KIND_MAIL_ACTIVE: Id = id_hex!("792EC015AB18E82DBB001A30B4CA2C0A");

/// Mail-account attributes (on the **secrets** branch).
pub mod mail_account {
    use super::*;
    attributes! {
        // The account's email address (e.g. "toby@trible.space"), in
        // cleartext — the human/select key. Also carried by the
        // KIND_MAIL_ACTIVE pointer to name the active account.
        "7F0AE7B9E5D59E9DF7EB539AD75CEE6D" as address: inlineencodings::ShortString;
        // Password-locked account body: `salt(16) ‖ nonce(24) ‖
        // secretbox(json)` where json = {pass, from_name, pop3_host,
        // pop3_port, smtp_host, smtp_port}. Same lockbox shape as the
        // secrets identity key, keyed on FACULTIES_SECRETS_PW.
        "7C878C936BCF83E1905C8FB58DEC29ED" as r#box:
            inlineencodings::Handle<blobencodings::RawBytes>;
    }
}

/// Message attributes — one per RFC 5322 header field we care
/// about, plus the original raw bytes for round-trip fidelity.
pub mod mail {
    use super::*;
    attributes! {
        // Sender (single). Points at a `relations` entry. Auto-
        // registered with `#unverified` tag on first ingest if
        // the address isn't already known.
        "CFAEF6367467548E6799AA8AE9E971C8" as from: inlineencodings::GenId;
        // TO recipients (repeated). Each points at a `relations`
        // entry; new addresses get `#unverified` on first sight.
        "B9865C959C0C385F430C2E4ADC266118" as to: inlineencodings::GenId;
        // CC recipients (repeated).
        "EB20C324A8462E4D6DB8FDD14F435A1F" as cc: inlineencodings::GenId;
        // BCC recipients (repeated). Only set on messages we
        // sent — incoming mail can't see the BCC list.
        "E4453C82084106CE5FD853AFC76F730F" as bcc: inlineencodings::GenId;
        // Subject line as a blob handle — real-world subjects
        // routinely exceed ShortString's 32-byte limit
        // ("Re: Re: Fwd: Re: [project] design review…").
        "D7D98E74C89105452D7F0FAAD6323F9D" as subject:
            inlineencodings::Handle<blobencodings::LongString>;
        // Plain-text body. For multipart messages we extract
        // the text/plain alternative; the original MIME tree
        // is preserved in `raw` for round-trip.
        "145DD52BBB0EC5F467C5F5CE2DA10360" as body:
            inlineencodings::Handle<blobencodings::LongString>;
        // RFC 5322 `Message-Id` header (the wire-format value).
        // The entity's id is derived from `blake3` of this
        // string, so this slot is the human-facing identifier
        // and the entity id is the queryable join key.
        "940B053EF570710BB715373A7CD2DE13" as message_id:
            inlineencodings::Handle<blobencodings::LongString>;
        // Direct reply parent(s) — RFC 5322 `In-Reply-To`
        // header. GenIds point at predicted mail entity ids
        // (derived from each referenced Message-Id); the
        // referenced messages may or may not be in our pile.
        "4020F38EAC780EAD45327874F119DF1C" as in_reply_to: inlineencodings::GenId;
        // Thread ancestor chain — RFC 5322 `References`
        // header. May diverge from the in_reply_to transitive
        // closure (truncated chains, multi-parent merges,
        // forwarded threads) so kept as a separate edge type.
        "8B037BC0D9EDCD9A2493D2615EFC707F" as references: inlineencodings::GenId;
        // RFC 5322 `Date` header as a TAI instant
        // (start == end, zero-length interval — "moment").
        // For incoming mail this is when the sender's client
        // claimed to send it (header value, may differ from
        // arrival time); for outgoing it's our compose time.
        "BDC561B8D6A649E9B41E065349B38592" as sent_at:
            inlineencodings::NsTAIInterval;
        // Original RFC 5322 bytes. Ground truth: every
        // decomposed attribute can be re-derived from this
        // by re-parsing if the schema evolves. Also the source
        // for re-export, re-send, or forensic inspection.
        "2C83197FC3F5008D1DF95CDE47A0280A" as raw:
            inlineencodings::Handle<blobencodings::RawBytes>;
        // Attachments (repeated). Each GenId points at a
        // `KIND_FILE` entity in the `files` branch; the bytes
        // live there content-addressed (BLAKE3-dedup'd with
        // any other file having the same contents).
        "D56BE0D02F9E7DB05B617FD467CB1788" as attachment: inlineencodings::GenId;
    }
}
