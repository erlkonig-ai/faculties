//! Collection-native Mail ontology.
//!
//! Mail is an immutable evidence/intent ledger.  Accounts are stable authored
//! anchors with intrinsic full-state configuration snapshots.  Wire messages,
//! source observations, parser projections, drafts, send attempts, SMTP
//! acceptances, and read observations are all intrinsic values.  Nothing in
//! this schema is a mutable mailbox row or a latest-write-wins pointer.

use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::*;

/// Stable extrinsic scope of the authored Mail collection.
///
/// Minted with `trible genid` on 2026-08-08.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("3714E5AF0ABF7E2E283FCF17FEC74D74");

/// Exact pre-collection repository branch consumed only by the coordinated
/// stopped-world cutover.
pub const LEGACY_BRANCH_NAME: &str = "mail";

// Every native id below was minted with `trible genid` for the recovered Mail
// collection lineage on 2026-08-08; the invocation transcript is retained in
// commit history. Its attribute literals predate encoding-derived anchor
// semantics and are therefore deliberately pinned with `unsafe as`: they are
// established byte identities being preserved, not new anchors minted by this
// cutover.
pub const KIND_MAIL_ACCOUNT: Id = id_hex!("FBDCF480BD02006BE630821FECB29B57");
pub const KIND_ACCOUNT_CONFIG: Id = id_hex!("0B65E7651DAB02FC7A6FCD5DACA9BE04");
pub const KIND_WIRE_MESSAGE: Id = id_hex!("6AA70240896503A5417F6053735BD4F5");
pub const KIND_POP_OBSERVATION: Id = id_hex!("446DFC5A803419764F30260D37AF91C7");
pub const KIND_OUTGOING_OBSERVATION: Id = id_hex!("DD9127C6BB02CA7DDE916B60C0266A29");
pub const KIND_PARSED_PROJECTION: Id = id_hex!("2ACE3D2EB81A54C4E80D36A8E65DBCAD");
pub const KIND_ATTACHMENT_OCCURRENCE: Id = id_hex!("A50DCF5386D9D7198DAAE94C2C462E23");
pub const KIND_DRAFT_INTENT: Id = id_hex!("49126028CC82AA54A59E5D58537F9F9B");
pub const KIND_SEND_ATTEMPT: Id = id_hex!("ED0FE344B3CB1A7380F6EC4AA91E0A71");
pub const KIND_SMTP_ACCEPTANCE: Id = id_hex!("61A4DE85297A172BCC824586AC91469C");
/// A persona opened one resident wire value. This evidence is independent of
/// direction; inbox unread state is the inbound-only projection over it.
pub const KIND_READ_OBSERVATION: Id = id_hex!("8F4B67CB606F157FBF9AF5D63BBAC60E");
/// Immutable observation recovered from the stopped-world legacy Mail DAG.
///
/// Unlike POP and outgoing observations, an imported observation claims no
/// transport coordinates which the old ledger did not record. Its exact old
/// semantic record is carried as a canonical `SimpleArchive`, with direction
/// made explicit at the import boundary.
///
/// Minted with `trible genid` on 2026-08-09.
pub const KIND_IMPORTED_OBSERVATION: Id = id_hex!("1E41F4179D12B650F9A3EAF555073A4A");

/// Canonical parser recipe used by this implementation.  A recipe change is
/// a new derivation, never an in-place reinterpretation of old evidence.
pub const RECIPE_RFC5322_V1: Id = id_hex!("473C29D86FBAB276DCD8E7D90CA43C93");

pub mod account {
    use super::*;
    attributes! {
        "320DD00D58ADC89A41419A70C281D234" unsafe as of: inlineencodings::GenId;
        "FB3FD9CE766CB77D20A221740EC4F1E1" unsafe as address: inlineencodings::Handle<blobencodings::LongString>;
        "B30AF29D86ADCBA02EA32484F4366A53" unsafe as display_name: inlineencodings::Handle<blobencodings::LongString>;
        "B4C2DEFAAF165750556F434DA2A31B99" unsafe as pop_endpoint: inlineencodings::Handle<blobencodings::LongString>;
        "18CC5707CEBBF42AF2BC5099CC5523C1" unsafe as smtp_endpoint: inlineencodings::Handle<blobencodings::LongString>;
        "B30A3C09EDE7FD84FBC92BD62E2B27B3" unsafe as username: inlineencodings::Handle<blobencodings::LongString>;
        /// Exact immutable `schemas::secrets::KIND_SECRET` version containing
        /// the mailbox password. Mail never owns or interprets its envelope.
        "2902B62BBC51167E42689D95ED417F87" unsafe as credential: inlineencodings::GenId;
        "486EFCC641A92842DACE180388FE76DA" unsafe as enabled: inlineencodings::Boolean;
    }
}

pub mod wire {
    use super::*;
    attributes! {
        "38F9B28DAE56DB810B2F6866F94E01D8" unsafe as claimed_message_id: inlineencodings::Handle<blobencodings::LongString>;
        /// Exact raw-byte digest used only when no Message-ID was claimed.
        /// Minted with `trible genid` on 2026-08-08.
        "F6DCFD2B486D1238D202380FDA50CDA0" unsafe as raw_digest: inlineencodings::Hash<inlineencodings::Blake3>;
    }
}

pub mod observation {
    use super::*;
    attributes! {
        "206FC56B4BC02505FD27821D5A1E9118" unsafe as wire: inlineencodings::GenId;
        "0692F397EFA950488D22EDC72AB24C6F" unsafe as account: inlineencodings::GenId;
        /// Exact immutable AccountConfig used for this maildrop session.
        /// Minted with `trible genid` on 2026-08-08.
        "C17C00F2BD0C6DAE9598052A809B21A7" unsafe as config: inlineencodings::GenId;
        "9AE9A14BA205663A0B85166D6982DC23" unsafe as uidl: inlineencodings::Handle<blobencodings::LongString>;
        "C6AA568EBF7BE4D7E98A74C6472710E6" unsafe as raw: inlineencodings::Handle<blobencodings::RawBytes>;
        "BEB35E6ED9637B6FB7EC74C3F604DCBC" unsafe as attempt: inlineencodings::GenId;
    }
}

pub mod imported {
    use super::*;
    attributes! {
        /// Stable entity id used by the historical Mail ledger.
        /// Minted with `trible genid` on 2026-08-09.
        "E280BE8A22A3BEF28890040339BF672D" unsafe as legacy_entity: inlineencodings::GenId;
        /// One of `IMPORT_RECEIVED`, `IMPORT_SENT`, or `IMPORT_DRAFT`.
        /// Minted with `trible genid` on 2026-08-09.
        "2432E1E4B67338C990FB251A0159BF23" unsafe as direction: inlineencodings::GenId;
        /// Exact canonical legacy record with every historical entity id
        /// preserved. Cross-collection identity epochs are never guessed or
        /// rewritten by Mail.
        /// Minted with `trible genid` on 2026-08-09.
        "77BE3936A96ADCA41C7737454D7A5043" unsafe as payload: inlineencodings::Handle<blobencodings::SimpleArchive>;
    }
}

// Historical Mail vocabulary retained inside `imported::payload`, in the
// additive top-level source evidence, and as explicit direction values. These
// ids were minted by the original schema; native Mail never emits them.
pub const LEGACY_KIND_MESSAGE: Id = id_hex!("4426CEA53841F34E8D3C0913818F340F");
pub const LEGACY_KIND_SPAM: Id = id_hex!("809C2F66A336C6D61140ABEFFA49513C");
pub const IMPORT_DRAFT: Id = id_hex!("C6A2C78ADD94CBEC207072FD3931017D");
pub const IMPORT_RECEIVED: Id = id_hex!("A8005F5F8119C6EEACEAFD5AF75A88CF");
pub const IMPORT_SENT: Id = id_hex!("E08FE75911353992E604DA7A4507AB56");

// Legacy consumers which have not yet moved to Mail projections still use
// these published names. They are source-vocabulary aliases, not native Mail
// kinds, and can disappear with those consumers.
pub const DEFAULT_BRANCH: &str = LEGACY_BRANCH_NAME;
pub const KIND_MESSAGE: Id = LEGACY_KIND_MESSAGE;
pub const KIND_SPAM: Id = LEGACY_KIND_SPAM;
pub const KIND_DRAFT: Id = IMPORT_DRAFT;

/// Attribute vocabulary of the exact payload embedded by the legacy cutover.
/// It is deliberately not used for new top-level Mail facts.
pub mod imported_legacy {
    use super::*;
    attributes! {
        "CFAEF6367467548E6799AA8AE9E971C8" unsafe as from: inlineencodings::GenId;
        "B9865C959C0C385F430C2E4ADC266118" unsafe as to: inlineencodings::GenId;
        "EB20C324A8462E4D6DB8FDD14F435A1F" unsafe as cc: inlineencodings::GenId;
        "E4453C82084106CE5FD853AFC76F730F" unsafe as bcc: inlineencodings::GenId;
        "D7D98E74C89105452D7F0FAAD6323F9D" unsafe as subject: inlineencodings::Handle<blobencodings::LongString>;
        "145DD52BBB0EC5F467C5F5CE2DA10360" unsafe as body: inlineencodings::Handle<blobencodings::LongString>;
        "940B053EF570710BB715373A7CD2DE13" unsafe as message_id: inlineencodings::Handle<blobencodings::LongString>;
        "4020F38EAC780EAD45327874F119DF1C" unsafe as in_reply_to: inlineencodings::GenId;
        "8B037BC0D9EDCD9A2493D2615EFC707F" unsafe as reference: inlineencodings::GenId;
        "BDC561B8D6A649E9B41E065349B38592" unsafe as sent_at: inlineencodings::NsTAIInterval;
        "2C83197FC3F5008D1DF95CDE47A0280A" unsafe as raw: inlineencodings::Handle<blobencodings::RawBytes>;
        "D56BE0D02F9E7DB05B617FD467CB1788" unsafe as attachment: inlineencodings::GenId;
    }

    // The historical schema exposed this plural spelling. Keep it as a pure
    // vocabulary alias so stopped-world readers address the published id.
    pub use reference as references;
}

/// Published legacy Mail vocabulary, retained for exact source readers and
/// attribute-identity regression tests. Native Mail does not emit these facts.
pub use imported_legacy as mail;

pub mod projection {
    use super::*;
    attributes! {
        "021346C625E37449536532D1D253DC55" unsafe as source: inlineencodings::GenId;
        "B3195D91897505CE52FAA710B64F8C39" unsafe as recipe: inlineencodings::GenId;
        "693A0C65EC874D4B813D5DE471862A56" unsafe as from: inlineencodings::Handle<blobencodings::LongString>;
        "2CD915F6C5EBFF88462EDB6431CC7308" unsafe as to: inlineencodings::Handle<blobencodings::LongString>;
        "2CEDE5781A15AA63BC8A96B53BA5CCCF" unsafe as cc: inlineencodings::Handle<blobencodings::LongString>;
        "3B0EE9C4A32A12F0E5ECED7DD7A1C2C2" unsafe as bcc: inlineencodings::Handle<blobencodings::LongString>;
        "BE300BC73D43B4B2D26BF311C482C93F" unsafe as subject: inlineencodings::Handle<blobencodings::LongString>;
        "2543D4138A229F661354986DA2F603EE" unsafe as body: inlineencodings::Handle<blobencodings::LongString>;
        "A0BBB3FB11DEB55F2E4D75FD27B0A684" unsafe as claimed_date: inlineencodings::NsTAIInterval;
        "4D6E52687548D8B41C8A540DC99579A9" unsafe as in_reply_to: inlineencodings::GenId;
        "189D3AF85498E7D5ECB1C8DAA86476D9" unsafe as reference: inlineencodings::GenId;
        "0F30F104BDA30064FC2AE6921BEE21BD" unsafe as spam: inlineencodings::Boolean;
        "BC35E2A9BDD0DD9C7AF08A65F5B2EE79" unsafe as attachment: inlineencodings::GenId;
    }
}

pub mod attachment_occurrence {
    use super::*;
    attributes! {
        "0291EB8E7038F0B78AE6653D9EE15716" unsafe as source: inlineencodings::GenId;
        "746FCEAE4C870750287BB419AEAD4FEB" unsafe as recipe: inlineencodings::GenId;
        "BD2D61BECA99DDCEE76945A4A927DA9F" unsafe as ordinal: inlineencodings::U256BE;
        "E99E09A77CFBADA4C52E66CBCDDF1FFB" unsafe as file: inlineencodings::GenId;
    }
}

pub mod draft {
    use super::*;
    attributes! {
        "646194A0B50EF9F3F129E51881B31E85" unsafe as nonce: inlineencodings::GenId;
        "FDE5CB39B0E017A71D8A0A52A47E293A" unsafe as account: inlineencodings::GenId;
        "451A23145E0B80752BA13EE8482474E5" unsafe as envelope_from: inlineencodings::Handle<blobencodings::LongString>;
        "63FF1B0500E80CC4DF919A6DF1D1CD17" unsafe as to: inlineencodings::Handle<blobencodings::LongString>;
        "CD2F3A03057E48AA8B558778B56B3E41" unsafe as cc: inlineencodings::Handle<blobencodings::LongString>;
        "A4680AC9889A23DCC9A871CF25D7322A" unsafe as bcc: inlineencodings::Handle<blobencodings::LongString>;
        "60DF1AE4A259395C0CA110465FF7B500" unsafe as subject: inlineencodings::Handle<blobencodings::LongString>;
        "7920F1CD7A5F3D8ADB961EE3E9A6CA73" unsafe as body: inlineencodings::Handle<blobencodings::LongString>;
        "F596F0814D0C8538A6D798963753C929" unsafe as attachment: inlineencodings::GenId;
        "25D38A7A459E9D7B68CDBEABB0F2D3F6" unsafe as in_reply_to: inlineencodings::GenId;
        "A0FBC3F6F8FD8A92C16552DED6B3F4C1" unsafe as reference: inlineencodings::GenId;
        /// Domain separator for the deterministic Decide anchor of a draft.
        "60342B478E9F020C5B5EBF78C3055DA6" unsafe as decision_for: inlineencodings::GenId;
    }
}

pub mod attempt {
    use super::*;
    attributes! {
        "6A4F4C255747BB671B9A9DC8983E1D3B" unsafe as draft: inlineencodings::GenId;
        "EEF682655269AE1D8C184F5EC61A31DE" unsafe as config: inlineencodings::GenId;
        "BC66E92E360DAA9B6EF0389D365B3C4A" unsafe as decision: inlineencodings::GenId;
        "77C530AC217B612DC54FDD53FFC48600" unsafe as decision_head: inlineencodings::GenId;
        "A9CA78DB98FC3F75C8C273FB84A15266" unsafe as raw: inlineencodings::Handle<blobencodings::RawBytes>;
        "45F9F4DF528B5F6FA7344B6770FEF9EA" unsafe as envelope_from: inlineencodings::Handle<blobencodings::LongString>;
        "CA8CA2B31C496E5AD1D933E569F45D6E" unsafe as to: inlineencodings::Handle<blobencodings::LongString>;
        "E507E852C0170BE65F55782244310BC0" unsafe as cc: inlineencodings::Handle<blobencodings::LongString>;
        "BA6376213674C97DCFD99CCBAAEBFE70" unsafe as bcc: inlineencodings::Handle<blobencodings::LongString>;
    }
}

pub mod acceptance {
    use super::*;
    attributes! {
        "376CB5933AF5E407211DBC71D7F8906B" unsafe as attempt: inlineencodings::GenId;
        "A1F7D5AD807A405E4655E9C745975D0A" unsafe as response: inlineencodings::Handle<blobencodings::LongString>;
        "77D9DC08DF92F2B55AF9FDDADA9203FF" unsafe as response_code: inlineencodings::U256BE;
    }
}

pub mod read {
    use super::*;
    attributes! {
        /// Resident wire value that was opened (received, sent, or draft).
        "A78FDA5D5EE265E2C1C08B502CFDBBC4" unsafe as wire: inlineencodings::GenId;
        /// Relations person anchor that performed the read.
        "D9AA51E81A4116FF0C31853C7CA46A09" unsafe as reader: inlineencodings::GenId;
    }
}
