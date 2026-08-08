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

// Every id in this file was minted with `trible genid` on 2026-08-08.  The
// complete invocation transcript is retained in commit history.
pub const KIND_MAIL_ACCOUNT: Id = id_hex!("FBDCF480BD02006BE630821FECB29B57");
pub const KIND_ACCOUNT_CONFIG: Id = id_hex!("0B65E7651DAB02FC7A6FCD5DACA9BE04");
pub const KIND_CREDENTIAL: Id = id_hex!("664764DBD9710091D6D357F69387B247");
pub const KIND_CREDENTIAL_ENVELOPE: Id = id_hex!("BEC76FD5BAB2F4BEBB2F4C3F81559BA8");
pub const KIND_WIRE_MESSAGE: Id = id_hex!("6AA70240896503A5417F6053735BD4F5");
pub const KIND_POP_OBSERVATION: Id = id_hex!("446DFC5A803419764F30260D37AF91C7");
pub const KIND_OUTGOING_OBSERVATION: Id = id_hex!("DD9127C6BB02CA7DDE916B60C0266A29");
pub const KIND_PARSED_PROJECTION: Id = id_hex!("2ACE3D2EB81A54C4E80D36A8E65DBCAD");
pub const KIND_ATTACHMENT_OCCURRENCE: Id = id_hex!("A50DCF5386D9D7198DAAE94C2C462E23");
pub const KIND_DRAFT_INTENT: Id = id_hex!("49126028CC82AA54A59E5D58537F9F9B");
pub const KIND_SEND_ATTEMPT: Id = id_hex!("ED0FE344B3CB1A7380F6EC4AA91E0A71");
pub const KIND_SMTP_ACCEPTANCE: Id = id_hex!("61A4DE85297A172BCC824586AC91469C");
pub const KIND_READ_OBSERVATION: Id = id_hex!("8F4B67CB606F157FBF9AF5D63BBAC60E");

/// Canonical parser recipe used by this implementation.  A recipe change is
/// a new derivation, never an in-place reinterpretation of old evidence.
pub const RECIPE_RFC5322_V1: Id = id_hex!("473C29D86FBAB276DCD8E7D90CA43C93");

pub mod account {
    use super::*;
    attributes! {
        "320DD00D58ADC89A41419A70C281D234" as of: inlineencodings::GenId;
        "FB3FD9CE766CB77D20A221740EC4F1E1" as address: inlineencodings::Handle<blobencodings::LongString>;
        "B30AF29D86ADCBA02EA32484F4366A53" as display_name: inlineencodings::Handle<blobencodings::LongString>;
        "B4C2DEFAAF165750556F434DA2A31B99" as pop_endpoint: inlineencodings::Handle<blobencodings::LongString>;
        "18CC5707CEBBF42AF2BC5099CC5523C1" as smtp_endpoint: inlineencodings::Handle<blobencodings::LongString>;
        "B30A3C09EDE7FD84FBC92BD62E2B27B3" as username: inlineencodings::Handle<blobencodings::LongString>;
        /// Stable random authored credential anchor. Randomized ciphertext
        /// lives on separate envelope values and therefore cannot perturb the
        /// logical full-state configuration id or disclose a password oracle.
        "2902B62BBC51167E42689D95ED417F87" as credential: inlineencodings::GenId;
        "486EFCC641A92842DACE180388FE76DA" as enabled: inlineencodings::Boolean;
    }
}

pub mod credential {
    use super::*;
    attributes! {
        "D1E8252E18C74402C747A06754C1CCA6" as of: inlineencodings::GenId;
        "9F759CF82998DD88CCB15D586528AEA3" as r#box: inlineencodings::Handle<blobencodings::RawBytes>;
    }
}

pub mod wire {
    use super::*;
    attributes! {
        "38F9B28DAE56DB810B2F6866F94E01D8" as message_id: inlineencodings::Handle<blobencodings::LongString>;
    }
}

pub mod observation {
    use super::*;
    attributes! {
        "206FC56B4BC02505FD27821D5A1E9118" as wire: inlineencodings::GenId;
        "0692F397EFA950488D22EDC72AB24C6F" as account: inlineencodings::GenId;
        "9AE9A14BA205663A0B85166D6982DC23" as uidl: inlineencodings::Handle<blobencodings::LongString>;
        "C6AA568EBF7BE4D7E98A74C6472710E6" as raw: inlineencodings::Handle<blobencodings::RawBytes>;
        "BEB35E6ED9637B6FB7EC74C3F604DCBC" as attempt: inlineencodings::GenId;
    }
}

pub mod projection {
    use super::*;
    attributes! {
        "021346C625E37449536532D1D253DC55" as source: inlineencodings::GenId;
        "B3195D91897505CE52FAA710B64F8C39" as recipe: inlineencodings::GenId;
        "693A0C65EC874D4B813D5DE471862A56" as from: inlineencodings::Handle<blobencodings::LongString>;
        "2CD915F6C5EBFF88462EDB6431CC7308" as to: inlineencodings::Handle<blobencodings::LongString>;
        "2CEDE5781A15AA63BC8A96B53BA5CCCF" as cc: inlineencodings::Handle<blobencodings::LongString>;
        "3B0EE9C4A32A12F0E5ECED7DD7A1C2C2" as bcc: inlineencodings::Handle<blobencodings::LongString>;
        "BE300BC73D43B4B2D26BF311C482C93F" as subject: inlineencodings::Handle<blobencodings::LongString>;
        "2543D4138A229F661354986DA2F603EE" as body: inlineencodings::Handle<blobencodings::LongString>;
        "A0BBB3FB11DEB55F2E4D75FD27B0A684" as claimed_date: inlineencodings::NsTAIInterval;
        "4D6E52687548D8B41C8A540DC99579A9" as in_reply_to: inlineencodings::GenId;
        "189D3AF85498E7D5ECB1C8DAA86476D9" as reference: inlineencodings::GenId;
        "0F30F104BDA30064FC2AE6921BEE21BD" as spam: inlineencodings::Boolean;
        "BC35E2A9BDD0DD9C7AF08A65F5B2EE79" as attachment: inlineencodings::GenId;
    }
}

pub mod attachment_occurrence {
    use super::*;
    attributes! {
        "0291EB8E7038F0B78AE6653D9EE15716" as source: inlineencodings::GenId;
        "746FCEAE4C870750287BB419AEAD4FEB" as recipe: inlineencodings::GenId;
        "BD2D61BECA99DDCEE76945A4A927DA9F" as ordinal: inlineencodings::U256BE;
        "E99E09A77CFBADA4C52E66CBCDDF1FFB" as file: inlineencodings::GenId;
    }
}

pub mod draft {
    use super::*;
    attributes! {
        "646194A0B50EF9F3F129E51881B31E85" as nonce: inlineencodings::GenId;
        "FDE5CB39B0E017A71D8A0A52A47E293A" as account: inlineencodings::GenId;
        "451A23145E0B80752BA13EE8482474E5" as envelope_from: inlineencodings::Handle<blobencodings::LongString>;
        "63FF1B0500E80CC4DF919A6DF1D1CD17" as to: inlineencodings::Handle<blobencodings::LongString>;
        "CD2F3A03057E48AA8B558778B56B3E41" as cc: inlineencodings::Handle<blobencodings::LongString>;
        "A4680AC9889A23DCC9A871CF25D7322A" as bcc: inlineencodings::Handle<blobencodings::LongString>;
        "60DF1AE4A259395C0CA110465FF7B500" as subject: inlineencodings::Handle<blobencodings::LongString>;
        "7920F1CD7A5F3D8ADB961EE3E9A6CA73" as body: inlineencodings::Handle<blobencodings::LongString>;
        "F596F0814D0C8538A6D798963753C929" as attachment: inlineencodings::GenId;
        "25D38A7A459E9D7B68CDBEABB0F2D3F6" as in_reply_to: inlineencodings::GenId;
        "A0FBC3F6F8FD8A92C16552DED6B3F4C1" as reference: inlineencodings::GenId;
        /// Domain separator for the deterministic Decide anchor of a draft.
        "60342B478E9F020C5B5EBF78C3055DA6" as decision_for: inlineencodings::GenId;
    }
}

pub mod attempt {
    use super::*;
    attributes! {
        "6A4F4C255747BB671B9A9DC8983E1D3B" as draft: inlineencodings::GenId;
        "EEF682655269AE1D8C184F5EC61A31DE" as config: inlineencodings::GenId;
        "BC66E92E360DAA9B6EF0389D365B3C4A" as decision: inlineencodings::GenId;
        "77C530AC217B612DC54FDD53FFC48600" as decision_head: inlineencodings::GenId;
        "A9CA78DB98FC3F75C8C273FB84A15266" as raw: inlineencodings::Handle<blobencodings::RawBytes>;
        "45F9F4DF528B5F6FA7344B6770FEF9EA" as envelope_from: inlineencodings::Handle<blobencodings::LongString>;
        "CA8CA2B31C496E5AD1D933E569F45D6E" as to: inlineencodings::Handle<blobencodings::LongString>;
        "E507E852C0170BE65F55782244310BC0" as cc: inlineencodings::Handle<blobencodings::LongString>;
        "BA6376213674C97DCFD99CCBAAEBFE70" as bcc: inlineencodings::Handle<blobencodings::LongString>;
    }
}

pub mod acceptance {
    use super::*;
    attributes! {
        "376CB5933AF5E407211DBC71D7F8906B" as attempt: inlineencodings::GenId;
        "A1F7D5AD807A405E4655E9C745975D0A" as response: inlineencodings::Handle<blobencodings::LongString>;
        "77D9DC08DF92F2B55AF9FDDADA9203FF" as response_code: inlineencodings::U256BE;
    }
}

pub mod read {
    use super::*;
    attributes! {
        "A78FDA5D5EE265E2C1C08B502CFDBBC4" as wire: inlineencodings::GenId;
        "D9AA51E81A4116FF0C31853C7CA46A09" as reader: inlineencodings::GenId;
    }
}
