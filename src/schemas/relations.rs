//! Relations schema: people and their labels, aliases, contact info.
//!
//! Used by `relations.rs` (the faculty CLI) and by any faculty that
//! needs to resolve a person by label or alias (e.g. `message.rs`).

use triblespace::macros::id_hex;
use triblespace::prelude::*;

pub const DEFAULT_BRANCH: &str = "relations";

pub const KIND_PERSON_ID: Id = id_hex!("D8ADDE47121F4E7868017463EC860726");

pub mod relations {
    use super::*;
    attributes! {
        "8F162B593D390E1424394DBF6883A72C" as alias: inlineencodings::ShortString;
        "299E28A10114DC8C3B1661CD90CB8DF6" as label_norm: inlineencodings::ShortString;
        "3E8812F6D22B2C93E2BCF0CE3C8C1979" as alias_norm: inlineencodings::ShortString;
        "32B22FBA3EC2ADC3FFEB48483FE8961F" as affinity: inlineencodings::ShortString;
        "F0AD0BBFAC4C4C899637573DC965622E" as first_name: inlineencodings::Handle<blobencodings::LongString>;
        "764DD765142B3F4725B614BD3B9118EC" as last_name: inlineencodings::Handle<blobencodings::LongString>;
        "DC0916CB5F640984EFE359A33105CA9A" as display_name: inlineencodings::Handle<blobencodings::LongString>;
        "9B3329149D54CB9A8E8075E4AA862649" as teams_user_id: inlineencodings::ShortString;
        "B563A063474CBE62ED25A8D0E9A1853C" as email: inlineencodings::ShortString;
        "9C2B10C740FCF7064A46F9B43D1FE278" as phone: inlineencodings::ShortString;
        // Generic contact facts (enrich every person, any source — booth leads,
        // mail senders, LinkedIn connections). LinkedIn-specific data stays in
        // the linkedin faculty; these are first-class here.
        "E3D486BD7C9C088D908DF1B9E1F4D925" as company: inlineencodings::Handle<blobencodings::LongString>;
        "173B771D35FEE90B83F2731DD3C59EF8" as position: inlineencodings::Handle<blobencodings::LongString>;
        "5A71C103E026FC1AC01E35EDAC274A5C" as profile_url: inlineencodings::Handle<blobencodings::LongString>;
        // Provenance: where this person came from ("linkedin" | "mail" | "summit" | …).
        "686FD344CD64C3F9C981C4028B1B6B9E" as source: inlineencodings::ShortString;
        // Identity resolution (non-destructive). Append-only stores can't
        // merge entities irreversibly, so a person's true identity is the
        // connected component under `same_as`. Imports auto-assert `same_as`
        // only on deterministic keys (matching email / profile_url); a
        // name-only collision is recorded as a `review_candidate` edge for an
        // agent to adjudicate with common-sense reasoning, recording the
        // verdict as `same_as` or `distinct_from` (both correctable via
        // supersede). All three point person → person.
        "0FCF3A17B2EBE7243BDDD791B901E2D6" as same_as: inlineencodings::GenId;
        "A89DC2F250432322D429D0E51316B6F3" as distinct_from: inlineencodings::GenId;
        "EB09A042DE6AA778D05C1EF795C434EE" as review_candidate: inlineencodings::GenId;
    }
}
