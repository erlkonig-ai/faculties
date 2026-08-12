//! Collection-native Secrets schema.
//!
//! Scopes are intrinsic in `(scope_creator, metadata::name)`. Identities,
//! grants, secret versions, and wraps are independent minted occurrences.
//! Retractions are monotone assertions on grant occurrences; repeated grants
//! therefore retain OR-set semantics under collection union.

use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::*;

/// Stable extrinsic scope of the Secrets `SimpleArchive`-union collection.
///
/// Minted with `trible genid` on 2026-08-09:
/// `EB72C4862219BE040D0F371359623D76`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("EB72C4862219BE040D0F371359623D76");

/// Exact name of the pre-collection Repository branch.
pub const LEGACY_BRANCH_NAME: &str = "secrets";

pub const KIND_IDENTITY: Id = id_hex!("0B870F06D1B502EBE1259C90234E8BA2");
pub const KIND_GRANT: Id = id_hex!("BB95E8D2D7DC644B39396A1B6C10ECC6");
pub const KIND_SECRET: Id = id_hex!("72B64C9F3644B8016B64820D7F3F23C1");
pub const KIND_WRAP: Id = id_hex!("EB8549BAF679C5D11ECEDB416AAD76E3");
pub const KIND_SCOPE: Id = id_hex!("B2920B23494B9DBD4500158D84432325");

attributes! {
    "FD0897D627CF18F4E49A93968A8D6301" unsafe as pub identity_sign_pk:
        inlineencodings::Handle<blobencodings::RawBytes>;
    "1E4279231655D8C67835865C3AFB629F" unsafe as pub identity_lockbox:
        inlineencodings::Handle<blobencodings::RawBytes>;
    "B3F0E5A5FFACC159B651BFDA19EAE18C" unsafe as pub grant_object:
        inlineencodings::GenId;
    "22F807F93FADFE092C8CE0698044680B" unsafe as pub grant_relation:
        inlineencodings::ShortString;
    "B44AF03BA7AF04ED81096D7900D70A12" unsafe as pub grant_subject:
        inlineencodings::GenId;
    "B177568BEE389D76D9D71110E9067EF1" unsafe as pub grant_issuer:
        inlineencodings::GenId;
    "73CE206E6B9B81CB2BD2388ECC5D3AA8" unsafe as pub grant_retracted_at:
        inlineencodings::NsTAIInterval;
    "A66C795299212D16BA6BA25BD1D9F983" unsafe as pub secret_scope:
        inlineencodings::GenId;
    "8FD8C43D3490ACD6AFAD6D691B748CA3" unsafe as pub secret_name:
        inlineencodings::ShortString;
    "7FC38805FDC9FA4D8449497B298B51BB" unsafe as pub secret_body:
        inlineencodings::Handle<blobencodings::RawBytes>;
    "D17EC6F6A9F9D6B7A3B9A329A9CFC4CC" unsafe as pub wrap_secret:
        inlineencodings::GenId;
    "CAD2A79E7F5B1A870F5814BDEE5C90F8" unsafe as pub wrap_recipient:
        inlineencodings::GenId;
    "B30CE37D4DC3CAACC34D946B3D71E37C" unsafe as pub wrap_dek:
        inlineencodings::Handle<blobencodings::RawBytes>;

    /// Ephemeral edge used only in an in-memory materialized path closure.
    "ABAF427C4F1CB01AA7091A9C38F0DA3A" unsafe as pub reaches:
        inlineencodings::GenId;

    /// Creator committed into a scope's intrinsic identity.
    "CE866212934742FF5B27DEF25E366E07" unsafe as pub scope_creator:
        inlineencodings::GenId;
}

// Historical reserved IDs, intentionally still documented rather than reused:
// grant_sig 74521A9057EBC9B75C957F25D504B5FA
// grant_issued_at 7411C2DDB81DC5C1B1AC85F4449B2EB9
// secret_created_at 6A0708F6F48490661F55240ED5D1C279
// identity_nickname FF6BE7814DFCA5401E48DBDF0429C3EB
// secrets_metadata B906AE45B1F40AE47C9924A18E7CE2B9

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_collection_and_attribute_ids_are_preserved() {
        assert_eq!(
            format!("{DEFAULT_SCOPE_ID:X}"),
            "EB72C4862219BE040D0F371359623D76"
        );
        assert_eq!(
            format!("{:X}", identity_sign_pk.id()),
            "FD0897D627CF18F4E49A93968A8D6301"
        );
        assert_eq!(
            format!("{:X}", identity_lockbox.id()),
            "1E4279231655D8C67835865C3AFB629F"
        );
        assert_eq!(
            format!("{:X}", grant_object.id()),
            "B3F0E5A5FFACC159B651BFDA19EAE18C"
        );
        assert_eq!(
            format!("{:X}", grant_relation.id()),
            "22F807F93FADFE092C8CE0698044680B"
        );
        assert_eq!(
            format!("{:X}", grant_subject.id()),
            "B44AF03BA7AF04ED81096D7900D70A12"
        );
        assert_eq!(
            format!("{:X}", grant_issuer.id()),
            "B177568BEE389D76D9D71110E9067EF1"
        );
        assert_eq!(
            format!("{:X}", grant_retracted_at.id()),
            "73CE206E6B9B81CB2BD2388ECC5D3AA8"
        );
        assert_eq!(
            format!("{:X}", secret_scope.id()),
            "A66C795299212D16BA6BA25BD1D9F983"
        );
        assert_eq!(
            format!("{:X}", secret_name.id()),
            "8FD8C43D3490ACD6AFAD6D691B748CA3"
        );
        assert_eq!(
            format!("{:X}", secret_body.id()),
            "7FC38805FDC9FA4D8449497B298B51BB"
        );
        assert_eq!(
            format!("{:X}", wrap_secret.id()),
            "D17EC6F6A9F9D6B7A3B9A329A9CFC4CC"
        );
        assert_eq!(
            format!("{:X}", wrap_recipient.id()),
            "CAD2A79E7F5B1A870F5814BDEE5C90F8"
        );
        assert_eq!(
            format!("{:X}", wrap_dek.id()),
            "B30CE37D4DC3CAACC34D946B3D71E37C"
        );
        assert_eq!(
            format!("{:X}", reaches.id()),
            "ABAF427C4F1CB01AA7091A9C38F0DA3A"
        );
        assert_eq!(
            format!("{:X}", scope_creator.id()),
            "CE866212934742FF5B27DEF25E366E07"
        );
    }
}
