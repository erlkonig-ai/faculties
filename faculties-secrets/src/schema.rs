//! Stable wire schema for vault-epoch Secrets.

use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::*;

/// Canonical immutable header of one vault epoch.
///
/// Minted with `trible genid` on 2026-08-23:
/// `F1EB21DC9B538B2EE5A578BC2B6539E4`.
pub const KIND_VAULT: Id = id_hex!("F1EB21DC9B538B2EE5A578BC2B6539E4");

// Secret bodies and DEK wraps retain their already-published wire meaning
// across the legacy-to-vault cutover. Vault epochs change custody and authorization,
// not the identity of those immutable records. These literal pins therefore
// preserve historical bytes whose encoding is unchanged; they are not newly
// minted attributes.
pub const KIND_SECRET: Id = id_hex!("72B64C9F3644B8016B64820D7F3F23C1");
pub const KIND_WRAP: Id = id_hex!("EB8549BAF679C5D11ECEDB416AAD76E3");

attributes! {
    "7FC38805FDC9FA4D8449497B298B51BB" unsafe as pub secret_body:
        inlineencodings::Handle<blobencodings::RawBytes>;
    "D17EC6F6A9F9D6B7A3B9A329A9CFC4CC" unsafe as pub wrap_secret:
        inlineencodings::GenId;
    "B30CE37D4DC3CAACC34D946B3D71E37C" unsafe as pub wrap_dek:
        inlineencodings::Handle<blobencodings::RawBytes>;

    /// Direct Ed25519 recipient of one sealed data-encryption key.
    ///
    /// Anchor minted with `trible genid` on 2026-08-23:
    /// `B511AAEB955CD121B6C5E72B3DCEC70F`.
    "B511AAEB955CD121B6C5E72B3DCEC70F" as pub wrap_recipient_key:
        inlineencodings::ED25519PublicKey;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_ids_are_stable() {
        for (actual, expected) in [
            (KIND_VAULT, "F1EB21DC9B538B2EE5A578BC2B6539E4"),
            (KIND_SECRET, "72B64C9F3644B8016B64820D7F3F23C1"),
            (KIND_WRAP, "EB8549BAF679C5D11ECEDB416AAD76E3"),
            (secret_body.id(), "7FC38805FDC9FA4D8449497B298B51BB"),
            (wrap_secret.id(), "D17EC6F6A9F9D6B7A3B9A329A9CFC4CC"),
            (wrap_dek.id(), "B30CE37D4DC3CAACC34D946B3D71E37C"),
            (
                // The minted literal above is the anchor; its encoding is
                // part of the safe attribute identity derived from it.
                wrap_recipient_key.id(),
                "082D781A1E4C849524EFC07280B42C8A",
            ),
        ] {
            assert_eq!(format!("{actual:X}"), expected);
        }
    }
}
