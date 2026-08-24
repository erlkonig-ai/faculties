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

/// Singleton custody-key declaration within one vault epoch.
///
/// Minted with `trible genid` on 2026-08-24:
/// `7DD14F755D8038BBC8F32242BEBD6031`.
pub const KIND_VAULT_CUSTODY: Id = id_hex!("7DD14F755D8038BBC8F32242BEBD6031");

/// One subject-specific delivery of a vault epoch's custody seed.
///
/// The record lives in the recipient's private access-inbox collection. It is
/// candidate evidence rather than authority: every named capability proof is
/// verified afresh before the sealed seed can be used.
///
/// Minted with `trible genid` on 2026-08-24:
/// `CFBD2DA0773F23E0C27E9CE23887AB4D`.
pub const KIND_ACCESS_ENVELOPE: Id = id_hex!("CFBD2DA0773F23E0C27E9CE23887AB4D");

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

    /// Ed25519 public half of one vault epoch's random custody keypair.
    ///
    /// Anchor minted with `trible genid` on 2026-08-24:
    /// `DA8C5893DEA1F00964C07F38B2B34D86`.
    "DA8C5893DEA1F00964C07F38B2B34D86" as pub custody_public_key:
        inlineencodings::ED25519PublicKey;

    /// Exact vault descriptor governed by an access envelope.
    ///
    /// Anchor minted with `trible genid` on 2026-08-24:
    /// `2C36A12555B4DFB50D4755F4E3029706`.
    "2C36A12555B4DFB50D4755F4E3029706" as pub access_vault:
        inlineencodings::Handle<blobencodings::SimpleArchive>;

    /// Exact leaf-signature credential proving `READ` for the inbox subject.
    ///
    /// Anchor minted with `trible genid` on 2026-08-24:
    /// `3CD584E94EF8A3D3B87CB6137BF9EDEF`.
    "3CD584E94EF8A3D3B87CB6137BF9EDEF" as pub access_read_credential:
        inlineencodings::Handle<blobencodings::SimpleArchive>;

    /// Exact leaf-signature credential admitting one vault commit signer.
    ///
    /// Anchor minted with `trible genid` on 2026-08-24:
    /// `3747F21F780651553D4D46B827E6A7E0`.
    "3747F21F780651553D4D46B827E6A7E0" as pub access_write_credential:
        inlineencodings::Handle<blobencodings::SimpleArchive>;

    /// Subject-sealed, context-bound custody seed.
    ///
    /// Anchor minted with `trible genid` on 2026-08-24:
    /// `693B927F0A8EFC1389B5E5DF6A9ED790`.
    "693B927F0A8EFC1389B5E5DF6A9ED790" as pub access_sealed_seed:
        inlineencodings::Handle<blobencodings::RawBytes>;
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
            (KIND_VAULT_CUSTODY, "7DD14F755D8038BBC8F32242BEBD6031"),
            (KIND_ACCESS_ENVELOPE, "CFBD2DA0773F23E0C27E9CE23887AB4D"),
            (secret_body.id(), "7FC38805FDC9FA4D8449497B298B51BB"),
            (wrap_secret.id(), "D17EC6F6A9F9D6B7A3B9A329A9CFC4CC"),
            (wrap_dek.id(), "B30CE37D4DC3CAACC34D946B3D71E37C"),
            (
                // The minted literal above is the anchor; its encoding is
                // part of the safe attribute identity derived from it.
                wrap_recipient_key.id(),
                "082D781A1E4C849524EFC07280B42C8A",
            ),
            (custody_public_key.id(), "176DF52B59F579E74CBD960B5EFDC2A7"),
            (access_vault.id(), "106941F1D8DC9C744373F22ED6E74675"),
            (
                access_read_credential.id(),
                "F99B956013F819583DEE21894E786EF6",
            ),
            (
                access_write_credential.id(),
                "DB5C707B5D3F67A12F5053955B62F6BB",
            ),
            (access_sealed_seed.id(), "9ABBB200A36063069AA2A29424A4575E"),
        ] {
            assert_eq!(format!("{actual:X}"), expected);
        }
    }
}
