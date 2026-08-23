//! Stable schema additions for vault-epoch Secrets.

use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::*;

/// Canonical immutable header of one vault epoch.
///
/// Minted with `trible genid` on 2026-08-23:
/// `F1EB21DC9B538B2EE5A578BC2B6539E4`.
pub const KIND_VAULT: Id = id_hex!("F1EB21DC9B538B2EE5A578BC2B6539E4");

attributes! {
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
    fn minted_ids_are_stable() {
        assert_eq!(
            format!("{KIND_VAULT:X}"),
            "F1EB21DC9B538B2EE5A578BC2B6539E4"
        );
        assert_ne!(wrap_recipient_key.id(), crate::schema::wrap_recipient.id());
    }
}
