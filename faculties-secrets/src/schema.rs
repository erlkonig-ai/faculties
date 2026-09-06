//! Stable wire schema for immutable encrypted secret versions and recipient wraps.

use triblespace::core::capability::{capability_action, CapabilityHandle};
use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::*;

/// Stable faculty scope used only to select the self-describing `secrets`
/// source collection through the shared collection-name/configuration layer.
///
/// Minted with `trible genid` on 2026-09-03:
/// `0A33FEA863F9A2F460F98B8F6EE7F0A3`.
pub const DEFAULT_SCOPE_ID: Id = id_hex!("0A33FEA863F9A2F460F98B8F6EE7F0A3");

/// Semantic action of the Secrets key-delivery capability definition.
///
/// Minted with installed `/Users/jp/.cargo/bin/trible genid` on 2026-09-06:
/// `4E350A11267E4E0DA8F547610594D148`.
pub const ACTION_KEY_DELIVERY: Id = id_hex!("4E350A11267E4E0DA8F547610594D148");

/// Stable definition of permission to deliver Secrets data-encryption keys.
///
/// The canonical SimpleArchive of these facts is the capability identity.
/// Collection READ only permits replication of encrypted evidence; it does not
/// imply this capability. Changing these definition facts changes its handle.
pub fn key_delivery_definition() -> Fragment {
    entity! {
        capability_action: ACTION_KEY_DELIVERY,
        triblespace::core::metadata::name: "secrets.key-delivery".to_owned(),
        triblespace::core::metadata::description:
            "Deliver data-encryption keys for Secrets versions by sealing additive envelopes to authorized recipients. Existing envelopes remain usable by possession after authority expires.".to_owned(),
    }
}

/// Exact content handle signed into Secrets key-delivery proof edges.
pub fn key_delivery_capability() -> CapabilityHandle {
    let definition: Blob<blobencodings::SimpleArchive> =
        key_delivery_definition().facts().clone().to_blob();
    definition.get_handle()
}

// These records retain their already-published wire meaning across the
// custody-vault removal. Old vault headers and access envelopes remain inert
// facts; readers only ask for these two shapes.
pub const KIND_SECRET: Id = id_hex!("72B64C9F3644B8016B64820D7F3F23C1");
pub const KIND_WRAP: Id = id_hex!("EB8549BAF679C5D11ECEDB416AAD76E3");

attributes! {
    "7FC38805FDC9FA4D8449497B298B51BB" unsafe as pub secret_body:
        inlineencodings::Handle<blobencodings::RawBytes>;
    "D17EC6F6A9F9D6B7A3B9A329A9CFC4CC" unsafe as pub wrap_secret:
        inlineencodings::GenId;
    "B30CE37D4DC3CAACC34D946B3D71E37C" unsafe as pub wrap_dek:
        inlineencodings::Handle<blobencodings::RawBytes>;

    /// Ed25519 recipient of one sealed data-encryption key.
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
    fn key_delivery_definition_is_stable_and_distinct_from_replication() {
        let capability = key_delivery_capability();
        assert_eq!(capability, key_delivery_capability());
        assert_ne!(capability, triblespace::core::collection::read_capability());
        assert_ne!(
            capability,
            triblespace::core::collection::write_capability()
        );
    }

    #[test]
    fn retained_wire_ids_are_stable() {
        for (actual, expected) in [
            (KIND_SECRET, "72B64C9F3644B8016B64820D7F3F23C1"),
            (KIND_WRAP, "EB8549BAF679C5D11ECEDB416AAD76E3"),
            (secret_body.id(), "7FC38805FDC9FA4D8449497B298B51BB"),
            (wrap_secret.id(), "D17EC6F6A9F9D6B7A3B9A329A9CFC4CC"),
            (wrap_dek.id(), "B30CE37D4DC3CAACC34D946B3D71E37C"),
            (wrap_recipient_key.id(), "082D781A1E4C849524EFC07280B42C8A"),
        ] {
            assert_eq!(format!("{actual:X}"), expected);
        }
    }
}
