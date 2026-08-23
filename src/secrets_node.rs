//! A node's pile signing key *is* its Secrets identity.
//!
//! Two things were separately true before this module existed. Every pile
//! writer has a durable Ed25519 key beside its pile — the one that signs its
//! collection commits and is its identity on the mesh. And every Secrets
//! identity is an Ed25519 keypair whose X25519 conversion seals and unseals.
//! Nothing bound them, so a node had two identities, and the binding that
//! would have joined them is exactly what never got built: rights management
//! is expressed over node identity, while the Secrets store spoke a private
//! dialect nobody could resolve against it.
//!
//! Binding them is this module. It is a small surface on purpose:
//!
//! - [`node_identity`] finds the Secrets identity a signing key is named as.
//! - [`acting_identity`] resolves an `--as` selector, defaulting to the node.
//! - [`identity_secret`] presents whatever opens that identity: the durable
//!   signing key for a node identity, the configured password for one that
//!   keeps a lockbox.
//!
//! The last one is why a password-locked identity keeps working unchanged.
//! Which key rests where is a property of the identity record, read from the
//! record — not a mode the caller selects, and not a fallback chain that could
//! silently try the wrong one.
//!
//! # Discovery is not entitlement
//!
//! [`crate::storage::discover_nodes`] lists every node that has ever written to
//! the pile, and [`faculties_secrets::prepare_node_identity`] names any of them
//! without their participation. Neither grants anything. A named node is a
//! *principal an admin may now grant to*; it is sealed to only when it is in a
//! scope's recipient set, and it reads a version only through a wrap addressed
//! to it. Nothing here consults, widens, or bypasses the grant fixpoint.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::id::Id;
use triblespace::core::repo::pile::PileReader;

use faculties_secrets::{identity_by_public_key, resolve_identity, IdentitySecret, SecretsCatalog};

use crate::storage::load_signer;

/// This node's Ed25519 public key, from its durable signing-key file.
///
/// For callers that hold only paths; anything already holding the signer
/// should ask it directly.
pub fn public_key(pile: &Path, key: Option<&Path>) -> Result<[u8; 32]> {
    Ok(load_signer(pile, key)?.verifying_key().to_bytes())
}

/// The Secrets identity a node's signing key is named as, if any.
pub fn node_identity(
    reader: &PileReader,
    catalog: &SecretsCatalog,
    signer: &SigningKey,
) -> Result<Option<Id>> {
    identity_by_public_key(reader, catalog, signer.verifying_key().as_bytes())
}

/// Resolve an identity selector, defaulting to this node's own identity.
///
/// An explicit selector still means exactly what it meant: a name or id
/// resolved against the catalog. Only its absence is new, and it resolves to
/// the one identity this node can prove it is.
pub fn acting_identity(
    reader: &PileReader,
    catalog: &SecretsCatalog,
    signer: &SigningKey,
    explicit: Option<&str>,
) -> Result<Id> {
    if let Some(selector) = explicit {
        return resolve_identity(reader, catalog, selector)
            .with_context(|| format!("resolve Secrets identity {selector:?}"));
    }
    node_identity(reader, catalog, signer)?.ok_or_else(|| {
        anyhow!(
            "this node's signing key is not a Secrets identity yet — run `secrets node adopt \
             --nickname <name>` to name it, or pass --as <identity>"
        )
    })
}

/// Whatever opens `identity`, chosen by what the identity record carries.
///
/// A record with a lockbox is opened by the configured root password; one
/// without is a node identity, opened by this node's signing key. The record
/// decides, so neither kind can be coaxed into accepting the other's material.
pub fn identity_secret(
    catalog: &SecretsCatalog,
    identity: Id,
    signer: &SigningKey,
    purpose: &str,
) -> Result<IdentitySecret> {
    let row = catalog
        .identities
        .get(&identity)
        .ok_or_else(|| anyhow!("identity {identity:x} not found"))?;
    if row.is_node_identity() {
        Ok(IdentitySecret::Node(signer.clone()))
    } else {
        Ok(IdentitySecret::Password(faculties_secrets::password::read(
            purpose,
        )?))
    }
}
