//! Name this node's durable pile key as its Secrets identity.
//!
//! A pile writer has always had one Ed25519 key beside its pile: it signs the
//! collection commits and is the node's identity on the mesh. The Secrets
//! store, separately, minted a second Ed25519 key per identity and locked its
//! private half behind a password. Two identities per node, and nothing that
//! binds them — which is why rights management, expressed over node identity,
//! never reached the secret store at all.
//!
//! There was never a cryptographic reason for two. Sealing already converts an
//! identity's *Ed25519* key to X25519, so one keypair does both jobs; the only
//! difference was where the private half rested. This migration binds the two
//! together for one pile, by publishing an identity record for the key that
//! pile's own commits already carry.
//!
//! It is **additive**, and narrowly so. It appends one identity record made of
//! public material. It does not touch the existing password-locked identity,
//! which keeps working exactly as it did; it does not rewrite a wrap; and — the
//! important restraint — **it grants nothing**. Naming a key makes it a
//! principal an admin may seal to. Making it a recipient is a separate,
//! authorized act by an effective admin, and re-sealing an existing version to
//! it needs a DEK that only a current holder can recover. Neither is something
//! a migration can perform, or should: it would be forging a grant from an
//! admin it does not act as. So the plan *reports* what remains and names the
//! two commands that own it, the way `teams_credentials` reports rather than
//! seals.
//!
//! Run it on a clone first. An APFS clone of a 12 GB pile costs about twenty
//! milliseconds.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use hifitime::Epoch;

use faculties::legacy_hint::open_scope;
use faculties::secrets::schema::DEFAULT_SCOPE_ID;
use faculties::secrets::{
    self as secrets_model, entity_name, identity_by_public_key, prepare_node_identity,
    validate_candidate, IntervalValue, SecretsCatalog,
};
use faculties::storage::{discover_nodes, load_signer, open_pile_strict};
use triblespace::core::id::Id;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileReader};
use triblespace::core::repo::BlobStore;
use triblespace::core::trible::TribleSet;
use triblespace::macros::entity;
use triblespace::prelude::*;

/// One node the pile attests, and the Secrets identity it is named as.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeRow {
    /// Key that signed this node's commits.
    pub public_key: [u8; 32],
    /// Commits in this pile whose signature it verifies.
    pub commits: usize,
    /// Secrets identity bound to that key, if it has been named.
    pub identity: Option<Id>,
    /// That identity's nickname.
    pub name: Option<String>,
    /// Whether this is the key of the pile being migrated.
    pub is_local: bool,
}

/// What still stands between the node identity and one scope's secrets.
///
/// Both fields are *entitlement*, not naming, which is why neither is
/// something this migration closes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeGap {
    pub scope: Id,
    pub scope_name: String,
    /// Whether the node identity is already in this scope's recipient set.
    pub member: bool,
    /// Credentials whose current version has no wrap for the node identity.
    pub unwrapped: Vec<String>,
}

/// What a run would do, or did.
#[derive(Clone, Debug)]
pub struct NodeIdentityReport {
    /// This pile's own signing key.
    pub local_public_key: [u8; 32],
    /// The identity it is named as, once it is.
    pub bound: Option<(Id, String)>,
    /// True only when this run appended the binding. A re-run reports the
    /// identity as bound with this false, so "already done" and "left to do"
    /// stay distinguishable however often the migration is replayed.
    pub bound_now: bool,
    /// Every node this pile attests, local or not.
    pub nodes: Vec<NodeRow>,
    /// Per-scope worklist for the bound identity. Empty while unbound: there
    /// is no principal yet to compute a gap for.
    pub gaps: Vec<ScopeGap>,
    /// Identities whose private half is a node key rather than a lockbox.
    pub node_identities: usize,
    /// Identities that still keep a password lockbox, and still work.
    pub lockbox_identities: usize,
}

impl NodeIdentityReport {
    /// Nodes this pile attests that no Secrets identity names.
    pub fn unnamed_nodes(&self) -> usize {
        self.nodes.iter().filter(|row| row.identity.is_none()).count()
    }
}

struct SecretsView {
    facts: TribleSet,
    reader: PileReader,
    catalog: SecretsCatalog,
}

fn read_secrets(pile: &mut Pile, signer: &ed25519_dalek::SigningKey) -> Result<SecretsView> {
    let facts = open_scope(&mut *pile, DEFAULT_SCOPE_ID, signer.clone())
        .materialize()
        .context("materialize Secrets collection")?;
    let reader = pile.reader().context("open Secrets attachment reader")?;
    let catalog = secrets_model::validate_catalog(&reader, &facts)
        .context("validate Secrets collection")?;
    Ok(SecretsView {
        facts,
        reader,
        catalog,
    })
}

fn now() -> Result<IntervalValue> {
    let at = Epoch::now().map_err(|error| anyhow::anyhow!("read current clock: {error:?}"))?;
    (at, at)
        .try_to_inline()
        .map_err(|error| anyhow::anyhow!("encode current clock: {error:?}"))
}

/// Every credential in `scope` whose current version has no wrap for
/// `identity`, by name.
fn unwrapped_for(catalog: &SecretsCatalog, scope: Id, identity: Id) -> Result<Vec<String>> {
    let names: BTreeSet<String> = catalog
        .secrets
        .values()
        .filter(|row| row.scope == scope)
        .map(|row| row.name.clone())
        .collect();
    let mut missing = Vec::new();
    for name in names {
        let Some(latest) = catalog.latest_secret(scope, &name)? else {
            continue;
        };
        if !catalog.wrap_holders(latest).contains(&identity) {
            missing.push(name);
        }
    }
    Ok(missing)
}

fn report(pile: &mut Pile, signer: &ed25519_dalek::SigningKey) -> Result<NodeIdentityReport> {
    let view = read_secrets(pile, signer)?;
    let observed = discover_nodes(pile)?;
    let local_public_key = signer.verifying_key().to_bytes();

    let mut nodes = Vec::new();
    for node in &observed {
        let identity =
            identity_by_public_key(&view.reader, &view.catalog, &node.public_key())?;
        let name = identity
            .map(|id| entity_name(&view.reader, &view.catalog, id))
            .transpose()?;
        nodes.push(NodeRow {
            public_key: node.public_key(),
            commits: node.commits(),
            identity,
            name,
            is_local: node.public_key() == local_public_key,
        });
    }

    let bound = match identity_by_public_key(&view.reader, &view.catalog, &local_public_key)? {
        Some(id) => Some((id, entity_name(&view.reader, &view.catalog, id)?)),
        None => None,
    };

    let mut gaps = Vec::new();
    if let Some((identity, _)) = bound {
        for scope in view.catalog.scopes.values() {
            let member = view.catalog.recipients_of(scope.id).contains(&identity);
            let unwrapped = unwrapped_for(&view.catalog, scope.id, identity)?;
            if member && unwrapped.is_empty() {
                continue;
            }
            gaps.push(ScopeGap {
                scope: scope.id,
                scope_name: entity_name(&view.reader, &view.catalog, scope.id)?,
                member,
                unwrapped,
            });
        }
    }

    let node_identities = view
        .catalog
        .identities
        .values()
        .filter(|row| row.is_node_identity())
        .count();
    Ok(NodeIdentityReport {
        local_public_key,
        bound,
        bound_now: false,
        nodes,
        gaps,
        node_identities,
        lockbox_identities: view.catalog.identities.len() - node_identities,
    })
}

/// Work out what binding this node would change, without writing.
pub fn plan(pile: &Path, key: Option<&Path>) -> Result<NodeIdentityReport> {
    let signer = load_signer(pile, key)
        .context("naming this node's key needs the durable signing key beside the pile")?;
    let mut store = open_pile_strict(pile)?;
    let result = report(&mut store, &signer);
    store.close().map_err(anyhow::Error::from)?;
    result
}

/// Append the identity record binding this node's signing key.
///
/// Idempotent by inspection rather than by replay: a key that already names an
/// identity is left exactly as it is, and the returned report says so with
/// `bound_now` false.
pub fn publish(pile: &Path, key: Option<&Path>, nickname: &str) -> Result<NodeIdentityReport> {
    let signer = load_signer(pile, key)
        .context("naming this node's key needs the durable signing key beside the pile")?;
    let before = plan(pile, key)?;
    if before.bound.is_some() {
        return Ok(before);
    }

    let store = open_pile_strict(pile)?;
    let mut collection = open_scope(store, DEFAULT_SCOPE_ID, signer.clone());
    let result: Result<()> = (|| {
        let view = read_secrets(collection.storage_mut(), &signer)?;
        let prepared =
            prepare_node_identity(nickname, &signer.verifying_key().to_bytes(), now()?)?;
        let mut fragment = prepared.fragment;
        validate_candidate(&view.reader, &view.facts, &fragment)
            .context("validate the node identity against the whole collection")?;
        fragment.describe_with(entity! {
            metadata::description: "migration: bind this node's signing key as a Secrets identity"
        });
        collection
            .commit(fragment)
            .context("commit the node identity")?;
        Ok(())
    })();
    let closed = collection.into_storage().close().map_err(anyhow::Error::from);
    result?;
    closed?;

    let mut after = plan(pile, key)?;
    after.bound_now = true;
    Ok(after)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    use faculties::secrets::{prepare_identity, scope_fragment, seal_version};
    use faculties::storage::initialize_signer;

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: std::path::PathBuf,
    }

    impl Fixture {
        /// A pile with one password-locked identity, one scope, and one sealed
        /// version — the shape the live pile was in before this migration.
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("test.pile");
            File::create(&pile).unwrap();
            let signer = initialize_signer(&pile, None).unwrap();

            let store = open_pile_strict(&pile).unwrap();
            let mut collection = open_scope(store, DEFAULT_SCOPE_ID, signer.clone());
            let alice = prepare_identity("alice", b"correct horse", now().unwrap()).unwrap();
            let mut foundation = alice.fragment;
            let scope = scope_fragment(alice.id, "prod", now().unwrap()).unwrap();
            let scope_id = scope.root().unwrap();
            foundation += scope;
            collection.commit(foundation).unwrap();

            let facts = collection.materialize().unwrap();
            let reader = collection.storage_mut().reader().unwrap();
            let catalog = secrets_model::validate_catalog(&reader, &facts).unwrap();
            let sealed = seal_version(
                &reader,
                &catalog,
                scope_id,
                "database",
                b"hunter2",
                now().unwrap(),
            )
            .unwrap();
            collection.commit(sealed.fragment).unwrap();
            collection.into_storage().close().unwrap();

            Self {
                _directory: directory,
                pile,
            }
        }
    }

    #[test]
    fn the_node_key_is_named_once_and_a_rerun_says_so() {
        let fixture = Fixture::new();

        let before = plan(&fixture.pile, None).unwrap();
        assert!(before.bound.is_none());
        assert!(!before.bound_now);
        assert_eq!(before.nodes.len(), 1, "one signer wrote this pile");
        assert!(before.nodes[0].is_local);
        assert_eq!(before.unnamed_nodes(), 1);
        assert_eq!(before.node_identities, 0);
        assert_eq!(before.lockbox_identities, 1);
        // Nothing to compute a gap against yet.
        assert!(before.gaps.is_empty());

        let published = publish(&fixture.pile, None, "the-node").unwrap();
        assert!(published.bound_now);
        let (identity, name) = published.bound.clone().unwrap();
        assert_eq!(name, "the-node");
        assert_eq!(published.node_identities, 1);
        // The password-locked identity is untouched and still counted.
        assert_eq!(published.lockbox_identities, 1);

        // Named, and entitled to nothing: not a recipient, holding no wrap.
        assert_eq!(published.gaps.len(), 1);
        assert!(!published.gaps[0].member);
        assert_eq!(published.gaps[0].unwrapped, vec!["database".to_owned()]);
        assert_eq!(published.gaps[0].scope_name, "prod");

        // A second run finds the binding already there and writes nothing,
        // and says which of the two it is.
        let again = publish(&fixture.pile, None, "the-node").unwrap();
        assert!(!again.bound_now);
        assert_eq!(again.bound.map(|(id, _)| id), Some(identity));
        assert_eq!(again.node_identities, 1);
    }
}
