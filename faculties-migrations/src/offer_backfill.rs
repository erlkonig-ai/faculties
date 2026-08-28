//! Migration-local repair for artifacts written before OFFER records existed.

use std::collections::{BTreeSet, VecDeque};

use anyhow::{anyhow, bail, Context, Result};

use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::blob::Blob;
use triblespace::core::collection::{CollectionCommit, CollectionHandle};
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::{Inline, INLINE_LEN};
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{
    ArtifactHandle, ArtifactOfferStore, BlobStore, BlobStoreGet, BlobStoreList,
};

/// Offer the complete resident closure a re-seated COMMIT can ask peers for.
///
/// Retired descriptor epochs predate OFFER. Reusing their exact data and
/// metadata handles is correct locally but otherwise gives the DHT no provider
/// for those dependencies. Validate every direct root before the first OFFER,
/// then use the store's conservative aligned-handle traversal to include all
/// resident nested attachments. Replay is a grow-only no-op.
pub(crate) fn offer_reused_commit_closure(
    pile: &mut Pile,
    collection: CollectionHandle,
    commits: &[CollectionCommit],
) -> Result<()> {
    let reader = pile
        .reader()
        .context("open reused COMMIT dependency reader")?;

    let mut roots = BTreeSet::from([collection.transmute()]);
    for commit in commits {
        roots.insert(Handle::<UnknownBlob>::from_hash(commit.data()));
        roots.insert(commit.metadata().transmute());
    }

    let mut queued = BTreeSet::new();
    let mut queue = VecDeque::new();
    for root in roots {
        if !resident(&reader, root)? {
            bail!(
                "reused COMMIT dependency {} is absent",
                hex::encode_upper(root.raw)
            );
        }
        queued.insert(root);
        queue.push_back(root);
    }

    let mut closure = BTreeSet::new();
    while let Some(handle) = queue.pop_front() {
        let blob = validate_candidate(&reader, handle)?;
        closure.insert(handle);

        // Match the store's canonical conservative child traversal, but keep
        // it fallible: `BlobChildren::children` intentionally suppresses a
        // corrupt-parent load error, while a migration must validate its
        // complete publication plan before the first OFFER is appended.
        for chunk in blob.bytes.as_ref().chunks_exact(INLINE_LEN) {
            let mut raw = [0u8; INLINE_LEN];
            raw.copy_from_slice(chunk);
            let child = Inline::<Handle<UnknownBlob>>::new(raw);
            if !queued.contains(&child) && resident(&reader, child)? {
                queued.insert(child);
                queue.push_back(child);
            }
        }
    }

    pile.offer_all(closure)
        .map_err(|error| anyhow!("offer complete reused COMMIT dependency closure: {error}"))
}

fn resident(
    reader: &triblespace::core::repo::pile::PileReader,
    handle: ArtifactHandle,
) -> Result<bool> {
    reader.contains_blob(handle).map_err(|error| {
        anyhow!(
            "inspect reused artifact {}: {error}",
            hex::encode_upper(handle.raw)
        )
    })
}

fn validate_candidate(
    reader: &triblespace::core::repo::pile::PileReader,
    handle: ArtifactHandle,
) -> Result<Blob<UnknownBlob>> {
    reader.get(handle).map_err(|error| {
        anyhow!(
            "refusing to offer corrupt reused artifact {}: {error}",
            hex::encode_upper(handle.raw)
        )
    })
}
