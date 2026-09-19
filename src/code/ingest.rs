//! Staging and publication for the Code collection.
//!
//! This is a near-verbatim copy of `ArchiveImportWriter` with the Archive scope
//! replaced by the Code scope and the block-DAG vocabulary replaced by the
//! extraction law. The two helpers it needs from `archive_collection.rs`
//! (`ensure_facts` and `fact_archive_contains`) are private there and that file
//! is in another agent's working set right now, so they are copied rather than
//! widened. Generalizing both into one `CollectionImportWriter<S>` is the
//! follow-up once that work lands; doing it first would mean editing a file
//! somebody else is holding.
//!
//! Commit granularity is one COMMIT per repository per run, never one per file.
//! `ArchiveImportWriter`'s own measurement is the reason: ~9.3 s of pile-opening
//! against ~1 s of projection put a 3,161-file backfill at 8.2 hours of pure
//! opening when the open was paid per unit. Pay it once.

use std::borrow::BorrowMut;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::blob::encodings::{simplearchive::SimpleArchive, UnknownBlob};
use triblespace::core::blob::Blob;
use triblespace::core::collection::{
    Collection, CollectionCommit, CollectionSnapshot, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace::core::inline::encodings::UnknownInline;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStorePut, SnapshotSource};
use triblespace::prelude::*;

use crate::collection_names::open_configured;
use crate::schemas::code::DEFAULT_SCOPE_ID;
use crate::storage::{load_signer, open_pile_strict, FactArchive};

/// Stage Code fragments for commit-last publication.
pub struct CodeImportWriter<P = Pile> {
    pile: P,
    collection: Collection<SimpleArchive>,
    signer: SigningKey,
    current: FactArchive,
    delta: Fragment,
}

impl CodeImportWriter {
    pub async fn open(
        pile_path: &std::path::Path,
        key_path: Option<&std::path::Path>,
    ) -> Result<Self> {
        let signer = load_signer(pile_path, key_path)?;
        let mut pile = open_pile_strict(pile_path)?;
        let result = async {
            let source = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
            let observed = ensure_facts(&mut pile, source, &signer).await?;
            let current = observed.view::<FactArchive>().context("read Code facts")?;
            Ok((source, current))
        }
        .await;
        match result {
            Ok((collection, current)) => {
                let mut writer = Self {
                    pile,
                    collection,
                    signer,
                    current,
                    delta: Fragment::empty(),
                };
                if let Err(error) = writer.stage_fragment(crate::code::law_fragment()) {
                    return close_pile(
                        writer.pile,
                        Err(error),
                        "closing Code pile after extraction-law staging failed",
                    );
                }
                Ok(writer)
            }
            Err(error) => close_pile(
                pile,
                Err(error),
                "closing Code pile after failed open also failed",
            ),
        }
    }
}

impl<P: BorrowMut<Pile>> CodeImportWriter<P> {
    /// Stage against a caller-owned pile. The caller controls its lifetime.
    pub async fn from_pile(mut pile: P, signer: &SigningKey) -> Result<Self> {
        let source = open_configured(pile.borrow_mut(), DEFAULT_SCOPE_ID, signer.verifying_key())?;
        let observed = ensure_facts(pile.borrow_mut(), source, signer).await?;
        let current = observed.view::<FactArchive>().context("read Code facts")?;
        let mut writer = Self {
            pile,
            collection: source,
            signer: signer.clone(),
            current,
            delta: Fragment::empty(),
        };
        writer.stage_fragment(crate::code::law_fragment())?;
        Ok(writer)
    }

    /// Whether this exact entity is already catalogued.
    ///
    /// The unit fast path: a hit means these exact bytes at this exact path in
    /// this exact repo are already here, so the file is not parsed at all. One
    /// Blake3 and one `exists!` per unchanged file is what makes a re-ingest of
    /// a corpus with three changed files cost three parses.
    pub fn holds_entity(&self, entity: Id) -> bool {
        use triblespace::core::metadata;
        exists!((tag: Id), pattern!(&self.current, [{ entity @ metadata::tag: ?tag }]))
            || exists!((tag: Id), pattern!(self.delta.facts(), [{ entity @ metadata::tag: ?tag }]))
    }

    pub fn stage_fragment(&mut self, fragment: Fragment) -> Result<()> {
        // A Fragment is the independently derivable source unit. A wholly known
        // candidate is an idempotent replay and can be skipped. Once it
        // contributes even one new fact, retain its complete closure in this
        // COMMIT element — set union makes that duplication semantically free,
        // while exact homomorphisms can derive every leaf without depending on
        // an implicit merge with historical commits.
        let (_, facts, metafacts, blobs) = fragment.into_parts();
        if facts.iter().all(|fact| {
            self.delta.facts().contains(fact) || fact_archive_contains(&self.current, fact)
        }) {
            return Ok(());
        }

        // Embedded payloads dominate an ingest's resident memory — a unit
        // carries its whole file. Append each content-addressed dependency
        // immediately, keeping payload bytes out of the long-lived delta. They
        // stay semantically unreachable until a signed COMMIT names the facts
        // referencing them.
        let embedded = embedded_blobs(blobs);
        stage_embedded_blobs(self.pile.borrow_mut(), embedded)?;

        self.delta += Fragment::from_parts(facts, metafacts, Default::default());
        Ok(())
    }

    pub fn delta_len(&self) -> usize {
        self.delta.facts().len()
    }

    /// Publish the staged delta as ONE signed COMMIT and keep the pile open.
    ///
    /// `current` MUST absorb what was just published, or the next unit's
    /// idempotence check would re-stage facts this commit already carries.
    pub fn commit_unit(&mut self) -> Result<Option<CollectionCommit>> {
        if self.delta.facts().is_empty() {
            return Ok(None);
        }
        let fragment = std::mem::replace(&mut self.delta, Fragment::empty());
        let published = fragment.facts().clone();
        crate::collection_names::require_command_write_admission(
            &mut *self.pile.borrow_mut(),
            self.collection,
            &self.signer,
            "Code",
            "code find",
        )?;
        let commit = self
            .pile
            .borrow_mut()
            .commit(self.collection, &self.signer, fragment)
            .context("commit authored Code projection unit")?;
        self.current = extend_archive(&self.current, &published);
        Ok(Some(commit))
    }
}

impl CodeImportWriter {
    /// Close the pile, publishing any still-staged delta first.
    pub fn close<T>(mut self, surrounding: Result<T>) -> Result<T> {
        let result = surrounding.and_then(|value| {
            self.commit_unit()?;
            Ok(value)
        });
        close_pile(
            self.pile,
            result,
            "closing Code pile after failure also failed",
        )
    }
}

fn stage_embedded_blobs<S>(store: &mut S, embedded: Vec<Blob<UnknownBlob>>) -> Result<()>
where
    S: BlobStorePut,
{
    for blob in embedded {
        store
            .put::<UnknownBlob, _>(blob)
            .context("stage Code embedded blob")?;
    }
    Ok(())
}

fn embedded_blobs(mut blobs: triblespace::core::blob::MemoryBlobStore) -> Vec<Blob<UnknownBlob>> {
    let reader = blobs
        .snapshot()
        .expect("MemoryBlobStore reader creation is infallible");
    let mut embedded: Vec<_> = reader.iter().collect();
    embedded.sort_unstable_by_key(|(store_key, _)| store_key.raw);
    embedded.into_iter().map(|(_, blob)| blob).collect()
}

/// Exact membership without rebuilding an in-memory `TribleSet` over the
/// maintained shard union.
fn fact_archive_contains(facts: &FactArchive, fact: &Trible) -> bool {
    exists!(facts.pattern(
        inlineencodings::GenId::inline_from(*fact.e()),
        inlineencodings::GenId::inline_from(*fact.a()),
        *fact.v::<UnknownInline>(),
    ))
}

fn extend_archive(current: &FactArchive, additions: &TribleSet) -> FactArchive {
    if additions.is_empty() {
        return current.clone();
    }
    current.with_segments([
        triblespace::core::blob::encodings::succinctarchive::SuccinctArchive::from(additions),
    ])
}

fn close_pile<T>(pile: Pile, result: Result<T>, failure_context: &str) -> Result<T> {
    match (result, pile.close()) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(close_error)) => Err(anyhow!("close Code pile: {close_error}")),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("{failure_context} also failed: {close_error}")))
        }
    }
}

/// Ensure the Code collection's maintained fact representation and return the
/// ordinary observation. Storage work, not domain decoding: consumers choose
/// their own typed queries over `view::<FactArchive>()`.
pub async fn ensure_facts(
    pile: &mut Pile,
    source: Collection<SimpleArchive>,
    signer: &SigningKey,
) -> Result<CollectionSnapshot<PileSnapshot, Rank9AcceleratedSuccinctArchiveBlob>> {
    let policy = source
        .policy(&pile.snapshot().context("freeze Code descriptor snapshot")?)
        .context("read Code collection policy")?;
    let succinct = pile
        .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
        .context("register Succinct Code fact collection")?;
    let rank9 = pile
        .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
        .context("register Rank9 Code fact collection")?;
    drop(
        pile.ensure(source, signer)
            .await
            .context("ensure Code source dependencies")?,
    );
    drop(
        pile.maintain(succinct, signer)
            .await
            .context("maintain Succinct Code fact collection")?,
    );
    let after = pile
        .maintain(rank9, signer)
        .await
        .context("maintain Rank9 Code fact collection")?;
    after
        .collection(rank9)
        .context("attach Code fact collection")
}

/// Attach the Code facts for reading.
///
/// A read ensures the collection's own accelerated FACT representation, which
/// is what `pattern!` is answered from and therefore not optional. It does not
/// touch the LEXICAL covers: `code index` maintains those, once and explicitly.
/// Correctness never depends on a BM25 cover — a stale one makes `code search`
/// say so and name the verb that fixes it — and a collection this size that
/// re-indexed itself on every read would make `code find` cost what an `orient
/// wake` costs.
pub fn ensure_local_with_storage(
    storage: &crate::storage::Storage,
) -> Result<CollectionSnapshot<PileSnapshot, Rank9AcceleratedSuccinctArchiveBlob>> {
    storage.with_pile(|pile, signer| {
        let source = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
        pollster::block_on(ensure_facts(pile, source, signer))
    })
}
