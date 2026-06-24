//! The shared multimodal embedding space.
//!
//! ONE space for everything Liora perceives or generates — file images,
//! photos, memory-chunk prose — so all four search directions
//! (text→text, text→image, image→text, image→image) are just cosine in one
//! HNSW. The space is nomic's *aligned* text+vision latent (768-d):
//! `nomic-embed-text-v1.5` and `nomic-embed-vision-v1.5` are deliberately
//! co-embedded into the same coordinates, so a text query and an image
//! candidate are directly comparable — `cosine(text_vec, image_vec)` is
//! meaningful with no extra alignment.
//!
//! Why one type, not three: a per-silo model (CLIP-512 for files, SigLIP-1152
//! for photos, nomic-768 for prose) is locally optimal but globally useless —
//! incomparable spaces can't be cross-searched, which is the *whole* point. So
//! the zoo collapses to one canonical [`Embedding768`] and one [`attr::embedding`]
//! attribute, reused across every faculty: "this entity's position in the
//! shared space." The dimension is part of the type, so a vector of any other
//! width fails to decode and can never slip into the index — a model swap stays
//! a clean break (new dim → new type), never a silent dimension clash.

use anybytes::View;
use triblespace::core::blob::{Blob, BlobEncoding, TryFromBlob};
use triblespace::core::id::ExclusiveId;
use triblespace::core::inline::{Encodes, InlineEncoding};
use triblespace::core::metadata::{self, MetaDescribe};
use triblespace::core::trible::Fragment;
use triblespace::macros::id_hex;
use triblespace::prelude::*;
use triblespace_search::hnsw::HNSWBuilder;
use triblespace_search::schemas::{put_embedding, Embedding};

/// Dimension of the shared space (nomic-embed-{text,vision}-v1.5).
pub const DIM: usize = 768;

// ── dimension-typed embedding encoding ────────────────────────────────────

/// Error decoding a dimension-typed embedding blob.
#[derive(Debug)]
pub enum EmbeddingDimError {
    /// The blob held a different number of floats than the type's dimension.
    WrongLen { expected: usize, got: usize },
    /// The bytes couldn't be viewed as `[f32]` (misalignment / bad length).
    View(anybytes::view::ViewError),
}

impl std::fmt::Display for EmbeddingDimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongLen { expected, got } => {
                write!(f, "embedding has {got} floats, expected {expected}")
            }
            Self::View(e) => write!(f, "embedding view: {e}"),
        }
    }
}
impl std::error::Error for EmbeddingDimError {}

/// A 768-d L2-normalized embedding in the shared nomic space, length-validated
/// on read so a foreign-dimension vector can never enter the index. Same wire
/// format as `triblespace_search::Embedding` (raw f32 LE), but reads check the
/// width — so a 512-d CLIP or 1152-d SigLIP vector simply fails to decode here,
/// at compile time (distinct `Handle<_>`) and at read time (the check below).
pub struct Embedding768;

impl BlobEncoding for Embedding768 {}

impl MetaDescribe for Embedding768 {
    fn describe() -> Fragment {
        let id = id_hex!("D135AA8404D09D112E5BD206494190C4");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "Embedding768",
            metadata::description: "768-d [f32] LE embedding blob in the shared nomic text+vision space (nomic-embed-{text,vision}-v1.5). L2-normalized; length-validated on read so it can never be mixed with another embedding dimension in one HNSW index.",
            metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

impl TryFromBlob<Embedding768> for View<[f32]> {
    type Error = EmbeddingDimError;
    fn try_from_blob(b: Blob<Embedding768>) -> Result<Self, Self::Error> {
        let floats = b.bytes.len() / 4;
        if floats != DIM {
            return Err(EmbeddingDimError::WrongLen { expected: DIM, got: floats });
        }
        b.bytes.view().map_err(EmbeddingDimError::View)
    }
}

impl Encodes<Vec<f32>> for Embedding768
where
    inlineencodings::Handle<Embedding768>: InlineEncoding,
{
    type Output = Blob<Embedding768>;
    fn encode(source: Vec<f32>) -> Blob<Embedding768> {
        let mut bytes = Vec::with_capacity(source.len() * 4);
        for v in &source {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        Blob::new(bytes.into())
    }
}

// ── the canonical embedding attribute ──────────────────────────────────────
// One attribute, reused across files, photos, and memory chunks — like
// `metadata::name`, it's a cross-cutting property, not owned by any one
// faculty. "This entity has a position in the shared multimodal space."

pub mod attr {
    use super::*;
    attributes! {
        "BCDCA79081A84E7428A2D06A7F222313" as embedding: inlineencodings::Handle<super::Embedding768>;
    }
}

// ── the shared nearest-neighbour core ──────────────────────────────────────

/// Pure nearest-neighbour core: build a succinct HNSW over `pairs`
/// (id, L2-normalized vector) and return every entry within `floor` cosine of
/// `query`, ranked descending. cosine == dot since the vectors are unit-norm.
///
/// The query vector's *origin* is irrelevant — it's the embedding of a query
/// image, a photo, a memory summary, or a text string, all in the one shared
/// space. Self-match and any domain filtering are the caller's job. No
/// pile/workspace dependency, so it's unit-testable with synthetic vectors and
/// shared by every faculty that searches the space (files, memory, …).
pub fn nearest(pairs: &[(Id, Vec<f32>)], query: &[f32], floor: f32) -> anyhow::Result<Vec<(f32, Id)>> {
    type LocalHandle = Inline<inlineencodings::Handle<Embedding>>;
    if pairs.is_empty() {
        return Ok(Vec::new());
    }
    let dim = query.len();
    let mut store = MemoryBlobStore::new();
    let mut builder = HNSWBuilder::new(dim).with_seed(42);
    let mut by_handle: std::collections::HashMap<LocalHandle, (Id, Vec<f32>)> =
        std::collections::HashMap::new();
    for (eid, v) in pairs {
        let lh = put_embedding(&mut store, v.clone())
            .map_err(|e| anyhow::anyhow!("stage embedding: {e:?}"))?;
        builder
            .insert(lh, v.clone())
            .map_err(|e| anyhow::anyhow!("hnsw insert: {e:?}"))?;
        by_handle.insert(lh, (*eid, v.clone()));
    }
    let local_query = put_embedding(&mut store, query.to_vec())
        .map_err(|e| anyhow::anyhow!("stage query: {e:?}"))?;
    let idx = builder.build();
    let reader = store
        .reader()
        .map_err(|e| anyhow::anyhow!("blob reader: {e:?}"))?;
    let view = idx.attach(&reader);
    let candidates = view
        .candidates_above(local_query, floor)
        .map_err(|e| anyhow::anyhow!("similarity search: {e:?}"))?;
    let mut rows: Vec<(f32, Id)> = candidates
        .into_iter()
        .filter_map(|h| {
            by_handle.get(&h).map(|(eid, v)| {
                let cos: f32 = query.iter().zip(v.iter()).map(|(a, b)| a * b).sum();
                (cos, *eid)
            })
        })
        .collect();
    rows.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedding768_roundtrips_and_rejects_wrong_dim() {
        let v: Vec<f32> = (0..DIM).map(|i| i as f32 * 0.001).collect();
        let blob = <Embedding768 as Encodes<Vec<f32>>>::encode(v.clone());
        let back: View<[f32]> =
            <View<[f32]> as TryFromBlob<Embedding768>>::try_from_blob(blob).unwrap();
        assert_eq!(back.as_ref(), v.as_slice(), "768-d round-trips byte-exact");

        // A foreign-dimension vector (e.g. a 512-d CLIP leftover) must NOT
        // decode — the width is validated on read, so it can never slip into
        // the shared index.
        let wrong: Vec<f32> = vec![0.0; 512];
        let blob = <Embedding768 as Encodes<Vec<f32>>>::encode(wrong);
        let err = <View<[f32]> as TryFromBlob<Embedding768>>::try_from_blob(blob);
        assert!(
            matches!(err, Err(EmbeddingDimError::WrongLen { expected: 768, got: 512 })),
            "wrong dimension is rejected on read"
        );
    }

    /// L2-normalize (mirrors `put_embedding`'s source normalization, which is
    /// what makes dot-product == cosine downstream).
    fn unit(mut v: Vec<f32>) -> Vec<f32> {
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if n > 0.0 {
            for x in &mut v {
                *x /= n;
            }
        }
        v
    }

    #[test]
    fn nearest_ranks_by_cosine_and_respects_floor() {
        let a = Id::new([1u8; 16]).unwrap();
        let b = Id::new([2u8; 16]).unwrap();
        let c = Id::new([3u8; 16]).unwrap();
        let pairs = vec![
            (a, unit(vec![1.0, 0.0, 0.0])),
            (b, unit(vec![0.0, 1.0, 0.0])),
            (c, unit(vec![0.9, 0.1, 0.0])),
        ];
        let query = unit(vec![1.0, 0.0, 0.0]);
        let ranked = nearest(&pairs, &query, 0.0).unwrap();
        assert_eq!(ranked.first().unwrap().1, a, "A is the nearest");

        // floor excludes the orthogonal vector b (cosine 0) but keeps a and c.
        let high = nearest(&pairs, &query, 0.5).unwrap();
        assert!(high.iter().all(|(_, id)| *id != b), "floor drops orthogonal b");
        assert!(high.iter().any(|(_, id)| *id == a), "floor keeps near a");
    }

    #[test]
    fn nearest_empty_is_empty() {
        let q = unit(vec![1.0, 0.0, 0.0]);
        assert!(nearest(&[], &q, 0.0).unwrap().is_empty());
    }
}
