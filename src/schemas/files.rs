//! Files schema: content-addressed file storage with directory trees and
//! import snapshots.
//!
//! Used by `files.rs` (the faculty CLI) and by any downstream consumer
//! that wants to read file entities, directory trees, or import snapshots
//! from a pile.

use anybytes::View;
use triblespace::core::blob::{Blob, BlobEncoding, TryFromBlob};
use triblespace::core::id::ExclusiveId;
use triblespace::core::inline::{Encodes, InlineEncoding};
use triblespace::core::metadata::{self, MetaDescribe};
use triblespace::core::trible::Fragment;
use triblespace::macros::id_hex;
use triblespace::prelude::*;
use triblespace_search::schemas::Embedding;

// ── dimension-typed embedding encoding ────────────────────────────────────
// A `[f32]` blob whose *dimension is part of the type*. Same wire format as
// triblespace_search::Embedding (raw f32 LE), but reads are length-validated,
// so a vector of any other dimension simply fails to decode. That makes it
// impossible to mix embedding dimensions in one HNSW index — e.g. a 1152-d
// SigLIP vector can never be read where a 512-d CLIP one is expected, at
// compile time (distinct `Handle<_>` types) and at read time (the check below).
// A model swap becomes: new typed attribute, ignore the old one, no dim clash.
//
// Named per dimension for now (matches one attribute = one model); generalise
// to `EmbeddingDim<const N>` if a third dimension ever appears. Lift this whole
// block into triblespace-search in the next coordinated triblespace release.

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

/// A 1152-d L2-normalized embedding (SigLIP2 so400m), length-validated on read.
pub struct Embedding1152;

impl BlobEncoding for Embedding1152 {}

impl MetaDescribe for Embedding1152 {
    fn describe() -> Fragment {
        let id = id_hex!("FC39A4E7CFC91BE6CA8B0A06031F3EB0");
        entity! { ExclusiveId::force_ref(&id) @
            metadata::name: "Embedding1152",
            metadata::description: "1152-d [f32] LE embedding blob (e.g. SigLIP2 so400m). Length-validated on read so it can never be mixed with another embedding dimension in one HNSW index.",
            metadata::tag: metadata::KIND_BLOB_ENCODING,
        }
    }
}

impl TryFromBlob<Embedding1152> for View<[f32]> {
    type Error = EmbeddingDimError;
    fn try_from_blob(b: Blob<Embedding1152>) -> Result<Self, Self::Error> {
        let floats = b.bytes.len() / 4;
        if floats != 1152 {
            return Err(EmbeddingDimError::WrongLen { expected: 1152, got: floats });
        }
        b.bytes.view().map_err(EmbeddingDimError::View)
    }
}

impl Encodes<Vec<f32>> for Embedding1152
where
    inlineencodings::Handle<Embedding1152>: InlineEncoding,
{
    type Output = Blob<Embedding1152>;
    fn encode(source: Vec<f32>) -> Blob<Embedding1152> {
        let mut bytes = Vec::with_capacity(source.len() * 4);
        for v in &source {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        Blob::new(bytes.into())
    }
}

// ── branch name ──────────────────────────────────────────────────────────
pub const FILES_BRANCH_NAME: &str = "files";

// ── kinds ────────────────────────────────────────────────────────────────
pub const KIND_FILE: Id = id_hex!("1F9C9DCA69504452F318BA11E81D47D1");
pub const KIND_DIRECTORY: Id = id_hex!("58CDFCBA4E4B91979766D50FB18777B5");
pub const KIND_IMPORT: Id = id_hex!("89655D039A90634F09207BFEB5BE65AD");

// ── attributes ───────────────────────────────────────────────────────────
pub mod file {
    use super::*;
    attributes! {
        // file leaf: content blob
        "C1E3A12230595280F22ABEB8733D082C" as content: inlineencodings::Handle<blobencodings::RawBytes>;
        // file/directory: name (filename or dirname)
        "AA6AB6F5E68F3A9D95681251C2B9DAFA" as name: inlineencodings::Handle<blobencodings::LongString>;
        // file leaf: MIME type
        "BFE2C88ECD13D56F80967C343FC072EE" as mime: inlineencodings::ShortString;
        // import: timestamp
        "3765160CC1A96BE38302B344718E4C49" as imported_at: inlineencodings::NsTAIInterval;
        // TODO: migrate to metadata::tag (GenId) — should use canonical tag
        // entities with metadata::name, not inline ShortString. See wiki.rs TagIndex.
        "CDA941A27F86A7551779CF9524DE1D0F" as tag: inlineencodings::ShortString;
        // directory: children (multi-valued, files or subdirectories)
        "0AC1D962B6E8170FDD73AE3743E16578" as children: inlineencodings::GenId;
        // import: root directory or file entity
        "7B36A7A304C26C5504EA54F5723FA135" as root: inlineencodings::GenId;
        // import: original filesystem path
        "E4B24BB9F469CEC6FD12926C56514E9F" as source_path: inlineencodings::Handle<blobencodings::LongString>;
        // file leaf: CLIP-512 embedding handle (v0, untyped Embedding) —
        // semantic-search exhaust, set on `add` for image/* files. Superseded
        // by `siglip_embedding` (dim-typed); kept so old piles still read.
        "433BE3AC7F95405872385898AD52FB73" as embedding: inlineencodings::Handle<Embedding>;
        // file leaf: SigLIP2 so400m 1152-d embedding — the current model, in a
        // dim-typed encoding so it can never be mixed with the 512-d CLIP one.
        // `files similar` queries this; a model swap = new typed attribute.
        "FE1369587907B516C64F80B0B5F25596" as siglip_embedding: inlineencodings::Handle<super::Embedding1152>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedding1152_roundtrips_and_rejects_wrong_dim() {
        let v: Vec<f32> = (0..1152).map(|i| i as f32 * 0.001).collect();
        let blob = <Embedding1152 as Encodes<Vec<f32>>>::encode(v.clone());
        let back: View<[f32]> =
            <View<[f32]> as TryFromBlob<Embedding1152>>::try_from_blob(blob).unwrap();
        assert_eq!(back.as_ref(), v.as_slice(), "1152-d round-trips byte-exact");

        // The type-safety: a 512-d vector stored as Embedding1152 must NOT
        // decode — the dimension is validated on read, so it can never slip
        // into a 1152-d index.
        let wrong: Vec<f32> = vec![0.0; 512];
        let blob = <Embedding1152 as Encodes<Vec<f32>>>::encode(wrong);
        let err = <View<[f32]> as TryFromBlob<Embedding1152>>::try_from_blob(blob);
        assert!(
            matches!(err, Err(EmbeddingDimError::WrongLen { expected: 1152, got: 512 })),
            "wrong dimension is rejected on read"
        );
    }
}
