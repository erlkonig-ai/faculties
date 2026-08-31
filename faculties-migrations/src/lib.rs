//! The one still-live additive Faculties collection migration.
//!
//! Historical experiments remain in Git history rather than forming a second
//! compatibility runtime. [`collection_policy`] recognizes exactly the
//! immediately previous ordinary collection descriptors and re-seats their
//! root-signed COMMITs under the current policy descriptors.

pub mod collection_policy;
