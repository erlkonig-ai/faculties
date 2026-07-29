//! Pure schema-migration transforms shared by the `migrations` faculty.
//!
//! This module deliberately does not choose branches, move named heads, or
//! record receipts. Those are repository-level policy owned by the faculty.
//! The transforms here operate on pinned branch snapshots and are therefore
//! deterministic, dry-run friendly, and independently testable.

pub mod media_types;
