//! Explicit additive migrations for the current Faculties storage epoch.
//!
//! Historical experiments remain in Git history rather than forming a second
//! compatibility runtime. Each live module owns only the retired vocabulary
//! it consumes and publishes ordinary current facts or collection records.

pub mod collection_policy;
pub mod secrets_reader_envelopes;
