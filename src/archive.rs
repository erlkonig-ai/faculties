//! Canonical Archive library operations and explicit frontend adapters.
//! Source-format scanners remain reusable in the existing archive_* modules.

pub mod cli;
pub mod mcp;
mod operations;
pub use operations::{parse_tai_timestamp, Archive, ImportReceipt, ImportSource, ImportSummary};
