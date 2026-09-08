//! Candidate disclosure findings, explicit coverage, and channel policy.
//!
//! Deterministic resident operations never load a model. Explicit semantic
//! operations require local-embed. Git, filesystem traversal, and hook mutation
//! remain explicit Rust/CLI operations, never caller-selected MCP host paths.

pub mod cli;
pub mod mcp;
mod operations;
pub mod presentation;

pub use operations::*;
