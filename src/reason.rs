//! Explicit reasoning annotations, independently callable from any frontend.

pub mod cli;
pub mod mcp;
pub mod operations;

pub use operations::{Reason, ReasonAction};
