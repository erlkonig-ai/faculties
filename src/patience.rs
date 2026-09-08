//! Timeout-extension events; command execution belongs only to the CLI.

pub mod cli;
pub mod mcp;
pub mod operations;

pub use operations::Patience;
