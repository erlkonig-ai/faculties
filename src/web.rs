//! Reusable provider-backed Web observations with distinct CLI/MCP frontends.
pub mod cli;
pub mod mcp;
mod operations;
pub mod presentation;
pub use operations::{ApiKeys, Endpoints, FetchReport, Provider, SearchReport, SearchResult, Web};
