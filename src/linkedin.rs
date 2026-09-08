//! LinkedIn's conservative import conduit into shared Relations state.
//!
//! Native operations own typed resident data and exact write receipts. CLI
//! snapshot paths/token inputs and the explicit MCP schemas are separate UX.

pub mod cli;
pub mod mcp;
pub mod operations;
mod render;
mod source;

pub use operations::{
    Connection, ImportReport, LinkedIn, ProfileWrite, PullOptions, PullReport, ResolutionReceipt,
    ReviewPair, ReviewPerson, ReviewReport,
};
pub use source::parse_snapshot;
