//! Shared notebook composition and finite, resident PNG capture.
//!
//! Interactive windows, filesystem capture and web export remain explicit CLI
//! actions. Native capture uses GORBIE's existing renderer and returns image
//! bytes directly; it never invokes a capture binary or reopens a PNG path.

pub mod cli;
#[cfg(feature = "widgets")]
mod composition;
pub mod mcp;
mod operations;

#[cfg(feature = "widgets")]
pub use composition::compose;
pub use operations::{CaptureOptions, CapturePage, CaptureSummary, Target, Viewer};
