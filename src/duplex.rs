//! The continuous spoken channel: finite session controls and an explicit host
//! runtime. The control library never loads weights, opens a microphone/speaker
//! or launches a process. The runtime subscribes to Soma and opens only the
//! explicitly named playback device; the microphone remains Soma's clock.
//!
//! Read publishes a one-sided floor hold before observing the transcript, but
//! the loop polls that hold: it is not a synchronous audio barrier. Read does
//! not consume the cursor; say/release advance to the transcript tail at their
//! own operation time. Queued prose is literal and means requested speech, not
//! confirmed delivery. Far-end entries describe presence/duration, never words
//! this one-text-stream model cannot transcribe.

pub mod cli;
pub mod mcp;
mod operations;
pub mod presentation;
pub mod runtime;
pub use operations::*;
