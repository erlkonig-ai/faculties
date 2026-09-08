//! Hearing: shared utterance segmentation, filtering and native embeddings.
//!
//! Recorded clips use resident bytes and explicit local model configuration.
//! The CLI alone owns Soma listening, software pause-file holds and historical
//! JSONL/raw-file handover. Capture stays open during holds; completed live
//! utterances are resampled once, never one capture frame at a time.

pub mod cli;
pub mod mcp;
mod operations;
mod segmenter;
pub use operations::{
    process_pcm16k, Backend, ClipSummary, Hear, Heard, ModelConfig, Observation, Options, Outcome,
    DEFAULT_MODEL, DEFAULT_PROMPT, HEAR_RATE,
};
