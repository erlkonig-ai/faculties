//! Native image generation. Model locations belong to the launcher; generated
//! PNGs are resident values. Frontends decide whether to save, perceive, or
//! explicitly remember them. Generation never shells out to another faculty.

pub mod cli;
#[cfg(any(feature = "imagine", test))]
mod configuration;
pub mod mcp;
mod operations;

pub use operations::{GeneratedImage, Imagine, ModelSources, Options, Variant};
