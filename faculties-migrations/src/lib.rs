//! The still-live one-shot migrations for the current Faculties storage epoch.
//!
//! Historical cutovers are intentionally absent. They have already been
//! consumed by the deployed pile, never shipped as a public compatibility
//! surface, and remain recoverable from Git history. Keeping only the active
//! epoch makes it possible to tell which transformations may still be run:
//!
//! 1. [`posture_findings`] publishes legacy finding bridges into Posture's
//!    retired descriptor.
//! 2. [`descriptor_authority`] re-seats ordinary faculty roots under mandatory
//!    authority and carries that bridge leaf with the rest of Posture.
//! 3. [`secrets_descriptor_authority`] performs the handle-aware Secrets
//!    re-seat after ordinary roots have moved.
//!
//! The `migrations` binary is the only consumer. Each migration is additive,
//! content-addressed, replayable, and checks the epoch ordering before it
//! writes.

pub mod descriptor_authority;
mod offer_backfill;
pub mod posture_findings;
pub mod secrets_descriptor_authority;
