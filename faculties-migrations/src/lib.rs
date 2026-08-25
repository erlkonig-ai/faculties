//! Explicit migrations between Faculties storage generations.
//!
//! This crate exists so the faculties do not carry it. Every faculty reads
//! native `Collection`s now; the transforms that got a pile there are needed
//! exactly once per pile, by one binary, and are dead weight in every command
//! that runs afterwards. Keeping them here means the library the faculties
//! depend on has no migration surface at all, while the migrations themselves
//! stay in the repository forever — an existing user's legacy pile has no other
//! path forward, and deleting that path would make their data invisible the day
//! they upgrade.
//!
//! Layout:
//!
//! - [`collection_cutover`] freezes immutable legacy sources and captures
//!   append-stable native collection prefixes for additive migrations.
//! - One `*_cutover` module per faculty holds that faculty's typed transform:
//!   `plan(&FrozenSource)` builds a plan whose `verify_conservation` proves the
//!   produced fragments re-union to exactly the original `TribleSet`, and
//!   `publish` writes them into the faculty's native scope.
//! - [`activation_cutover`] erases every typed plan into one aggregate plan and
//!   proves complete legacy-source coverage.
//! - [`disposable_cutover`] builds that aggregate plan into a disposable
//!   sibling pile and atomically replaces an unchanged live pile.
//! - [`secrets_custody_cutover`] upgrades the later native direct-recipient
//!   generation online through ordered additive COMMITs and a domain replan.
//!
//! The `migrations` binary is the only consumer.

pub mod activation_cutover;
pub mod archive_cutover;
pub mod atlas_cutover;
pub mod body_cutover;
pub mod cognition_cutover;
pub mod collection_cutover;
pub mod collection_naming;
pub mod comb_cutover;
pub mod compass_cutover;
pub mod decide_cutover;
pub mod discord_cutover;
pub mod disposable_cutover;
pub mod files_cutover;
pub mod habit_cutover;
pub mod headspace_cutover;
mod legacy_authority;
pub mod legacy_password;
pub(crate) mod legacy_secrets_v1;
pub mod mail_credentials;
pub mod mail_cutover;
pub mod memory_cutover;
pub mod message_cutover;
pub mod orient_cutover;
pub mod planner_cutover;
pub mod posture_cutover;
pub mod posture_findings;
pub mod relations_cutover;
pub mod secrets_custody_cutover;
pub mod secrets_cutover;
pub mod secrets_vault_cutover;
pub mod status_cutover;
pub mod status_register;
pub mod teams_credentials;
pub mod teams_cutover;
pub mod voice_cutover;
pub mod web_cutover;
pub mod wiki_cutover;

pub mod per_faculty;
