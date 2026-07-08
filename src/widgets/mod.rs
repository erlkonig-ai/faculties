//! GORBIE-embeddable viewers for faculty data.
//!
//! Only available behind the `widgets` feature flag.

pub mod atlas;
pub mod compass;
pub mod decide;
pub mod discord;
pub mod files;
pub mod gauge;
pub mod headspace;
pub mod mail;
pub mod memory;
pub mod messages;
pub mod planner;
pub mod relations;
pub mod review;
pub mod status;
pub mod storage;
pub mod teams;
pub mod timeline;
pub mod triage;
pub mod wiki;

pub use atlas::AtlasViewer;
pub use compass::CompassBoard;
pub use decide::DecidePanel;
pub use discord::DiscordViewer;
pub use files::FilesViewer;
pub use gauge::GaugeViewer;
pub use headspace::HeadspaceViewer;
pub use mail::MailViewer;
pub use memory::MemoryViewer;
pub use messages::MessagesPanel;
pub use planner::PlannerViewer;
pub use relations::RelationsViewer;
pub use review::ReviewPanel;
pub use status::StatusViewer;
pub use storage::StorageState;
pub use teams::TeamsViewer;
pub use timeline::{BranchTimeline, SourceKind, TimelineSource};
pub use triage::TriageViewer;
pub use wiki::WikiViewer;
