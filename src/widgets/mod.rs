//! GORBIE-embeddable viewers for faculty data.
//!
//! Only available behind the `widgets` feature flag.

pub mod compass;
pub mod decide;
pub mod headspace;
pub mod mail;
pub mod messages;
pub mod planner;
pub mod relations;
pub mod storage;
pub mod timeline;
pub mod wiki;

pub use compass::CompassBoard;
pub use decide::DecidePanel;
pub use headspace::HeadspaceViewer;
pub use mail::MailViewer;
pub use messages::MessagesPanel;
pub use planner::PlannerViewer;
pub use relations::RelationsViewer;
pub use storage::StorageState;
pub use timeline::{BranchTimeline, SourceKind, TimelineSource};
pub use wiki::WikiViewer;
