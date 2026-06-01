//! GORBIE-embeddable viewers for faculty data.
//!
//! Only available behind the `widgets` feature flag.

pub mod compass;
pub mod decide;
pub mod gauge;
pub mod headspace;
pub mod mail;
pub mod memory;
pub mod messages;
pub mod planner;
pub mod relations;
pub mod storage;
pub mod timeline;
pub mod wiki;

pub use compass::CompassBoard;
pub use decide::DecidePanel;
pub use gauge::GaugeViewer;
pub use headspace::HeadspaceViewer;
pub use mail::MailViewer;
pub use memory::MemoryViewer;
pub use messages::MessagesPanel;
pub use planner::PlannerViewer;
pub use relations::RelationsViewer;
pub use storage::StorageState;
pub use timeline::{BranchTimeline, SourceKind, TimelineSource};
pub use wiki::WikiViewer;
