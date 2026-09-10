//! Explicit finite capture only; neither GUI startup nor filesystem/web export
//! is a remotely supplied operation. The launcher owns pile and signing key.

use std::path::PathBuf;
use std::time::Duration;

use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;

use super::{CaptureOptions, Target};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;

pub struct Viewer(super::Viewer);
impl Viewer {
    pub fn new(pile: impl Into<PathBuf>, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile.into(), key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self(super::Viewer::with_storage(storage))
    }
}

const TOOLS: &[Tool] = &[Tool {
    name: "viewer_capture",
    description: "Render the selected shared notebook against the launcher-configured pile, returning ordered card/page metadata and resident PNG images. Requires the native widgets feature and a local GPU; discovery does not open either. This is one finite capture, not a window, watcher, host file path or web export. The images include normal viewer loading/error banners; capture does not certify source completeness. Dashboard preserves all existing widgets and may initialize their own local GPU computations. Settle timeout is per layout pass; output bounds limit PNG bytes/images, not raw renderer allocations or transport base64. Previously emitted pages are not retried on failure.",
    input_schema: r#"{"type":"object","properties":{"target":{"type":"string","enum":["dashboard","atlas","discord","files","gauge","headspace","memory","messages","planner","status","teams","triage"]},"scale":{"type":"number","minimum":0.25,"maximum":4,"default":2},"settle_ms":{"type":"integer","minimum":0,"maximum":5000,"default":2000},"max_images":{"type":"integer","minimum":1,"maximum":256,"default":64},"max_bytes":{"type":"integer","minimum":1,"maximum":33554432,"default":4194304}},"required":["target"],"additionalProperties":false}"#,
}];

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CaptureTarget {
    Dashboard,
    Atlas,
    Discord,
    Files,
    Gauge,
    Headspace,
    Memory,
    Messages,
    Planner,
    Status,
    Teams,
    Triage,
}
impl From<CaptureTarget> for Target {
    fn from(value: CaptureTarget) -> Self {
        match value {
            CaptureTarget::Dashboard => Self::Dashboard,
            CaptureTarget::Atlas => Self::Atlas,
            CaptureTarget::Discord => Self::Discord,
            CaptureTarget::Files => Self::Files,
            CaptureTarget::Gauge => Self::Gauge,
            CaptureTarget::Headspace => Self::Headspace,
            CaptureTarget::Memory => Self::Memory,
            CaptureTarget::Messages => Self::Messages,
            CaptureTarget::Planner => Self::Planner,
            CaptureTarget::Status => Self::Status,
            CaptureTarget::Teams => Self::Teams,
            CaptureTarget::Triage => Self::Triage,
        }
    }
}
fn scale() -> f32 {
    2.0
}
fn settle_ms() -> u64 {
    2000
}
fn max_images() -> usize {
    64
}
fn max_bytes() -> usize {
    4 * 1024 * 1024
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    target: CaptureTarget,
    #[serde(default = "scale")]
    scale: f32,
    #[serde(default = "settle_ms")]
    settle_ms: u64,
    #[serde(default = "max_images")]
    max_images: usize,
    #[serde(default = "max_bytes")]
    max_bytes: usize,
}

impl Faculty for Viewer {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        if name != "viewer_capture" {
            bail!("unknown Viewer MCP tool {name:?}");
        }
        let a: Capture = decode_arguments(arguments)?;
        let options = CaptureOptions {
            scale: a.scale,
            settle_timeout: Duration::from_millis(a.settle_ms),
            max_images: a.max_images,
            max_bytes: a.max_bytes,
        };
        options.validate().map_err(invalid_arguments)?;
        let summary = self.0.capture(a.target.into(), &options, out)?;
        out.line(format!(
            "{} PNG image(s), {} encoded bytes",
            summary.images, summary.bytes
        ))
    }
}
