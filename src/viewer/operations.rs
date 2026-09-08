use std::path::PathBuf;
use std::time::Duration;

use anybytes::Bytes;
use anyhow::{bail, Result};

use crate::out::Out;

/// A maintained notebook composition, not a binary or a filesystem path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
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

impl Target {
    pub const ALL: [Self; 12] = [
        Self::Dashboard,
        Self::Atlas,
        Self::Discord,
        Self::Files,
        Self::Gauge,
        Self::Headspace,
        Self::Memory,
        Self::Messages,
        Self::Planner,
        Self::Status,
        Self::Teams,
        Self::Triage,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Dashboard => "dashboard",
            Self::Atlas => "atlas",
            Self::Discord => "discord",
            Self::Files => "files",
            Self::Gauge => "gauge",
            Self::Headspace => "headspace",
            Self::Memory => "memory",
            Self::Messages => "messages",
            Self::Planner => "planner",
            Self::Status => "status",
            Self::Teams => "teams",
            Self::Triage => "triage",
        }
    }

    /// Original notebook card order, including the shared storage top bar.
    pub fn card_names(self) -> &'static [&'static str] {
        match self {
            Self::Dashboard => &[
                "storage",
                "status",
                "headspace",
                "timeline",
                "gauge",
                "wiki",
                "compass",
                "decide",
                "mail",
                "planner",
                "messages",
                "discord",
                "teams",
                "relations",
                "memory",
                "files",
                "triage",
                "atlas",
            ],
            Self::Atlas => &["storage", "atlas"],
            Self::Discord => &["storage", "discord"],
            Self::Files => &["storage", "files"],
            Self::Gauge => &["storage", "gauge"],
            Self::Headspace => &["storage", "headspace"],
            Self::Memory => &["storage", "memory"],
            Self::Messages => &["storage", "messages"],
            Self::Planner => &["storage", "planner"],
            Self::Status => &["storage", "status"],
            Self::Teams => &["storage", "teams"],
            Self::Triage => &["storage", "triage"],
        }
    }
}

/// Explicit renderer and resident-output bounds. The byte bound counts encoded
/// PNGs, not transport base64 or raw GPU allocations. A large card may already
/// have been rendered when its next PNG exceeds an output bound.
#[derive(Clone, Copy, Debug)]
pub struct CaptureOptions {
    pub scale: f32,
    pub settle_timeout: Duration,
    pub max_images: usize,
    pub max_bytes: usize,
}
impl Default for CaptureOptions {
    fn default() -> Self {
        Self {
            scale: 2.0,
            settle_timeout: Duration::from_millis(2000),
            max_images: 64,
            max_bytes: 4 * 1024 * 1024,
        }
    }
}
impl CaptureOptions {
    /// Validate every caller-controlled bound before GPU or pile acquisition.
    pub fn validate(&self) -> Result<()> {
        if !self.scale.is_finite() || !(0.25..=4.0).contains(&self.scale) {
            bail!("capture scale must be finite and in 0.25..=4");
        }
        if self.settle_timeout > Duration::from_secs(5) {
            bail!("capture settle timeout must be at most 5000 ms per layout pass");
        }
        if !(1..=256).contains(&self.max_images) {
            bail!("capture max_images must be in 1..=256");
        }
        if !(1..=32 * 1024 * 1024).contains(&self.max_bytes) {
            bail!("capture max_bytes must be in 1..=33554432");
        }
        Ok(())
    }
}

/// One encoded image in notebook order. All indices are zero-based; a tall
/// card has several successive pages. `png` contains bytes, never a host path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturePage {
    pub card_index: usize,
    pub page_index: usize,
    pub page_count: usize,
    pub width: u32,
    pub height: u32,
    pub png: Bytes,
}
impl CapturePage {
    pub fn emit(&self, target: Target, out: &mut Out<'_>) -> Result<()> {
        out.line(
            serde_json::json!({
                "target": target.name(),
                "card_index": self.card_index,
                "card": target.card_names().get(self.card_index),
                "page_index": self.page_index,
                "page_count": self.page_count,
                "width": self.width,
                "height": self.height,
                "mime_type": "image/png",
            })
            .to_string(),
        )?;
        out.image(self.png.clone(), "image/png")
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CaptureSummary {
    pub images: usize,
    pub bytes: usize,
}

/// Launcher-owned storage configuration. Constructing a Viewer does no I/O.
#[derive(Clone, Debug)]
pub struct Viewer {
    pub(crate) pile: PathBuf,
    pub(crate) key: Option<PathBuf>,
}
impl Viewer {
    pub fn new(pile: impl Into<PathBuf>, key: Option<PathBuf>) -> Self {
        Self {
            pile: pile.into(),
            key,
        }
    }

    pub fn capture(
        &self,
        target: Target,
        options: &CaptureOptions,
        out: &mut Out<'_>,
    ) -> Result<CaptureSummary> {
        self.capture_with(target, options, |page| page.emit(target, out))
    }

    /// Render with synchronous typed delivery. The first renderer or consumer
    /// error is returned; accepted pages are not retried or rerouted.
    pub fn capture_with(
        &self,
        target: Target,
        options: &CaptureOptions,
        mut emit: impl FnMut(CapturePage) -> Result<()>,
    ) -> Result<CaptureSummary> {
        options.validate()?;
        #[cfg(all(feature = "widgets", not(target_arch = "wasm32")))]
        {
            let viewer = self.clone();
            let mut budget = OutputBudget::new(*options);
            GORBIE::NotebookConfig::new(format!("faculties {} capture", target.name()))
                .capture(
                    GORBIE::CaptureOptions {
                        pixels_per_point: options.scale,
                        settle_timeout: options.settle_timeout,
                    },
                    move |nb| super::compose(nb, &viewer, target),
                    |image| {
                        budget
                            .accept(
                                CapturePage {
                                    card_index: image.card_index,
                                    page_index: image.tile_index,
                                    page_count: image.tile_count,
                                    width: image.width,
                                    height: image.height,
                                    png: image.bytes.into(),
                                },
                                &mut emit,
                            )
                            .map_err(anyhow::Error::into_boxed_dyn_error)
                    },
                )
                .map_err(anyhow::Error::from_boxed)?;
            Ok(budget.summary)
        }
        #[cfg(not(all(feature = "widgets", not(target_arch = "wasm32"))))]
        {
            let _ = (target, &mut emit, &self.pile, &self.key);
            bail!("resident notebook capture requires the native `widgets` feature; no GPU or pile was opened")
        }
    }
}

#[cfg(any(test, all(feature = "widgets", not(target_arch = "wasm32"))))]
struct OutputBudget {
    options: CaptureOptions,
    summary: CaptureSummary,
}
#[cfg(any(test, all(feature = "widgets", not(target_arch = "wasm32"))))]
impl OutputBudget {
    fn new(options: CaptureOptions) -> Self {
        Self {
            options,
            summary: CaptureSummary::default(),
        }
    }
    fn accept(
        &mut self,
        page: CapturePage,
        emit: &mut impl FnMut(CapturePage) -> Result<()>,
    ) -> Result<()> {
        let bytes = self
            .summary
            .bytes
            .checked_add(page.png.len())
            .ok_or_else(|| anyhow::anyhow!("capture byte count overflow"))?;
        if self.summary.images >= self.options.max_images || bytes > self.options.max_bytes {
            bail!("capture output exceeds max_images/max_bytes; accepted pages are retained, not retried");
        }
        emit(page)?;
        self.summary.images += 1;
        self.summary.bytes = bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page() -> CapturePage {
        CapturePage {
            card_index: 0,
            page_index: 0,
            page_count: 1,
            width: 1,
            height: 1,
            png: Bytes::from(vec![1_u8, 2, 3]),
        }
    }

    #[test]
    fn budgets_reject_next_output_without_repeating_accepted_pages() {
        for options in [
            CaptureOptions {
                max_images: 1,
                ..Default::default()
            },
            CaptureOptions {
                max_bytes: 5,
                ..Default::default()
            },
        ] {
            let mut budget = OutputBudget::new(options);
            let mut seen = 0;
            budget
                .accept(page(), &mut |_| {
                    seen += 1;
                    Ok(())
                })
                .unwrap();
            assert!(budget
                .accept(page(), &mut |_| {
                    seen += 1;
                    Ok(())
                })
                .is_err());
            assert_eq!(seen, 1);
            assert_eq!(
                budget.summary,
                CaptureSummary {
                    images: 1,
                    bytes: 3
                }
            );
        }
    }

    #[test]
    fn failed_emission_does_not_claim_acceptance() {
        let mut budget = OutputBudget::new(CaptureOptions::default());
        assert!(budget
            .accept(page(), &mut |_| bail!("closed receiver"))
            .is_err());
        assert_eq!(budget.summary, CaptureSummary::default());
    }
}
