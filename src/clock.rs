//! Fallible access to wall-clock time for authored faculty observations.
//!
//! A clock failure must never be converted into a fabricated historical
//! instant.  In an append-only collection that fallback would become signed,
//! durable evidence.  Keep the system-clock effect behind this small boundary
//! and let callers propagate failure before they construct or commit facts.

use anyhow::{anyhow, Result};
use hifitime::{Epoch, HifitimeError};
use triblespace::core::inline::{Inline, TryToInline};
use triblespace::prelude::inlineencodings::NsTAIInterval;

fn read_with(read: impl FnOnce() -> std::result::Result<Epoch, HifitimeError>) -> Result<Epoch> {
    read().map_err(|error| anyhow!("read current clock: {error}"))
}

/// Read the current system time without inventing a fallback instant.
pub fn now() -> Result<Epoch> {
    read_with(Epoch::now)
}

/// Encode an explicit epoch as a point-valued [`NsTAIInterval`].
pub fn point(epoch: Epoch) -> Result<Inline<NsTAIInterval>> {
    (epoch, epoch)
        .try_to_inline()
        .map_err(|error| anyhow!("encode epoch as NsTAIInterval: {error:?}"))
}

/// Read and encode the current system time as a point-valued interval.
pub fn point_now() -> Result<Inline<NsTAIInterval>> {
    point(now()?)
}

/// Read the current TAI coordinate in nanoseconds.
pub fn tai_nanoseconds_now() -> Result<i128> {
    Ok(now()?.to_tai_duration().total_nanoseconds())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn rust_sources(root: &Path, output: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rust_sources(&path, output);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                output.push(path);
            }
        }
    }

    #[test]
    fn clock_failure_remains_an_error() {
        let error = read_with(|| Err(HifitimeError::SystemTimeError)).unwrap_err();
        assert!(error.to_string().contains("read current clock"));
    }

    #[test]
    fn explicit_epoch_encodes_as_an_exact_point() {
        let epoch = Epoch::from_unix_seconds(1_700_000_000.25);
        let encoded = point(epoch).unwrap();
        let decoded: (Epoch, Epoch) = encoded.try_from_inline().unwrap();
        assert_eq!(decoded, (epoch, epoch));
    }

    #[test]
    fn system_epoch_reads_stay_behind_the_fallible_clock_boundary() {
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let clock_source = source_root.join("clock.rs");
        let mut sources = Vec::new();
        rust_sources(&source_root, &mut sources);
        sources.sort();
        for path in sources {
            if path == clock_source {
                continue;
            }
            let source = std::fs::read_to_string(&path).unwrap();
            assert!(
                !source.contains("Epoch::now()") && !source.contains("hifitime::Epoch::now()"),
                "{} reads the system epoch outside faculties::clock",
                path.display()
            );
        }
    }
}
