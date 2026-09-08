use super::SpeechDisposition;

/// Audio retention or journaling failed after a known playback outcome.
/// The context preserves that outcome without implying that playback should
/// be retried. The underlying error remains in the returned anyhow chain.
#[derive(Debug)]
pub struct SpeechRetentionError {
    pub disposition: SpeechDisposition,
}
impl std::fmt::Display for SpeechRetentionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("audio retention or journaling failed after ")?;
        match self.disposition {
            SpeechDisposition::LocalPlaybackDrained => {
                formatter.write_str("local playback drained")
            }
            SpeechDisposition::ReachyRequestAccepted => formatter
                .write_str("Reachy accepted the playback request; completion was not observed"),
            SpeechDisposition::DryRun => formatter.write_str("a dry run"),
            SpeechDisposition::TextFallback => formatter.write_str("text fallback"),
        }
    }
}
impl std::error::Error for SpeechRetentionError {}

/// Classify an already-completed retention attempt. Accepting a result instead
/// of a closure makes this boundary unable to retry or issue a fallback.
pub(super) fn retain_after_playback<T>(
    disposition: SpeechDisposition,
    retained: anyhow::Result<T>,
) -> anyhow::Result<T> {
    retained.map_err(|error| error.context(SpeechRetentionError { disposition }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_retention_preserves_known_playback_and_the_underlying_error() {
        for (disposition, diagnostic) in [
            (
                SpeechDisposition::LocalPlaybackDrained,
                "local playback drained",
            ),
            (
                SpeechDisposition::ReachyRequestAccepted,
                "completion was not observed",
            ),
        ] {
            let error = retain_after_playback::<u8>(
                disposition,
                Err(
                    std::io::Error::new(std::io::ErrorKind::PermissionDenied, "journal denied")
                        .into(),
                ),
            )
            .unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<SpeechRetentionError>()
                    .unwrap()
                    .disposition,
                disposition,
            );
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::PermissionDenied,
            );
            assert!(error
                .downcast_ref::<super::super::SpeechReportingError>()
                .is_none());
            assert!(format!("{error:#}").contains(diagnostic));
            assert!(format!("{error:#}").contains("journal denied"));
        }
    }

    #[test]
    fn successful_retention_returns_the_original_result() {
        assert_eq!(
            retain_after_playback(SpeechDisposition::LocalPlaybackDrained, Ok(7_u8)).unwrap(),
            7,
        );
    }
}
