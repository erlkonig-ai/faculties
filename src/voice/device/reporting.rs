use super::SpeechDisposition;

/// An output sink rejected a speech report. This is not evidence of a device
/// failure. `playback` is known only when the local queue has already drained;
/// otherwise playback may have begun but was interrupted by the reporting error.
#[derive(Debug)]
pub struct SpeechReportingError {
    pub playback: Option<SpeechDisposition>,
}
impl std::fmt::Display for SpeechReportingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.playback {
            Some(SpeechDisposition::LocalPlaybackDrained) => {
                formatter.write_str("speech reporting failed after local playback drained")
            }
            _ => formatter.write_str("speech reporting failed; playback completion is unknown"),
        }
    }
}
impl std::error::Error for SpeechReportingError {}

#[cfg(any(feature = "voice", test))]
pub(super) fn report(
    out: &mut crate::out::Out<'_>,
    line: String,
    playback: Option<SpeechDisposition>,
) -> anyhow::Result<()> {
    out.line(line)
        .map_err(|error| error.context(SpeechReportingError { playback }))
}

/// The chunk has left the generator; retain it before the first fallible
/// report. On failure the caller can drain the rest without losing this chunk.
#[cfg(any(feature = "voice", test))]
pub(super) fn retain_before_report(
    samples: &mut Vec<f32>,
    chunk: &[f32],
    report: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    samples.extend_from_slice(chunk);
    report()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::out::Out;

    #[test]
    fn consumed_chunk_survives_reporting_failure_and_remaining_drain() {
        let mut stream = [vec![0.1, 0.2], vec![0.3], vec![0.4, 0.5]].into_iter();
        let mut samples = stream.next().unwrap();
        let chunk = stream.next().unwrap();
        let mut calls = 0;
        let mut reject = |_| {
            calls += 1;
            anyhow::bail!("output disconnected")
        };
        let error = retain_before_report(&mut samples, &chunk, || {
            report(&mut Out::new(&mut reject), "underrun".into(), None)
        })
        .unwrap_err();
        let stage = error.downcast_ref::<SpeechReportingError>().unwrap();
        assert_eq!(stage.playback, None);
        assert!(format!("{error:#}").contains("output disconnected"));
        for chunk in stream {
            samples.extend_from_slice(&chunk);
        }
        assert_eq!(samples, [0.1, 0.2, 0.3, 0.4, 0.5]);
        assert_eq!(calls, 1);
        let audio = crate::voice::synthesis::AudioClip::from_samples(&samples, 24_000).unwrap();
        assert_eq!(audio.sample_count, 5);
    }

    #[test]
    fn failed_completion_report_preserves_known_local_drain() {
        let error = report(
            &mut Out::new(&mut |_| anyhow::bail!("delivery failed")),
            "played".into(),
            Some(SpeechDisposition::LocalPlaybackDrained),
        )
        .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<SpeechReportingError>()
                .unwrap()
                .playback,
            Some(SpeechDisposition::LocalPlaybackDrained)
        );
    }

    #[test]
    fn accepted_reporting_keeps_one_copy_of_the_chunk() {
        let mut samples = vec![0.1];
        retain_before_report(&mut samples, &[0.2], || Ok(())).unwrap();
        assert_eq!(samples, [0.1, 0.2]);
    }
}
