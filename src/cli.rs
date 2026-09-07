//! CLI projection of a native faculty: argument lowering and output routing.
//!
//! `DRIVE_ENDPOINT` selects Drive's existing framed organ transport for
//! perception: text, images, and audio. Without it, text is written exactly to
//! stdout and media receives a descriptive text marker. Explicit Blob exports
//! always write byte-for-byte to stdout, without opening a sensory connection.
//! A configured perception endpoint failure is an error, never a stdout fallback.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::organ_client::DriveOutput;
use crate::out::{Out, Part};
use crate::spec::{CliRequest, Invocation, Spec};

/// Run a synchronous native command through its generated CLI.
pub fn run(
    spec: &'static Spec,
    execute: fn(&Invocation, &mut Out<'_>) -> Result<()>,
) -> Result<()> {
    match spec
        .lower_cli_from(std::env::args_os())
        .unwrap_or_else(|error| error.exit())
    {
        CliRequest::Help(help) => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(help.as_bytes())?;
            stdout.flush()?;
            Ok(())
        }
        CliRequest::Invoke(invocation) => {
            let mut sink = Output::from_env(spec.name);
            let result = execute(&invocation, &mut Out::new(&mut |part| sink.emit(part)));
            let finished = sink.finish(result.as_ref().err());
            match (result, finished) {
                (Ok(()), result) => result,
                (Err(error), Ok(())) => Err(error),
                (Err(error), Err(finish_error)) => Err(error.context(format!(
                    "finishing faculty output also failed: {finish_error:#}"
                ))),
            }
        }
    }
}

struct DriveConfig {
    endpoint: OsString,
    key: Option<PathBuf>,
    label: &'static str,
}

enum Output<W> {
    Terminal(W),
    Drive {
        stdout: W,
        config: Option<DriveConfig>,
        output: Option<DriveOutput>,
    },
}

impl Output<io::Stdout> {
    fn from_env(label: &'static str) -> Self {
        let Some(endpoint) = std::env::var_os("DRIVE_ENDPOINT") else {
            return Self::Terminal(io::stdout());
        };
        Self::Drive {
            stdout: io::stdout(),
            config: Some(DriveConfig {
                endpoint,
                key: std::env::var_os("DRIVE_KEY").map(PathBuf::from),
                label,
            }),
            output: None,
        }
    }
}

impl<W: Write> Output<W> {
    fn emit(&mut self, part: Part) -> Result<()> {
        match (self, part) {
            (Self::Terminal(stdout), part)
            | (Self::Drive { stdout, .. }, part @ Part::Blob { .. }) => {
                render_terminal(stdout, part)
            }
            (Self::Drive { config, output, .. }, part) => {
                if output.is_none() {
                    // Take before attempting IO: an uncertain connection is
                    // never retried if a handler ignores the emission error.
                    let config = config
                        .take()
                        .context("configured Drive output connection previously failed")?;
                    let endpoint = config
                        .endpoint
                        .to_str()
                        .context("DRIVE_ENDPOINT is not UTF-8")?;
                    *output = Some(
                        DriveOutput::open(endpoint, config.key.as_deref(), config.label)
                            .context("open configured Drive output")?,
                    );
                }
                output.as_mut().expect("opened above").emit(part)
            }
        }
    }

    fn finish(self, error: Option<&anyhow::Error>) -> Result<()> {
        match self {
            Self::Terminal(mut stdout) => stdout.flush().context("flush faculty stdout"),
            Self::Drive {
                mut stdout, output, ..
            } => {
                let flushed = stdout.flush().context("flush faculty stdout");
                let finished = match output {
                    Some(output) => output.finish(error.or(flushed.as_ref().err())),
                    None => Ok(()),
                };
                match (flushed, finished) {
                    (Ok(()), result) | (result, Ok(())) => result,
                    (Err(error), Err(finish_error)) => Err(error.context(format!(
                        "finishing Drive output also failed: {finish_error:#}"
                    ))),
                }
            }
        }
    }
}

fn render_terminal(writer: &mut impl Write, part: Part) -> Result<()> {
    match part {
        Part::Text { text } => writer.write_all(text.as_bytes())?,
        Part::Image { bytes, mime_type } => {
            writeln!(writer, "[image: {mime_type}, {} bytes]", bytes.len())?;
        }
        Part::Audio { bytes, mime_type } => {
            writeln!(writer, "[audio: {mime_type}, {} bytes]", bytes.len())?;
        }
        Part::Blob { bytes, .. } => writer.write_all(bytes.as_ref())?,
    }
    writer.flush().context("emit faculty stdout")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_exact_and_media_never_dumps_binary_to_the_terminal() {
        let mut output = Vec::new();
        for part in [
            Part::Text {
                text: "hello\n".into(),
            },
            Part::Image {
                bytes: vec![0xff_u8, 0].into(),
                mime_type: "image/png".into(),
            },
            Part::Audio {
                bytes: vec![1_u8, 2, 3].into(),
                mime_type: "audio/wav".into(),
            },
            Part::Text {
                text: "tail".into(),
            },
        ] {
            render_terminal(&mut output, part).unwrap();
        }
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "hello\n[image: image/png, 2 bytes]\n[audio: audio/wav, 3 bytes]\ntail"
        );
    }

    #[test]
    fn output_error_is_not_hidden() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert!(render_terminal(&mut Broken, Part::Text { text: "x".into() }).is_err());
    }

    #[test]
    fn explicit_blob_export_is_byte_exact_even_for_non_utf8() {
        let bytes = anybytes::Bytes::from(vec![0_u8, 0xff, b'\n', 0x80]);
        let mut output = Vec::new();
        render_terminal(
            &mut output,
            Part::Blob {
                bytes: bytes.clone(),
                mime_type: "application/octet-stream".into(),
                uri: "files:test-export".into(),
            },
        )
        .unwrap();
        assert_eq!(output, bytes.as_ref());
    }

    fn unusable_drive<W>(stdout: W) -> Output<W> {
        Output::Drive {
            stdout,
            config: Some(DriveConfig {
                endpoint: "not-an-endpoint".into(),
                key: None,
                label: "test",
            }),
            output: None,
        }
    }

    #[test]
    fn raw_exports_and_empty_output_never_open_a_sensory_connection() {
        for export in [false, true] {
            let mut stdout = Vec::new();
            let mut output = unusable_drive(&mut stdout);
            if export {
                output
                    .emit(Part::Blob {
                        bytes: vec![0_u8, 255, 10, 128].into(),
                        // Export intent, not MIME, determines the destination.
                        mime_type: "image/png".into(),
                        uri: "files:original".into(),
                    })
                    .unwrap();
            }
            output.finish(None).unwrap();
            assert_eq!(
                stdout,
                if export {
                    vec![0, 255, 10, 128]
                } else {
                    vec![]
                }
            );
        }
    }

    #[test]
    fn perception_connection_failure_does_not_retry_or_fall_back() {
        let mut stdout = Vec::new();
        let mut output = unusable_drive(&mut stdout);
        let failed = output
            .emit(Part::Text {
                text: "first".into(),
            })
            .unwrap_err();
        assert!(format!("{failed:#}").contains("open configured Drive output"));
        let repeated = output
            .emit(Part::Text {
                text: "second".into(),
            })
            .unwrap_err();
        assert!(format!("{repeated:#}").contains("previously failed"));
        output.finish(Some(&failed)).unwrap();
        assert!(stdout.is_empty());
    }

    #[test]
    fn mixed_output_splits_exports_from_ordered_perceptions_over_real_iroh() {
        use framed_stream::{EndStatus, Frame, FramedReader};
        use std::time::Duration;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let endpoint = runtime.block_on(async {
            iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .alpns(vec![b"organ/1".to_vec()])
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .bind()
                .await
                .unwrap()
        });
        let direct = endpoint
            .bound_sockets()
            .into_iter()
            .find(|address| address.is_ipv4())
            .unwrap();
        let receiver = endpoint.clone();
        let received = runtime.spawn(async move {
            tokio::time::timeout(Duration::from_secs(15), async {
                let connection = receiver.accept().await.unwrap().await.unwrap();
                let mut stream = connection.accept_uni().await.unwrap();
                stream.read_to_end(64 * 1024).await.unwrap()
            })
            .await
            .unwrap()
        });
        let mut stdout = Vec::new();
        let mut output = Output::Drive {
            stdout: &mut stdout,
            config: Some(DriveConfig {
                endpoint: format!("{}@{direct}", endpoint.id()).into(),
                key: None,
                label: "mixed",
            }),
            output: None,
        };
        for part in [
            Part::Text {
                text: "first\n".into(),
            },
            Part::Blob {
                bytes: vec![0_u8, 255, 10, 128].into(),
                mime_type: "image/png".into(),
                uri: "files:export-not-a-perception".into(),
            },
            Part::Image {
                bytes: vec![1_u8, 2].into(),
                mime_type: "image/png".into(),
            },
            Part::Audio {
                bytes: vec![3_u8, 4].into(),
                mime_type: "audio/wav".into(),
            },
        ] {
            output.emit(part).unwrap();
        }
        output
            .finish(Some(&anyhow::anyhow!("later handler failure")))
            .unwrap();
        assert_eq!(stdout, [0, 255, 10, 128]);
        let bytes = runtime.block_on(received).unwrap();
        let mut reader = FramedReader::open(bytes.strip_prefix(b"sense mixed\n").unwrap()).unwrap();
        for (mime, bytes) in [
            (framed_stream::TEXT_PLAIN, b"first\n".as_slice()),
            ("image/png", &[1, 2][..]),
            ("audio/wav", &[3, 4][..]),
        ] {
            let Frame::Record(record) = reader.next_frame().unwrap() else {
                panic!("missing perception")
            };
            assert_eq!(record.content_type(), mime);
            assert_eq!(record.payload, bytes);
        }
        assert_eq!(
            reader.next_frame().unwrap(),
            Frame::End(EndStatus::Aborted("later handler failure".into()))
        );
        runtime.block_on(endpoint.close());
    }
}
