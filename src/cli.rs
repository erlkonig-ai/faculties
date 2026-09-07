//! CLI projection of a native faculty: argument lowering and output routing.
//!
//! `DRIVE_ENDPOINT` selects Drive's existing framed organ transport. Without
//! it, text is written exactly to stdout and media receives a descriptive text
//! marker. An explicit Blob export writes byte-for-byte to stdout. An explicitly
//! configured endpoint failure is an error, not a reason
//! to silently deliver the same output through another channel.

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
            let mut sink = Output::from_env(spec.name)?;
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

enum Output {
    Terminal(io::Stdout),
    Drive(DriveOutput),
}

impl Output {
    fn from_env(label: &str) -> Result<Self> {
        let Some(endpoint) = std::env::var_os("DRIVE_ENDPOINT") else {
            return Ok(Self::Terminal(io::stdout()));
        };
        let endpoint = endpoint
            .into_string()
            .map_err(|_| anyhow::anyhow!("DRIVE_ENDPOINT is not UTF-8"))?;
        let key = std::env::var_os("DRIVE_KEY").map(PathBuf::from);
        DriveOutput::open(&endpoint, key.as_deref(), label)
            .map(Self::Drive)
            .context("open configured Drive output")
    }

    fn emit(&mut self, part: Part) -> Result<()> {
        match self {
            Self::Terminal(stdout) => render_terminal(&mut stdout.lock(), part),
            Self::Drive(output) => output.emit(part),
        }
    }

    fn finish(self, error: Option<&anyhow::Error>) -> Result<()> {
        match self {
            Self::Terminal(mut stdout) => stdout.flush().context("flush faculty stdout"),
            Self::Drive(output) => output.finish(error),
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
}
