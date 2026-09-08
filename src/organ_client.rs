//! Synchronous CLI adapter for Drive's existing `organ/1` media receiver.
//!
//! No custody key is borrowed implicitly. The default sender is an ephemeral
//! transport identity; a receiver with a peer allowlist needs an explicit
//! dedicated sender key via `DRIVE_KEY`. This adapter is not used by MCP.

mod audio;

use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use framed_stream::{EndStatus, FramedWriter, TEXT_PLAIN, UNIT_BYTES};
use iroh_base::{EndpointAddr, EndpointId, SecretKey};
use triblespace::core::signing_key_file;

use crate::out::Part;

const ALPN: &[u8] = b"organ/1";
const IO_DEADLINE: Duration = Duration::from_secs(15);

pub(crate) struct DriveOutput {
    writer: FramedWriter<Stream>,
}

impl DriveOutput {
    pub(crate) fn open(address: &str, key: Option<&Path>, label: &str) -> Result<Self> {
        let (identity, direct) = match address.split_once('@') {
            Some((identity, direct)) => (identity, Some(direct.parse()?)),
            None => (address, None),
        };
        let identity: EndpointId = identity.parse().context("parse Drive endpoint id")?;
        let mut address = EndpointAddr::from(identity);
        if let Some(direct) = direct {
            address = address.with_ip_addr(direct);
        }
        let secret = key
            .map(signing_key_file::load_existing)
            .transpose()?
            .map(|key| SecretKey::from(key.to_bytes()));
        Self::connect(address, secret, label)
    }

    fn connect(address: EndpointAddr, secret: Option<SecretKey>, label: &str) -> Result<Self> {
        anyhow::ensure!(
            label.len() + 7 <= 256 && !label.contains(['\r', '\n']),
            "invalid faculty label"
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("faculty-output")
            .build()?;
        let (endpoint, send) = runtime.block_on(async {
            let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::N0);
            if let Some(secret) = secret {
                builder = builder.secret_key(secret);
            }
            let endpoint = builder.bind().await?;
            let send = tokio::time::timeout(IO_DEADLINE, async {
                let connection = endpoint.connect(address, ALPN).await?;
                let mut send = connection.open_uni().await?;
                send.write_all(format!("sense {label}\n").as_bytes())
                    .await?;
                Ok::<_, anyhow::Error>((connection, send))
            })
            .await
            .context("Drive connection timed out")?;
            match send {
                Ok((connection, send)) => Ok((endpoint, (connection, send))),
                Err(error) => {
                    endpoint.close().await;
                    Err(error)
                }
            }
        })?;
        let (connection, send) = send;
        let stream = Stream {
            runtime: Some(runtime),
            endpoint,
            connection,
            send,
        };
        Ok(Self {
            writer: FramedWriter::open(stream, TEXT_PLAIN, UNIT_BYTES)?,
        })
    }

    pub(crate) fn emit(&mut self, part: Part) -> Result<()> {
        write_part(&mut self.writer, part)
    }

    pub(crate) fn finish(self, error: Option<&anyhow::Error>) -> Result<()> {
        let status = match error {
            None => EndStatus::Complete,
            Some(error) => EndStatus::Aborted(format!("{error:#}").chars().take(1024).collect()),
        };
        self.writer.finish(status)?.finish()
    }
}

fn write_part<W: Write>(writer: &mut FramedWriter<W>, part: Part) -> Result<()> {
    match part {
        Part::Text { text } => writer.record_as(TEXT_PLAIN, text.as_bytes(), text.len() as u64),
        Part::Image { bytes, mime_type } => {
            writer.record_as(&mime_type, bytes.as_ref(), bytes.len() as u64)
        }
        Part::Audio { bytes, mime_type } => {
            let (bytes, mime_type) = audio::prepare(bytes, &mime_type)?;
            writer.record_as(&mime_type, bytes.as_ref(), bytes.len() as u64)
        }
        Part::Blob { .. } => anyhow::bail!("binary exports are not sensory input"),
    }
}

struct Stream {
    runtime: Option<tokio::runtime::Runtime>,
    endpoint: iroh::Endpoint,
    connection: iroh::endpoint::Connection,
    send: iroh::endpoint::SendStream,
}

impl Stream {
    fn finish(mut self) -> Result<()> {
        self.runtime
            .as_ref()
            .expect("live output runtime")
            .block_on(async {
                self.send.finish().context("finish Drive stream")?;
                let stopped = tokio::time::timeout(IO_DEADLINE, self.send.stopped())
                    .await
                    .context("Drive delivery timed out")??;
                anyhow::ensure!(
                    stopped.is_none(),
                    "Drive stopped its input stream: {stopped:?}"
                );
                Ok(())
            })
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.runtime
            .as_ref()
            .expect("live output runtime")
            .block_on(async {
                tokio::time::timeout(IO_DEADLINE, self.send.write_all(bytes))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Drive output timed out"))?
                    .map_err(io::Error::other)?;
                Ok(bytes.len())
            })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            self.connection.close(0u32.into(), b"faculty output ended");
            runtime.block_on(self.endpoint.close());
            runtime.shutdown_background();
        }
    }
}

#[cfg(test)]
mod tests {
    use framed_stream::{Frame, FramedReader};

    use super::*;

    #[test]
    fn mixed_parts_roundtrip_through_existing_drive_framing() {
        let mut writer = FramedWriter::open(Vec::new(), TEXT_PLAIN, UNIT_BYTES).unwrap();
        write_part(
            &mut writer,
            Part::Text {
                text: "hello\n".into(),
            },
        )
        .unwrap();
        write_part(
            &mut writer,
            Part::Image {
                bytes: vec![1_u8, 2, 3].into(),
                mime_type: "image/png".into(),
            },
        )
        .unwrap();
        write_part(
            &mut writer,
            Part::Audio {
                bytes: vec![4_u8, 5].into(),
                mime_type: "audio/L16;rate=24000;channels=1".into(),
            },
        )
        .unwrap();
        let bytes = writer.finish(EndStatus::Complete).unwrap();
        let mut reader = FramedReader::open(bytes.as_slice()).unwrap();
        let mut types = Vec::new();
        let mut payloads = Vec::new();
        loop {
            match reader.next_frame().unwrap() {
                Frame::Record(record) => {
                    types.push(record.content_type().to_owned());
                    payloads.push(record.payload);
                }
                Frame::End(status) => {
                    assert_eq!(status, EndStatus::Complete);
                    break;
                }
                Frame::Gap(_) => panic!("unexpected gap"),
            }
        }
        assert_eq!(
            types,
            [TEXT_PLAIN, "image/png", "audio/L16;rate=24000;channels=1"]
        );
        assert_eq!(payloads, [b"hello\n".to_vec(), vec![1, 2, 3], vec![4, 5]]);
    }

    #[test]
    fn explicit_exports_are_rejected_without_becoming_sense_records() {
        let mut writer = FramedWriter::open(Vec::new(), TEXT_PLAIN, UNIT_BYTES).unwrap();
        let error = write_part(
            &mut writer,
            Part::Blob {
                bytes: vec![0_u8, 255].into(),
                mime_type: "image/png".into(),
                uri: "files:original".into(),
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("not sensory input"));
        assert_eq!(writer.index(), 0);
        assert_eq!(writer.offset(), 0);
        let bytes = writer.finish(EndStatus::Complete).unwrap();
        let mut reader = FramedReader::open(bytes.as_slice()).unwrap();
        assert_eq!(
            reader.next_frame().unwrap(),
            Frame::End(EndStatus::Complete)
        );
    }

    #[test]
    fn native_sender_delivers_the_complete_stream_over_real_iroh() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let endpoint = runtime.block_on(async {
            iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
                .alpns(vec![ALPN.to_vec()])
                .bind_addr("127.0.0.1:0")
                .unwrap()
                .bind()
                .await
                .unwrap()
        });
        let address = EndpointAddr::from(endpoint.id()).with_ip_addr(
            endpoint
                .bound_sockets()
                .into_iter()
                .find(|address| address.is_ipv4())
                .unwrap(),
        );
        let receiver = endpoint.clone();
        let received = runtime.spawn(async move {
            tokio::time::timeout(IO_DEADLINE, async {
                let connection = receiver.accept().await.unwrap().await.unwrap();
                let mut stream = connection.accept_uni().await.unwrap();
                stream.read_to_end(64 * 1024).await.unwrap()
            })
            .await
            .unwrap()
        });
        let mut output = DriveOutput::connect(address, None, "atlas").unwrap();
        output
            .emit(Part::Text {
                text: "first\n".into(),
            })
            .unwrap();
        output
            .emit(Part::Image {
                bytes: vec![0_u8, 1, 2].into(),
                mime_type: "image/png".into(),
            })
            .unwrap();
        output.finish(None).unwrap();
        let bytes = runtime.block_on(received).unwrap();
        let body = bytes
            .strip_prefix(b"sense atlas\n")
            .expect("native organ hello");
        let mut reader = FramedReader::open(body).unwrap();
        let Frame::Record(text) = reader.next_frame().unwrap() else {
            panic!("missing text")
        };
        assert_eq!(text.payload, b"first\n");
        let Frame::Record(image) = reader.next_frame().unwrap() else {
            panic!("missing image")
        };
        assert_eq!(image.content_type(), "image/png");
        assert_eq!(image.payload, [0, 1, 2]);
        assert_eq!(
            reader.next_frame().unwrap(),
            Frame::End(EndStatus::Complete)
        );
        runtime.block_on(endpoint.close());
    }
}
