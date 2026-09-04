//! The sense side of her organs: how a command she runs pushes a framed
//! stream into drive's endpoint.
//!
//! Her organs are iroh endpoints under the box's mesh key (`drive::organ`).
//! A sense dials one, opens one unidirectional stream, writes a hello line
//! naming itself, then an ordinary framed stream whose preamble declares the
//! content type -- raw media, never derived -- and keeps writing records for
//! as long as it runs. Ending the stream (or the process) ends the session;
//! the organ says so and she reads nothing further from it.
//!
//! The organ is named `<id>[@ip:port]`: the endpoint id as `trible pile net
//! identity` prints it, optionally with a direct address so a sense on the
//! same network need not discover it.

use std::io::Write;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use iroh_base::{EndpointAddr, EndpointId, SecretKey};

/// The protocol a sense speaks to an organ (`drive::organ::ALPN`).
pub const ALPN: &[u8] = b"organ/1";

/// The custody mesh key of the box, the identity the organ's allowlist knows.
pub fn default_key_path() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    home.join(".local/share/triblespace/custody/network.key")
}

/// An open session into an organ: a `Write` whose bytes go down one iroh
/// stream. Wrap it in a [`framed_stream::FramedWriter`] via [`open`].
pub struct OrganSink {
    runtime: tokio::runtime::Runtime,
    _endpoint: iroh::Endpoint,
    _connection: iroh::endpoint::Connection,
    send: iroh::endpoint::SendStream,
}

impl Write for OrganSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.runtime
            .block_on(self.send.write_all(buf))
            .map_err(|error| std::io::Error::other(format!("organ stream: {error}")))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl OrganSink {
    /// Say the stream is over and wait for the organ to have it all.
    pub fn close(mut self) -> Result<()> {
        self.runtime.block_on(async {
            self.send.finish().context("finish the organ stream")?;
            // Wait for the peer to acknowledge before the endpoint goes away
            // with the tail of the stream still in flight.
            let _ = self.send.stopped().await;
            Ok::<(), anyhow::Error>(())
        })?;
        self.runtime.block_on(async {
            self._connection.close(0u32.into(), b"done");
            self._endpoint.close().await;
        });
        Ok(())
    }
}

/// Dial `organ` as `label`, and start a framed stream of `content_type`
/// counted in `unit`. The returned writer's records go straight to her.
pub fn open(
    organ: &str,
    key: &Path,
    label: &str,
    content_type: &str,
    unit: &str,
) -> Result<framed_stream::FramedWriter<OrganSink>> {
    let (id, direct) = parse_organ(organ)?;
    let secret = load_secret(key)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .thread_name("sense-organ")
        .build()
        .context("build the sense's runtime")?;
    let (endpoint, connection, mut send) = runtime.block_on(async {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret)
            .bind()
            .await
            .map_err(|error| anyhow::anyhow!("bind the sense's endpoint: {error}"))?;
        let mut addr = EndpointAddr::from(id);
        if let Some(sock) = direct {
            addr = addr.with_ip_addr(sock);
        }
        let connection = endpoint
            .connect(addr, ALPN)
            .await
            .map_err(|error| anyhow::anyhow!("dial the organ {organ}: {error}"))?;
        let mut send = connection
            .open_uni()
            .await
            .map_err(|error| anyhow::anyhow!("open a stream into the organ: {error}"))?;
        send.write_all(format!("sense {label}\n").as_bytes())
            .await
            .map_err(|error| anyhow::anyhow!("say hello to the organ: {error}"))?;
        Ok::<_, anyhow::Error>((endpoint, connection, send))
    })?;
    eprintln!(
        "sense {label}: connected to organ {} as {}",
        id,
        endpoint.id()
    );
    let _ = &mut send;
    let sink = OrganSink {
        runtime,
        _endpoint: endpoint,
        _connection: connection,
        send,
    };
    framed_stream::FramedWriter::open(sink, content_type, unit)
        .context("open the framed stream into the organ")
}

/// `<id>[@ip:port]`.
fn parse_organ(organ: &str) -> Result<(EndpointId, Option<std::net::SocketAddr>)> {
    let (id, direct) = match organ.split_once('@') {
        Some((id, addr)) => (
            id,
            Some(
                addr.parse::<std::net::SocketAddr>()
                    .with_context(|| format!("organ address {addr:?} is not ip:port"))?,
            ),
        ),
        None => (organ, None),
    };
    let id = EndpointId::from_str(id.trim())
        .map_err(|error| anyhow::anyhow!("organ id {id:?}: {error}"))?;
    Ok((id, direct))
}

/// The mesh signing key: 32 bytes as 64 hex characters.
fn load_secret(path: &Path) -> Result<SecretKey> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read the sense's key {}", path.display()))?;
    let hex = text.trim();
    anyhow::ensure!(
        hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "{} is not a 64-hex-character signing key",
        path.display()
    );
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("checked hex");
    }
    Ok(SecretKey::from(bytes))
}
