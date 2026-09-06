//! Read one exact immutable blob through a network-backed store snapshot.
//!
//! `cargo run --release --example snapshot_blob -- --pile /path/to/self.pile <64-hex-handle>`
//!
//! Uses the existing `TRIBLESPACE_PEERS` bootstrap configuration. Missing bytes
//! may be fetched and cached, but this example does not select a collection,
//! load a signing key, or publish a WANT. Standard output contains only the byte
//! count. Diagnostics go to standard error; `RUST_LOG` overrides the default
//! `warn,triblespace_net::host=debug` filter, including exact-fetch misses,
//! errors, and end-to-end deadlines.

use std::path::PathBuf;

use anybytes::Bytes;
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use faculties::storage::{open_store, runtime};
use tracing_subscriber::EnvFilter;
use triblespace::core::blob::encodings::UnknownBlob;
use triblespace::core::inline::encodings::hash::{Blake3, Handle, Hash};
use triblespace::core::inline::Inline;
use triblespace::core::repo::{SnapshotSource, StorageClose};

#[derive(Parser)]
#[command(about = "Fetch one exact blob through a frozen snapshot; print only its byte count")]
struct Args {
    /// Existing pile whose local blob cache may receive the requested bytes.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Exact 64-hex-character BLAKE3 blob handle.
    handle: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let filter =
        std::env::var("RUST_LOG").unwrap_or_else(|_| "warn,triblespace_net::host=debug".to_owned());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(filter).context("parse RUST_LOG")?)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init()
        .map_err(|error| anyhow!("initialize tracing: {error}"))?;

    let hash = Hash::<Blake3>::from_hex(&args.handle)
        .map_err(|_| anyhow!("expected an exact 64-hex-character BLAKE3 blob handle"))?;
    let handle: Inline<Handle<UnknownBlob>> = Handle::from_hash(hash);
    let runtime = runtime()?;
    let mut store = open_store(&args.pile)?;
    let result = runtime.block_on(async {
        let snapshot = store.snapshot().context("freeze store snapshot")?;
        let bytes: Bytes = snapshot.get(handle).await.context("read exact blob")?;
        Ok::<_, anyhow::Error>(bytes.len())
    });
    let count = match (result, store.close()) {
        (Ok(count), Ok(())) => count,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(anyhow!("close pile: {error}")),
        (Err(error), Err(close_error)) => {
            return Err(error.context(format!("closing pile also failed: {close_error}")))
        }
    };
    println!("{count} bytes");
    Ok(())
}
