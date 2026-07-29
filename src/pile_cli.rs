//! Small pile helpers shared by the faculty binaries.
//!
//! These lived as private functions inside `bin/secrets.rs` for as long as
//! `secrets` was their only caller. Moving the mail-account *writer* out to
//! the `mail` faculty — where an operator would actually look for it —
//! meant a second binary needed the same six helpers, and duplicating them
//! is how two copies of a pile-open path drift apart. A drifted `open_repo`
//! is not a cosmetic problem: this one deliberately refuses to auto-repair
//! a corrupt pile, and a second copy that quietly did repair it would be a
//! data-loss bug with a plausible-looking diff.

use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use rand_core::OsRng;

use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::blobencodings::RawBytes;
use triblespace::prelude::inlineencodings::{self, Handle};
use triblespace::prelude::*;

/// Handle type `put_bytes` returns.
pub type BytesHandle = Inline<Handle<RawBytes>>;

/// A time coordinate, as the secrets/mail schemas store it.
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

/// Open a pile as a repository, refusing to auto-repair a corrupt one.
///
/// The refusal is the point: a stale binary that "repairs" a pile can
/// truncate data written by a newer one. Repair stays an explicit,
/// destructive operator action (`trible pile amputate`).
pub fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile =
        Pile::open(path).map_err(|e| anyhow::anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.refresh() {
        let _ = pile.close();
        return Err(match err {
            triblespace::core::repo::pile::ReadError::CorruptPile { valid_length } => anyhow::anyhow!(
                "pile corrupt at byte {valid_length}: refusing to auto-repair (a stale binary \
                 could truncate newer data). If, and only if, the tail is a genuinely torn write, truncate it explicitly (DESTRUCTIVE) with: trible pile amputate {}",
                path.display()
            ),
            other => anyhow::anyhow!("refresh pile {}: {other:?}", path.display()),
        });
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))
}

/// Run `f` against an open repository, closing it afterwards.
///
/// A close failure is reported even when the body succeeded — a commit that
/// did not reach the file is not a commit — but never masks an error the
/// body already produced.
pub fn with_repo<T>(pile: &Path, f: impl FnOnce(&mut Repository<Pile>) -> Result<T>) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let result = f(&mut repo);
    let close_res = repo
        .close()
        .map_err(|e| anyhow::anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

/// Store opaque bytes in the workspace.
pub fn put_bytes(ws: &mut Workspace<Pile>, bytes: Vec<u8>) -> BytesHandle {
    ws.put::<RawBytes, _>(bytes)
}

/// Read a CLI value that may be inline, `@file`, or `@-` for stdin.
///
/// The `@-` form is what keeps a password out of `argv`, where it would
/// otherwise be visible to `ps` and land in shell history.
pub fn load_value(raw: &str) -> Result<Vec<u8>> {
    if let Some(rest) = raw.strip_prefix('@') {
        if rest == "-" {
            use std::io::Read;
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("read stdin")?;
            Ok(buf)
        } else {
            std::fs::read(rest).with_context(|| format!("read {rest}"))
        }
    } else {
        Ok(raw.as_bytes().to_vec())
    }
}

/// Now, falling back to the epoch rather than failing a write on a clock
/// that cannot be read.
pub fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

/// A zero-width interval at `at` — the "this happened here" coordinate.
pub fn instant_interval(at: Epoch) -> IntervalValue {
    (at, at).try_to_inline().unwrap()
}
