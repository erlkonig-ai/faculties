//! Resident capture and intent operations. Device access lives in `device`;
//! publication, selected reads and returned bytes need no output or transport.

use super::{CaptureRow, IntervalValue, RawHandle, TextHandle};
use crate::clock;
use crate::collection_names::open_configured;
use crate::files::presentation::{present, ViewOptions};
use crate::out::Part;
use crate::schemas::body::{capture, DEFAULT_SCOPE_ID, KIND_CAPTURE, KIND_INTENT};
use crate::storage::{load_signer, open_pile_strict, publish_fragment, FactArchive};
use anybytes::Bytes;
use anyhow::{bail, Context, Result};
use hifitime::Epoch;
use std::path::{Path, PathBuf};
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::{BlobStoreGet, SnapshotSource};
use triblespace::prelude::*;

/// Already acquired signals. Bytes are archived exactly, never decoded or
/// normalized by capture. A subsequent bounded view may validate/convert them.
#[derive(Clone, Debug)]
pub enum Signal {
    Vision {
        bytes: Bytes,
        mime: String,
        width: u64,
        height: u64,
    },
    Audio {
        bytes: Bytes,
        mime: String,
    },
    Touch,
}

#[derive(Clone, Debug)]
pub struct CaptureInput {
    pub signal: Signal,
    /// Literal proprioception or touch signature; no path or JSON interpretation.
    pub pose: String,
    pub note: Option<String>,
}

impl CaptureInput {
    pub fn validate(&self) -> Result<()> {
        let (mime, kind) = match &self.signal {
            Signal::Vision {
                mime,
                width,
                height,
                ..
            } => {
                if *width == 0 || *height == 0 {
                    bail!("vision dimensions must be positive");
                }
                (mime, "image")
            }
            Signal::Audio { mime, .. } => (mime, "audio"),
            Signal::Touch => return Ok(()),
        };
        // Body's published MIME field is ShortString, not the Files MIME model.
        if mime.len() > 32 || mime.contains('\0') {
            bail!("Body MIME must fit 32 UTF-8 bytes and contain no NUL");
        }
        let parsed: mime::Mime = mime.parse().context("invalid capture MIME type")?;
        if parsed.type_().as_str() != kind || parsed.essence_str().contains('*') {
            bail!("{kind} capture requires a concrete {kind} MIME type");
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct CaptureReceipt {
    pub id: Id,
    pub modality: String,
    pub bytes: usize,
    pub dimensions: Option<(u64, u64)>,
    pub note: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CaptureSummary {
    pub id: Id,
    pub tai_ns: i128,
    pub modality: String,
    pub note: String,
}

#[derive(Clone, Debug)]
pub struct CaptureExport {
    pub id: Id,
    pub bytes: Bytes,
    pub mime: Option<String>,
}
impl CaptureExport {
    pub fn uri(&self) -> String {
        format!("body:{:x}", self.id)
    }
}

#[derive(Clone, Debug)]
pub struct IntentObservation {
    pub id: Id,
    pub tai_ns: i128,
    pub text: String,
}

#[derive(Clone, Debug)]
pub struct Body {
    pile: PathBuf,
    key: Option<PathBuf>,
}
impl Body {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self { pile, key }
    }
    fn storage(&self) -> BodyStorage<'_> {
        BodyStorage {
            pile: &self.pile,
            key: self.key.as_deref(),
        }
    }

    /// One complete immutable capture and all its resident attachments.
    pub fn capture(&self, input: &CaptureInput) -> Result<CaptureReceipt> {
        let fragment = capture_fragment(input, clock::point_now()?)?;
        let id = fragment.root().expect("capture has one intrinsic root");
        let (modality, bytes, dimensions) = match &input.signal {
            Signal::Vision {
                bytes,
                width,
                height,
                ..
            } => ("vision", bytes.len(), Some((*width, *height))),
            Signal::Audio { bytes, .. } => ("audio", bytes.len(), None),
            Signal::Touch => ("touch", 0, None),
        };
        self.storage().publish(fragment)?;
        Ok(CaptureReceipt {
            id,
            modality: modality.to_owned(),
            bytes,
            dimensions,
            note: input.note.clone(),
        })
    }

    pub fn set_intent(&self, text: &str) -> Result<IntentObservation> {
        let created = clock::point_now()?;
        let fragment = intent_fragment(text, created);
        let id = fragment.root().expect("intent has one intrinsic root");
        self.storage().publish(fragment)?;
        Ok(IntentObservation {
            id,
            tai_ns: interval_key(created),
            text: text.to_owned(),
        })
    }

    pub fn intent(&self) -> Result<Option<IntentObservation>> {
        self.storage().with_indexed_view(latest_intent)
    }

    /// Notes only: this does not acquire frame or pose payloads.
    pub fn list(&self) -> Result<Vec<CaptureSummary>> {
        self.storage().with_view(|space, reader| {
            let mut rows = Vec::new();
            for (id, modality, created) in find!(
                (c: Id, m: String, t: IntervalValue),
                pattern!(space, [{ ?c @ metadata::tag: KIND_CAPTURE, capture::modality: ?m, metadata::created_at: ?t }])
            ) {
                let note = find!(h: TextHandle, pattern!(space, [{ id @ capture::note: ?h }]))
                    .next().map(|handle| reader.get::<View<str>, _>(handle)
                        .map(|text| text.to_string())
                        .map_err(|error| anyhow::anyhow!("read note for capture {id:X}: {error}")))
                    .transpose()?.unwrap_or_default();
                rows.push(CaptureSummary { id, tai_ns: interval_key(created), modality, note });
            }
            rows.sort_by(|a, b| (b.tai_ns, b.id).cmp(&(a.tai_ns, a.id)));
            Ok(rows)
        })
    }

    /// Exact original bytes, never a perception. A touch has no file payload.
    /// The selected capture/frame and reader stay in one frozen observation.
    pub fn get(&self, id: &str) -> Result<CaptureExport> {
        validate_selector(id)?;
        self.storage().with_view(|space, reader| {
            let ids = find!(c: Id, pattern!(space, [{ ?c @ metadata::tag: KIND_CAPTURE }]));
            let needle = id.to_ascii_lowercase();
            let mut matches = ids.filter(|candidate| format!("{candidate:x}").starts_with(&needle));
            let id = matches
                .next()
                .with_context(|| format!("no capture matching '{id}'"))?;
            if matches.next().is_some() {
                bail!("ambiguous capture prefix '{needle}'");
            }
            let handle = find!(h: RawHandle, pattern!(space, [{ id @ capture::frame: ?h }]))
                .next()
                .context("capture has no frame payload (a touch capture has no file)")?;
            let mime = find!(m: String, pattern!(space, [{ id @ capture::mime: ?m }])).next();
            let bytes = reader
                .get(handle)
                .map_err(|error| anyhow::anyhow!("read frame for capture {id:X}: {error}"))?;
            Ok(CaptureExport { id, bytes, mime })
        })
    }

    /// Bounded derived perception through the shared Files presenter. Original
    /// bytes remain unchanged; unsupported media returns an explicit error.
    pub fn view(&self, id: &str, options: &ViewOptions) -> Result<Part> {
        options.validate()?;
        let export = self.get(id)?;
        let mime = export
            .mime
            .as_deref()
            .context("capture has no MIME type; use get for original bytes")?;
        present(export.bytes, mime, options)
    }
}

pub fn validate_selector(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "capture selector must be a nonempty hexadecimal ID or prefix, at most 32 characters"
        );
    }
    Ok(())
}

/// Build the same canonical record used by the device path, without a store.
pub fn capture_fragment(input: &CaptureInput, created: IntervalValue) -> Result<Fragment> {
    input.validate()?;
    super::validate_point("capture creation time", created)?;
    let mut fragment = Fragment::empty();
    let (modality, frame, mime, width, height) = match &input.signal {
        Signal::Vision {
            bytes,
            mime,
            width,
            height,
        } => (
            "vision",
            Some(fragment.put::<blobencodings::RawBytes, _>(bytes.clone())),
            Some(mime.clone()),
            Some((*width).to_inline()),
            Some((*height).to_inline()),
        ),
        Signal::Audio { bytes, mime } => (
            "audio",
            Some(fragment.put::<blobencodings::RawBytes, _>(bytes.clone())),
            Some(mime.clone()),
            None,
            None,
        ),
        Signal::Touch => ("touch", None, None, None, None),
    };
    let pose = fragment.put::<blobencodings::UTF8String, _>(input.pose.clone());
    let note = input
        .note
        .as_ref()
        .map(|note| fragment.put::<blobencodings::UTF8String, _>(note.clone()));
    fragment += super::capture_record(&CaptureRow {
        id: KIND_CAPTURE,
        created_at: created,
        frame,
        mime,
        width,
        height,
        modality: modality.to_owned(),
        note,
        pose,
    });
    Ok(fragment)
}

fn intent_fragment(text: &str, created: IntervalValue) -> Fragment {
    let mut fragment = Fragment::empty();
    let text = fragment.put::<blobencodings::UTF8String, _>(text.to_owned());
    fragment += super::intent_record(&super::IntentRow {
        id: KIND_INTENT,
        created_at: created,
        text,
    });
    fragment
}

pub(super) fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_inline().expect("valid TAI interval");
    lower.to_tai_duration().total_nanoseconds()
}

fn latest_intent(snapshot: &super::BodySnapshot) -> Result<Option<IntentObservation>> {
    let Some(row) = super::latest_intent(snapshot.facts(), snapshot.intent_register())? else {
        return Ok(None);
    };
    let text: View<str> = snapshot
        .store_snapshot()
        .get(row.text)
        .map_err(|error| anyhow::anyhow!("read latest intent {:X}: {error}", row.id))?;
    Ok(Some(IntentObservation {
        id: row.id,
        tai_ns: interval_key(row.created_at),
        text: text.to_string(),
    }))
}

#[derive(Clone, Copy)]
struct BodyStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

impl BodyStorage<'_> {
    fn publish(&self, fragment: Fragment) -> Result<()> {
        publish_fragment(self.pile, self.key, DEFAULT_SCOPE_ID, fragment)?;
        Ok(())
    }

    fn with_pile<T>(
        &self,
        f: impl FnOnce(&mut Pile, &ed25519_dalek::SigningKey) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = f(&mut pile, &signer);
        let close = pile.close();
        match (result, close) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(anyhow::anyhow!("close pile: {error}")),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(close_error)) => {
                Err(error.context(format!("closing pile also failed: {close_error}")))
            }
        }
    }

    fn with_view<T>(&self, f: impl FnOnce(&FactArchive, &PileSnapshot) -> Result<T>) -> Result<T> {
        self.with_pile(|pile, signer| {
            let source = open_configured(pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
            let descriptor_snapshot = pile.snapshot()?;
            let policy = source.policy(&descriptor_snapshot)?;
            drop(descriptor_snapshot);
            let collection_succinct =
                pile.derive::<SuccinctArchiveBlob>(source, (), policy.clone())?;
            let collection_rank9 = pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(
                collection_succinct,
                (),
                policy,
            )?;
            let store_snapshot = pollster::block_on(async {
                drop(pile.ensure(source).await?);
                drop(pile.maintain(collection_succinct).await?);
                pile.maintain(collection_rank9).await
            })
            .context("maintain Body fact collection")?;
            let facts = store_snapshot
                .collection(collection_rank9)
                .context("observe maintained Body fact collection")?
                .view::<FactArchive>()
                .context("read maintained Body fact collection")?;
            f(&facts, &store_snapshot)
        })
    }

    fn with_indexed_view<T>(&self, f: impl FnOnce(&super::BodySnapshot) -> Result<T>) -> Result<T> {
        self.with_pile(|pile, signer| {
            let snapshot = pollster::block_on(super::materialize_indexed_collection(pile, signer))?;
            f(&snapshot)
        })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
