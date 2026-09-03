//! Read-only GORBIE-embeddable viewer for the `files` faculty.
//!
//! The files branch can hold tens of thousands of intrinsic file records
//! backed by content-addressed blobs — far too many to render as cards. This widget
//! instead focuses on **imports** (`KIND_IMPORT` entities), which
//! are the meaningful "I brought a file/directory in at this time"
//! moments. Each import knows its source filesystem path, when it
//! was imported, and which root file/directory entity it produced.
//!
//! Card layout:
//! - Section header: total imports count + most-recent import age.
//! - Per-import card: hashed accent header with the import's
//!   short timestamp, plus a "RE-IMPORT" badge when the same
//!   source path has been imported before; body shows the source
//!   path, any attached tags as chips, and the import id +
//!   root-entity id at the bottom.
//!
//! v1 limits: no drill-down into the imported directory tree (the
//! files CLI is the right tool for that), no MIME-type histogram
//! across the whole pile (would require walking every KIND_FILE
//! entity and on a pile with 50k files would dominate refresh
//! time — left as a parking-lot polish item).
//!
//! ```ignore
//! let mut panel = FilesViewer::default();
//! panel.render(ctx, files_ws);
//! ```

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Timelike, Utc};
use hifitime::Epoch;

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use triblespace::core::blob::Blob;
use triblespace::core::id::Id;
use triblespace::core::metadata;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::inlineencodings::{Handle, NsTAIInterval, ShortString};
use triblespace::prelude::*;

use crate::files::{ContentHandle, NameHandle};
use crate::schemas::files::{file, KIND_DIRECTORY, KIND_FILE, KIND_IMPORT};
use crate::widgets::storage::{DatasetRevision, DatasetView};

/// Cap on the number of import cards rendered. Older imports remain
/// in the pile; the `files imports` CLI is the right tool for long
/// history. Most piles will have far fewer than 60 imports anyway.
const MAX_IMPORTS: usize = 60;

// ── Palette ──────────────────────────────────────────────────────────

fn color_muted(ui: &egui::Ui) -> egui::Color32 {
    if ui.visuals().dark_mode {
        egui::Color32::from_rgb(0x9a, 0x9a, 0x9a)
    } else {
        egui::Color32::from_rgb(0x6a, 0x6a, 0x6a)
    }
}

fn color_frame(ui: &egui::Ui) -> egui::Color32 {
    if ui.visuals().dark_mode {
        egui::Color32::from_rgb(0x29, 0x32, 0x36)
    } else {
        egui::Color32::from_rgb(0xec, 0xec, 0xec)
    }
}

fn import_color(id: Id) -> egui::Color32 {
    colorhash::ral_categorical(id.as_ref())
}

fn mix(a: egui::Color32, b: egui::Color32, t: f32) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    let lerp = |x: u8, y: u8| {
        ((x as f32) * (1.0 - t) + (y as f32) * t)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    egui::Color32::from_rgb(lerp(a.r(), b.r()), lerp(a.g(), b.g()), lerp(a.b(), b.b()))
}

// ── Row struct ───────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct ImportRow {
    id: Id,
    imported_at: DateTime<Utc>,
    source_path: String,
    root: Id,
    tags: Vec<String>,
    /// True when another import already exists for the same
    /// `source_path` — likely a re-ingest of the same artefact.
    /// Surfaced as a "RE-IMPORT" badge so the user can tell at a
    /// glance when a card is a refresh of an existing thing.
    is_reimport: bool,
}

struct FilesLive {
    cached_revision: DatasetRevision,
    imports: Vec<ImportRow>,
    total: usize,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl FilesLive {
    fn refresh(dataset: DatasetView<'_>) -> Self {
        let mut imports = Vec::new();
        for (id, imported_at, source_path, root) in find!(
            (
                id: Id,
                imported_at: Inline<NsTAIInterval>,
                source_path: Inline<Handle<UTF8String>>,
                root: Id
            ),
            pattern!(dataset.facts, [{
                ?id @ metadata::tag: &KIND_IMPORT,
                file::imported_at: ?imported_at,
                file::source_path: ?source_path,
                file::root: ?root,
            }])
        ) {
            let Ok((imported_at, _)): Result<(Epoch, Epoch), _> = imported_at.try_from_inline()
            else {
                continue;
            };
            let Some(imported_at) = epoch_to_chrono(imported_at).ok() else {
                continue;
            };
            let Ok(source_path): Result<anybytes::View<str>, _> = dataset.reader.get(source_path)
            else {
                continue;
            };
            let tags = find!(
                value: Inline<ShortString>,
                pattern!(dataset.facts, [{ id @ file::tag: ?value }])
            )
            .filter_map(|value| String::try_from_inline(&value).ok())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
            imports.push(ImportRow {
                id,
                imported_at,
                source_path: source_path.to_string(),
                root,
                tags,
                is_reimport: false,
            });
        }
        imports.sort_by(|left, right| {
            (
                left.id,
                left.imported_at,
                &left.source_path,
                left.root,
                &left.tags,
            )
                .cmp(&(
                    right.id,
                    right.imported_at,
                    &right.source_path,
                    right.root,
                    &right.tags,
                ))
        });
        imports.dedup_by(|left, right| {
            left.id == right.id
                && left.imported_at == right.imported_at
                && left.source_path == right.source_path
                && left.root == right.root
                && left.tags == right.tags
        });
        let total = imports.len();

        // Re-import is a set property. No traversal order establishes which
        // import was "first" or which one supersedes another.
        let mut path_counts = BTreeMap::<&str, usize>::new();
        for row in &imports {
            *path_counts.entry(&row.source_path).or_insert(0) += 1;
        }
        let duplicate_paths = path_counts
            .into_iter()
            .filter_map(|(path, count)| (count > 1).then_some(path.to_owned()))
            .collect::<BTreeSet<_>>();
        for row in &mut imports {
            row.is_reimport = duplicate_paths.contains(&row.source_path);
        }

        // Time orders independent import projections for presentation only;
        // repeated values remain separate rows above.
        imports.sort_by(|a, b| b.imported_at.cmp(&a.imported_at).then(b.id.cmp(&a.id)));
        imports.truncate(MAX_IMPORTS);

        FilesLive {
            cached_revision: dataset.revision,
            imports,
            total,
        }
    }
}

fn epoch_to_chrono(e: Epoch) -> anyhow::Result<DateTime<Utc>> {
    let secs = e.to_unix_seconds();
    if !secs.is_finite() {
        anyhow::bail!("Files timestamp is not finite");
    }
    let whole = secs.floor();
    if whole < i64::MIN as f64 || whole > i64::MAX as f64 {
        anyhow::bail!("Files timestamp is outside the displayable UTC range");
    }
    let nanos = ((secs - whole) * 1e9).round().clamp(0.0, 999_999_999.0) as u32;
    Utc.timestamp_opt(whole as i64, nanos)
        .single()
        .ok_or_else(|| anyhow::anyhow!("Files timestamp is outside the displayable UTC range"))
}

fn current_utc() -> Option<DateTime<Utc>> {
    crate::clock::now()
        .ok()
        .and_then(|epoch| epoch_to_chrono(epoch).ok())
}

fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

fn format_date(d: NaiveDate) -> String {
    let weekday = d.format("%a").to_string().to_uppercase();
    let month = d.format("%b").to_string().to_uppercase();
    format!("{weekday} {} {month} {}", d.day(), d.year())
}

fn format_time(t: DateTime<Utc>) -> String {
    format!("{:02}:{:02}", t.hour(), t.minute())
}

/// Shorten an arbitrarily long filesystem path so the most
/// recognisable parts (last 2 path components) remain visible at
/// the end. `/very/long/leading/path/foo/bar.pdf` →
/// `…/foo/bar.pdf`. Helpful for tmpdir scratch paths the agent
/// uses, which often look like
/// `/private/var/folders/.../files-fetch/2605.05242.pdf`.
fn shorten_path(path: &str) -> String {
    let mut parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() <= 3 {
        return path.to_string();
    }
    let last_two: Vec<&str> = parts.split_off(parts.len() - 2);
    format!("…/{}", last_two.join("/"))
}

fn age_label(now: DateTime<Utc>, at: DateTime<Utc>) -> String {
    let dur = now - at;
    let secs = dur.num_seconds().max(0);
    if secs < 60 {
        return format!("{}S AGO", secs);
    }
    if secs < 3_600 {
        return format!("{}M AGO", secs / 60);
    }
    if secs < 86_400 {
        return format!("{}H AGO", secs / 3_600);
    }
    let days = secs / 86_400;
    if days < 7 {
        return format!("{days}D AGO");
    }
    if days < 30 {
        return format!("{}W AGO", days / 7);
    }
    if days < 365 {
        return format!("{}MO AGO", days / 30);
    }
    format!("{}Y AGO", days / 365)
}

// ── Widget ───────────────────────────────────────────────────────────

pub struct FilesViewer {
    live: Option<FilesLive>,
}

impl Default for FilesViewer {
    fn default() -> Self {
        Self { live: None }
    }
}

impl FilesViewer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render(&mut self, ctx: &mut CardCtx<'_>, dataset: DatasetView<'_>) {
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_revision != dataset.revision,
        };
        if need_refresh {
            self.live = Some(FilesLive::refresh(dataset));
        }

        // Click-time action: open the import's root file/directory.
        // The card's OPEN button only sets this request; the actual
        // blob extraction happens after the section closure ends, when
        // the immutable `live` borrow has been released and we can use
        // the dataset reader for blob reads again.
        let mut open_root: Option<Id> = None;

        ctx.section("Files", |ctx| {
            let Some(live) = self.live.as_ref() else {
                return;
            };

            ctx.grid(|g| {
                let shown = live.imports.len();
                let now = current_utc();
                let newest_age = live
                    .imports
                    .first()
                    .map(|r| r.imported_at)
                    .and_then(|at| now.map(|now| age_label(now, at)));

                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let summary = match (shown < live.total, newest_age.as_deref()) {
                        (true, Some(age)) => {
                            format!("SHOWING {shown} OF {} IMPORTS · NEWEST {age}", live.total)
                        }
                        (false, Some(age)) => format!(
                            "{shown} IMPORT{} · NEWEST {age}",
                            if shown == 1 { "" } else { "S" }
                        ),
                        (_, None) => format!("{shown} IMPORT{}", if shown == 1 { "" } else { "S" }),
                    };
                    ui.label(
                        egui::RichText::new(summary)
                            .monospace()
                            .strong()
                            .small()
                            .color(color_muted(ui)),
                    );
                });

                if live.imports.is_empty() {
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(16.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new("\u{1F4C2}") // 📂
                                    .size(28.0)
                                    .color(color_muted(ui)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("No imports yet.")
                                    .monospace()
                                    .small()
                                    .strong()
                                    .color(color_muted(ui)),
                            );
                        });
                        ui.add_space(16.0);
                    });
                    return;
                }

                for import in &live.imports {
                    g.full(|ctx| {
                        render_import_card(ctx.ui_mut(), import, now, &mut open_root);
                    });
                }
            });
        });

        if let Some(root) = open_root {
            open_entity(dataset, root);
        }
    }
}

/// Extract `entity_id` (a file or directory) from the pile into
/// `$TMPDIR/faculties-files/` and fire the platform `open` command on the
/// result — same flow the wiki widget uses for `files:` links, but
/// extended to handle directory roots by recursing through
/// `file::children`. Best-effort: errors log to stderr.
fn open_entity(dataset: DatasetView<'_>, entity_id: Id) {
    let tmp_dir = std::env::temp_dir().join("faculties-files");
    if let Err(e) = std::fs::create_dir_all(&tmp_dir) {
        eprintln!("[files] mkdir {}: {e}", tmp_dir.display());
        return;
    }
    match extract_tree(dataset, entity_id, &tmp_dir, 0) {
        Ok(path) => {
            eprintln!("[files] opening: {}", path.display());
            let _ = std::process::Command::new("open").arg(&path).spawn();
        }
        Err(e) => eprintln!("[files] extract: {e}"),
    }
}

/// Recursively materialise a file/directory entity under `dest`.
/// Files write their content blob to `dest/<name>`; directories
/// create `dest/<name>/` and recurse through their `children`.
/// Returns the path of the materialised entry. Depth-capped at 32
/// as a cycle guard — the files faculty never writes cyclic trees,
/// but a corrupted pile shouldn't be able to hang the viewer.
fn extract_tree(
    dataset: DatasetView<'_>,
    entity_id: Id,
    dest: &std::path::Path,
    depth: u32,
) -> Result<std::path::PathBuf, String> {
    if depth > 32 {
        return Err(format!("max depth exceeded at {}", id_hex(entity_id)));
    }

    let files = find!(
        (name: NameHandle, content: ContentHandle),
        pattern!(dataset.facts, [{
            entity_id @ metadata::tag: &KIND_FILE,
            file::name: ?name,
            file::content: ?content,
        }])
    )
    .collect::<BTreeSet<_>>();
    let directories = find!(
        name: NameHandle,
        pattern!(dataset.facts, [{
            entity_id @ metadata::tag: &KIND_DIRECTORY,
            file::name: ?name,
        }])
    )
    .collect::<BTreeSet<_>>();

    match (files.first().copied(), directories.first().copied()) {
        (Some((name, content)), None) => {
            let name: anybytes::View<str> = dataset
                .reader
                .get(name)
                .map_err(|error| format!("get name for {}: {error:?}", id_hex(entity_id)))?;
            let blob: Blob<RawBytes> = dataset
                .reader
                .get(content)
                .map_err(|error| format!("get blob for {}: {error:?}", name.as_ref()))?;
            let name = crate::files::leaf_name(name.as_ref());
            let path = dest.join(&name);
            std::fs::write(&path, &*blob.bytes)
                .map_err(|error| format!("write {name}: {error}"))?;
            Ok(path)
        }
        (None, Some(name)) => {
            let name: anybytes::View<str> = dataset
                .reader
                .get(name)
                .map_err(|error| format!("get name for {}: {error:?}", id_hex(entity_id)))?;
            let name = crate::files::leaf_name(name.as_ref());
            let dir = dest.join(&name);
            std::fs::create_dir_all(&dir).map_err(|error| format!("mkdir {name}: {error}"))?;
            let children = find!(
                child: Id,
                pattern!(dataset.facts, [{ entity_id @ file::children: ?child }])
            )
            .collect::<BTreeSet<_>>();
            for child in children {
                if let Err(e) = extract_tree(dataset, child, &dir, depth + 1) {
                    eprintln!("[files] skipping child: {e}");
                }
            }
            Ok(dir)
        }
        (None, None) => Err(format!("unknown Files node {}", id_hex(entity_id))),
        (Some(_), Some(_)) => Err(format!(
            "Files node {} is both a file and directory",
            id_hex(entity_id)
        )),
    }
}

// ── Import card ──────────────────────────────────────────────────────

fn render_import_card(
    ui: &mut egui::Ui,
    row: &ImportRow,
    now: Option<DateTime<Utc>>,
    open_root: &mut Option<Id>,
) {
    let bubble_fill = ui.visuals().window_fill;
    let accent = import_color(row.id);
    let text_on_accent = colorhash::text_color_on(accent);
    let body_text = colorhash::text_color_on(bubble_fill);
    let body_muted = mix(body_text, bubble_fill, 0.22);

    egui::Frame::NONE
        .fill(bubble_fill)
        .stroke(egui::Stroke::new(1.0, color_frame(ui)))
        .shadow(egui::epaint::Shadow {
            offset: [2, 2],
            blur: 0,
            spread: 0,
            color: egui::Color32::from_black_alpha(48),
        })
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(egui::Margin::ZERO)
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.spacing_mut().item_spacing.y = 0.0;

            // ── Header: date · time · RE-IMPORT badge ──
            egui::Frame::NONE
                .fill(accent)
                .corner_radius(egui::CornerRadius::ZERO)
                .inner_margin(egui::Margin {
                    left: 10,
                    right: 10,
                    top: 6,
                    bottom: 6,
                })
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 2.0;

                    ui.horizontal(|ui| {
                        let header = format!(
                            "{} · {}",
                            format_date(row.imported_at.date_naive()),
                            format_time(row.imported_at),
                        );
                        ui.label(
                            egui::RichText::new(header)
                                .monospace()
                                .strong()
                                .color(text_on_accent),
                        );
                        if let Some(now) = now {
                            ui.label(
                                egui::RichText::new(format!(
                                    "· {}",
                                    age_label(now, row.imported_at)
                                ))
                                .monospace()
                                .small()
                                .color(text_on_accent),
                            );
                        }
                        if row.is_reimport {
                            ui.label(
                                egui::RichText::new("· RE-IMPORT")
                                    .monospace()
                                    .small()
                                    .strong()
                                    .color(text_on_accent),
                            );
                        }

                        // OPEN — extracts the import's root file or
                        // directory tree to $TMPDIR/faculties-files/ and
                        // fires the platform opener, mirroring the
                        // wiki widget's files:-link behaviour.
                        // `Align::Min` cross-axis: Center would feed
                        // the frame-delayed cell-sizing loop.
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                            let btn = ui.add(
                                egui::Button::new(
                                    egui::RichText::new("OPEN \u{2197}") // ↗
                                        .monospace()
                                        .small()
                                        .strong(),
                                )
                                .min_size(egui::vec2(56.0, 18.0)),
                            );
                            if btn.clicked() {
                                *open_root = Some(row.root);
                            }
                        });
                    });

                    // Source path is the most useful identifier for
                    // an import — emphasise it as the card title.
                    ui.label(
                        egui::RichText::new(shorten_path(&row.source_path))
                            .monospace()
                            .size(14.0)
                            .color(text_on_accent),
                    );
                });

            // ── Body: tags + ids ──
            egui::Frame::NONE
                .fill(bubble_fill)
                .corner_radius(egui::CornerRadius::ZERO)
                .inner_margin(egui::Margin {
                    left: 10,
                    right: 10,
                    top: 6,
                    bottom: 8,
                })
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 4.0;

                    // Full source path on its own line — repeats the
                    // shortened heading but with every component
                    // visible (useful when the leading tmp/var/folders
                    // bit matters).
                    ui.label(
                        egui::RichText::new(&row.source_path)
                            .monospace()
                            .small()
                            .color(body_muted),
                    );

                    if !row.tags.is_empty() {
                        ui.horizontal_wrapped(|ui| {
                            ui.spacing_mut().item_spacing = egui::vec2(4.0, 4.0);
                            for tag in &row.tags {
                                render_tag_chip(ui, tag);
                            }
                        });
                    }

                    // Two ids at the bottom: the import entity itself
                    // and its root file/directory pointer. Mono small
                    // so they stay reachable without dominating.
                    let footer = format!("IMPORT {} · ROOT {}", id_hex(row.id), id_hex(row.root));
                    ui.label(
                        egui::RichText::new(footer)
                            .monospace()
                            .small()
                            .color(body_muted),
                    );
                });
        });
}

fn render_tag_chip(ui: &mut egui::Ui, label: &str) {
    let fill = colorhash::ral_categorical(label.as_bytes());
    let text = colorhash::text_color_on(fill);
    egui::Frame::NONE
        .fill(fill)
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(egui::Margin::symmetric(5, 1))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(label)
                    .monospace()
                    .small()
                    .strong()
                    .color(text),
            );
        });
}
