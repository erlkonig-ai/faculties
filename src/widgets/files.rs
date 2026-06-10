//! Read-only GORBIE-embeddable viewer for the `files` faculty.
//!
//! The files branch can hold tens of thousands of content-addressed
//! file entities — far too many to render as cards. This widget
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

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Timelike, Utc};
use hifitime::Epoch;

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use triblespace::core::blob::Blob;
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{CommitHandle, Workspace};
use triblespace::core::trible::TribleSet;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use triblespace::prelude::View;

use crate::schemas::files::{file as file_attrs, KIND_IMPORT};

type TextHandle = Inline<Handle<LongString>>;
type FileHandle = Inline<Handle<RawBytes>>;

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
        ((x as f32) * (1.0 - t) + (y as f32) * t).round().clamp(0.0, 255.0) as u8
    };
    egui::Color32::from_rgb(
        lerp(a.r(), b.r()),
        lerp(a.g(), b.g()),
        lerp(a.b(), b.b()),
    )
}

// ── Row struct ───────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct ImportRow {
    id: Id,
    imported_at: Option<DateTime<Utc>>,
    source_path: Option<String>,
    root: Option<Id>,
    tags: Vec<String>,
    /// True when another import already exists for the same
    /// `source_path` — likely a re-ingest of the same artefact.
    /// Surfaced as a "RE-IMPORT" badge so the user can tell at a
    /// glance when a card is a refresh of an existing thing.
    is_reimport: bool,
}

struct FilesLive {
    cached_head: Option<CommitHandle>,
    imports: Vec<ImportRow>,
    total: usize,
    /// Retained fact space so click-time actions (opening a card's
    /// root file/directory) can resolve names/content/children
    /// without a re-checkout. TribleSet is six PATCH root pointers —
    /// keeping it is cheap.
    space: TribleSet,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl FilesLive {
    fn refresh(ws: &mut Workspace<Pile>) -> Self {
        let space = ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[files] checkout: {e:?}");
                TribleSet::new()
            });
        let cached_head = ws.head();

        let mut by_id: HashMap<Id, ImportRow> = HashMap::new();

        // Enumerate KIND_IMPORT entities + their imported_at (we want
        // to sort by it). The Inline<NsTAIInterval> projects as a
        // (Epoch, Epoch) tuple in 0.44.
        for (id,) in find!(
            (id: Id,),
            pattern!(&space, [{ ?id @ metadata::tag: KIND_IMPORT }])
        ) {
            by_id.insert(
                id,
                ImportRow {
                    id,
                    imported_at: None,
                    source_path: None,
                    root: None,
                    tags: Vec::new(),
                    is_reimport: false,
                },
            );
        }
        let total = by_id.len();

        // imported_at time interval.
        for (id, range) in find!(
            (id: Id, t: (Epoch, Epoch)),
            pattern!(&space, [{ ?id @ file_attrs::imported_at: ?t }])
        ) {
            if let Some(row) = by_id.get_mut(&id) {
                let (start, _end) = range;
                row.imported_at = Some(epoch_to_chrono(start));
            }
        }

        // Source path — a Handle<LongString>, dereffed via ws.get on
        // demand. Reading text per import is cheap because there's
        // usually a handful of imports per pile (vs. tens of
        // thousands of files).
        let path_rows: Vec<(Id, TextHandle)> = find!(
            (id: Id, h: TextHandle),
            pattern!(&space, [{ ?id @ file_attrs::source_path: ?h }])
        )
        .collect();
        for (id, h) in path_rows {
            if let Some(row) = by_id.get_mut(&id) {
                row.source_path = read_text(ws, h);
            }
        }

        // Root file/directory entity pointer.
        for (id, root) in find!(
            (id: Id, r: Id),
            pattern!(&space, [{ ?id @ file_attrs::root: ?r }])
        ) {
            if let Some(row) = by_id.get_mut(&id) {
                row.root = Some(root);
            }
        }

        // Tags (multi-valued ShortString). Each import can carry
        // any number, and we collect them all to render as chips.
        for (id, tag) in find!(
            (id: Id, t: String),
            pattern!(&space, [{ ?id @ file_attrs::tag: ?t }])
        ) {
            if let Some(row) = by_id.get_mut(&id) {
                row.tags.push(tag);
            }
        }
        for row in by_id.values_mut() {
            row.tags.sort();
            row.tags.dedup();
        }

        // Mark re-imports — same source_path as another import. A
        // single-pass HashSet is enough; we don't care which one
        // was first, just that any duplicate exists.
        let mut path_counts: HashMap<&str, usize> = HashMap::new();
        for row in by_id.values() {
            if let Some(p) = row.source_path.as_deref() {
                *path_counts.entry(p).or_insert(0) += 1;
            }
        }
        let dup_paths: HashSet<String> = path_counts
            .into_iter()
            .filter_map(|(p, c)| (c > 1).then(|| p.to_string()))
            .collect();
        for row in by_id.values_mut() {
            if let Some(p) = row.source_path.as_deref() {
                row.is_reimport = dup_paths.contains(p);
            }
        }

        // Sort newest first, then clamp to MAX_IMPORTS so a long
        // history doesn't blow up the card count.
        let mut imports: Vec<ImportRow> = by_id.into_values().collect();
        imports.sort_by(|a, b| {
            b.imported_at
                .cmp(&a.imported_at)
                .then(b.id.cmp(&a.id))
        });
        imports.truncate(MAX_IMPORTS);

        FilesLive {
            cached_head,
            imports,
            total,
            space,
        }
    }
}

fn epoch_to_chrono(e: Epoch) -> DateTime<Utc> {
    let secs = e.to_unix_seconds();
    Utc.timestamp_opt(secs as i64, ((secs.fract() * 1e9) as u32).min(999_999_999))
        .single()
        .unwrap_or_else(Utc::now)
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, LongString>(h).ok().map(|v| {
        let s: &str = v.as_ref();
        s.to_string()
    })
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

    pub fn render(
        &mut self,
        ctx: &mut CardCtx<'_>,
        ws: &mut Workspace<Pile>,
    ) {
        let head = ws.head();
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_head != head,
        };
        if need_refresh {
            self.live = Some(FilesLive::refresh(ws));
        }

        // Click-time action: open the import's root file/directory.
        // The card's OPEN button only sets this request; the actual
        // blob extraction happens after the section closure ends, when
        // the immutable `live` borrow has been released and we can use
        // `ws` for blob reads again.
        let mut open_root: Option<Id> = None;

        ctx.section("Files", |ctx| {
            let Some(live) = self.live.as_ref() else { return };

            ctx.grid(|g| {
                let shown = live.imports.len();
                let now = Utc::now();
                let newest_age = live
                    .imports
                    .first()
                    .and_then(|r| r.imported_at)
                    .map(|t| age_label(now, t));

                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let summary = match (shown < live.total, newest_age.as_deref()) {
                        (true, Some(age)) => format!(
                            "SHOWING {shown} OF {} IMPORTS · NEWEST {age}",
                            live.total
                        ),
                        (false, Some(age)) => format!(
                            "{shown} IMPORT{} · NEWEST {age}",
                            if shown == 1 { "" } else { "S" }
                        ),
                        (_, None) => format!(
                            "{shown} IMPORT{}",
                            if shown == 1 { "" } else { "S" }
                        ),
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
            if let Some(live) = self.live.as_ref() {
                open_entity(ws, &live.space, root);
            }
        }
    }
}

/// Extract `entity_id` (a file or directory) from the pile into
/// `$TMPDIR/liora-files/` and fire the platform `open` command on the
/// result — same flow the wiki widget uses for `files:` links, but
/// extended to handle directory roots by recursing through
/// `file::children`. Best-effort: errors log to stderr.
fn open_entity(ws: &mut Workspace<Pile>, space: &TribleSet, entity_id: Id) {
    let tmp_dir = std::env::temp_dir().join("liora-files");
    if let Err(e) = std::fs::create_dir_all(&tmp_dir) {
        eprintln!("[files] mkdir {}: {e}", tmp_dir.display());
        return;
    }
    match extract_tree(ws, space, entity_id, &tmp_dir, 0) {
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
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    entity_id: Id,
    dest: &std::path::Path,
    depth: u32,
) -> Result<std::path::PathBuf, String> {
    if depth > 32 {
        return Err(format!("max depth exceeded at {}", id_hex(entity_id)));
    }

    let name = find!(
        h: TextHandle,
        pattern!(space, [{ entity_id @ file_attrs::name: ?h }])
    )
    .next()
    .and_then(|h| read_text(ws, h))
    .unwrap_or_else(|| short_hex_name(entity_id));

    // File leaf: has a content blob.
    if let Some(content) = find!(
        h: FileHandle,
        pattern!(space, [{ entity_id @ file_attrs::content: ?h }])
    )
    .next()
    {
        let blob: Blob<RawBytes> = ws
            .get(content)
            .map_err(|e| format!("get blob for {name}: {e:?}"))?;
        let path = dest.join(&name);
        std::fs::write(&path, &*blob.bytes).map_err(|e| format!("write {name}: {e}"))?;
        return Ok(path);
    }

    // Directory: create and recurse. An entity with neither content
    // nor children still materialises as an empty directory — that's
    // the honest representation of what's in the pile.
    let dir = dest.join(&name);
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {name}: {e}"))?;
    let children: Vec<Id> = find!(
        c: Id,
        pattern!(space, [{ entity_id @ file_attrs::children: ?c }])
    )
    .collect();
    for child in children {
        // Best-effort per child: one unreadable blob shouldn't kill
        // the rest of the tree.
        if let Err(e) = extract_tree(ws, space, child, &dir, depth + 1) {
            eprintln!("[files] skipping child: {e}");
        }
    }
    Ok(dir)
}

fn short_hex_name(id: Id) -> String {
    let s = format!("{id:x}");
    s.chars().take(8).collect()
}

// ── Import card ──────────────────────────────────────────────────────

fn render_import_card(
    ui: &mut egui::Ui,
    row: &ImportRow,
    now: DateTime<Utc>,
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
                        let header = match row.imported_at {
                            Some(t) => format!(
                                "{} · {}",
                                format_date(t.date_naive()),
                                format_time(t),
                            ),
                            None => "(no timestamp)".to_string(),
                        };
                        ui.label(
                            egui::RichText::new(header)
                                .monospace()
                                .strong()
                                .color(text_on_accent),
                        );
                        if let Some(t) = row.imported_at {
                            ui.label(
                                egui::RichText::new(format!("· {}", age_label(now, t)))
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
                        // directory tree to $TMPDIR/liora-files/ and
                        // fires the platform opener, mirroring the
                        // wiki widget's files:-link behaviour.
                        // `Align::Min` cross-axis: Center would feed
                        // the frame-delayed cell-sizing loop.
                        if row.root.is_some() {
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Min),
                                |ui| {
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
                                        *open_root = row.root;
                                    }
                                },
                            );
                        }
                    });

                    // Source path is the most useful identifier for
                    // an import — emphasise it as the card title.
                    if let Some(path) = row.source_path.as_ref() {
                        ui.label(
                            egui::RichText::new(shorten_path(path))
                                .monospace()
                                .size(14.0)
                                .color(text_on_accent),
                        );
                    }
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
                    if let Some(path) = row.source_path.as_ref() {
                        ui.label(
                            egui::RichText::new(path)
                                .monospace()
                                .small()
                                .color(body_muted),
                        );
                    }

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
                    let mut footer = format!("IMPORT {}", id_hex(row.id));
                    if let Some(r) = row.root {
                        footer.push_str(&format!(" · ROOT {}", id_hex(r)));
                    }
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
