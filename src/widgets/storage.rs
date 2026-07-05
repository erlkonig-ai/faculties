//! Shared pile state for faculty widgets.
//!
//! A single `StorageState` holds an open `Repository<Pile>` and
//! renders the top-bar pile-path selector / error banner. Widgets pull a
//! fresh [`Workspace`] each frame via [`StorageState::workspace`]; if the
//! callsite mutates the workspace, it pushes back with
//! [`StorageState::push`]. Nothing is cached across frames — the storage
//! itself (pile + repo) is the only shared state.
//!
//! ```ignore
//! let storage = nb.state(
//!     "storage",
//!     StorageState::new("./self.pile"),
//!     |ctx, st| st.top_bar(ctx),
//! );
//!
//! nb.state("wiki", WikiViewer::default(), |ctx, wiki| {
//!     let mut st = storage.read_mut(ctx);
//!     let Some(mut ws) = st.workspace("wiki") else { return };
//!     wiki.render(ctx, &mut ws, None);
//!     st.push(&mut ws); // no-op if head didn't advance
//! });
//! ```

use std::path::PathBuf;

use GORBIE::prelude::CardCtx;
use triblespace::core::id::Id;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{BlobStore, BlobStoreGet, PinStore, Repository, Workspace};
use triblespace::core::trible::TribleSet;
use triblespace::core::inline::encodings::hash::{Blake3, Handle};
use triblespace::core::inline::Inline;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::View;

type TextHandle = Inline<Handle<LongString>>;

/// Shared open pile + repository. Workspaces are pulled fresh per call.
pub struct StorageState {
    /// Open repository. `None` when the last open attempt failed; see
    /// [`StorageState::error`] for the message.
    repo: Option<Repository<Pile>>,
    /// Canonical path the pile was opened from.
    pile_path: PathBuf,
    /// Editable text buffer for the top-bar path field.
    pile_path_text: String,
    /// Pile-open error banner shown above child widgets.
    error: Option<String>,
    /// Transient toast from the last push (clears on next successful push).
    toast: Option<String>,
}

impl StorageState {
    /// Stash the pile path for lazy open. No I/O happens here — the
    /// pile is opened on the first call that needs it (`workspace`,
    /// `top_bar`, `push`).
    ///
    /// This matters because `GORBIE::NotebookCtx::state` takes its
    /// initial value eagerly: it's constructed every frame and
    /// discarded when state already exists. A heavy constructor
    /// (opening a pile) every frame would spam pile-not-closed warnings
    /// and churn mmap handles.
    pub fn new(pile_path: impl Into<PathBuf>) -> Self {
        let pile_path = pile_path.into();
        let pile_path_text = pile_path.to_string_lossy().into_owned();
        Self {
            repo: None,
            pile_path,
            pile_path_text,
            error: None,
            toast: None,
        }
    }

    /// Open the pile at `self.pile_path` if it isn't already open.
    /// No-op if the repo is already open or the last open attempt
    /// failed (see `error`).
    fn ensure_open(&mut self) {
        if self.repo.is_some() || self.error.is_some() {
            return;
        }
        self.open_current_path();
    }

    /// Reopen against a new path.
    pub fn set_pile_path(&mut self, path: impl Into<PathBuf>) {
        let path = path.into();
        if path == self.pile_path && self.repo.is_some() {
            return;
        }
        self.pile_path = path;
        self.pile_path_text = self.pile_path.to_string_lossy().into_owned();
        self.toast = None;
        self.open_current_path();
    }

    fn open_current_path(&mut self) {
        // Cleanly close the existing repo before replacing it, so the
        // old pile's drop path doesn't emit a "dropped without close()"
        // warning.
        if let Some(repo) = self.repo.take() {
            let _ = repo.close();
        }
        self.error = None;
        let mut pile = match Pile::open(&self.pile_path) {
            Ok(p) => p,
            Err(e) => {
                self.error = Some(format!("open pile: {e:?}"));
                return;
            }
        };
        if let Err(err) = pile.refresh() {
            let _ = pile.close();
            self.error = Some(format!(
                "pile corrupt ({err:?}): refusing to auto-repair (a stale binary could truncate \
                 newer data). Repair a torn tail explicitly with: trible pile amputate {}",
                self.pile_path.display()
            ));
            return;
        }
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let mut repo = match Repository::new(pile, signing_key, TribleSet::new()) {
            Ok(r) => r,
            Err(e) => {
                self.error = Some(format!("repo: {e:?}"));
                return;
            }
        };
        if let Err(e) = repo.storage_mut().refresh() {
            self.error = Some(format!("refresh: {e:?}"));
            return;
        }
        self.repo = Some(repo);
    }

    /// Pull a fresh workspace for `branch`. `None` if no repo is open or
    /// the branch is missing. Each call is a fresh pull — workspaces are
    /// NOT cached across frames.
    pub fn workspace(&mut self, branch: &str) -> Option<Workspace<Pile>> {
        self.ensure_open();
        let repo = self.repo.as_mut()?;
        let bid = find_branch(repo, branch)?;
        match repo.pull(bid) {
            Ok(ws) => Some(ws),
            Err(e) => {
                self.toast = Some(format!("pull {branch}: {e:?}"));
                None
            }
        }
    }

    /// Push `ws` back. Internally a no-op when the workspace's head
    /// didn't advance (the underlying `Repository::push` short-circuits
    /// on `base_head == head`), so callers can invoke this
    /// unconditionally. On CAS failure / storage error, stores a toast.
    /// Uses `Repository::push` which handles merge-retry internally.
    pub fn push(&mut self, ws: &mut Workspace<Pile>) {
        self.ensure_open();
        let Some(repo) = self.repo.as_mut() else {
            return;
        };
        match repo.push(ws) {
            Ok(()) => {
                self.toast = None;
            }
            Err(e) => {
                self.toast = Some(format!("push: {e:?}"));
            }
        }
    }

    /// Current error message (pile open / refresh failure),
    /// if any.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Current toast (from the last failed push / pull), if any.
    pub fn toast(&self) -> Option<&str> {
        self.toast.as_deref()
    }

    /// Render the top bar: pile path field + Open button + optional
    /// error/toast banner. Call once per frame at the start of a
    /// notebook.
    pub fn top_bar(&mut self, ctx: &mut CardCtx<'_>) {
        self.ensure_open();
        let is_open = self.repo.is_some();
        let has_error = self.error.is_some();
        let mut reopen = false;
        let status_color = if has_error {
            egui::Color32::from_rgb(0xcc, 0x0a, 0x17) // RAL 3020
        } else if is_open {
            egui::Color32::from_rgb(0x23, 0x7f, 0x52) // RAL 6032
        } else {
            egui::Color32::from_rgb(0x4d, 0x55, 0x59) // RAL 7012
        };
        let panel_fill = ctx.ctx().global_style().visuals.panel_fill;
        let bar_bg = egui::Color32::from_rgba_unmultiplied(
            panel_fill.r().saturating_sub(6),
            panel_fill.g().saturating_sub(6),
            panel_fill.b().saturating_sub(6),
            255,
        );
        let muted = egui::Color32::from_rgb(0x8a, 0x8a, 0x8a);
        let ui = ctx.ui_mut();
        egui::Frame::NONE
            .fill(bar_bg)
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_black_alpha(40),
            ))
            .corner_radius(egui::CornerRadius::same(4))
            .inner_margin(egui::Margin::symmetric(10, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    // Status dot.
                    let (dot_rect, _) = ui.allocate_exact_size(
                        egui::vec2(10.0, 10.0),
                        egui::Sense::hover(),
                    );
                    ui.painter().circle_filled(dot_rect.center(), 4.0, status_color);
                    ui.label(
                        egui::RichText::new("PILE")
                            .small()
                            .monospace()
                            .strong()
                            .color(status_color),
                    );
                    // Subtle divider glyph between label and field.
                    ui.label(egui::RichText::new("│").small().color(muted));
                    // Path field uses GORBIE's wide LCD-style
                    // TextField (auto-sizes to available_width), with
                    // OPEN placed on the right via right_to_left so
                    // the field flows up against the button.
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            let open_btn = ui.add(
                                egui::Button::new(
                                    egui::RichText::new("OPEN")
                                        .small()
                                        .monospace()
                                        .strong(),
                                )
                                .min_size(egui::vec2(52.0, 22.0)),
                            );
                            if open_btn.clicked() {
                                reopen = true;
                            }
                            ui.with_layout(
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    let resp = ui.add(
                                        GORBIE::widgets::TextField::singleline(
                                            &mut self.pile_path_text,
                                        ),
                                    );
                                    if resp.lost_focus()
                                        && ui.input(|i| i.key_pressed(egui::Key::Enter))
                                    {
                                        reopen = true;
                                    }
                                },
                            );
                        },
                    );
                });
            });
        if reopen {
            let trimmed = self.pile_path_text.trim().to_string();
            self.set_pile_path(PathBuf::from(trimmed));
        }

        if let Some(err) = self.error.as_ref() {
            render_banner(
                ctx,
                "\u{26a0}",
                &format!("pile open error: {err}"),
                ctx.ctx().global_style().visuals.error_fg_color,
            );
        }
        let mut dismiss_toast = false;
        if let Some(toast) = self.toast.as_ref() {
            let ui = ctx.ui_mut();
            let warn_fg = egui::Color32::from_rgb(0xf7, 0xba, 0x0b); // RAL 1003
            let warn_bg = egui::Color32::from_rgb(0x33, 0x2d, 0x12);
            egui::Frame::NONE
                .fill(warn_bg)
                .stroke(egui::Stroke::new(1.0, warn_fg))
                .corner_radius(egui::CornerRadius::same(3))
                .inner_margin(egui::Margin::symmetric(8, 4))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        ui.label(
                            egui::RichText::new("\u{26a0}")
                                .small()
                                .color(warn_fg),
                        );
                        ui.label(
                            egui::RichText::new(toast.as_str())
                                .monospace()
                                .small()
                                .color(warn_fg),
                        );
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if ui.small_button("\u{00d7}").clicked() {
                                    dismiss_toast = true;
                                }
                            },
                        );
                    });
                });
        }
        if dismiss_toast {
            self.toast = None;
        }
    }

    /// Cleanly close the underlying pile. Called automatically on drop
    /// but exposed so callers can surface close failures.
    pub fn close(&mut self) -> Result<(), String> {
        if let Some(repo) = self.repo.take() {
            repo.close()
                .map_err(|e| format!("close pile: {e:?}"))?;
        }
        Ok(())
    }
}

impl Drop for StorageState {
    fn drop(&mut self) {
        // Take the repo out so `close` can consume it. Swallow errors on
        // drop — nothing to do with them here; callers who care should
        // call `close()` explicitly before dropping.
        let _ = self.close();
    }
}

/// Render a single-line colored banner (icon + message) used for the
/// pile-open error path. Toast rendering is inline because it also
/// needs a dismiss button.
fn render_banner(ctx: &mut CardCtx<'_>, icon: &str, msg: &str, color: egui::Color32) {
    let ui = ctx.ui_mut();
    let bg = egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 40);
    egui::Frame::NONE
        .fill(bg)
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(egui::CornerRadius::same(3))
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(egui::RichText::new(icon).small().color(color));
                ui.label(
                    egui::RichText::new(msg)
                        .monospace()
                        .small()
                        .color(color),
                );
            });
        });
}

/// Walk a repository's branches and return the id of the branch named
/// `name`, or `None` if no such branch exists.
pub(crate) fn find_branch(repo: &mut Repository<Pile>, name: &str) -> Option<Id> {
    let reader = repo.storage_mut().reader().ok()?;
    for item in repo.storage_mut().pins().ok()? {
        let bid = item.ok()?;
        let head = repo.storage_mut().head(bid).ok()??;
        let meta: TribleSet = reader.get(head).ok()?;
        let got = find!(
            (h: TextHandle),
            pattern!(&meta, [{ metadata::name: ?h }])
        )
        .into_iter()
        .next()
        .and_then(|(h,)| reader.get::<View<str>, LongString>(h).ok())
        .map(|v: View<str>| {
            let s: &str = v.as_ref();
            s.to_string()
        });
        if got.as_deref() == Some(name) {
            return Some(bid);
        }
    }
    None
}

// Compile-time check that `StorageState` is `Send + Sync`. Required for
// GORBIE 0.11.1's RwLock-backed state store.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<StorageState>();
};
