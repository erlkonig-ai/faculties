//! Read-only GORBIE-embeddable viewer for the `headspace` faculty.
//!
//! Headspace is the playground's active-agent config: which model
//! profile is active, what its model name / base URL / reasoning
//! effort / token budgets look like, plus the inactive profiles
//! available to switch to. This widget renders the live state as a
//! single "you are here" card plus a compact roster of other
//! profiles.
//!
//! The data lives in the immutable Headspace collection. Complete profile and
//! config snapshots form independent supersession DAGs; the shared Headspace
//! resolver keeps forks visible rather than selecting a timestamp winner.
//!
//! ```ignore
//! let mut panel = HeadspaceViewer::default();
//! panel.render(ctx, config_ws);
//! ```

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use crate::headspace::{self, Catalog, ProfileValue, Resolution};
use crate::widgets::storage::{DatasetRevision, DatasetView};
use triblespace::core::id::Id;

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

fn profile_color(id: Id) -> egui::Color32 {
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

struct HeadspaceLive {
    cached_revision: DatasetRevision,
    catalog: Catalog,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl HeadspaceLive {
    fn refresh(dataset: DatasetView<'_>) -> Self {
        HeadspaceLive {
            cached_revision: dataset.revision,
            catalog: headspace::project(dataset.reader, dataset.facts),
        }
    }
}

fn short_hex(id: Id) -> String {
    let full = format!("{id:x}");
    full.chars().take(8).collect()
}

fn id_hex(id: Id) -> String {
    format!("{id:x}")
}

fn format_tokens(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f32 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0}K", n as f32 / 1_000.0)
    } else {
        format!("{n}")
    }
}

// ── Widget ───────────────────────────────────────────────────────────

pub struct HeadspaceViewer {
    live: Option<HeadspaceLive>,
}

impl Default for HeadspaceViewer {
    fn default() -> Self {
        Self { live: None }
    }
}

impl HeadspaceViewer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn render(&mut self, ctx: &mut CardCtx<'_>, dataset: DatasetView<'_>) {
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_revision != dataset.revision,
        };
        if need_refresh {
            self.live = Some(HeadspaceLive::refresh(dataset));
        }

        ctx.section("Headspace", |ctx| {
            let Some(live) = self.live.as_ref() else {
                return;
            };
            let catalog = &live.catalog;
            let settled_config = settled(&catalog.config);

            ctx.grid(|g| {
                // Header line — total profile count + persona summary.
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let label = format!(
                        "{} PROFILE{}{}",
                        catalog.profiles.len(),
                        if catalog.profiles.len() == 1 { "" } else { "S" },
                        match settled_config.and_then(|config| config.persona) {
                            Some(pid) => format!(" · PERSONA {}", short_hex(pid).to_uppercase()),
                            None => String::new(),
                        },
                    );
                    ui.label(
                        egui::RichText::new(label)
                            .monospace()
                            .strong()
                            .small()
                            .color(color_muted(ui)),
                    );
                });

                // Active-profile hero card.
                match &catalog.config {
                    Resolution::Missing => g.full(|ctx| {
                        render_diagnostic(
                            ctx.ui_mut(),
                            "No Headspace snapshots; built-in defaults are active.",
                        );
                    }),
                    Resolution::Forked(heads) => g.full(|ctx| {
                        render_diagnostic(
                            ctx.ui_mut(),
                            &format!("Config fork: {} live heads.", heads.len()),
                        );
                    }),
                    Resolution::Invalid(error) => g.full(|ctx| {
                        render_diagnostic(ctx.ui_mut(), &format!("Invalid Headspace: {error}"));
                    }),
                    Resolution::Unique(_) | Resolution::Agreed(_) => {
                        let config = settled_config.expect("settled resolution has a value");
                        match catalog.profiles.get(&config.active_profile) {
                            Some(resolution) if settled(resolution).is_some() => g.full(|ctx| {
                                render_active_card(
                                    ctx.ui_mut(),
                                    settled(resolution).unwrap(),
                                    config.persona,
                                );
                            }),
                            Some(Resolution::Forked(heads)) => g.full(|ctx| {
                                render_diagnostic(
                                    ctx.ui_mut(),
                                    &format!("Active profile fork: {} live heads.", heads.len()),
                                );
                            }),
                            Some(Resolution::Invalid(error)) => g.full(|ctx| {
                                render_diagnostic(
                                    ctx.ui_mut(),
                                    &format!("Invalid active profile: {error}"),
                                );
                            }),
                            _ => g.full(|ctx| {
                                render_diagnostic(ctx.ui_mut(), "Active profile is missing.");
                            }),
                        }
                    }
                }

                // Other profiles roster.
                let active_anchor = settled_config.map(|config| config.active_profile);
                let mut others: Vec<&ProfileValue> = catalog
                    .profiles
                    .iter()
                    .filter(|(anchor, _)| Some(**anchor) != active_anchor)
                    .filter_map(|(_, resolution)| settled(resolution))
                    .collect();
                if !others.is_empty() {
                    others.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new("OTHER PROFILES")
                                .monospace()
                                .strong()
                                .small()
                                .color(color_muted(ui)),
                        );
                    });
                    for p in others {
                        g.full(|ctx| {
                            render_other_profile_card(ctx.ui_mut(), p);
                        });
                    }
                }

                for (anchor, resolution) in &catalog.profiles {
                    let message = match resolution {
                        Resolution::Forked(heads) => Some(format!(
                            "Profile {} fork: {} live heads.",
                            short_hex(*anchor),
                            heads.len()
                        )),
                        Resolution::Invalid(error) => {
                            Some(format!("Profile {} invalid: {error}", short_hex(*anchor)))
                        }
                        Resolution::Missing => {
                            Some(format!("Profile {} is missing.", short_hex(*anchor)))
                        }
                        Resolution::Unique(_) | Resolution::Agreed(_) => None,
                    };
                    if let Some(message) = message {
                        g.full(|ctx| render_diagnostic(ctx.ui_mut(), &message));
                    }
                }
            });
        });
    }
}

fn settled<T>(resolution: &Resolution<T>) -> Option<&T> {
    match resolution {
        Resolution::Unique(snapshot) => Some(&snapshot.value),
        Resolution::Agreed(snapshots) => snapshots.first().map(|snapshot| &snapshot.value),
        Resolution::Missing | Resolution::Forked(_) | Resolution::Invalid(_) => None,
    }
}

fn render_diagnostic(ui: &mut egui::Ui, message: &str) {
    ui.add_space(8.0);
    ui.label(
        egui::RichText::new(message)
            .monospace()
            .small()
            .color(color_muted(ui)),
    );
    ui.add_space(8.0);
}

// ── Active-profile hero card ────────────────────────────────────────

fn render_active_card(ui: &mut egui::Ui, p: &ProfileValue, persona_id: Option<Id>) {
    let bubble_fill = ui.visuals().window_fill;
    let accent = profile_color(p.anchor);
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

            // ── Header: profile name + ACTIVE badge on accent ──
            egui::Frame::NONE
                .fill(accent)
                .corner_radius(egui::CornerRadius::ZERO)
                .inner_margin(egui::Margin {
                    left: 10,
                    right: 10,
                    top: 8,
                    bottom: 8,
                })
                .show(ui, |ui| {
                    // Force the header to span the card's full width
                    // so the accent fill paints edge-to-edge — without
                    // this, the Frame sizes to content and you get a
                    // colour bar shorter than the card.
                    ui.set_min_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("ACTIVE")
                                .monospace()
                                .small()
                                .strong()
                                .color(text_on_accent),
                        );
                        ui.label(
                            egui::RichText::new("·")
                                .monospace()
                                .small()
                                .color(text_on_accent),
                        );
                        ui.label(
                            egui::RichText::new(&p.name)
                                .size(18.0)
                                .color(text_on_accent),
                        );
                    });
                    ui.label(
                        egui::RichText::new(id_hex(p.anchor))
                            .monospace()
                            .small()
                            .color(text_on_accent),
                    );
                });

            // ── Body: model, URL, reasoning, token budget ──
            egui::Frame::NONE
                .fill(bubble_fill)
                .corner_radius(egui::CornerRadius::ZERO)
                .inner_margin(egui::Margin {
                    left: 10,
                    right: 10,
                    top: 8,
                    bottom: 10,
                })
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.spacing_mut().item_spacing.y = 4.0;

                    // Model name as a primary line.
                    ui.label(
                        egui::RichText::new(&p.model)
                            .monospace()
                            .strong()
                            .size(14.0)
                            .color(body_text),
                    );

                    ui.label(
                        egui::RichText::new(&p.base_url)
                            .monospace()
                            .small()
                            .color(body_muted),
                    );

                    // Pill row: reasoning effort, stream/no-stream, api-key indicator.
                    ui.add_space(2.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(4.0, 4.0);
                        if let Some(eff) = p.reasoning_effort.as_ref() {
                            render_chip(ui, &format!("REASONING {}", eff.to_uppercase()));
                        }
                        render_chip(ui, if p.stream { "STREAM" } else { "NO-STREAM" });
                        if p.api_key.is_some() {
                            render_chip(ui, "API KEY \u{1F511}"); // 🔑
                        }
                        if let Some(persona) = persona_id {
                            render_chip(
                                ui,
                                &format!("PERSONA {}", short_hex(persona).to_uppercase()),
                            );
                        }
                    });

                    // Token-budget bar — context window split into
                    // (max output) | (safety margin) | (the rest available
                    // for input). Visual proportion at a glance.
                    ui.add_space(6.0);
                    render_token_budget(
                        ui,
                        p.context_window_tokens,
                        p.max_output_tokens,
                        p.context_safety_margin_tokens,
                        p.chars_per_token,
                        accent,
                        body_text,
                        body_muted,
                    );
                });
        });
}

fn render_token_budget(
    ui: &mut egui::Ui,
    window: u64,
    max_out: u64,
    safety: u64,
    chars_per_tok: u64,
    accent: egui::Color32,
    body_text: egui::Color32,
    body_muted: egui::Color32,
) {
    // Header line: "CONTEXT 200K · OUT 16K · SAFETY 1K · ~4 ch/tok"
    let parts = format!(
        "CONTEXT {} · OUT {} · SAFETY {} · ~{} CH/TOK",
        format_tokens(window),
        format_tokens(max_out),
        format_tokens(safety),
        chars_per_tok.max(1),
    );
    ui.label(
        egui::RichText::new(parts)
            .monospace()
            .small()
            .color(body_muted),
    );

    // Bar: full width, 8 px tall. Two segments — safety + max-out
    // (carved off the right), the remainder is "available for input"
    // shown in the accent colour. Gives a quick visual read of
    // "how much room do I have for context".
    let bar_height = 8.0;
    let (bar_rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), bar_height),
        egui::Sense::hover(),
    );
    let painter = ui.painter();
    // Background: framing colour for "context window" total.
    let frame = color_frame(ui);
    painter.rect_filled(bar_rect, egui::CornerRadius::ZERO, frame);

    let total = window.max(1) as f32;
    let safety_w = (safety as f32 / total) * bar_rect.width();
    let out_w = (max_out as f32 / total) * bar_rect.width();
    let used_w = safety_w + out_w;
    let input_w = (bar_rect.width() - used_w).max(0.0);

    // Input segment (accent — what the agent has to work with).
    let input_rect = egui::Rect::from_min_size(bar_rect.min, egui::vec2(input_w, bar_height));
    painter.rect_filled(input_rect, egui::CornerRadius::ZERO, accent);

    // Max-output segment (muted accent — reserved for the reply).
    let out_rect = egui::Rect::from_min_size(
        egui::pos2(bar_rect.left() + input_w, bar_rect.top()),
        egui::vec2(out_w, bar_height),
    );
    painter.rect_filled(
        out_rect,
        egui::CornerRadius::ZERO,
        mix(accent, body_text, 0.55),
    );

    // Safety segment (the right edge — the do-not-cross buffer).
    let safety_rect = egui::Rect::from_min_size(
        egui::pos2(bar_rect.left() + input_w + out_w, bar_rect.top()),
        egui::vec2(safety_w, bar_height),
    );
    painter.rect_filled(
        safety_rect,
        egui::CornerRadius::ZERO,
        mix(body_text, frame, 0.40),
    );
}

// ── Inactive-profile card ───────────────────────────────────────────

fn render_other_profile_card(ui: &mut egui::Ui, p: &ProfileValue) {
    let bubble_fill = ui.visuals().window_fill;
    let accent = profile_color(p.anchor);
    let body_text = colorhash::text_color_on(bubble_fill);
    let body_muted = mix(body_text, bubble_fill, 0.30);

    egui::Frame::NONE
        .fill(bubble_fill)
        .stroke(egui::Stroke::new(1.0, color_frame(ui)))
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
                // 8-px swatch indicating profile colour identity.
                let (swatch, _) =
                    ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                ui.painter()
                    .rect_filled(swatch, egui::CornerRadius::ZERO, accent);
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(&p.name)
                        .monospace()
                        .strong()
                        .size(13.0)
                        .color(body_text),
                );
                ui.label(
                    egui::RichText::new("·")
                        .monospace()
                        .small()
                        .color(body_muted),
                );
                ui.label(
                    egui::RichText::new(&p.model)
                        .monospace()
                        .small()
                        .color(body_muted),
                );
            });
            ui.label(
                egui::RichText::new(id_hex(p.anchor))
                    .monospace()
                    .small()
                    .color(body_muted),
            );
        });
}

// ── Small chip used in the active card's pill row ──────────────────

fn render_chip(ui: &mut egui::Ui, label: &str) {
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
