//! Read-only GORBIE-embeddable viewer for the `headspace` faculty.
//!
//! Headspace is the playground's active-agent config: which model profile is
//! active, what its model name / base URL / reasoning effort / token budgets
//! look like, plus the inactive profiles available to switch to. This widget
//! renders the live state as a single "you are here" card plus a compact
//! roster of other profiles.
//!
//! It consumes the exact native Headspace and Secrets collection snapshots.
//! The shared projector preserves missing, agreed, and forked DAG heads; this
//! widget never chooses a timestamp winner and never decrypts a credential.
//!
//! ```ignore
//! let mut panel = HeadspaceViewer::default();
//! panel.render(ctx, headspace_view, secrets_view);
//! ```

use std::collections::HashMap;

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use crate::headspace::{self, ProfileValue, Resolution};
use triblespace::core::id::Id;

use super::storage::{DatasetRevision, DatasetView, SecretsView};

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

// ── Row structs ──────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct ModelProfile {
    id: Id,
    name: String,
    model_name: Option<String>,
    base_url: Option<String>,
    reasoning_effort: Option<String>,
    stream: Option<bool>,
    context_window_tokens: Option<u64>,
    max_output_tokens: Option<u64>,
    context_safety_margin_tokens: Option<u64>,
    chars_per_token: Option<u64>,
    has_api_key: bool,
    resolution: Option<String>,
}

impl ModelProfile {
    fn empty(id: Id) -> Self {
        Self {
            id,
            name: String::new(),
            model_name: None,
            base_url: None,
            reasoning_effort: None,
            stream: None,
            context_window_tokens: None,
            max_output_tokens: None,
            context_safety_margin_tokens: None,
            chars_per_token: None,
            has_api_key: false,
            resolution: None,
        }
    }

    fn from_value(value: &ProfileValue, resolution: Option<String>) -> Self {
        Self {
            id: value.anchor,
            name: value.name.clone(),
            model_name: Some(value.model.clone()),
            base_url: Some(value.base_url.clone()),
            reasoning_effort: value.reasoning_effort.clone(),
            stream: Some(value.stream),
            context_window_tokens: Some(value.context_window_tokens),
            max_output_tokens: Some(value.max_output_tokens),
            context_safety_margin_tokens: Some(value.context_safety_margin_tokens),
            chars_per_token: Some(value.chars_per_token),
            has_api_key: value.model_secret_version.is_some(),
            resolution,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ActiveConfig {
    persona_id: Option<Id>,
    active_profile_id: Option<Id>,
    resolution: Option<String>,
}

struct HeadspaceLive {
    headspace_revision: DatasetRevision,
    secrets_revision: DatasetRevision,
    active: ActiveConfig,
    profiles: HashMap<Id, ModelProfile>,
    diagnostic: Option<String>,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl HeadspaceLive {
    fn refresh(headspace_view: DatasetView<'_>, secrets_view: SecretsView<'_>) -> Self {
        let result = (|| {
            let catalog = headspace::project_result(headspace_view.reader, headspace_view.facts)
                .map_err(|error| format!("Headspace collection: {error:#}"))?;
            headspace::validate_secret_references_v2(&catalog, secrets_view.snapshot)
                .map_err(|error| format!("Headspace secret references: {error:#}"))?;
            Ok::<_, String>((load_active_config(&catalog), load_profiles(&catalog)))
        })();

        let (active, profiles, diagnostic) = match result {
            Ok((active, profiles)) => (active, profiles, None),
            Err(error) => (ActiveConfig::default(), HashMap::new(), Some(error)),
        };
        Self {
            headspace_revision: headspace_view.revision,
            secrets_revision: secrets_view.revision,
            active,
            profiles,
            diagnostic,
        }
    }
}

fn load_active_config(catalog: &headspace::Catalog) -> ActiveConfig {
    match &catalog.config {
        Resolution::Missing => ActiveConfig {
            resolution: Some("NO NATIVE CONFIG".to_owned()),
            ..ActiveConfig::default()
        },
        Resolution::Unique(snapshot) => ActiveConfig {
            persona_id: snapshot.value.persona,
            active_profile_id: Some(snapshot.value.active_profile),
            resolution: None,
        },
        Resolution::Agreed(snapshots) => snapshots
            .first()
            .map(|snapshot| ActiveConfig {
                persona_id: snapshot.value.persona,
                active_profile_id: Some(snapshot.value.active_profile),
                resolution: Some(format!("{} CONFIG HEADS AGREE", snapshots.len())),
            })
            .unwrap_or_default(),
        Resolution::Forked(snapshots) => ActiveConfig {
            resolution: Some(format!("CONFIG FORK · {} HEADS", snapshots.len())),
            ..ActiveConfig::default()
        },
        Resolution::Invalid(error) => ActiveConfig {
            resolution: Some(format!("INVALID CONFIG · {error}")),
            ..ActiveConfig::default()
        },
    }
}

fn load_profiles(catalog: &headspace::Catalog) -> HashMap<Id, ModelProfile> {
    let mut out = HashMap::new();
    for (anchor, resolution) in &catalog.profiles {
        let profile = match resolution {
            Resolution::Unique(snapshot) => ModelProfile::from_value(&snapshot.value, None),
            Resolution::Agreed(snapshots) => snapshots
                .first()
                .map(|snapshot| {
                    ModelProfile::from_value(
                        &snapshot.value,
                        Some(format!("{} HEADS AGREE", snapshots.len())),
                    )
                })
                .unwrap_or_else(|| ModelProfile::empty(*anchor)),
            Resolution::Forked(snapshots) => {
                let mut profile = ModelProfile::empty(*anchor);
                profile.name = format!("forked-{}", short_hex(*anchor));
                profile.resolution = Some(format!("FORK · {} HEADS", snapshots.len()));
                profile
            }
            Resolution::Missing => {
                let mut profile = ModelProfile::empty(*anchor);
                profile.name = format!("missing-{}", short_hex(*anchor));
                profile.resolution = Some("MISSING".to_owned());
                profile
            }
            Resolution::Invalid(error) => {
                let mut profile = ModelProfile::empty(*anchor);
                profile.name = format!("invalid-{}", short_hex(*anchor));
                profile.resolution = Some(format!("INVALID · {error}"));
                profile
            }
        };
        out.insert(*anchor, profile);
    }
    out
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

    pub fn render(
        &mut self,
        ctx: &mut CardCtx<'_>,
        headspace_view: DatasetView<'_>,
        secrets_view: SecretsView<'_>,
    ) {
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(live) => {
                live.headspace_revision != headspace_view.revision
                    || live.secrets_revision != secrets_view.revision
            }
        };
        if need_refresh {
            self.live = Some(HeadspaceLive::refresh(headspace_view, secrets_view));
        }

        ctx.section("Headspace", |ctx| {
            let Some(live) = self.live.as_ref() else {
                return;
            };

            if let Some(diagnostic) = live.diagnostic.as_deref() {
                render_diagnostic(ctx.ui_mut(), diagnostic);
                return;
            }

            ctx.grid(|g| {
                if let Some(resolution) = live.active.resolution.as_deref() {
                    g.full(|ctx| render_diagnostic(ctx.ui_mut(), resolution));
                }

                // Header line — total profile count + persona summary.
                g.full(|ctx| {
                    let ui = ctx.ui_mut();
                    let label = format!(
                        "{} PROFILE{}{}",
                        live.profiles.len(),
                        if live.profiles.len() == 1 { "" } else { "S" },
                        match live.active.persona_id {
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
                let active = live
                    .active
                    .active_profile_id
                    .and_then(|pid| live.profiles.get(&pid));
                if let Some(p) = active {
                    g.full(|ctx| {
                        render_active_card(ctx.ui_mut(), p, live.active.persona_id);
                    });
                } else {
                    g.full(|ctx| {
                        let ui = ctx.ui_mut();
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new("No active model profile.")
                                .monospace()
                                .small()
                                .color(color_muted(ui)),
                        );
                        ui.add_space(8.0);
                    });
                }

                // Other profiles roster.
                let mut others: Vec<&ModelProfile> = live
                    .profiles
                    .values()
                    .filter(|p| Some(p.id) != live.active.active_profile_id)
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
            });
        });
    }
}

// ── Active-profile hero card ────────────────────────────────────────

fn render_active_card(ui: &mut egui::Ui, p: &ModelProfile, persona_id: Option<Id>) {
    let bubble_fill = ui.visuals().window_fill;
    let accent = profile_color(p.id);
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
                        egui::RichText::new(id_hex(p.id))
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
                    if let Some(m) = p.model_name.as_ref() {
                        ui.label(
                            egui::RichText::new(m)
                                .monospace()
                                .strong()
                                .size(14.0)
                                .color(body_text),
                        );
                    }

                    if let Some(url) = p.base_url.as_ref() {
                        ui.label(
                            egui::RichText::new(url)
                                .monospace()
                                .small()
                                .color(body_muted),
                        );
                    }

                    // Pill row: reasoning effort, stream/no-stream, api-key indicator.
                    ui.add_space(2.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(4.0, 4.0);
                        if let Some(resolution) = p.resolution.as_deref() {
                            render_chip(ui, resolution);
                        }
                        if let Some(eff) = p.reasoning_effort.as_ref() {
                            render_chip(ui, &format!("REASONING {}", eff.to_uppercase()));
                        }
                        match p.stream {
                            Some(true) => render_chip(ui, "STREAM"),
                            Some(false) => render_chip(ui, "NO-STREAM"),
                            None => {}
                        }
                        if p.has_api_key {
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
                    if let Some(window) = p.context_window_tokens {
                        ui.add_space(6.0);
                        render_token_budget(
                            ui,
                            window,
                            p.max_output_tokens.unwrap_or(0),
                            p.context_safety_margin_tokens.unwrap_or(0),
                            p.chars_per_token.unwrap_or(4),
                            accent,
                            body_text,
                            body_muted,
                        );
                    }
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

fn render_other_profile_card(ui: &mut egui::Ui, p: &ModelProfile) {
    let bubble_fill = ui.visuals().window_fill;
    let accent = profile_color(p.id);
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
                if let Some(m) = p.model_name.as_ref() {
                    ui.label(
                        egui::RichText::new("·")
                            .monospace()
                            .small()
                            .color(body_muted),
                    );
                    ui.label(egui::RichText::new(m).monospace().small().color(body_muted));
                }
                if let Some(resolution) = p.resolution.as_deref() {
                    render_chip(ui, resolution);
                }
            });
            ui.label(
                egui::RichText::new(id_hex(p.id))
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

fn render_diagnostic(ui: &mut egui::Ui, message: &str) {
    let color = egui::Color32::from_rgb(0xd1, 0x83, 0x16);
    let background = egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 36);
    egui::Frame::NONE
        .fill(background)
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(egui::CornerRadius::ZERO)
        .inner_margin(egui::Margin::symmetric(8, 5))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new(message)
                    .monospace()
                    .small()
                    .strong()
                    .color(color),
            );
        });
}
