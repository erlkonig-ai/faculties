//! Read-only GORBIE-embeddable viewer for the `headspace` faculty.
//!
//! Headspace is the playground's active-agent config: which model
//! profile is active, what its model name / base URL / reasoning
//! effort / token budgets look like, plus the inactive profiles
//! available to switch to. This widget renders the live state as a
//! single "you are here" card plus a compact roster of other
//! profiles.
//!
//! The data lives on the `config` branch (the faculty's
//! `CONFIG_BRANCH` constant). One `KIND_CONFIG_ID` entity carries
//! the active configuration; the active model profile is referenced
//! by `active_model_profile_id` and resolves to a
//! `KIND_MODEL_PROFILE_ID` entity that holds the model-name,
//! base-url, token-budget, etc. attributes. The latest entry per
//! kind is selected by `metadata::updated_at` — appends are
//! history-preserving so older rows stay readable via timeline.
//!
//! ```ignore
//! let mut panel = HeadspaceViewer::default();
//! panel.render(ctx, config_ws);
//! ```

use std::collections::HashMap;

use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{CommitHandle, Workspace};
use triblespace::core::trible::TribleSet;
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{NsTAIInterval, U256BE};
use triblespace::prelude::View;

use crate::schemas::headspace::{
    playground_config, KIND_CONFIG_ID, KIND_MODEL_PROFILE_ID,
};

type TextHandle = Inline<Handle<LongString>>;

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
        ((x as f32) * (1.0 - t) + (y as f32) * t).round().clamp(0.0, 255.0) as u8
    };
    egui::Color32::from_rgb(
        lerp(a.r(), b.r()),
        lerp(a.g(), b.g()),
        lerp(a.b(), b.b()),
    )
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
        }
    }
}

#[derive(Clone, Debug, Default)]
struct ActiveConfig {
    persona_id: Option<Id>,
    active_profile_id: Option<Id>,
}

struct HeadspaceLive {
    cached_head: Option<CommitHandle>,
    active: ActiveConfig,
    /// All known model profiles, keyed by their profile id (the
    /// `playground_config::model_profile_id` value on the catalog
    /// entry — distinct from the entry's own entity id, which is
    /// the timestamped revision row).
    profiles: HashMap<Id, ModelProfile>,
}

// ── Live snapshot ────────────────────────────────────────────────────

impl HeadspaceLive {
    fn refresh(ws: &mut Workspace<Pile>) -> Self {
        let space = ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[headspace] checkout: {e:?}");
                TribleSet::new()
            });
        let cached_head = ws.head();
        let active = load_active_config(ws, &space);
        let profiles = load_profiles(ws, &space);
        HeadspaceLive {
            cached_head,
            active,
            profiles,
        }
    }
}

/// Pick the most-recently-updated `KIND_CONFIG_ID` entity and read
/// its persona pointer + active-profile pointer. There can be many
/// historical config rows; `metadata::updated_at` orders them and
/// the latest wins.
fn load_active_config(_ws: &mut Workspace<Pile>, space: &TribleSet) -> ActiveConfig {
    let mut best: Option<(Id, i128)> = None;
    for (config_id, updated_at) in find!(
        (config_id: Id, updated_at: Inline<NsTAIInterval>),
        pattern!(space, [{
            ?config_id @
            metadata::tag: KIND_CONFIG_ID,
            metadata::updated_at: ?updated_at,
        }])
    ) {
        let key = interval_key(updated_at);
        match best {
            Some((_, ck)) if ck >= key => {}
            _ => best = Some((config_id, key)),
        }
    }
    let Some((config_id, _)) = best else {
        return ActiveConfig::default();
    };
    let persona_id = find!(
        v: Id,
        pattern!(space, [{ config_id @ playground_config::persona_id: ?v }])
    )
    .next();
    let active_profile_id = find!(
        v: Id,
        pattern!(space, [{
            config_id @ playground_config::active_model_profile_id: ?v
        }])
    )
    .next();
    ActiveConfig {
        persona_id,
        active_profile_id,
    }
}

/// Walk every `KIND_MODEL_PROFILE_ID` catalog entry, keep only the
/// latest per `model_profile_id`, and load its attributes. The
/// catalog stores append-only revisions per profile id; the latest
/// `metadata::updated_at` is the live row.
fn load_profiles(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
) -> HashMap<Id, ModelProfile> {
    // Map profile_id → (entry_id, updated_at key) — pick the latest.
    let mut latest: HashMap<Id, (Id, i128)> = HashMap::new();
    for (entry_id, profile_id, updated_at) in find!(
        (entry_id: Id, profile_id: Id, updated_at: Inline<NsTAIInterval>),
        pattern!(space, [{
            ?entry_id @
            metadata::tag: KIND_MODEL_PROFILE_ID,
            metadata::updated_at: ?updated_at,
            playground_config::model_profile_id: ?profile_id,
        }])
    ) {
        let key = interval_key(updated_at);
        latest
            .entry(profile_id)
            .and_modify(|slot| {
                if key > slot.1 {
                    *slot = (entry_id, key);
                }
            })
            .or_insert((entry_id, key));
    }

    let mut out: HashMap<Id, ModelProfile> = HashMap::new();
    for (profile_id, (entry_id, _)) in latest {
        let mut p = ModelProfile::empty(profile_id);

        // Friendly name from metadata::name (Handle<LongString>).
        let name_handle = find!(
            h: TextHandle,
            pattern!(space, [{ entry_id @ metadata::name: ?h }])
        )
        .next();
        p.name = name_handle
            .and_then(|h| read_text(ws, h))
            .unwrap_or_else(|| format!("profile-{}", short_hex(profile_id)));

        // Model name (Handle<LongString>).
        let model_handle = find!(
            h: TextHandle,
            pattern!(space, [{ entry_id @ playground_config::model_name: ?h }])
        )
        .next();
        p.model_name = model_handle.and_then(|h| read_text(ws, h));

        // Base URL (Handle<LongString>).
        let url_handle = find!(
            h: TextHandle,
            pattern!(space, [{ entry_id @ playground_config::model_base_url: ?h }])
        )
        .next();
        p.base_url = url_handle.and_then(|h| read_text(ws, h));

        // Reasoning effort (Handle<LongString>).
        let effort_handle = find!(
            h: TextHandle,
            pattern!(space, [{ entry_id @ playground_config::model_reasoning_effort: ?h }])
        )
        .next();
        p.reasoning_effort = effort_handle.and_then(|h| read_text(ws, h));

        // API key presence (Handle<LongString>) — we don't surface
        // the secret, just whether one is configured.
        p.has_api_key = find!(
            h: TextHandle,
            pattern!(space, [{ entry_id @ playground_config::model_api_key: ?h }])
        )
        .next()
        .is_some();

        // U256BE numerics — extracted to u64 when the upper 24 bytes
        // are zero (i.e. the value really fits a u64).
        p.stream =
            find_u64(space, entry_id, |id| {
                find!(
                    v: Inline<U256BE>,
                    pattern!(space, [{ id @ playground_config::model_stream: ?v }])
                )
                .next()
            })
            .map(|n| n != 0);
        p.context_window_tokens = find_u64(space, entry_id, |id| {
            find!(
                v: Inline<U256BE>,
                pattern!(space, [{ id @ playground_config::model_context_window_tokens: ?v }])
            )
            .next()
        });
        p.max_output_tokens = find_u64(space, entry_id, |id| {
            find!(
                v: Inline<U256BE>,
                pattern!(space, [{ id @ playground_config::model_max_output_tokens: ?v }])
            )
            .next()
        });
        p.context_safety_margin_tokens = find_u64(space, entry_id, |id| {
            find!(
                v: Inline<U256BE>,
                pattern!(space, [{
                    id @ playground_config::model_context_safety_margin_tokens: ?v
                }])
            )
            .next()
        });
        p.chars_per_token = find_u64(space, entry_id, |id| {
            find!(
                v: Inline<U256BE>,
                pattern!(space, [{ id @ playground_config::model_chars_per_token: ?v }])
            )
            .next()
        });
        out.insert(profile_id, p);
    }
    out
}

fn interval_key(interval: Inline<NsTAIInterval>) -> i128 {
    // Two i128s packed as big-endian-ordered halves. Use the first
    // (start) bound as the sort key — matches what headspace.rs does.
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&interval.raw[..16]);
    i128::from_be_bytes(bytes)
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, LongString>(h).ok().map(|v| {
        let s: &str = v.as_ref();
        s.to_string()
    })
}

/// Decode a 32-byte big-endian U256 to u64 when the value fits.
/// `query` is a tiny closure that does the per-attribute find!() —
/// keeps the call sites readable without generic type plumbing.
fn find_u64<F>(_space: &TribleSet, entity_id: Id, query: F) -> Option<u64>
where
    F: FnOnce(Id) -> Option<Inline<U256BE>>,
{
    let raw = query(entity_id)?;
    if raw.raw[..24].iter().any(|b| *b != 0) {
        return None;
    }
    let bytes: [u8; 8] = raw.raw[24..32].try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
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
        ws: &mut Workspace<Pile>,
    ) {
        let head = ws.head();
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_head != head,
        };
        if need_refresh {
            self.live = Some(HeadspaceLive::refresh(ws));
        }

        ctx.section("Headspace", |ctx| {
            let Some(live) = self.live.as_ref() else { return };

            ctx.grid(|g| {
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

fn render_active_card(
    ui: &mut egui::Ui,
    p: &ModelProfile,
    persona_id: Option<Id>,
) {
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
    let input_rect = egui::Rect::from_min_size(
        bar_rect.min,
        egui::vec2(input_w, bar_height),
    );
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
                let (swatch, _) = ui.allocate_exact_size(
                    egui::vec2(10.0, 10.0),
                    egui::Sense::hover(),
                );
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
                    ui.label(
                        egui::RichText::new(m)
                            .monospace()
                            .small()
                            .color(body_muted),
                    );
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
