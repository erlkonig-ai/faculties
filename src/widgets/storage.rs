//! Immutable dataset access shared by faculty widgets.
//!
//! Widgets consume borrowed [`DatasetView`] values through a keyed
//! [`WidgetContext`]. `StorageState` owns the currently loaded snapshot and the
//! top-bar path selector and has no write path. Every source is materialized
//! from its fixed V4 descriptor-handle collection under the pile's durable
//! signer. Repository branches, mutable heads, and compatibility fallbacks do
//! not participate in this boundary. The interactive viewer loads the full
//! catalog; focused capture binaries request only their source dependency
//! closure.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use triblespace::core::collection::{Collection, CollectionId};
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStore;
use triblespace::core::trible::TribleSet;
use triblespace::prelude::Id;
use GORBIE::prelude::CardCtx;

use crate::collection_cutover::{load_signer, open_pile_strict};
use crate::schemas::atlas::DEFAULT_SCOPE_ID as ATLAS_SCOPE_ID;
use crate::schemas::blockdag::DEFAULT_SCOPE_ID as ARCHIVE_SCOPE_ID;
use crate::schemas::cognition::DEFAULT_SCOPE_ID as COGNITION_SCOPE_ID;
use crate::schemas::compass::DEFAULT_SCOPE_ID as COMPASS_SCOPE_ID;
use crate::schemas::decide::DEFAULT_SCOPE_ID as DECIDE_SCOPE_ID;
use crate::schemas::discord::DEFAULT_SCOPE_ID as DISCORD_SCOPE_ID;
use crate::schemas::files::DEFAULT_SCOPE_ID as FILES_SCOPE_ID;
use crate::schemas::headspace::DEFAULT_SCOPE_ID as HEADSPACE_SCOPE_ID;
use crate::schemas::mail::DEFAULT_SCOPE_ID as MAIL_SCOPE_ID;
use crate::schemas::memory::DEFAULT_SCOPE_ID as MEMORY_SCOPE_ID;
use crate::schemas::message::DEFAULT_SCOPE_ID as MESSAGES_SCOPE_ID;
use crate::schemas::planner::DEFAULT_SCOPE_ID as PLANNER_SCOPE_ID;
use crate::schemas::relations::DEFAULT_SCOPE_ID as RELATIONS_SCOPE_ID;
use crate::schemas::status::DEFAULT_SCOPE_ID as STATUS_SCOPE_ID;
use crate::schemas::teams::DEFAULT_SCOPE_ID as TEAMS_SCOPE_ID;
use crate::schemas::wiki::DEFAULT_SCOPE_ID as WIKI_SCOPE_ID;
use crate::secrets::schema::DEFAULT_SCOPE_ID as SECRETS_SCOPE_ID;
use crate::legacy_hint::open_scope;

/// Stable logical input requested by a widget.
///
/// These keys describe consumers, not storage layout. Several consumers may
/// intentionally share one exact collection (Reason and Triage both observe
/// Cognition), while the descriptor identity remains hidden behind this
/// boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SourceKey {
    Archive,
    Atlas,
    Compass,
    Decide,
    Discord,
    Files,
    Headspace,
    Mail,
    Memory,
    Messages,
    Planner,
    Reason,
    Relations,
    Secrets,
    Status,
    Teams,
    Triage,
    Wiki,
}

impl SourceKey {
    /// Every logical input understood by the viewer core.
    pub const ALL: [Self; 18] = [
        Self::Archive,
        Self::Atlas,
        Self::Compass,
        Self::Decide,
        Self::Discord,
        Self::Files,
        Self::Headspace,
        Self::Mail,
        Self::Memory,
        Self::Messages,
        Self::Planner,
        Self::Reason,
        Self::Relations,
        Self::Secrets,
        Self::Status,
        Self::Teams,
        Self::Triage,
        Self::Wiki,
    ];

    /// Logical inputs that must accompany this source for rendering or
    /// validation. Storage layout stays out of this relation: the transitive
    /// closure is computed over semantic source keys and scopes are deduplicated
    /// only afterwards.
    fn dependencies(self) -> &'static [Self] {
        match self {
            Self::Headspace => &[Self::Secrets],
            Self::Mail => &[Self::Files, Self::Decide, Self::Relations, Self::Secrets],
            Self::Messages | Self::Planner | Self::Status => &[Self::Relations],
            Self::Triage => &[
                Self::Headspace,
                Self::Secrets,
                Self::Relations,
                Self::Messages,
            ],
            _ => &[],
        }
    }
}

fn source_closure(sources: impl IntoIterator<Item = SourceKey>) -> BTreeSet<SourceKey> {
    let mut closure = BTreeSet::new();
    let mut pending: Vec<_> = sources.into_iter().collect();
    while let Some(source) = pending.pop() {
        if closure.insert(source) {
            pending.extend_from_slice(source.dependencies());
        }
    }
    closure
}

/// Opaque cache identity for one logical dataset view.
///
/// Widgets compare revisions for equality; the storage backend owns their
/// construction. The digest combines the canonical descriptor handle with an
/// opaque in-process fingerprint of the materialized fact set. It is a widget
/// cache token, not a durable collection record or an authorization proof.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DatasetRevision([u8; 32]);

impl DatasetRevision {
    fn from_collection(collection: CollectionId, facts: &TribleSet) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"faculties.viewer.dataset-revision.v1");
        hasher.update(&collection.raw);
        match facts.fingerprint().as_u128() {
            Some(fingerprint) => {
                hasher.update(&[1]);
                hasher.update(&fingerprint.to_le_bytes());
            }
            None => {
                hasher.update(&[0]);
                hasher.update(&[0; 16]);
            }
        }
        hasher.update(&(facts.len() as u128).to_le_bytes());
        Self(*hasher.finalize().as_bytes())
    }
}

/// Borrowed immutable input for one widget dataset.
#[derive(Clone, Copy, Debug)]
pub struct DatasetView<'a> {
    pub facts: &'a TribleSet,
    pub reader: &'a PileReader,
    pub revision: DatasetRevision,
}

/// Keyed borrowed inputs for one viewer render.
#[derive(Clone, Copy, Debug)]
pub struct WidgetContext<'a> {
    datasets: Option<&'a BTreeMap<SourceKey, LoadedDataset>>,
}

impl<'a> WidgetContext<'a> {
    /// Return the exact requested logical dataset, or `None` when that source
    /// is absent. Missing sources never shift another source into its place.
    pub fn dataset(&self, key: SourceKey) -> Option<DatasetView<'a>> {
        self.datasets?.get(&key).map(LoadedDataset::view)
    }
}

#[derive(Clone, Debug)]
struct LoadedDataset {
    facts: TribleSet,
    reader: PileReader,
    revision: DatasetRevision,
}

impl LoadedDataset {
    fn new(collection: CollectionId, facts: TribleSet, reader: PileReader) -> Self {
        let revision = DatasetRevision::from_collection(collection, &facts);
        Self {
            facts,
            reader,
            revision,
        }
    }

    fn view(&self) -> DatasetView<'_> {
        DatasetView {
            facts: &self.facts,
            reader: &self.reader,
            revision: self.revision,
        }
    }
}

#[derive(Clone, Copy)]
struct CollectionSource {
    key: SourceKey,
    scope: Id,
    label: &'static str,
}

// Deliberately private: a widget asks for a semantic source key, not a scope,
// descriptor, branch, or migration epoch. The descriptor handle is derived
// canonically from each fixed scope when the pile is loaded.
const COLLECTION_SOURCE_CATALOG: &[CollectionSource] = &[
    CollectionSource {
        key: SourceKey::Archive,
        scope: ARCHIVE_SCOPE_ID,
        label: "Archive",
    },
    CollectionSource {
        key: SourceKey::Atlas,
        scope: ATLAS_SCOPE_ID,
        label: "Atlas",
    },
    CollectionSource {
        key: SourceKey::Compass,
        scope: COMPASS_SCOPE_ID,
        label: "Compass",
    },
    CollectionSource {
        key: SourceKey::Decide,
        scope: DECIDE_SCOPE_ID,
        label: "Decide",
    },
    CollectionSource {
        key: SourceKey::Discord,
        scope: DISCORD_SCOPE_ID,
        label: "Discord",
    },
    CollectionSource {
        key: SourceKey::Files,
        scope: FILES_SCOPE_ID,
        label: "Files",
    },
    CollectionSource {
        key: SourceKey::Headspace,
        scope: HEADSPACE_SCOPE_ID,
        label: "Headspace",
    },
    CollectionSource {
        key: SourceKey::Mail,
        scope: MAIL_SCOPE_ID,
        label: "Mail",
    },
    CollectionSource {
        key: SourceKey::Memory,
        scope: MEMORY_SCOPE_ID,
        label: "Memory",
    },
    CollectionSource {
        key: SourceKey::Messages,
        scope: MESSAGES_SCOPE_ID,
        label: "Messages",
    },
    CollectionSource {
        key: SourceKey::Planner,
        scope: PLANNER_SCOPE_ID,
        label: "Planner",
    },
    CollectionSource {
        key: SourceKey::Reason,
        scope: COGNITION_SCOPE_ID,
        label: "Cognition",
    },
    CollectionSource {
        key: SourceKey::Relations,
        scope: RELATIONS_SCOPE_ID,
        label: "Relations",
    },
    CollectionSource {
        key: SourceKey::Secrets,
        scope: SECRETS_SCOPE_ID,
        label: "Secrets",
    },
    CollectionSource {
        key: SourceKey::Status,
        scope: STATUS_SCOPE_ID,
        label: "Status",
    },
    CollectionSource {
        key: SourceKey::Teams,
        scope: TEAMS_SCOPE_ID,
        label: "Teams",
    },
    CollectionSource {
        key: SourceKey::Triage,
        scope: COGNITION_SCOPE_ID,
        label: "Cognition",
    },
    CollectionSource {
        key: SourceKey::Wiki,
        scope: WIKI_SCOPE_ID,
        label: "Wiki",
    },
];

fn materialization_scopes(sources: &BTreeSet<SourceKey>) -> Vec<(Id, &'static str)> {
    let mut scopes: Vec<_> = COLLECTION_SOURCE_CATALOG
        .iter()
        .filter(|source| sources.contains(&source.key))
        .map(|source| (source.scope, source.label))
        .collect();
    scopes.sort_by_key(|(scope, _)| *scope);
    scopes.dedup_by_key(|(scope, _)| *scope);
    scopes
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    length: u64,
    modified: Option<SystemTime>,
}

/// Shared read-only pile state and top-bar path selector.
pub struct StorageState {
    datasets: Option<BTreeMap<SourceKey, LoadedDataset>>,
    sources: BTreeSet<SourceKey>,
    pile_path: PathBuf,
    pile_path_text: String,
    stamp: Option<FileStamp>,
    error: Option<String>,
}

impl StorageState {
    /// Stash a pile path for lazy full-catalog loading. No I/O happens here,
    /// which keeps eager notebook-state construction cheap.
    pub fn new(pile_path: impl Into<PathBuf>) -> Self {
        Self::with_sources(pile_path, SourceKey::ALL)
    }

    /// Stash a pile path for lazy, source-scoped loading.
    ///
    /// The requested semantic inputs are expanded through their declarative
    /// dependency closure. Only those collection scopes are materialized and
    /// validated; consumers can observe the requested keys and their logical
    /// dependencies, but never unrelated keys that happen to share a scope.
    pub fn for_sources(
        pile_path: impl Into<PathBuf>,
        sources: impl IntoIterator<Item = SourceKey>,
    ) -> Self {
        Self::with_sources(pile_path, sources)
    }

    fn with_sources(
        pile_path: impl Into<PathBuf>,
        sources: impl IntoIterator<Item = SourceKey>,
    ) -> Self {
        let pile_path = pile_path.into();
        let pile_path_text = pile_path.to_string_lossy().into_owned();
        Self {
            datasets: None,
            sources: source_closure(sources),
            pile_path,
            pile_path_text,
            stamp: None,
            error: None,
        }
    }

    /// Borrow all currently loaded datasets through their logical keys.
    ///
    /// The first call loads lazily. Later calls cheaply compare the pile file
    /// stamp and reload after an external append. A failed live reload retains
    /// the last coherent snapshot and surfaces the error until explicit OPEN.
    pub fn context(&mut self) -> WidgetContext<'_> {
        self.ensure_loaded();
        WidgetContext {
            datasets: self.datasets.as_ref(),
        }
    }

    /// Reopen against `path`. Passing the current path still forces a reload,
    /// which is the behavior of the top-bar OPEN action.
    pub fn set_pile_path(&mut self, path: impl Into<PathBuf>) {
        let path = path.into();
        let changed = path != self.pile_path;
        self.pile_path = path;
        self.pile_path_text = self.pile_path.to_string_lossy().into_owned();
        self.error = None;
        if changed {
            self.datasets = None;
            self.stamp = None;
        }
        self.reload_current_path();
    }

    fn ensure_loaded(&mut self) {
        if self.datasets.is_none() {
            if self.error.is_none() {
                self.reload_current_path();
            }
            return;
        }
        if self.error.is_some() {
            return;
        }
        match file_stamp(&self.pile_path) {
            Ok(stamp) if Some(stamp) != self.stamp => self.reload_current_path(),
            Ok(_) => {}
            Err(error) => self.error = Some(error),
        }
    }

    fn reload_current_path(&mut self) {
        match load_consistent_catalog(&self.pile_path, &self.sources) {
            Ok((datasets, stamp)) => {
                self.datasets = Some(datasets);
                self.stamp = Some(stamp);
                self.error = None;
            }
            Err(error) => {
                self.error = Some(error);
            }
        }
    }

    /// Current pile load/reload error, if any.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Render the path selector and load status. OPEN always reloads, including
    /// when the entered path is unchanged.
    pub fn top_bar(&mut self, ctx: &mut CardCtx<'_>) {
        self.ensure_loaded();
        let is_open = self.datasets.is_some();
        let has_error = self.error.is_some();
        let mut reopen = false;
        let status_color = if has_error {
            egui::Color32::from_rgb(0xcc, 0x0a, 0x17)
        } else if is_open {
            egui::Color32::from_rgb(0x23, 0x7f, 0x52)
        } else {
            egui::Color32::from_rgb(0x4d, 0x55, 0x59)
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
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_black_alpha(40)))
            .corner_radius(egui::CornerRadius::same(4))
            .inner_margin(egui::Margin::symmetric(10, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;
                    let (dot_rect, _) =
                        ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                    ui.painter()
                        .circle_filled(dot_rect.center(), 4.0, status_color);
                    ui.label(
                        egui::RichText::new("PILE")
                            .small()
                            .monospace()
                            .strong()
                            .color(status_color),
                    );
                    ui.label(egui::RichText::new("│").small().color(muted));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let open_btn = ui.add(
                            egui::Button::new(
                                egui::RichText::new("OPEN").small().monospace().strong(),
                            )
                            .min_size(egui::vec2(52.0, 22.0)),
                        );
                        if open_btn.clicked() {
                            reopen = true;
                        }
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            let response = ui.add(GORBIE::widgets::TextField::singleline(
                                &mut self.pile_path_text,
                            ));
                            if response.lost_focus()
                                && ui.input(|input| input.key_pressed(egui::Key::Enter))
                            {
                                reopen = true;
                            }
                        });
                    });
                });
            });
        if reopen {
            self.set_pile_path(PathBuf::from(self.pile_path_text.trim()));
        }

        if let Some(error) = self.error.as_ref() {
            render_banner(
                ctx,
                "\u{26a0}",
                &format!("pile load error: {error}"),
                ctx.ctx().global_style().visuals.error_fg_color,
            );
        }
    }
}

fn file_stamp(path: &Path) -> Result<FileStamp, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("inspect pile {}: {error}", path.display()))?;
    Ok(FileStamp {
        length: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

fn load_consistent_catalog(
    path: &Path,
    sources: &BTreeSet<SourceKey>,
) -> Result<(BTreeMap<SourceKey, LoadedDataset>, FileStamp), String> {
    for _ in 0..2 {
        let before = file_stamp(path)?;
        let datasets = load_catalog(path, sources)?;
        let after = file_stamp(path)?;
        if before == after {
            return Ok((datasets, after));
        }
    }
    Err(format!(
        "pile {} changed repeatedly while loading viewer datasets; retry OPEN",
        path.display()
    ))
}

fn load_catalog(
    path: &Path,
    sources: &BTreeSet<SourceKey>,
) -> Result<BTreeMap<SourceKey, LoadedDataset>, String> {
    let signer = load_signer(path, None)
        .map_err(|error| format!("load durable collection signer: {error:#}"))?;
    let mut pile = open_pile_strict(path).map_err(|error| format!("open pile: {error:#}"))?;

    let loaded = (|| {
        let mut by_scope = BTreeMap::<Id, (CollectionId, TribleSet)>::new();

        for (scope, label) in materialization_scopes(sources) {
            let (collection_id, facts) = {
                let mut collection = open_scope(&mut pile, scope, signer.clone());
                let collection_id = collection.descriptor().handle();
                let facts = collection
                    .materialize()
                    .map_err(|error| format!("materialize {label} collection: {error}"))?;
                (collection_id, facts)
            };
            by_scope.insert(scope, (collection_id, facts));
        }

        let reader = pile
            .reader()
            .map_err(|error| format!("open immutable viewer blob snapshot: {error}"))?;
        validate_catalog(&reader, &by_scope, sources)?;

        Ok(COLLECTION_SOURCE_CATALOG
            .iter()
            .filter(|source| sources.contains(&source.key))
            .map(|source| {
                let (collection, facts) = by_scope
                    .get(&source.scope)
                    .expect("every fixed viewer scope was materialized");
                (
                    source.key,
                    LoadedDataset::new(*collection, facts.clone(), reader.clone()),
                )
            })
            .collect())
    })();

    let closed = pile.close().map_err(|error| format!("close pile: {error}"));
    match (loaded, closed) {
        (Ok(datasets), Ok(())) => Ok(datasets),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(close_error)) => Err(format!("{error}; {close_error}")),
    }
}

fn validate_catalog(
    reader: &PileReader,
    by_scope: &BTreeMap<Id, (CollectionId, TribleSet)>,
    sources: &BTreeSet<SourceKey>,
) -> Result<(), String> {
    let facts = |source: SourceKey| {
        let scope = COLLECTION_SOURCE_CATALOG
            .iter()
            .find(|candidate| candidate.key == source)
            .expect("every source key has a fixed collection scope")
            .scope;
        &by_scope
            .get(&scope)
            .expect("validator scope was materialized")
            .1
    };

    if sources.contains(&SourceKey::Archive) {
        match crate::blockdag::validate_catalog(reader, facts(SourceKey::Archive))
            .map_err(|error| format!("validate Archive collection: {error:#}"))?
        {
            crate::blockdag::CatalogValidation::Accepted => {}
            crate::blockdag::CatalogValidation::Pending { missing } => {
                return Err(format!(
                    "validate Archive collection: {} attachment blob(s) are missing",
                    missing.len()
                ));
            }
            crate::blockdag::CatalogValidation::Rejected(error) => {
                return Err(format!("validate Archive collection: {error}"));
            }
        }
    }
    if sources.contains(&SourceKey::Atlas) {
        crate::atlas::validate_catalog(reader, facts(SourceKey::Atlas))
            .map_err(|error| format!("validate Atlas collection: {error:#}"))?;
    }
    if sources.contains(&SourceKey::Compass) {
        crate::compass::validate_known_payloads(reader, facts(SourceKey::Compass))
            .map_err(|error| format!("validate Compass collection: {error:#}"))?;
    }
    if sources.contains(&SourceKey::Decide) {
        crate::decide::validate_catalog(reader, facts(SourceKey::Decide))
            .map_err(|error| format!("validate Decide collection: {error:#}"))?;
    }
    if sources.contains(&SourceKey::Discord) {
        crate::discord::validate_catalog(reader, facts(SourceKey::Discord))
            .map_err(|error| format!("validate Discord collection: {error:#}"))?;
    }
    if sources.contains(&SourceKey::Files) {
        crate::files::validate_catalog(reader, facts(SourceKey::Files))
            .map_err(|error| format!("validate Files collection: {error:#}"))?;
    }
    let secrets = if sources.contains(&SourceKey::Secrets) {
        Some(
            crate::secrets::validate_catalog(reader, facts(SourceKey::Secrets))
                .map_err(|error| format!("validate Secrets collection: {error:#}"))?,
        )
    } else {
        None
    };
    if sources.contains(&SourceKey::Headspace) {
        let headspace = crate::headspace::project_result(reader, facts(SourceKey::Headspace))
            .map_err(|error| format!("validate Headspace collection: {error:#}"))?;
        crate::headspace::validate_secret_references(
            &headspace,
            secrets
                .as_ref()
                .expect("Headspace source closure includes Secrets"),
        )
        .map_err(|error| format!("validate Headspace secret references: {error:#}"))?;
    }
    if sources.contains(&SourceKey::Relations) {
        crate::relations::validate_catalog(reader, facts(SourceKey::Relations))
            .map_err(|error| format!("validate Relations collection: {error:#}"))?;
    }
    if sources.contains(&SourceKey::Messages) {
        crate::message::validate_catalog(
            reader,
            facts(SourceKey::Messages),
            facts(SourceKey::Relations),
        )
        .map_err(|error| format!("validate Messages collection: {error:#}"))?;
    }
    if sources.contains(&SourceKey::Memory) {
        crate::memory::validate_catalog(reader, facts(SourceKey::Memory))
            .map_err(|error| format!("validate Memory collection: {error:#}"))?;
    }
    if sources.contains(&SourceKey::Planner) {
        crate::planner::validate_catalog(reader, facts(SourceKey::Planner))
            .map_err(|error| format!("validate Planner collection: {error:#}"))?;
    }
    if sources.contains(&SourceKey::Status) {
        crate::status::validate_catalog(reader, facts(SourceKey::Status))
            .map_err(|error| format!("validate Status collection: {error:#}"))?;
    }
    if sources.contains(&SourceKey::Teams) {
        crate::teams::validate_catalog(reader, facts(SourceKey::Teams))
            .map_err(|error| format!("validate Teams collection: {error:#}"))?;
    }
    if sources.contains(&SourceKey::Wiki) {
        crate::wiki::validate_catalog(reader, facts(SourceKey::Wiki))
            .map_err(|error| format!("validate Wiki collection: {error:#}"))?;
    }
    if sources.contains(&SourceKey::Reason) || sources.contains(&SourceKey::Triage) {
        let source = if sources.contains(&SourceKey::Reason) {
            SourceKey::Reason
        } else {
            SourceKey::Triage
        };
        crate::cognition::validate_catalog(reader, facts(source))
            .map_err(|error| format!("validate Cognition collection: {error:#}"))?;
    }

    if sources.contains(&SourceKey::Mail) {
        crate::mail::validate_catalog(
            reader,
            facts(SourceKey::Mail),
            facts(SourceKey::Files),
            facts(SourceKey::Decide),
            facts(SourceKey::Relations),
            secrets
                .as_ref()
                .expect("Mail source closure includes Secrets"),
        )
        .map_err(|error| format!("validate Mail collection: {error:#}"))?;
    }
    Ok(())
}

fn render_banner(ctx: &mut CardCtx<'_>, icon: &str, message: &str, color: egui::Color32) {
    let ui = ctx.ui_mut();
    let background = egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 40);
    egui::Frame::NONE
        .fill(background)
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(egui::CornerRadius::same(3))
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(egui::RichText::new(icon).small().color(color));
                ui.label(
                    egui::RichText::new(message)
                        .monospace()
                        .small()
                        .color(color),
                );
            });
        });
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<StorageState>();
};

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;
    use std::fs::File;

    use anybytes::View;
    use hifitime::Epoch;
    use triblespace::core::metadata;
    use triblespace::core::repo::BlobStoreGet;
    use triblespace::macros::{entity, find, pattern};
    use triblespace::prelude::*;

    fn create_pile(path: &Path) {
        File::create(path).unwrap();
        crate::collection_cutover::initialize_signer(path, None).unwrap();
    }

    fn publish_reason(path: &Path, text: &str, second: f64) {
        let instant = Epoch::from_tai_seconds(second);
        crate::cognition::publish_event(
            path,
            None,
            crate::cognition::reason_fragment(
                None,
                None,
                text,
                None,
                (instant, instant).try_to_inline().unwrap(),
            ),
        )
        .unwrap();
    }

    fn publish_malformed_status(path: &Path) {
        let instant = Epoch::from_tai_seconds(3.0);
        let mut fragment = crate::status::status_fragment(
            Id::new([0x31; 16]).unwrap(),
            "malformed",
            (instant, instant).try_to_inline().unwrap(),
        )
        .unwrap();
        let event = fragment.root().unwrap();
        fragment += entity! {
            ExclusiveId::force_ref(&event) @ metadata::tag: &Id::new([0x32; 16]).unwrap()
        };

        let signer = load_signer(path, None).unwrap();
        let mut pile = open_pile_strict(path).unwrap();
        Collection::new(&mut pile, STATUS_SCOPE_ID, signer)
            .commit(fragment)
            .unwrap();
        pile.close().unwrap();
    }

    fn visible_keys(context: WidgetContext<'_>) -> BTreeSet<SourceKey> {
        SourceKey::ALL
            .into_iter()
            .filter(|key| context.dataset(*key).is_some())
            .collect()
    }

    #[test]
    fn storage_load_and_context_do_not_change_pile_length() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("viewer.pile");
        create_pile(&path);
        publish_reason(&path, "read only", 1.0);
        let length = std::fs::metadata(&path).unwrap().len();
        let mut storage = StorageState::new(&path);

        let context = storage.context();
        let view = context.dataset(SourceKey::Reason).unwrap();
        let text = find!(
            text: Inline<inlineencodings::Handle<blobencodings::LongString>>,
            pattern!(view.facts, [{ metadata::tag: crate::schemas::reason::KIND_REASON_ID,
                                    crate::schemas::reason::reason_schema::text: ?text }])
        )
        .next()
        .unwrap();
        let text: View<str> = view.reader.get(text).unwrap();
        assert_eq!(&*text, "read only");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        assert!(storage.error().is_none());
    }

    #[test]
    fn open_reloads_the_same_path_and_stamp_refreshes_live_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("reload.pile");
        create_pile(&path);
        publish_reason(&path, "first", 1.0);
        let mut storage = StorageState::new(&path);
        let first = storage
            .context()
            .dataset(SourceKey::Reason)
            .unwrap()
            .revision;

        publish_reason(&path, "second", 2.0);
        storage.set_pile_path(&path);
        let second = storage
            .context()
            .dataset(SourceKey::Reason)
            .unwrap()
            .revision;
        assert_ne!(second, first);

        publish_reason(&path, "third", 3.0);
        let third = storage
            .context()
            .dataset(SourceKey::Reason)
            .unwrap()
            .revision;
        assert_ne!(third, second);
    }

    #[test]
    fn shared_collection_is_loaded_once_and_exposed_under_semantic_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("shared.pile");
        create_pile(&path);
        publish_reason(&path, "one source", 1.0);
        let mut storage = StorageState::new(&path);
        let context = storage.context();

        let reason = context.dataset(SourceKey::Reason).unwrap();
        let triage = context.dataset(SourceKey::Triage).unwrap();
        assert_eq!(reason.revision, triage.revision);
        assert_eq!(reason.facts, triage.facts);
    }

    #[test]
    fn scoped_storage_expands_dependencies_without_exposing_shared_scope_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("triage.pile");
        create_pile(&path);
        let mut storage = StorageState::for_sources(&path, [SourceKey::Triage]);

        assert_eq!(
            visible_keys(storage.context()),
            BTreeSet::from([
                SourceKey::Headspace,
                SourceKey::Messages,
                SourceKey::Relations,
                SourceKey::Secrets,
                SourceKey::Triage,
            ])
        );
        assert!(storage.error().is_none());
    }

    #[test]
    fn source_dependencies_expand_transitively() {
        assert_eq!(
            source_closure([SourceKey::Mail]),
            BTreeSet::from([
                SourceKey::Decide,
                SourceKey::Files,
                SourceKey::Mail,
                SourceKey::Relations,
                SourceKey::Secrets,
            ])
        );
        assert_eq!(
            source_closure([SourceKey::Headspace]),
            BTreeSet::from([SourceKey::Headspace, SourceKey::Secrets])
        );
        for source in [SourceKey::Messages, SourceKey::Planner, SourceKey::Status] {
            assert_eq!(
                source_closure([source]),
                BTreeSet::from([source, SourceKey::Relations])
            );
        }
    }

    #[test]
    fn shared_scope_is_planned_once_but_each_requested_semantic_key_is_exposed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("shared-scoped.pile");
        create_pile(&path);
        publish_reason(&path, "shared", 1.0);

        let sources = source_closure([SourceKey::Reason, SourceKey::Triage]);
        assert_eq!(
            materialization_scopes(&sources)
                .into_iter()
                .filter(|(scope, _)| *scope == COGNITION_SCOPE_ID)
                .count(),
            1
        );

        let mut storage = StorageState::for_sources(&path, [SourceKey::Reason, SourceKey::Triage]);
        let context = storage.context();
        let reason = context.dataset(SourceKey::Reason).unwrap();
        let triage = context.dataset(SourceKey::Triage).unwrap();
        assert_eq!(reason.revision, triage.revision);
        assert_eq!(reason.facts, triage.facts);
    }

    #[test]
    fn unrelated_malformed_source_does_not_break_narrow_load_but_full_load_rejects_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("malformed-unrelated.pile");
        create_pile(&path);
        publish_reason(&path, "still visible", 1.0);
        publish_malformed_status(&path);

        let mut narrow = StorageState::for_sources(&path, [SourceKey::Reason]);
        let context = narrow.context();
        assert!(context.dataset(SourceKey::Reason).is_some());
        assert!(context.dataset(SourceKey::Triage).is_none());
        assert!(context.dataset(SourceKey::Status).is_none());
        assert!(narrow.error().is_none());

        let mut full = StorageState::new(&path);
        assert!(full.context().dataset(SourceKey::Reason).is_none());
        assert!(full.error().unwrap().contains("Status"));
    }

    #[test]
    fn full_storage_exposes_every_source() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("full.pile");
        create_pile(&path);
        let mut storage = StorageState::new(&path);

        assert_eq!(
            visible_keys(storage.context()),
            SourceKey::ALL.into_iter().collect()
        );
        assert!(storage.error().is_none());
    }

    #[test]
    fn fixed_catalog_covers_every_source_key_once() {
        let catalog: BTreeSet<_> = COLLECTION_SOURCE_CATALOG
            .iter()
            .map(|source| source.key)
            .collect();
        assert_eq!(catalog, SourceKey::ALL.into_iter().collect());
        assert_eq!(catalog.len(), COLLECTION_SOURCE_CATALOG.len());
        assert_eq!(
            COLLECTION_SOURCE_CATALOG
                .iter()
                .filter(|source| source.scope == COGNITION_SCOPE_ID)
                .count(),
            2
        );
    }

    #[test]
    fn missing_durable_signer_fails_without_mutating_the_pile() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unsigned.pile");
        File::create(&path).unwrap();
        let length = std::fs::metadata(&path).unwrap().len();
        let mut storage = StorageState::new(&path);

        assert!(storage.context().dataset(SourceKey::Wiki).is_none());
        assert!(storage
            .error()
            .expect("missing signer is surfaced")
            .contains("signer"));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
    }
}
