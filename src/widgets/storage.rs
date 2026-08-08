//! Immutable dataset access shared by faculty widgets.
//!
//! Widgets consume borrowed [`DatasetView`] values through a keyed
//! [`WidgetContext`]. `StorageState` owns the currently loaded snapshot and the
//! top-bar path selector and has no write path. It loads collection-native
//! faculties directly from one immutable collection snapshot under the
//! existing durable signer; the private legacy catalog remains only for
//! faculties which have not made that cutover yet.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use triblespace::core::repo::pile::PileReader;
use triblespace::core::trible::TribleSet;
use triblespace::prelude::Id;
use GORBIE::prelude::CardCtx;

use crate::collection_access::{
    self, CollectionRevision, CollectionView, LegacyBranchRevision, LegacyBranchView,
};
use crate::schemas::atlas::DEFAULT_SCOPE_ID as ATLAS_SCOPE_ID;
use crate::schemas::cognition::DEFAULT_SCOPE_ID as COGNITION_SCOPE_ID;
use crate::schemas::compass::DEFAULT_SCOPE_ID as COMPASS_SCOPE_ID;
use crate::schemas::decide::DEFAULT_SCOPE_ID as DECIDE_SCOPE_ID;
use crate::schemas::discord::DEFAULT_SCOPE_ID as DISCORD_SCOPE_ID;
use crate::schemas::files::DEFAULT_SCOPE_ID as FILES_SCOPE_ID;
use crate::schemas::headspace::DEFAULT_SCOPE_ID as HEADSPACE_SCOPE_ID;
use crate::schemas::message::DEFAULT_SCOPE_ID as MESSAGES_SCOPE_ID;
use crate::schemas::relations::DEFAULT_SCOPE_ID as RELATIONS_SCOPE_ID;
use crate::schemas::status::DEFAULT_SCOPE_ID as STATUS_SCOPE_ID;
use crate::schemas::teams::DEFAULT_SCOPE_ID as TEAMS_SCOPE_ID;

/// Stable logical input requested by a widget.
///
/// These keys describe consumers, not storage branch names. A source may be
/// backed by a collection or, during the cutover, by the private legacy
/// catalog below.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SourceKey {
    Archive,
    Atlas,
    Compass,
    Decide,
    Discord,
    Files,
    Headspace,
    Memory,
    Messages,
    Planner,
    Reason,
    Relations,
    Status,
    Teams,
    Triage,
    Wiki,
}

impl SourceKey {
    /// Every logical input understood by the viewer core.
    pub const ALL: [Self; 16] = [
        Self::Archive,
        Self::Atlas,
        Self::Compass,
        Self::Decide,
        Self::Discord,
        Self::Files,
        Self::Headspace,
        Self::Memory,
        Self::Messages,
        Self::Planner,
        Self::Reason,
        Self::Relations,
        Self::Status,
        Self::Teams,
        Self::Triage,
        Self::Wiki,
    ];
}

/// Opaque cache identity for one logical dataset view.
///
/// Widgets compare revisions for equality; the storage backend owns their
/// construction. Collection and temporary legacy sources both project their
/// exact semantic revisions into this boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DatasetRevision([u8; 32]);

impl DatasetRevision {
    fn from_collection(revision: CollectionRevision) -> Self {
        Self(*revision.as_bytes())
    }

    fn from_legacy(revision: LegacyBranchRevision) -> Self {
        Self(*revision.as_bytes())
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
    fn from_collection(view: CollectionView) -> Self {
        Self {
            facts: view.facts,
            reader: view.reader,
            revision: DatasetRevision::from_collection(view.revision),
        }
    }

    fn from_legacy(view: LegacyBranchView) -> Self {
        Self {
            facts: view.facts,
            reader: view.reader,
            revision: DatasetRevision::from_legacy(view.revision),
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
struct LegacySource {
    key: SourceKey,
    branches: &'static [&'static str],
}

#[derive(Clone, Copy)]
struct CollectionSource {
    key: SourceKey,
    scope: Id,
    label: &'static str,
}

// Deliberately private: storage identity stays behind SourceKey/DatasetView.
// The loader materializes every distinct scope once from one immutable
// CollectionSnapshot, then shares that exact result with any logical sources
// which intentionally name the same scope.
const COLLECTION_SOURCE_CATALOG: &[CollectionSource] = &[
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
        key: SourceKey::Messages,
        scope: MESSAGES_SCOPE_ID,
        label: "Messages",
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
        key: SourceKey::Status,
        scope: STATUS_SCOPE_ID,
        label: "Status",
    },
    CollectionSource {
        key: SourceKey::Teams,
        scope: TEAMS_SCOPE_ID,
        label: "Teams",
    },
];

// Temporary and deliberately private. Collection-native sources are absent;
// every remaining source is loaded only from legacy state until its own
// schema migration lands.
const LEGACY_SOURCE_CATALOG: &[LegacySource] = &[
    LegacySource {
        key: SourceKey::Archive,
        branches: &["archive"],
    },
    LegacySource {
        key: SourceKey::Memory,
        branches: &["memory", "cognition"],
    },
    LegacySource {
        key: SourceKey::Planner,
        branches: &["planner"],
    },
    LegacySource {
        key: SourceKey::Triage,
        branches: &["cognition"],
    },
    LegacySource {
        key: SourceKey::Wiki,
        branches: &["wiki"],
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileStamp {
    length: u64,
    modified: Option<SystemTime>,
}

/// Shared read-only pile state and top-bar path selector.
pub struct StorageState {
    datasets: Option<BTreeMap<SourceKey, LoadedDataset>>,
    pile_path: PathBuf,
    pile_path_text: String,
    stamp: Option<FileStamp>,
    error: Option<String>,
}

impl StorageState {
    /// Stash a pile path for lazy loading. No I/O happens here, which keeps
    /// eager notebook-state construction cheap.
    pub fn new(pile_path: impl Into<PathBuf>) -> Self {
        let pile_path = pile_path.into();
        let pile_path_text = pile_path.to_string_lossy().into_owned();
        Self {
            datasets: None,
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
        match load_consistent_catalog(&self.pile_path) {
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
) -> Result<(BTreeMap<SourceKey, LoadedDataset>, FileStamp), String> {
    for _ in 0..2 {
        let before = file_stamp(path)?;
        let datasets = load_catalog(path)?;
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

fn load_catalog(path: &Path) -> Result<BTreeMap<SourceKey, LoadedDataset>, String> {
    let mut by_branch: BTreeMap<&'static str, Option<LoadedDataset>> = BTreeMap::new();
    let mut datasets = BTreeMap::new();
    for source in LEGACY_SOURCE_CATALOG {
        let mut selected = None;
        for &branch in source.branches {
            if !by_branch.contains_key(branch) {
                let loaded = collection_access::materialize_named_legacy_branch(path, branch)
                    .map_err(|error| format!("load legacy {branch} dataset: {error:#}"))?
                    .map(LoadedDataset::from_legacy);
                by_branch.insert(branch, loaded);
            }
            if let Some(dataset) = by_branch.get(branch).and_then(Option::as_ref) {
                selected = Some(dataset.clone());
                break;
            }
        }
        if let Some(dataset) = selected {
            datasets.insert(source.key, dataset);
        }
    }
    let signer = collection_access::load_signer(path, None)
        .map_err(|error| format!("load collection signer: {error:#}"))?;
    let allowed = HashSet::from([signer.verifying_key()]);
    let snapshot = collection_access::CollectionSnapshot::open(path)
        .map_err(|error| format!("open collection snapshot: {error:#}"))?;
    datasets.extend(load_collection_catalog(&snapshot, &allowed)?);
    Ok(datasets)
}

fn load_collection_catalog(
    snapshot: &collection_access::CollectionSnapshot,
    allowed: &HashSet<ed25519_dalek::VerifyingKey>,
) -> Result<BTreeMap<SourceKey, LoadedDataset>, String> {
    let mut by_scope: BTreeMap<Id, LoadedDataset> = BTreeMap::new();

    // Phase one freezes every distinct collection scope before any domain
    // validation begins. Cross-collection validators therefore always see
    // peers from this exact CollectionSnapshot, independent of catalog order.
    for source in COLLECTION_SOURCE_CATALOG {
        if let std::collections::btree_map::Entry::Vacant(entry) = by_scope.entry(source.scope) {
            let view = snapshot
                .materialize_scope(source.scope, allowed)
                .map_err(|error| format!("materialize {} collection: {error:#}", source.label))?;
            entry.insert(LoadedDataset::from_collection(view));
        }
    }

    // Phase two validates the fully materialized map. Keep these calls at the
    // shared domain boundaries: they are the same exact validators used by
    // the faculty writers, not viewer-specific approximations.
    let dataset = |scope: Id| {
        by_scope
            .get(&scope)
            .expect("every catalog scope was materialized in phase one")
    };
    let compass = dataset(COMPASS_SCOPE_ID);
    crate::compass::validate_catalog(&compass.reader, &compass.facts)
        .map_err(|error| format!("validate Compass collection: {error:#}"))?;
    let decide = dataset(DECIDE_SCOPE_ID);
    crate::decide::validate_catalog(&decide.reader, &decide.facts)
        .map_err(|error| format!("validate Decide collection: {error:#}"))?;
    let files = dataset(FILES_SCOPE_ID);
    crate::files::validate_catalog(&files.reader, &files.facts)
        .map_err(|error| format!("validate Files collection: {error:#}"))?;
    let headspace = dataset(HEADSPACE_SCOPE_ID);
    crate::headspace::validate_catalog(&headspace.reader, &headspace.facts)
        .map_err(|error| format!("validate Headspace collection: {error:#}"))?;
    let relations = dataset(RELATIONS_SCOPE_ID);
    crate::relations::validate_catalog(&relations.reader, &relations.facts)
        .map_err(|error| format!("validate Relations collection: {error:#}"))?;
    let messages = dataset(MESSAGES_SCOPE_ID);
    crate::message::validate_catalog(&messages.reader, &messages.facts, &relations.facts)
        .map_err(|error| format!("validate Messages collection: {error:#}"))?;
    let status = dataset(STATUS_SCOPE_ID);
    crate::status::validate_catalog(&status.reader, &status.facts)
        .map_err(|error| format!("validate Status collection: {error:#}"))?;

    let datasets = COLLECTION_SOURCE_CATALOG
        .iter()
        .map(|source| {
            (
                source.key,
                by_scope
                    .get(&source.scope)
                    .expect("validated catalog scope exists")
                    .clone(),
            )
        })
        .collect();
    Ok(datasets)
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

    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::metadata;
    use triblespace::core::repo::{BlobStoreGet, Repository};
    use triblespace::macros::{entity, find, pattern};
    use triblespace::prelude::*;

    fn create_branch(path: &Path, name: &str, text: &str) -> Id {
        create_branches(path, &[(name, text)])[name]
    }

    fn create_branches(path: &Path, branches: &[(&str, &str)]) -> BTreeMap<String, Id> {
        File::create(path).unwrap();
        let pile = collection_access::open_pile_strict(path).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x31; 32]), Fragment::empty()).unwrap();
        let mut ids = BTreeMap::new();
        for &(name, text) in branches {
            let branch = *repository.create_branch(name, None).unwrap();
            let mut workspace = repository.pull(branch).unwrap();
            workspace.commit(
                entity! { metadata::description: text.to_owned() },
                "fixture",
            );
            repository.push(&mut workspace).unwrap();
            ids.insert(name.to_owned(), branch);
        }
        repository.close().unwrap();
        collection_access::initialize_signer(path, None).unwrap();
        ids
    }

    fn append_branch(path: &Path, branch: Id, text: &str) {
        let pile = collection_access::open_pile_strict(path).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x32; 32]), Fragment::empty()).unwrap();
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(
            entity! { metadata::description: text.to_owned() },
            "append fixture",
        );
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
    }

    #[test]
    fn storage_load_and_context_do_not_change_pile_length() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("viewer.pile");
        create_branch(&path, "wiki", "read only");
        let length = std::fs::metadata(&path).unwrap().len();
        let mut storage = StorageState::new(&path);

        let context = storage.context();
        let view = context.dataset(SourceKey::Wiki).unwrap();
        let description = find!(
            (description: Inline<inlineencodings::Handle<blobencodings::LongString>>),
            pattern!(view.facts, [{ metadata::description: ?description }])
        )
        .next()
        .unwrap()
        .0;
        let text: View<str> = view.reader.get(description).unwrap();
        assert_eq!(&*text, "read only");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        assert!(storage.error().is_none());
    }

    #[test]
    fn open_reloads_the_same_path_and_stamp_refreshes_live_data() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("reload.pile");
        let branch = create_branch(&path, "wiki", "first");
        let mut storage = StorageState::new(&path);
        let first = storage.context().dataset(SourceKey::Wiki).unwrap().revision;

        append_branch(&path, branch, "second");
        storage.set_pile_path(&path);
        let second = storage.context().dataset(SourceKey::Wiki).unwrap().revision;
        assert_ne!(second, first);

        append_branch(&path, branch, "third");
        let third = storage.context().dataset(SourceKey::Wiki).unwrap().revision;
        assert_ne!(third, second);
    }

    #[test]
    fn collection_only_catalog_exposes_every_native_source_and_ignores_other_scopes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("collection-only.pile");
        let key = directory.path().join("writer.key");
        File::create(&path).unwrap();
        collection_access::initialize_signer(&path, Some(&key)).unwrap();
        collection_access::initialize_signer(&path, None).unwrap();
        collection_access::publish_fragment(
            &path,
            Some(&key),
            Id::new([0x41; 16]).unwrap(),
            entity! { metadata::tag: &Id::new([0x42; 16]).unwrap() },
            Fragment::empty(),
        )
        .unwrap();
        let length = std::fs::metadata(&path).unwrap().len();
        let mut storage = StorageState::new(&path);
        let context = storage.context();

        for source in COLLECTION_SOURCE_CATALOG {
            assert!(context.dataset(source.key).unwrap().facts.is_empty());
        }
        for source in LEGACY_SOURCE_CATALOG {
            assert!(context.dataset(source.key).is_none());
        }
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
    }

    #[test]
    fn collection_sources_never_fall_back_to_same_named_legacy_branches() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("shadowed-legacy.pile");
        create_branches(
            &path,
            &[
                ("atlas", "legacy atlas"),
                ("discord", "legacy discord"),
                ("files", "legacy files"),
                ("config", "legacy headspace"),
                ("message", "legacy messages"),
                ("relations", "legacy relations"),
                ("status", "legacy status"),
                ("teams", "legacy teams"),
            ],
        );

        let mut storage = StorageState::new(&path);
        let context = storage.context();
        for key in [
            SourceKey::Atlas,
            SourceKey::Discord,
            SourceKey::Files,
            SourceKey::Headspace,
            SourceKey::Messages,
            SourceKey::Relations,
            SourceKey::Status,
            SourceKey::Teams,
        ] {
            assert!(
                context.dataset(key).unwrap().facts.is_empty(),
                "{key:?} unexpectedly read its former legacy branch"
            );
        }
    }

    #[test]
    fn compass_source_materializes_the_collection_and_tracks_its_revision() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("compass-collection.pile");
        File::create(&path).unwrap();
        collection_access::initialize_signer(&path, None).unwrap();

        let goal = Id::new([0x53; 16]).unwrap();
        let epoch = Epoch::from_unix_seconds(1.0);
        let at: crate::compass::IntervalValue = (epoch, epoch).try_to_inline().unwrap();
        let (mut fragment, _, initial) =
            crate::compass::goal_fragment(goal, "Collection goal", vec![], None, "todo", None, at)
                .unwrap();
        fragment += crate::compass::priority_snapshot_fragment([], &[])
            .unwrap()
            .0;
        collection_access::publish_fragment(
            &path,
            None,
            COMPASS_SCOPE_ID,
            fragment,
            Fragment::empty(),
        )
        .unwrap();

        let mut storage = StorageState::new(&path);
        let first = storage.context().dataset(SourceKey::Compass).unwrap();
        assert!(crate::compass::goal_anchors(first.facts).contains(&goal));
        let first_revision = first.revision;

        let epoch = Epoch::from_unix_seconds(2.0);
        let at: crate::compass::IntervalValue = (epoch, epoch).try_to_inline().unwrap();
        let moved = crate::compass::status_fragment(goal, "doing", &[initial], None, at).unwrap();
        collection_access::publish_fragment(
            &path,
            None,
            COMPASS_SCOPE_ID,
            moved,
            Fragment::empty(),
        )
        .unwrap();

        let second = storage.context().dataset(SourceKey::Compass).unwrap();
        assert_ne!(second.revision, first_revision);
        assert!(matches!(
            crate::compass::status_resolution(second.facts, goal),
            crate::compass::StatusResolution::Unique(snapshot) if snapshot.value == "doing"
        ));
    }

    #[test]
    fn decide_source_materializes_the_collection_and_tracks_its_revision() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("decide-collection.pile");
        File::create(&path).unwrap();
        collection_access::initialize_signer(&path, None).unwrap();

        let decision = Id::new([0x61; 16]).unwrap();
        let epoch = Epoch::from_unix_seconds(1.0);
        let at: crate::decide::IntervalValue = (epoch, epoch).try_to_inline().unwrap();
        let fragment = crate::decide::decision_fragment(
            decision,
            "Collection decision",
            Some("Context".into()),
            None,
            at,
        )
        .unwrap()
        .0;
        collection_access::publish_fragment(
            &path,
            None,
            DECIDE_SCOPE_ID,
            fragment,
            Fragment::empty(),
        )
        .unwrap();

        let mut storage = StorageState::new(&path);
        let first = storage.context().dataset(SourceKey::Decide).unwrap();
        assert!(crate::decide::decision_anchors(first.facts).contains(&decision));
        let first_revision = first.revision;

        let epoch = Epoch::from_unix_seconds(2.0);
        let at: crate::decide::IntervalValue = (epoch, epoch).try_to_inline().unwrap();
        let factor = crate::decide::factor_fragment(
            Id::new([0x62; 16]).unwrap(),
            decision,
            crate::decide::FactorSide::Pro,
            "A reason",
            at,
        )
        .unwrap()
        .0;
        collection_access::publish_fragment(
            &path,
            None,
            DECIDE_SCOPE_ID,
            factor,
            Fragment::empty(),
        )
        .unwrap();

        let second = storage.context().dataset(SourceKey::Decide).unwrap();
        assert_ne!(second.revision, first_revision);
        assert_eq!(
            crate::decide::factors_for_decision(second.facts, decision)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn malformed_decide_collection_is_a_load_error_not_an_empty_dataset() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("malformed-decide.pile");
        File::create(&path).unwrap();
        collection_access::initialize_signer(&path, None).unwrap();

        let decision = Id::new([0x71; 16]).unwrap();
        let epoch = Epoch::from_unix_seconds(1.0);
        let at: crate::decide::IntervalValue = (epoch, epoch).try_to_inline().unwrap();
        let mut fragment = crate::decide::decision_fragment(decision, "Broken", None, None, at)
            .unwrap()
            .0;
        let outcome = fragment.put("Outcome".to_owned());
        let bogus = Id::new([0x72; 16]).unwrap();
        fragment += entity! { ExclusiveId::force_ref(&bogus) @
            metadata::tag: &crate::schemas::decide::KIND_RESOLUTION_SNAPSHOT,
            crate::schemas::decide::resolution::of: &decision,
            crate::schemas::decide::decide::outcome: outcome,
            crate::schemas::decide::resolution::forced: true,
            metadata::finished_at: at,
        };
        collection_access::publish_fragment(
            &path,
            None,
            DECIDE_SCOPE_ID,
            fragment,
            Fragment::empty(),
        )
        .unwrap();

        let mut storage = StorageState::new(&path);
        assert!(storage.context().dataset(SourceKey::Decide).is_none());
        let error = storage.error().unwrap();
        assert!(error.contains("validate Decide collection"));
        assert!(error.contains("does not match intrinsic root"));
    }

    #[test]
    fn malformed_headspace_collection_is_a_load_error_not_an_empty_dataset() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("malformed-headspace.pile");
        File::create(&path).unwrap();
        collection_access::initialize_signer(&path, None).unwrap();
        collection_access::publish_fragment(
            &path,
            None,
            HEADSPACE_SCOPE_ID,
            entity! { metadata::tag: &crate::schemas::headspace::KIND_CONFIG_ID },
            Fragment::empty(),
        )
        .unwrap();

        let mut storage = StorageState::new(&path);
        assert!(storage.context().dataset(SourceKey::Headspace).is_none());
        let error = storage.error().unwrap();
        assert!(error.contains("validate Headspace collection"));
        assert!(error.contains("active_model_profile_id"));
    }

    #[test]
    fn failed_live_reload_retains_the_last_coherent_collection_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("retain-last-good.pile");
        File::create(&path).unwrap();
        collection_access::initialize_signer(&path, None).unwrap();
        collection_access::publish_fragment(
            &path,
            None,
            ATLAS_SCOPE_ID,
            entity! { metadata::tag: &Id::new([0x73; 16]).unwrap() },
            Fragment::empty(),
        )
        .unwrap();

        let mut storage = StorageState::new(&path);
        let retained_revision = storage
            .context()
            .dataset(SourceKey::Atlas)
            .unwrap()
            .revision;

        let decision = Id::new([0x74; 16]).unwrap();
        let epoch = Epoch::from_unix_seconds(1.0);
        let at: crate::decide::IntervalValue = (epoch, epoch).try_to_inline().unwrap();
        let mut malformed = crate::decide::decision_fragment(decision, "Broken", None, None, at)
            .unwrap()
            .0;
        let outcome = malformed.put("Outcome".to_owned());
        let bogus = Id::new([0x75; 16]).unwrap();
        malformed += entity! { ExclusiveId::force_ref(&bogus) @
            metadata::tag: &crate::schemas::decide::KIND_RESOLUTION_SNAPSHOT,
            crate::schemas::decide::resolution::of: &decision,
            crate::schemas::decide::decide::outcome: outcome,
            crate::schemas::decide::resolution::forced: true,
            metadata::finished_at: at,
        };
        collection_access::publish_fragment(
            &path,
            None,
            DECIDE_SCOPE_ID,
            malformed,
            Fragment::empty(),
        )
        .unwrap();

        let retained = storage.context().dataset(SourceKey::Atlas).unwrap();
        assert_eq!(retained.revision, retained_revision);
        assert!(!retained.facts.is_empty());
        assert!(storage
            .error()
            .unwrap()
            .contains("validate Decide collection"));
    }

    #[test]
    fn reason_reads_the_cognition_collection_while_legacy_consumers_keep_the_branch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fallback.pile");
        create_branch(&path, "cognition", "legacy cognition");
        let marker = Id::new([0x76; 16]).unwrap();
        collection_access::publish_fragment(
            &path,
            None,
            COGNITION_SCOPE_ID,
            entity! { metadata::tag: &marker },
            Fragment::empty(),
        )
        .unwrap();
        let mut storage = StorageState::new(&path);
        let context = storage.context();

        let memory = context.dataset(SourceKey::Memory).unwrap();
        let reason = context.dataset(SourceKey::Reason).unwrap();
        let triage = context.dataset(SourceKey::Triage).unwrap();
        assert_eq!(memory.revision, triage.revision);
        assert_ne!(memory.revision, reason.revision);
        assert!(exists!(
            pattern!(reason.facts, [{ metadata::tag: &marker }])
        ));
        assert!(!exists!(
            pattern!(memory.facts, [{ metadata::tag: &marker }])
        ));
        for key in [SourceKey::Archive, SourceKey::Planner, SourceKey::Wiki] {
            assert!(context.dataset(key).is_none());
        }
        assert!(context
            .dataset(SourceKey::Headspace)
            .unwrap()
            .facts
            .is_empty());
    }

    #[test]
    fn temporary_catalog_covers_every_source_key_once() {
        let legacy: BTreeSet<_> = LEGACY_SOURCE_CATALOG
            .iter()
            .map(|source| source.key)
            .collect();
        let collections: BTreeSet<_> = COLLECTION_SOURCE_CATALOG
            .iter()
            .map(|source| source.key)
            .collect();
        assert_eq!(
            legacy,
            BTreeSet::from([
                SourceKey::Archive,
                SourceKey::Memory,
                SourceKey::Planner,
                SourceKey::Triage,
                SourceKey::Wiki,
            ])
        );
        assert_eq!(
            collections,
            BTreeSet::from([
                SourceKey::Atlas,
                SourceKey::Compass,
                SourceKey::Decide,
                SourceKey::Discord,
                SourceKey::Files,
                SourceKey::Headspace,
                SourceKey::Messages,
                SourceKey::Reason,
                SourceKey::Relations,
                SourceKey::Status,
                SourceKey::Teams,
            ])
        );
        assert!(legacy.is_disjoint(&collections));
        let complete: BTreeSet<_> = legacy.union(&collections).copied().collect();
        assert_eq!(complete, SourceKey::ALL.into_iter().collect());
        assert_eq!(legacy.len(), LEGACY_SOURCE_CATALOG.len());
        assert_eq!(collections.len(), COLLECTION_SOURCE_CATALOG.len());
    }

    #[test]
    fn semantic_commit_changes_only_its_collection_source_revision() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source-revisions.pile");
        File::create(&path).unwrap();
        collection_access::initialize_signer(&path, None).unwrap();
        let mut storage = StorageState::new(&path);
        let before: BTreeMap<_, _> = {
            let context = storage.context();
            COLLECTION_SOURCE_CATALOG
                .iter()
                .map(|source| (source.key, context.dataset(source.key).unwrap().revision))
                .collect()
        };

        collection_access::publish_fragment(
            &path,
            None,
            ATLAS_SCOPE_ID,
            entity! { metadata::tag: &Id::new([0x81; 16]).unwrap() },
            Fragment::empty(),
        )
        .unwrap();

        let context = storage.context();
        for source in COLLECTION_SOURCE_CATALOG {
            let after = context.dataset(source.key).unwrap().revision;
            if source.key == SourceKey::Atlas {
                assert_ne!(after, before[&source.key]);
            } else {
                assert_eq!(after, before[&source.key], "changed {:?}", source.key);
            }
        }
    }

    #[test]
    fn collection_catalog_materializes_every_source_from_one_frozen_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("shared-snapshot.pile");
        File::create(&path).unwrap();
        collection_access::initialize_signer(&path, None).unwrap();
        collection_access::publish_fragment(
            &path,
            None,
            ATLAS_SCOPE_ID,
            entity! { metadata::tag: &Id::new([0x91; 16]).unwrap() },
            Fragment::empty(),
        )
        .unwrap();

        let signer = collection_access::load_signer(&path, None).unwrap();
        let allowed = HashSet::from([signer.verifying_key()]);
        let frozen = collection_access::CollectionSnapshot::open(&path).unwrap();

        collection_access::publish_fragment(
            &path,
            None,
            FILES_SCOPE_ID,
            crate::files::fragment(b"snapshot".to_vec(), "snapshot.txt", "text/plain").unwrap(),
            Fragment::empty(),
        )
        .unwrap();

        let frozen_catalog = load_collection_catalog(&frozen, &allowed).unwrap();
        assert!(!frozen_catalog[&SourceKey::Atlas].facts.is_empty());
        assert!(frozen_catalog[&SourceKey::Files].facts.is_empty());

        let current = collection_access::CollectionSnapshot::open(&path).unwrap();
        let current_catalog = load_collection_catalog(&current, &allowed).unwrap();
        assert!(!current_catalog[&SourceKey::Atlas].facts.is_empty());
        assert!(!current_catalog[&SourceKey::Files].facts.is_empty());
    }

    #[test]
    fn messages_validate_against_relations_materialized_later_from_the_same_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cross-validated.pile");
        File::create(&path).unwrap();
        collection_access::initialize_signer(&path, None).unwrap();

        let sender = Id::new([0x93; 16]).unwrap();
        let recipient = Id::new([0x94; 16]).unwrap();
        let message = Id::new([0x95; 16]).unwrap();
        let epoch = Epoch::from_unix_seconds(3.0);
        let at: crate::message::IntervalValue = (epoch, epoch).try_to_inline().unwrap();
        collection_access::publish_fragment(
            &path,
            None,
            MESSAGES_SCOPE_ID,
            crate::message::message_fragment(
                message,
                sender,
                &crate::message::Recipient::Person(recipient),
                "hello",
                at,
            ),
            Fragment::empty(),
        )
        .unwrap();

        let mut relations = crate::relations::person_fragment(
            sender,
            crate::relations::ProfileInput {
                label: "Sender".to_owned(),
                ..crate::relations::ProfileInput::default()
            },
        )
        .unwrap()
        .0;
        relations += crate::relations::person_fragment(
            recipient,
            crate::relations::ProfileInput {
                label: "Recipient".to_owned(),
                ..crate::relations::ProfileInput::default()
            },
        )
        .unwrap()
        .0;
        collection_access::publish_fragment(
            &path,
            None,
            RELATIONS_SCOPE_ID,
            relations,
            Fragment::empty(),
        )
        .unwrap();

        // Messages precedes Relations in COLLECTION_SOURCE_CATALOG. A loader
        // that validates while materializing would reject this valid catalog.
        let signer = collection_access::load_signer(&path, None).unwrap();
        let allowed = HashSet::from([signer.verifying_key()]);
        let snapshot = collection_access::CollectionSnapshot::open(&path).unwrap();
        let catalog = load_collection_catalog(&snapshot, &allowed).unwrap();
        assert!(crate::message::row_by_id(&catalog[&SourceKey::Messages].facts, message).is_ok());
        assert!(!catalog[&SourceKey::Relations].facts.is_empty());
    }

    #[test]
    fn message_validation_rejects_a_recipient_absent_from_the_exact_relations_scope() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cross-validation-rejects.pile");
        File::create(&path).unwrap();
        collection_access::initialize_signer(&path, None).unwrap();

        let sender = Id::new([0x96; 16]).unwrap();
        let recipient = Id::new([0x97; 16]).unwrap();
        let message = Id::new([0x98; 16]).unwrap();
        let epoch = Epoch::from_unix_seconds(4.0);
        let at: crate::message::IntervalValue = (epoch, epoch).try_to_inline().unwrap();
        collection_access::publish_fragment(
            &path,
            None,
            MESSAGES_SCOPE_ID,
            crate::message::message_fragment(
                message,
                sender,
                &crate::message::Recipient::Person(recipient),
                "hello",
                at,
            ),
            Fragment::empty(),
        )
        .unwrap();

        let signer = collection_access::load_signer(&path, None).unwrap();
        let allowed = HashSet::from([signer.verifying_key()]);
        let snapshot = collection_access::CollectionSnapshot::open(&path).unwrap();
        let error = load_collection_catalog(&snapshot, &allowed).unwrap_err();
        assert!(error.contains("validate Messages collection"));
        assert!(error.contains("sender"));
    }

    #[test]
    fn status_validation_rejects_non_status_facts_from_the_frozen_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("status-validation-rejects.pile");
        File::create(&path).unwrap();
        collection_access::initialize_signer(&path, None).unwrap();
        let unrelated_kind = Id::new([0x99; 16]).unwrap();
        collection_access::publish_fragment(
            &path,
            None,
            STATUS_SCOPE_ID,
            entity! { metadata::tag: &unrelated_kind },
            Fragment::empty(),
        )
        .unwrap();

        let signer = collection_access::load_signer(&path, None).unwrap();
        let allowed = HashSet::from([signer.verifying_key()]);
        let snapshot = collection_access::CollectionSnapshot::open(&path).unwrap();
        let error = load_collection_catalog(&snapshot, &allowed).unwrap_err();

        assert!(error.contains("validate Status collection"));
        assert!(error.contains("outside canonical Status events"));
    }
}
