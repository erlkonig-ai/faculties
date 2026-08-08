//! Immutable dataset access shared by faculty widgets.
//!
//! Widgets consume borrowed [`DatasetView`] values through a keyed
//! [`WidgetContext`]. `StorageState` owns the currently loaded snapshot and the
//! top-bar path selector and has no write path. It loads Compass and Decide
//! directly from their union collections under the existing durable signer;
//! the private legacy catalog remains only for faculties which have not made
//! that cutover yet.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use triblespace::core::repo::pile::PileReader;
use triblespace::core::trible::TribleSet;
use GORBIE::prelude::CardCtx;

use crate::collection_access::{
    self, CollectionRevision, CollectionView, LegacyBranchRevision, LegacyBranchView,
};
use crate::schemas::compass::DEFAULT_SCOPE_ID as COMPASS_SCOPE_ID;
use crate::schemas::decide::DEFAULT_SCOPE_ID as DECIDE_SCOPE_ID;

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

// Temporary and deliberately private. Compass and Decide are absent because
// they have made the collection cutover; every remaining source is loaded
// only from legacy state until its own schema migration lands.
const LEGACY_SOURCE_CATALOG: &[LegacySource] = &[
    LegacySource {
        key: SourceKey::Archive,
        branches: &["archive"],
    },
    LegacySource {
        key: SourceKey::Atlas,
        branches: &["atlas"],
    },
    LegacySource {
        key: SourceKey::Discord,
        branches: &["discord"],
    },
    LegacySource {
        key: SourceKey::Files,
        branches: &["files"],
    },
    LegacySource {
        key: SourceKey::Headspace,
        branches: &["config"],
    },
    LegacySource {
        key: SourceKey::Memory,
        branches: &["memory", "cognition"],
    },
    LegacySource {
        key: SourceKey::Messages,
        branches: &["message"],
    },
    LegacySource {
        key: SourceKey::Planner,
        branches: &["planner"],
    },
    LegacySource {
        key: SourceKey::Reason,
        branches: &["cognition"],
    },
    LegacySource {
        key: SourceKey::Relations,
        branches: &["relations"],
    },
    LegacySource {
        key: SourceKey::Status,
        branches: &["status"],
    },
    LegacySource {
        key: SourceKey::Teams,
        branches: &["teams"],
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
    let compass = snapshot
        .materialize_scope(COMPASS_SCOPE_ID, &allowed)
        .map_err(|error| format!("materialize Compass collection: {error:#}"))?;
    crate::compass::validate_catalog(&compass.reader, &compass.facts)
        .map_err(|error| format!("validate Compass collection: {error:#}"))?;
    datasets.insert(SourceKey::Compass, LoadedDataset::from_collection(compass));
    let decide = snapshot
        .materialize_scope(DECIDE_SCOPE_ID, &allowed)
        .map_err(|error| format!("materialize Decide collection: {error:#}"))?;
    crate::decide::validate_catalog(&decide.reader, &decide.facts)
        .map_err(|error| format!("validate Decide collection: {error:#}"))?;
    datasets.insert(SourceKey::Decide, LoadedDataset::from_collection(decide));
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
        File::create(path).unwrap();
        let pile = collection_access::open_pile_strict(path).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x31; 32]), Fragment::empty()).unwrap();
        let branch = *repository.create_branch(name, None).unwrap();
        let mut workspace = repository.pull(branch).unwrap();
        workspace.commit(
            entity! { metadata::description: text.to_owned() },
            "fixture",
        );
        repository.push(&mut workspace).unwrap();
        repository.close().unwrap();
        collection_access::initialize_signer(path, None).unwrap();
        branch
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
    fn collection_sources_have_no_legacy_fallback_and_other_scopes_are_ignored() {
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

        let compass = context.dataset(SourceKey::Compass).unwrap();
        let decide = context.dataset(SourceKey::Decide).unwrap();
        assert!(compass.facts.is_empty());
        assert!(decide.facts.is_empty());
        assert!(SourceKey::ALL
            .into_iter()
            .filter(|key| !matches!(key, SourceKey::Compass | SourceKey::Decide))
            .all(|key| context.dataset(key).is_none()));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
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
    fn memory_fallback_is_private_to_the_legacy_catalog() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fallback.pile");
        create_branch(&path, "cognition", "legacy cognition");
        let mut storage = StorageState::new(&path);
        let context = storage.context();

        let memory = context.dataset(SourceKey::Memory).unwrap();
        let reason = context.dataset(SourceKey::Reason).unwrap();
        let triage = context.dataset(SourceKey::Triage).unwrap();
        assert_eq!(memory.revision, reason.revision);
        assert_eq!(memory.revision, triage.revision);
    }

    #[test]
    fn temporary_catalog_covers_every_source_key_once() {
        let legacy: BTreeSet<_> = LEGACY_SOURCE_CATALOG
            .iter()
            .map(|source| source.key)
            .collect();
        assert!(!legacy.contains(&SourceKey::Compass));
        assert!(!legacy.contains(&SourceKey::Decide));
        let mut complete = legacy.clone();
        complete.insert(SourceKey::Compass);
        complete.insert(SourceKey::Decide);
        assert_eq!(complete, SourceKey::ALL.into_iter().collect());
        assert_eq!(legacy.len(), LEGACY_SOURCE_CATALOG.len());
    }
}
