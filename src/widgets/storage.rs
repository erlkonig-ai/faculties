//! Immutable dataset access shared by faculty widgets.
//!
//! Widgets consume borrowed [`DatasetView`] values through a keyed
//! [`WidgetContext`]. `StorageState` owns the currently loaded snapshot and the
//! top-bar path selector. Every source is observed through a maintained
//! Rank9-accelerated Succinct view derived from its fixed V4 descriptor-handle
//! collection under the pile's durable
//! signer. Repository branches, mutable heads, and compatibility fallbacks do
//! not participate in this boundary. The interactive viewer loads all sources;
//! focused capture binaries request only their source dependency
//! closure. Loading ensures roots and maintains each immediate derivation.
//! One common store snapshot attaches facts and positive latest/LWW indexes
//! independently; those unsigned artifacts are cache exhaust, not
//! authoritative writes. Most sources are
//! fixed descriptor-handle collections. Secrets uses the same explicit
//! collection configuration and is attached only when the pile signer is
//! admitted to READ it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::latest::LatestIndex;
use triblespace::core::collection::lww_register::LwwIndex;
use triblespace::core::collection::{
    Collection, CollectionHandle, CollectionSnapshotExt, CollectionStoreExt, Support,
};
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::Id;
use GORBIE::prelude::CardCtx;

use crate::collection_names::open_configured;
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
use crate::secrets::{storage as secret_storage, SecretsSnapshot};
use crate::storage::{load_signer, open_pile_strict, open_secrets_collection_read, FactArchive};

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

    /// Logical inputs that must accompany this source for rendering. Storage
    /// layout stays out of this relation: the transitive closure is computed
    /// over semantic source keys and scopes are deduplicated only afterwards.
    fn dependencies(self) -> &'static [Self] {
        match self {
            Self::Headspace => &[Self::Secrets],
            Self::Mail | Self::Messages | Self::Planner | Self::Status => &[Self::Relations],
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
/// construction. The digest includes each attached relation's descriptor and
/// its own resident support. It is a widget cache token, not a durable
/// collection record or an authorization proof, and physical Succinct
/// compaction cannot perturb it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DatasetRevision([u8; 32]);

impl DatasetRevision {
    fn hash_collection_support(
        hasher: &mut blake3::Hasher,
        collection: CollectionHandle,
        support: &Support,
    ) {
        hasher.update(&collection.raw);
        for member in support.members() {
            hasher.update(&member.raw);
        }
        hasher.update(&(support.len() as u128).to_le_bytes());
    }

    fn from_collection(collection: CollectionHandle, support: &Support) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"faculties.viewer.dataset-revision.v3");
        Self::hash_collection_support(&mut hasher, collection, support);
        Self(*hasher.finalize().as_bytes())
    }

    fn include_collection(&mut self, collection: CollectionHandle, support: &Support) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"faculties.viewer.dataset-relation.v1");
        hasher.update(&self.0);
        Self::hash_collection_support(&mut hasher, collection, support);
        self.0 = *hasher.finalize().as_bytes();
    }

    fn from_secrets(snapshot: &SecretsSnapshot<PileSnapshot>) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"faculties.viewer.secrets-revision.v3");
        Self::hash_collection_support(&mut hasher, snapshot.collection(), snapshot.support());
        Self(*hasher.finalize().as_bytes())
    }
}

/// Borrowed immutable input for one widget dataset.
#[derive(Clone, Copy)]
pub struct DatasetView<'a> {
    pub facts: &'a FactArchive,
    pub reader: &'a PileSnapshot,
    pub revision: DatasetRevision,
    lww_registers: &'a BTreeMap<(Id, Id), LwwIndex>,
    latest_indexes: &'a BTreeMap<Id, LatestIndex>,
}

impl DatasetView<'_> {
    /// Maintained LWW order for the requested identity and order attributes.
    pub fn lww_register(&self, identity: Id, orders: Id) -> Option<&LwwIndex> {
        self.lww_registers.get(&(identity, orders))
    }

    /// Known latest states for the requested supersession edge attribute.
    pub fn latest_index(&self, observes: Id) -> Option<&LatestIndex> {
        self.latest_indexes.get(&observes)
    }
}

/// Keyed borrowed inputs for one viewer render.
#[derive(Clone, Copy)]
pub struct WidgetContext<'a> {
    datasets: Option<&'a BTreeMap<SourceKey, LoadedDataset>>,
    secrets: Option<&'a LoadedSecrets>,
}

impl<'a> WidgetContext<'a> {
    /// Return the exact requested logical dataset, or `None` when that source
    /// is absent. Missing sources never shift another source into its place.
    pub fn dataset(&self, key: SourceKey) -> Option<DatasetView<'a>> {
        self.datasets?.get(&key).map(LoadedDataset::view)
    }

    /// Return the explicitly configured readable Secrets collection.
    pub fn secrets(&self) -> Option<SecretsView<'a>> {
        self.secrets.map(LoadedSecrets::view)
    }

    /// Whether this semantic source is present in the loaded closure.
    pub fn contains(&self, key: SourceKey) -> bool {
        match key {
            SourceKey::Secrets => self.secrets.is_some(),
            _ => self
                .datasets
                .is_some_and(|datasets| datasets.contains_key(&key)),
        }
    }
}

/// Borrowed Secrets snapshot plus its viewer cache token.
#[derive(Clone, Copy)]
pub struct SecretsView<'a> {
    pub snapshot: &'a SecretsSnapshot<PileSnapshot>,
    pub revision: DatasetRevision,
}

struct LoadedDataset {
    facts: FactArchive,
    reader: PileSnapshot,
    revision: DatasetRevision,
    lww_registers: BTreeMap<(Id, Id), LwwIndex>,
    latest_indexes: BTreeMap<Id, LatestIndex>,
}

impl LoadedDataset {
    fn new(
        facts: FactArchive,
        revision: DatasetRevision,
        reader: PileSnapshot,
        lww_registers: BTreeMap<(Id, Id), LwwIndex>,
        latest_indexes: BTreeMap<Id, LatestIndex>,
    ) -> Self {
        Self {
            facts,
            reader,
            revision,
            lww_registers,
            latest_indexes,
        }
    }

    fn view(&self) -> DatasetView<'_> {
        DatasetView {
            facts: &self.facts,
            reader: &self.reader,
            revision: self.revision,
            lww_registers: &self.lww_registers,
            latest_indexes: &self.latest_indexes,
        }
    }
}

struct LoadedSecrets {
    snapshot: SecretsSnapshot<PileSnapshot>,
    revision: DatasetRevision,
}

struct LoadedInputs {
    datasets: BTreeMap<SourceKey, LoadedDataset>,
    secrets: Option<LoadedSecrets>,
}

impl LoadedSecrets {
    fn new(snapshot: SecretsSnapshot<PileSnapshot>) -> Self {
        let revision = DatasetRevision::from_secrets(&snapshot);
        Self { snapshot, revision }
    }

    fn view(&self) -> SecretsView<'_> {
        SecretsView {
            snapshot: &self.snapshot,
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

fn collection_scopes(sources: &BTreeSet<SourceKey>) -> Vec<(Id, &'static str)> {
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
    secrets: Option<LoadedSecrets>,
    sources: BTreeSet<SourceKey>,
    pile_path: PathBuf,
    pile_path_text: String,
    stamp: Option<FileStamp>,
    error: Option<String>,
}

impl StorageState {
    /// Stash a pile path for lazy all-source loading. No I/O happens here,
    /// which keeps eager notebook-state construction cheap.
    pub fn new(pile_path: impl Into<PathBuf>) -> Self {
        Self::with_sources(pile_path, SourceKey::ALL)
    }

    /// Stash a pile path for lazy, source-scoped loading.
    ///
    /// The requested semantic inputs are expanded through their declarative
    /// dependency closure. Only those collection scopes are maintained;
    /// consumers can observe the requested keys and their logical dependencies,
    /// but never unrelated keys that happen to share a scope.
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
            secrets: None,
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
            secrets: self.secrets.as_ref(),
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
            self.secrets = None;
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
        match pollster::block_on(load_consistent_inputs(&self.pile_path, &self.sources)) {
            Ok((inputs, stamp)) => {
                self.datasets = Some(inputs.datasets);
                self.secrets = inputs.secrets;
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

async fn load_consistent_inputs(
    path: &Path,
    sources: &BTreeSet<SourceKey>,
) -> Result<(LoadedInputs, FileStamp), String> {
    for _ in 0..2 {
        let before = file_stamp(path)?;
        let inputs = load_inputs(path, sources).await?;
        let after = file_stamp(path)?;
        if before == after {
            return Ok((inputs, after));
        }
    }
    Err(format!(
        "pile {} changed repeatedly while loading viewer datasets; retry OPEN",
        path.display()
    ))
}

async fn load_inputs(path: &Path, sources: &BTreeSet<SourceKey>) -> Result<LoadedInputs, String> {
    let signer = load_signer(path, None)
        .map_err(|error| format!("load durable collection signer: {error:#}"))?;
    let mut pile = open_pile_strict(path).map_err(|error| format!("open pile: {error:#}"))?;

    let loaded = async {
        let mut by_scope = BTreeMap::<Id, Collection<Rank9AcceleratedSuccinctArchiveBlob>>::new();
        let mut lww_by_scope = BTreeMap::<Id, BTreeMap<(Id, Id), LwwIndex>>::new();
        let mut latest_by_scope = BTreeMap::<Id, BTreeMap<Id, LatestIndex>>::new();

        let mut collections = Vec::new();
        for (scope, label) in collection_scopes(sources) {
            let source = open_configured(&mut pile, scope, signer.verifying_key())
                .map_err(|error| format!("register {label} collection: {error:#}"))?;
            let descriptor_snapshot = pile
                .snapshot()
                .map_err(|error| format!("freeze {label} descriptor snapshot: {error}"))?;
            let policy = source
                .policy(&descriptor_snapshot)
                .map_err(|error| format!("read {label} collection policy: {error:#}"))?;
            drop(descriptor_snapshot);
            let succinct = pile
                .derive::<SuccinctArchiveBlob>(source, (), policy.clone())
                .map_err(|error| format!("register Succinct {label} collection: {error:#}"))?;
            let rank9 = pile
                .derive::<Rank9AcceleratedSuccinctArchiveBlob>(succinct, (), policy)
                .map_err(|error| format!("register Rank9 {label} collection: {error:#}"))?;
            collections.push((scope, label, source, succinct, rank9));
        }

        let compass_register = sources
            .contains(&SourceKey::Compass)
            .then(|| {
                crate::compass::status_register_collection(&mut pile, signer.verifying_key())
                    .map_err(|error| format!("register Compass status collection: {error:#}"))
            })
            .transpose()?;
        let wiki_latest = sources
            .contains(&SourceKey::Wiki)
            .then(|| {
                crate::wiki::latest_collection(&mut pile, signer.verifying_key())
                    .map_err(|error| format!("register Wiki observation collection: {error:#}"))
            })
            .transpose()?;

        let secrets_collection = sources
            .contains(&SourceKey::Secrets)
            .then(|| {
                open_secrets_collection_read(&mut pile, signer.verifying_key())
                    .map_err(|error| format!("open configured Secrets collection: {error:#}"))
            })
            .transpose()?;

        for (_, label, source, _, _) in &collections {
            drop(
                pile.ensure(*source)
                    .await
                    .map_err(|error| format!("ensure {label} source collection: {error:#}"))?,
            );
        }
        if let Some(collection) = secrets_collection {
            drop(
                pile.ensure(collection.source())
                    .await
                    .map_err(|error| format!("ensure Secrets source collection: {error:#}"))?,
            );
        }

        // Keep the Secrets credential path pinned to its existing explicit
        // support boundary after root acquisition.
        let before = pile
            .snapshot()
            .map_err(|error| format!("freeze shared viewer support snapshot: {error}"))?;
        let secrets_support = secrets_collection
            .map(|collection| {
                collection
                    .source()
                    .admitted(&before)
                    .map(|support| (collection, support))
                    .map_err(|error| format!("admit Secrets collection support: {error:#}"))
            })
            .transpose()?;
        drop(before);

        for (_, label, _, succinct, rank9) in &collections {
            drop(
                pile.maintain(*succinct).await.map_err(|error| {
                    format!("maintain Succinct {label} fact archive: {error:#}")
                })?,
            );
            drop(
                pile.maintain(*rank9)
                    .await
                    .map_err(|error| format!("maintain Rank9 {label} fact archive: {error:#}"))?,
            );
        }

        for (scope, _, _, _, rank9) in collections {
            by_scope.insert(scope, rank9);
        }

        // Positive indexes are independently maintained query relations. Their
        // support need not equal fact support to admit only known winners.
        if let Some(target) = compass_register {
            drop(
                pile.maintain(target)
                    .await
                    .map_err(|error| format!("maintain Compass status register: {error}"))?,
            );
        }

        if let Some(target) = wiki_latest {
            drop(
                pile.maintain(target)
                    .await
                    .map_err(|error| format!("maintain Wiki supersession index: {error}"))?,
            );
        }

        let secrets = if let Some((collection, support)) = secrets_support {
            let store_snapshot = collection
                .ensure_exact(&mut pile, &support)
                .await
                .map_err(|error| format!("ensure configured Secrets collection: {error:#}"))?;
            let snapshot = secret_storage::snapshot_exact(store_snapshot, collection, support)
                .map_err(|error| format!("attach exact Secrets collection: {error:#}"))?;
            Some(LoadedSecrets::new(snapshot))
        } else {
            None
        };

        // Secrets discovery already owns the final immutable snapshot when it
        // participates. Reuse it so all facts, attachments, and credentials
        // inhabit literally one known-prefix observation. A viewer without
        // Secrets freezes the same boundary itself.
        let store_snapshot = match secrets.as_ref() {
            Some(secrets) => secrets.snapshot.store_snapshot().clone(),
            None => pile
                .snapshot()
                .map_err(|error| format!("freeze maintained viewer snapshot: {error}"))?,
        };

        let mut facts_by_scope = BTreeMap::new();
        let mut revisions_by_scope = BTreeMap::new();
        for (scope, rank9) in &by_scope {
            let label = COLLECTION_SOURCE_CATALOG
                .iter()
                .find(|source| source.scope == *scope)
                .expect("every maintained viewer scope has a source label")
                .label;
            let collection = store_snapshot
                .collection(*rank9)
                .map_err(|error| format!("attach maintained {label} collection: {error}"))?;
            let facts = collection
                .view::<FactArchive>()
                .map_err(|error| format!("read maintained {label} collection: {error}"))?;
            revisions_by_scope.insert(
                *scope,
                DatasetRevision::from_collection(rank9.handle(), collection.support()),
            );
            facts_by_scope.insert(*scope, facts);
        }

        if let Some(target) = compass_register {
            let collection = store_snapshot
                .collection(target)
                .map_err(|error| format!("attach Compass status register: {error}"))?;
            let index = collection
                .view::<LwwIndex>()
                .map_err(|error| format!("read Compass status register: {error}"))?;
            revisions_by_scope
                .get_mut(&COMPASS_SCOPE_ID)
                .expect("Compass facts were attached")
                .include_collection(target.handle(), collection.support());
            lww_by_scope.entry(COMPASS_SCOPE_ID).or_default().insert(
                (
                    crate::schemas::compass::board::status_of.id(),
                    triblespace::core::metadata::created_at.id(),
                ),
                index,
            );
        }

        if let Some(target) = wiki_latest {
            let collection = store_snapshot
                .collection(target)
                .map_err(|error| format!("attach Wiki supersession index: {error}"))?;
            let index = collection
                .view::<LatestIndex>()
                .map_err(|error| format!("read Wiki supersession index: {error}"))?;
            revisions_by_scope
                .get_mut(&WIKI_SCOPE_ID)
                .expect("Wiki facts were attached")
                .include_collection(target.handle(), collection.support());
            latest_by_scope
                .entry(WIKI_SCOPE_ID)
                .or_default()
                .insert(triblespace::core::metadata::supersedes.id(), index);
        }

        let datasets = COLLECTION_SOURCE_CATALOG
            .iter()
            .filter(|source| sources.contains(&source.key))
            .map(|source| {
                let revision = revisions_by_scope
                    .get(&source.scope)
                    .expect("every fixed viewer scope was maintained");
                let facts = facts_by_scope
                    .get(&source.scope)
                    .expect("every maintained viewer scope was attached");
                let lww_registers = lww_by_scope.get(&source.scope).cloned().unwrap_or_default();
                let latest_indexes = latest_by_scope
                    .get(&source.scope)
                    .cloned()
                    .unwrap_or_default();
                (
                    source.key,
                    LoadedDataset::new(
                        facts.clone(),
                        *revision,
                        store_snapshot.clone(),
                        lww_registers,
                        latest_indexes,
                    ),
                )
            })
            .collect();
        Ok(LoadedInputs { datasets, secrets })
    }
    .await;

    let closed = pile.close().map_err(|error| format!("close pile: {error}"));
    match (loaded, closed) {
        (Ok(datasets), Ok(())) => Ok(datasets),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(close_error)) => Err(format!("{error}; {close_error}")),
    }
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
    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::metadata;
    use triblespace::core::repo::{BlobStoreGet, StoreSnapshot};
    use triblespace::macros::{entity, find, pattern};
    use triblespace::prelude::*;

    use crate::test_support::initialize_open_collection_fixture;

    fn create_pile(path: &Path) {
        File::create(path).unwrap();
        initialize_open_collection_fixture(path, None);
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
        let collection =
            crate::collection_names::open(&mut pile, STATUS_SCOPE_ID, signer.verifying_key())
                .unwrap();
        pile.commit(collection, &signer, fragment).unwrap();
        pile.close().unwrap();
    }

    fn visible_keys(context: WidgetContext<'_>) -> BTreeSet<SourceKey> {
        SourceKey::ALL
            .into_iter()
            .filter(|key| context.contains(*key))
            .collect()
    }

    #[test]
    fn storage_load_settles_once_and_context_refresh_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("viewer.pile");
        create_pile(&path);
        publish_reason(&path, "read only", 1.0);
        let length = std::fs::metadata(&path).unwrap().len();
        let mut storage = StorageState::new(&path);

        let context = storage.context();
        let view = context.dataset(SourceKey::Reason).unwrap();
        let text = find!(
            text: Inline<inlineencodings::Handle<blobencodings::UTF8String>>,
            pattern!(view.facts, [{ metadata::tag: crate::schemas::reason::KIND_REASON_ID,
                                    crate::schemas::reason::reason_schema::text: ?text }])
        )
        .next()
        .unwrap();
        let text: View<str> = view.reader.get(text).unwrap();
        assert_eq!(&*text, "read only");
        assert_eq!(view.facts.segment_count(), 1);
        let settled_length = std::fs::metadata(&path).unwrap().len();
        assert!(settled_length >= length);
        let _ = storage.context();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), settled_length);
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
        assert!(reason.facts.iter().eq(triage.facts.iter()));
        let secrets = context.secrets().unwrap();
        let secrets_reader = secrets.snapshot.store_snapshot();
        for reader in [reason.reader, triage.reader] {
            assert_eq!(reader.instant(), secrets_reader.instant());
            assert!(reader.changes_since(secrets_reader).is_empty());
            assert!(secrets_reader.changes_since(reader).is_empty());
        }
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
            BTreeSet::from([SourceKey::Mail, SourceKey::Relations])
        );
        assert_eq!(
            source_closure([SourceKey::Headspace]),
            BTreeSet::from([SourceKey::Headspace, SourceKey::Secrets])
        );
        assert_eq!(
            source_closure([SourceKey::Teams]),
            BTreeSet::from([SourceKey::Teams])
        );
        for source in [SourceKey::Messages, SourceKey::Planner, SourceKey::Status] {
            assert_eq!(
                source_closure([source]),
                BTreeSet::from([source, SourceKey::Relations])
            );
        }
    }

    #[test]
    fn dataset_revision_changes_when_only_latest_support_advances() {
        pollster::block_on(async {
            use triblespace::core::collection::latest::LatestBlob;

            let signer = SigningKey::from_bytes(&[35; 32]);
            let mut store = MemoryRepo::default();
            let source = store
                .collection(
                    "latest-cache",
                    crate::collection_names::private_policy(signer.verifying_key()),
                )
                .unwrap();
            let target = store
                .derive::<LatestBlob>(
                    source,
                    metadata::supersedes.id(),
                    crate::collection_names::private_policy(signer.verifying_key()),
                )
                .unwrap();
            let root = genid();
            let next = genid();
            store
                .commit(source, &signer, entity! { &root @ metadata::name: "root" })
                .unwrap();
            let ready = store.maintain(target).await.unwrap();
            let lagging = ready.collection(target).unwrap();
            store
                .commit(
                    source,
                    &signer,
                    entity! { &next @ metadata::supersedes: &root },
                )
                .unwrap();
            let snapshot = store.snapshot().unwrap();
            let facts = snapshot.collection(source).unwrap();
            let mut before = DatasetRevision::from_collection(source.handle(), facts.support());
            before.include_collection(target.handle(), lagging.support());

            let ready = store.maintain(target).await.unwrap();
            let advanced = ready.collection(target).unwrap();
            let mut after = DatasetRevision::from_collection(source.handle(), facts.support());
            after.include_collection(target.handle(), advanced.support());
            assert_ne!(
                before, after,
                "index-only progress invalidates widget projections"
            );
            assert_eq!(facts.support(), ready.collection(source).unwrap().support());
        });
    }

    #[test]
    fn wiki_dataset_attaches_positive_latest_index_without_advancing_source() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wiki-latest.pile");
        create_pile(&path);
        let signer = load_signer(&path, None).unwrap();
        let (author_fragment, author) = crate::wiki::author_record(&signer.verifying_key());
        let instant = Epoch::from_tai_seconds(1.0);
        let (root_fragment, root) = crate::wiki::revision_record(crate::wiki::RevisionDraft {
            title: "root".to_owned(),
            content: "root".to_owned(),
            tags: BTreeSet::new(),
            predecessors: BTreeSet::new(),
            author,
            authored_at: (instant, instant).try_to_inline().unwrap(),
        })
        .unwrap();
        let (successor_fragment, successor) =
            crate::wiki::revision_record(crate::wiki::RevisionDraft {
                title: "successor".to_owned(),
                content: "successor".to_owned(),
                tags: BTreeSet::new(),
                predecessors: BTreeSet::from([root]),
                author,
                authored_at: (instant, instant).try_to_inline().unwrap(),
            })
            .unwrap();
        let mut pile = open_pile_strict(&path).unwrap();
        crate::wiki::commit_collection(
            &mut pile,
            &signer,
            author_fragment + root_fragment + successor_fragment,
        )
        .unwrap();
        let collection =
            crate::collection_names::open(&mut pile, WIKI_SCOPE_ID, signer.verifying_key())
                .unwrap();
        let store_snapshot = pile.snapshot().unwrap();
        let cover_before = collection.admitted(&store_snapshot).unwrap();
        pile.close().unwrap();

        let mut storage = StorageState::for_sources(&path, [SourceKey::Wiki]);
        let dataset = storage.context().dataset(SourceKey::Wiki).unwrap();
        let latest = dataset
            .latest_index(metadata::supersedes.id())
            .expect("Wiki dataset carries its positive latest relation");
        let entries = crate::wiki::entries(dataset.facts, latest);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].frontier.len(), 1);
        assert_eq!(entries[0].frontier[0].id, successor);

        let mut pile = open_pile_strict(&path).unwrap();
        let collection =
            crate::collection_names::open(&mut pile, WIKI_SCOPE_ID, signer.verifying_key())
                .unwrap();
        let store_snapshot = pile.snapshot().unwrap();
        let cover_after = collection.admitted(&store_snapshot).unwrap();
        pile.close().unwrap();
        assert_eq!(cover_after, cover_before);
    }

    #[test]
    fn shared_scope_is_planned_once_but_each_requested_semantic_key_is_exposed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("shared-scoped.pile");
        create_pile(&path);
        publish_reason(&path, "shared", 1.0);

        let sources = source_closure([SourceKey::Reason, SourceKey::Triage]);
        assert_eq!(
            collection_scopes(&sources)
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
        assert!(reason.facts.iter().eq(triage.facts.iter()));
    }

    #[test]
    fn malformed_source_facts_do_not_block_ordinary_source_attachment() {
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
        let context = full.context();
        assert!(context.dataset(SourceKey::Reason).is_some());
        assert!(context.dataset(SourceKey::Status).is_some());
        assert!(full.error().is_none());
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
    fn fixed_catalog_covers_every_fixed_source_key_once() {
        let catalog: BTreeSet<_> = COLLECTION_SOURCE_CATALOG
            .iter()
            .map(|source| source.key)
            .collect();
        let mut expected: BTreeSet<_> = SourceKey::ALL.into_iter().collect();
        expected.remove(&SourceKey::Secrets);
        assert_eq!(catalog, expected);
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
    fn secrets_is_a_dynamic_aggregate_not_a_fixed_dataset() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("secrets.pile");
        create_pile(&path);
        let mut storage = StorageState::for_sources(&path, [SourceKey::Secrets]);

        let context = storage.context();
        assert!(context.contains(SourceKey::Secrets));
        assert!(context.secrets().is_some());
        assert!(context.dataset(SourceKey::Secrets).is_none());
        assert!(storage.error().is_none());
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
