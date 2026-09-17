//! Full-featured GORBIE-embeddable wiki viewer.
//!
//! Renders the maintained Wiki revision collection from a triblespace pile. The widget holds only
//! UI state plus cached query results; the host passes a wiki dataset
//! (and optionally a files dataset) at render time:
//!
//! ```ignore
//! let mut viewer = WikiViewer::default();
//! // Inside a GORBIE card, with `wiki_view` and optional `files_view`:
//! viewer.render(ctx, wiki_view, files_view);
//! ```
//!
//! Features:
//! - Search bar at the top
//! - A force-directed graph of current entry-frontier revisions + links
//!   derived from immutable content, laid out by the shared solver in
//!   `GORBIE::graph`
//! - Floating wiki-page cards that open when the user clicks a node, a
//!   `wiki:<hex>` link in typst content, or a file entry
//! - Fork-visible revision cards without inventing a scalar latest state
//! - `files:` link handling — resolves the shared file selector language to a
//!   file blob (against the optional files dataset),
//!   writes it to `$TMPDIR/faculties-files/`, and opens it via the platform
//!   `open` command.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use triblespace::core::blob::Blob;
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::blobencodings::{RawBytes, UTF8String};
use triblespace::prelude::*;
use GORBIE::graph::{self, GraphViewport, KeyedLayout, LayoutParams};
use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use crate::schemas::files::{file as file_attrs, KIND_FILE};
use crate::schemas::wiki::{extract_link_targets, TAG_ARCHIVED_ID};
use crate::widgets::storage::{DatasetRevision, DatasetView};
use crate::wiki::{EntryRecord, RevisionRecord};

/// Handle to a long-string blob living in a pile.
type TextHandle = Inline<Handle<UTF8String>>;

/// Handle to a file-bytes blob living in a pile.
type FileHandle = crate::files::ContentHandle;

/// Format an Id as a lowercase hex string.
fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn resolved_file_name(resolved: &crate::files::ResolvedFile) -> String {
    resolved
        .unique_name()
        .map(crate::files::leaf_name)
        .unwrap_or_else(|| crate::files::content_hash_hex(resolved.content))
}

/// Deterministic per-entry color via GORBIE's colorhash palette.
/// The caller passes the entry's canonical root-set representative strictly as
/// a UI key; storage identity remains the complete root set.
fn frag_color(id: Id) -> egui::Color32 {
    colorhash::ral_categorical(id.as_ref())
}

// ── cached wiki query state ──────────────────────────────────────────

/// One visible revision head in a logical Wiki entry.
///
/// `entry_key` is only a deterministic UI/color key (a legacy fragment
/// selector when present, otherwise the first root). The entry's real identity
/// remains its complete component in the revision read model; no scalar anchor
/// is smuggled back into storage semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct VisibleHead {
    entry_key: Id,
    revision_id: Id,
    archived: bool,
    fork_width: usize,
}

/// The dataset revisions for which presentation caches were built.
struct WikiLive {
    cached_revision: DatasetRevision,
    files_cached_revision: Option<DatasetRevision>,
}

impl WikiLive {
    /// Confirm that the maintained supersession order needed for frontiers is
    /// attached to this exact immutable dataset view.
    fn refresh(wiki: DatasetView<'_>, files: Option<DatasetView<'_>>) -> Result<Self, String> {
        wiki.latest_index(metadata::supersedes.id())
            .ok_or_else(|| "maintained Wiki supersession index missing".to_owned())?;
        Ok(WikiLive {
            cached_revision: wiki.revision,
            files_cached_revision: files.map(|files| files.revision),
        })
    }

    fn text(reader: &PileSnapshot, h: TextHandle) -> String {
        crate::wiki::read_text(reader, h).unwrap_or_default()
    }

    // ── maintained revision/entry projection ─────────────────────────

    fn entry_key(entry: &EntryRecord) -> Option<Id> {
        entry
            .roots
            .first()
            .or_else(|| entry.members.first())
            .copied()
    }

    fn revision<P: TriblePattern>(facts: &P, revision: Id) -> Option<RevisionRecord> {
        crate::wiki::revision_records(facts, revision)
            .into_iter()
            .min_by_key(|row| (row.title, row.content, row.author, row.native))
    }

    fn title<P: TriblePattern>(facts: &P, wiki_reader: &PileSnapshot, revision: Id) -> String {
        Self::revision(facts, revision)
            .map(|row| Self::text(wiki_reader, row.title))
            .unwrap_or_default()
    }

    fn content<P: TriblePattern>(facts: &P, wiki_reader: &PileSnapshot, revision: Id) -> String {
        Self::revision(facts, revision)
            .map(|row| Self::text(wiki_reader, row.content))
            .unwrap_or_default()
    }

    /// Complete frontiers of every entry which has at least one live head.
    ///
    /// An archived/live fork keeps both heads visible: hiding the archived
    /// side would falsely present a resolved state. Entries whose complete
    /// frontier is archived are absent from the default graph.
    fn projected_heads<P: TriblePattern>(
        facts: &P,
        latest: &triblespace::core::collection::latest::LatestIndex,
    ) -> Vec<VisibleHead> {
        let mut heads = Vec::new();
        for entry in crate::wiki::entries(facts, latest) {
            if entry
                .frontier
                .iter()
                .all(|revision| revision.tags.contains(&TAG_ARCHIVED_ID))
            {
                continue;
            }
            let Some(entry_key) = Self::entry_key(&entry) else {
                continue;
            };
            let fork_width = entry.frontier.len();
            for revision in entry.frontier {
                heads.push(VisibleHead {
                    entry_key,
                    revision_id: revision.id,
                    archived: revision.tags.contains(&TAG_ARCHIVED_ID),
                    fork_width,
                });
            }
        }
        heads
    }

    fn visible_heads(wiki: DatasetView<'_>) -> Vec<VisibleHead> {
        let Some(order) = wiki.latest_index(metadata::supersedes.id()) else {
            return Vec::new();
        };
        let mut heads = Self::projected_heads(wiki.facts, order);
        heads.sort_by(|left, right| {
            Self::title(wiki.facts, wiki.reader, left.revision_id)
                .to_lowercase()
                .cmp(&Self::title(wiki.facts, wiki.reader, right.revision_id).to_lowercase())
                .then_with(|| left.entry_key.cmp(&right.entry_key))
                .then_with(|| left.revision_id.cmp(&right.revision_id))
        });
        heads
    }

    fn all_selectors<P: TriblePattern>(facts: &P) -> BTreeSet<Id> {
        crate::wiki::revision_ids(facts)
    }

    /// Resolve one full selector. A selector is a revision id or nothing.
    fn resolve_selector<P: TriblePattern>(facts: &P, selector: Id) -> Vec<Id> {
        if !crate::wiki::revision_records(facts, selector).is_empty() {
            vec![selector]
        } else {
            Vec::new()
        }
    }

    /// Resolve a selector as a live entry reference. Unlike an immutable
    /// revision link, this deliberately follows the selected revision's
    /// connected component to its complete current frontier.
    fn resolve_entry_selector_with_order<P: TriblePattern>(
        facts: &P,
        latest: &triblespace::core::collection::latest::LatestIndex,
        selector: Id,
    ) -> Vec<Id> {
        let mut heads = BTreeSet::new();
        for revision in Self::resolve_selector(facts, selector) {
            if let Some(entry) = crate::wiki::entry(facts, latest, revision) {
                heads.extend(entry.frontier.iter().map(|head| head.id));
            }
        }
        heads.into_iter().collect()
    }

    fn resolve_entry_selector(wiki: DatasetView<'_>, selector: Id) -> Vec<Id> {
        wiki.latest_index(metadata::supersedes.id())
            .map(|order| Self::resolve_entry_selector_with_order(wiki.facts, order, selector))
            .unwrap_or_default()
    }

    /// Resolve a hex prefix to the set-valued result of its unique selector.
    /// No timestamp, fact order, or lowest-id winner resolves ambiguity.
    fn resolve_prefix<P: TriblePattern>(facts: &P, prefix: &str) -> Option<Vec<Id>> {
        let needle = prefix.trim().to_lowercase();
        if needle.is_empty()
            || needle.len() > 32
            || !needle.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        let mut matches = Self::all_selectors(facts)
            .into_iter()
            .filter(|id| format!("{id:x}").starts_with(&needle));
        let selector = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        let resolved = Self::resolve_selector(facts, selector);
        (!resolved.is_empty()).then_some(resolved)
    }

    /// Resolve links parsed from immutable revision content.
    fn links<P: TriblePattern>(facts: &P, wiki_reader: &PileSnapshot, revision: Id) -> Vec<Id> {
        let mut links = BTreeSet::new();
        for raw in extract_link_targets(&Self::content(facts, wiki_reader, revision)) {
            if let Some(selector) = Id::from_hex(&raw) {
                links.extend(Self::resolve_selector(facts, selector));
            }
        }
        links.into_iter().collect()
    }

    /// Convert a link's exact revision targets into the current entry
    /// frontiers used by the graph. This changes only graph topology; opening
    /// the link still shows every exact set-valued target.
    fn graph_link_targets(wiki: DatasetView<'_>, revision: Id) -> Vec<Id> {
        let Some(order) = wiki.latest_index(metadata::supersedes.id()) else {
            return Vec::new();
        };
        let mut heads = BTreeSet::new();
        for target in Self::links(wiki.facts, wiki.reader, revision) {
            if let Some(entry) = crate::wiki::entry(wiki.facts, order, target) {
                heads.extend(entry.frontier.iter().map(|head| head.id));
            }
        }
        heads.into_iter().collect()
    }

    // ── file resolution ──────────────────────────────────────────────

    /// Resolve one `files:<selector>` directly against the maintained Files
    /// archive. Ambiguity is local to this explicit open action and never
    /// invalidates unrelated file rows.
    fn resolve_file(files: DatasetView<'_>, hex: &str) -> Result<(FileHandle, String), String> {
        let reference = crate::files::resolve_reference(files.facts, hex)
            .map_err(|error| format!("resolve files:{hex}: {error:#}"))?;
        let resolved = match reference {
            crate::files::FileReference::Entity(id) => {
                let candidates = find!(
                    (content: FileHandle, name: crate::files::NameHandle),
                    pattern!(files.facts, [{
                        id @ metadata::tag: &KIND_FILE,
                        file_attrs::content: ?content,
                        file_attrs::name: ?name,
                    }])
                )
                .collect::<BTreeSet<_>>();
                let contents = candidates
                    .iter()
                    .map(|(content, _)| *content)
                    .collect::<BTreeSet<_>>();
                let content = match contents.len() {
                    1 => *contents.first().expect("length checked"),
                    0 => return Err(format!("files entity {id:x} is not a readable file")),
                    count => {
                        return Err(format!(
                            "files entity {id:x} has {count} content projections"
                        ));
                    }
                };
                let names = candidates
                    .into_iter()
                    .filter(|(candidate, _)| *candidate == content)
                    .filter_map(|(_, handle)| {
                        let name: anybytes::View<str> = files.reader.get(handle).ok()?;
                        Some(name.to_string())
                    })
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                crate::files::ResolvedFile { content, names }
            }
            crate::files::FileReference::Content(content) => {
                let names = find!(
                    name: crate::files::NameHandle,
                    pattern!(files.facts, [{
                        _?file @ metadata::tag: &KIND_FILE,
                        file_attrs::content: &content,
                        file_attrs::name: ?name,
                    }])
                )
                .filter_map(|handle| {
                    let name: anybytes::View<str> = files.reader.get(handle).ok()?;
                    Some(name.to_string())
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
                crate::files::ResolvedFile { content, names }
            }
        };
        let name = resolved_file_name(&resolved);
        Ok((resolved.content, name))
    }

    /// Resolve `files:<selector>`, write the blob to `$TMPDIR/faculties-files/<name>`,
    /// and fire `open` on it. Logs errors to stderr rather than surfacing
    /// them through the UI (this is a best-effort side channel).
    fn open_file(files: Option<DatasetView<'_>>, hex: &str) {
        let Some(files) = files else {
            eprintln!("[files] no files dataset available");
            return;
        };
        let (handle, name) = match Self::resolve_file(files, hex) {
            Ok(resolved) => resolved,
            Err(error) => {
                eprintln!("[files] {error}");
                return;
            }
        };

        let result = (|| -> Result<std::path::PathBuf, String> {
            let blob: Blob<RawBytes> = files
                .reader
                .get(handle)
                .map_err(|e| format!("get blob: {e:?}"))?;
            let tmp_dir = std::env::temp_dir().join("faculties-files");
            std::fs::create_dir_all(&tmp_dir).map_err(|e| format!("mkdir: {e}"))?;
            let path = tmp_dir.join(&name);
            std::fs::write(&path, &*blob.bytes).map_err(|e| format!("write: {e}"))?;
            Ok(path)
        })();

        match result {
            Ok(path) => {
                eprintln!("[files] opening: {}", path.display());
                let _ = std::process::Command::new("open").arg(&path).spawn();
            }
            Err(e) => eprintln!("[files] error: {e}"),
        }
    }
}

// ── force-directed graph ──────────────────────────────────────────────

struct WikiGraph {
    nodes: Vec<GraphNode>,
    edges: Vec<(usize, usize)>,
    /// Positions, under the force law this file used to carry itself.
    ///
    /// The seam is narrow on purpose: the layout owns positions by index, and
    /// this widget owns everything else at the same index. There is no node
    /// payload on the other side of it, which is what lets the peer mesh and
    /// the collection lattice share the same solver without sharing a node
    /// type with the wiki.
    layout: KeyedLayout,
}

struct GraphNode {
    revision_id: Id,
    entry_key: Id,
    archived: bool,
    label: String,
}

impl WikiGraph {
    fn from_wiki(wiki: DatasetView<'_>) -> Self {
        let (nodes, edges) = Self::read(wiki);
        let keys = Self::keys(&nodes);
        let pairs = Self::pairs(&edges);
        let layout = KeyedLayout::new(keys, &pairs, LayoutParams::default());
        WikiGraph {
            nodes,
            edges,
            layout,
        }
    }

    /// Bring the graph up to date with a new dataset revision, carrying every
    /// node that survived.
    ///
    /// This replaces dropping the whole graph, which is what this viewer used
    /// to do: on any revision change it rebuilt from scratch, so every node was
    /// re-seeded on a fresh ring with zero velocity and the whole settle was
    /// paid again. One `wiki create` by anyone else working the same pile
    /// teleported the layout back to a circle. Now survivors keep position
    /// *and* velocity,
    /// and the new nodes arrive where their neighbours already are, heated —
    /// so a write nudges the picture where it landed instead of resetting it.
    fn refresh(&mut self, wiki: DatasetView<'_>) {
        let (nodes, edges) = Self::read(wiki);
        let keys = Self::keys(&nodes);
        let pairs = Self::pairs(&edges);
        self.layout.sync(&keys, &pairs);
        self.nodes = nodes;
        self.edges = edges;
    }

    fn keys(nodes: &[GraphNode]) -> Vec<u64> {
        nodes
            .iter()
            .map(|node| graph::key_of(node.revision_id.as_ref()))
            .collect()
    }

    fn pairs(edges: &[(usize, usize)]) -> Vec<(u32, u32)> {
        edges.iter().map(|&(a, b)| (a as u32, b as u32)).collect()
    }

    fn read(wiki: DatasetView<'_>) -> (Vec<GraphNode>, Vec<(usize, usize)>) {
        let heads = WikiLive::visible_heads(wiki);
        let mut revision_to_idx = BTreeMap::new();
        let mut nodes = Vec::new();

        for (i, head) in heads.iter().enumerate() {
            let title = WikiLive::title(wiki.facts, wiki.reader, head.revision_id);
            revision_to_idx.insert(head.revision_id, i);
            let mut label = if title.is_empty() {
                fmt_id(head.revision_id)
            } else {
                title
            };
            if head.fork_width > 1 {
                label.push_str(" [fork]");
            }
            if head.archived {
                label.push_str(" [archived]");
            }
            nodes.push(GraphNode {
                revision_id: head.revision_id,
                entry_key: head.entry_key,
                archived: head.archived,
                label,
            });
        }

        let mut seen = HashSet::new();
        let mut edges = Vec::new();
        let mut unresolved = 0usize;
        for head in &heads {
            let from = revision_to_idx[&head.revision_id];
            for target in WikiLive::graph_link_targets(wiki, head.revision_id) {
                if let Some(&to) = revision_to_idx.get(&target) {
                    if from != to && seen.insert((from, to)) {
                        edges.push((from, to));
                    }
                } else {
                    unresolved += 1;
                }
            }
        }
        if unresolved > 0 {
            eprintln!("[wiki] graph: {unresolved} link targets are outside the visible frontier");
        }

        (nodes, edges)
    }

    /// Advance the layout one step.
    ///
    /// The force law this calls is the one this file used to carry: it moved
    /// down into `GORBIE::graph` so the peer mesh and the collection lattice
    /// could use the same physics, and `LayoutParams::default()` is that law
    /// constant for constant.
    fn step(&mut self) -> GORBIE::graph::LayoutStats {
        self.layout.layout_mut().step()
    }

    fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn positions(&self) -> &[[f32; 2]] {
        self.layout.layout().positions()
    }

    /// Paint the force-directed graph. Returns both the clicked node
    /// (if any) and the viewport rect so callers can overlay
    /// additional widgets (search bar, etc.) inside it.
    fn show(
        &self,
        ui: &mut egui::Ui,
        search: &mut GORBIE::search::SearchSession,
    ) -> (Option<Id>, egui::Rect) {
        // Bounded viewport height. Inside the notebook's auto_shrink
        // ScrollArea `ui.available_height()` is f32::INFINITY, and
        // allocating a vec2(x, INF) rect here doesn't just swallow
        // clicks below — it advances the layout cursor to y=INFINITY,
        // so any widget rendered after the wiki section (compass,
        // messages, timeline, etc.) lands off-screen and the whole
        // notebook appears blank. Cap at a sane fixed max.
        const GRAPH_MAX_HEIGHT: f32 = 900.0;
        let available = ui.available_size();
        let h = available.y.max(400.0).min(GRAPH_MAX_HEIGHT);
        // egui's drag sense is z-aware (only the topmost widget under
        // the pointer claims the drag), so a float being dragged over
        // the graph viewport doesn't trigger a pan. Earlier 0.34
        // versions hit a `hit_test.rs:365` panic with click_and_drag
        // adjacent to clickers; the upstream fix in 0.34.x lets us
        // use the proper sense again.
        let (response, painter) =
            ui.allocate_painter(egui::vec2(available.x, h), egui::Sense::click_and_drag());
        let rect = response.rect;

        // Pan, zoom and the two hard-won details that make them work inside a
        // notebook's ScrollArea now live in `GORBIE::graph::viewport`, where
        // the mesh and the lattice get them too.
        let view_id = ui.id().with("wiki_graph_view");
        let mut view = GraphViewport::load(ui, view_id);
        view.interact(ui, &response, rect);
        // Frame the graph until the reader takes the framing over. This viewer
        // has never done it, and at its live size it opened entirely
        // off-screen: the old ring seed was 200 + 5n world units, which is
        // 17 110 at three thousand nodes against a visible half-width of 7 680
        // at the old zoom floor. The reader had to find the graph by dragging.
        const LABEL_MARGIN: f32 = 40.0;
        view.fit_unless_touched(rect, self.layout.layout().stats().bounds, LABEL_MARGIN);
        view.store(ui, view_id);
        let zoom = view.zoom();
        let positions = self.positions();
        let to_screen = |world: [f32; 2]| view.to_screen(rect, world);

        // The shared mark size, not a second copy of the constant. A mark is a
        // symbol rather than a measured object, so it holds its size instead of
        // shrinking to a speck when a large graph is framed or growing into a
        // plate when one node is.
        let node_radius = graph::MARK * view.mark_scale();
        let edge_color = ui.visuals().weak_text_color();
        let node_match_fill = GORBIE::themes::ral(1003);
        let needle_lower = search.query().to_lowercase();
        let node_stroke = ui.visuals().widgets.noninteractive.bg_stroke;
        let label_color = ui.visuals().text_color();
        let font_id = egui::TextStyle::Small.resolve(ui.style());

        let edge_stroke = egui::Stroke::new(0.5, edge_color);
        for &(a, b) in &self.edges {
            let p1 = to_screen(positions[a]);
            let p2 = to_screen(positions[b]);
            if !(rect.expand(50.0).contains(p1) || rect.expand(50.0).contains(p2)) {
                continue;
            }
            painter.line_segment([p1, p2], edge_stroke);
        }

        let mut clicked = None;
        let hover_pos = response.hover_pos();
        let show_labels = zoom > 0.3;
        // Slightly-translucent background behind each label so text
        // stays readable over crossing edges. Use a dark tint of the
        // panel fill; fall back to near-black when the theme is light.
        let panel_fill = ui.visuals().panel_fill;
        let label_bg = {
            let (r, g, b) = (panel_fill.r(), panel_fill.g(), panel_fill.b());
            egui::Color32::from_rgba_unmultiplied(r, g, b, 220)
        };
        for (index, node) in self.nodes.iter().enumerate() {
            // Search-active and the node's title matches? Report to
            // the search session BEFORE the visibility check, so
            // off-screen matches still bump the global `n / total`
            // counter. We use the revision id as the graph-node match id
            // match id to avoid colliding with text-level matches for
            // the same fragment (e.g. wiki:id in a meta row).
            let is_match =
                !needle_lower.is_empty() && node.label.to_lowercase().contains(&needle_lower);
            let _match_info = if is_match {
                let revision_bytes: &[u8] = node.revision_id.as_ref();
                let id = egui::Id::new(("wiki_graph_node", revision_bytes));
                Some(search.report(id))
            } else {
                None
            };

            let pos = to_screen(positions[index]);
            if !rect.expand(20.0).contains(pos) {
                continue;
            }

            // Scale node radius by degree: isolated nodes at the base
            // size, hub revisions grow logarithmically. Caps at 3×.
            // The degree comes from the layout's own adjacency rather than
            // from a second count kept here: the solver already builds it, and
            // two counts of the same edges are two chances to disagree.
            let deg_scale = (1.0 + self.layout.layout().degree(index).ln() * 0.4).min(3.0);
            let r = node_radius * deg_scale;
            // Matching nodes paint in RAL 1003 (signal yellow) — same
            // color GORBIE uses for word-level search underlines, so
            // the graph and the floats highlight in lock-step.
            let fill = if is_match {
                node_match_fill
            } else if node.archived {
                egui::Color32::from_rgb(0x66, 0x66, 0x66)
            } else {
                frag_color(node.entry_key)
            };
            // Drawn through the shared mark kit, so a wiki node, a peer and a
            // collection are the same vocabulary rather than three sketches of
            // it. The outline is a second call because the kit takes one
            // colour per mark; the result is the shape `painter.circle` drew.
            graph::draw_node(
                &painter,
                pos,
                r / graph::MARK,
                graph::Glyph::Circle,
                graph::Stroke2::Filled,
                fill,
                1,
            );
            painter.circle_stroke(pos, r, node_stroke);
            if show_labels {
                // Measure the label first so we know whether it fits
                // on the right. If painting to the right of the node
                // would clip past the viewport, flip to the left side
                // instead — keeps labels on-screen and reduces the
                // "labels all pile up at the right edge" look on
                // dense graphs.
                let galley =
                    painter.layout_no_wrap(node.label.clone(), font_id.clone(), label_color);
                let right_anchor = pos + egui::vec2(r + 4.0, 0.0);
                let right_rect = egui::Align2::LEFT_CENTER
                    .anchor_rect(egui::Rect::from_min_size(right_anchor, galley.size()));
                let label_rect = if right_rect.right() <= rect.right() - 2.0 {
                    right_rect
                } else {
                    // `Align2::RIGHT_CENTER.anchor_rect(rect)` already
                    // positions the result so its right-center sits at
                    // `rect.min`; passing `left_anchor` directly puts
                    // the label's right edge just left of the node.
                    let left_anchor = pos - egui::vec2(r + 4.0, 0.0);
                    egui::Align2::RIGHT_CENTER
                        .anchor_rect(egui::Rect::from_min_size(left_anchor, galley.size()))
                };
                painter.rect_filled(label_rect.expand2(egui::vec2(3.0, 1.0)), 2.0, label_bg);
                painter.galley(label_rect.min, galley, label_color);
            }

            if let Some(hp) = hover_pos {
                if (hp - pos).length() < r + 8.0 {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    if response.clicked() {
                        clicked = Some(node.revision_id);
                    }
                }
            }
        }

        // Top-right overlay: node/edge counts + interaction hint.
        // Matches the timeline viewport's SPAN + zoom-hint treatment
        // so the two big viewports share a visual idiom.
        {
            let meta_label = format!(
                "{} FRAGMENTS · {} LINKS",
                self.nodes.len(),
                self.edges.len()
            );
            let hint_label = "DRAG \u{2192} PAN · PINCH/\u{2318}+SCROLL \u{2192} ZOOM";
            let meta_font = egui::FontId::monospace(10.0);
            let hint_font = egui::FontId::monospace(9.0);
            let meta_color = egui::Color32::from_rgb(0xc8, 0xc8, 0xc8);
            let hint_color = egui::Color32::from_rgb(0x7a, 0x7a, 0x7a);
            let top = rect.top() + 6.0;
            let right = rect.right() - 8.0;
            let gap = 12.0;
            let hint_galley = painter.layout_no_wrap(hint_label.to_string(), hint_font, hint_color);
            let meta_galley = painter.layout_no_wrap(meta_label, meta_font, meta_color);
            let hint_pos = egui::pos2(right - hint_galley.size().x, top);
            painter.galley(hint_pos, hint_galley, hint_color);
            let meta_pos = egui::pos2(hint_pos.x - gap - meta_galley.size().x, top);
            painter.galley(meta_pos, meta_galley, meta_color);
        }

        (clicked, rect)
    }
}

// ── link interception ────────────────────────────────────────────────

/// A clicked URL in rendered Typst content that the viewer should
/// handle internally (rather than letting egui open it in a browser).
/// `pub(crate)` so sibling widgets can reuse the same
/// typst-render-and-intercept path instead of reimplementing it.
pub(crate) enum LinkClick {
    /// `wiki:<hex>` link — `Id` is a revision or a set-valued legacy fragment.
    Wiki(Id),
    /// `wiki:entry:<hex>` link — follow the selected entry to its complete
    /// current frontier without imposing a last-writer-wins head.
    WikiEntry(Id),
    /// `files:<selector>` link — `String` is the hex selector payload.
    File(String),
}

fn parse_wiki_link_target(target: &str) -> Option<(Id, bool)> {
    let (kind, hex) = target
        .rsplit_once(':')
        .map_or((None, target), |(kind, hex)| (Some(kind), hex));
    let id = Id::from_hex(hex)?;
    Some((
        id,
        kind.is_some_and(|kind| kind.eq_ignore_ascii_case("entry")),
    ))
}

/// Render typst `content` into `ctx` and intercept any `wiki:` / `files:`
/// URL open commands it emitted. Returns the last click seen (or `None`).
///
/// Egui emits link clicks as `OutputCommand::OpenUrl` entries on its
/// output queue; we peek at the commands added during `ctx.typst(…)`,
/// keep the non-matching ones (so e.g. `https:` links still open the
/// browser), and pull out the `wiki:` / `files:` ones as `LinkClick`s.
pub(crate) fn render_wiki_content(ctx: &mut CardCtx<'_>, content: &str) -> Option<LinkClick> {
    let cmd_count_before = ctx.ctx().output(|o| o.commands.len());
    ctx.typst(content);

    let mut clicked = None;
    ctx.ctx().output_mut(|o| {
        let new_commands: Vec<egui::OutputCommand> =
            o.commands.drain(cmd_count_before..).collect();
        for cmd in new_commands {
            match &cmd {
                egui::OutputCommand::OpenUrl(open_url) => {
                    if let Some(target) = open_url.url.strip_prefix("wiki:") {
                        if let Some((id, follow_entry)) = parse_wiki_link_target(target) {
                            clicked = Some(if follow_entry {
                                LinkClick::WikiEntry(id)
                            } else {
                                // Other qualifiers describe the edge (for
                                // example `reviews`) but retain exact target
                                // semantics.
                                LinkClick::Wiki(id)
                            });
                        } else {
                            eprintln!(
                                "[wiki] link click: wiki:{target} ({} target chars) → failed to parse as Id (expected 32 hex chars)",
                                target.len()
                            );
                        }
                    } else if let Some(hex) = open_url.url.strip_prefix("files:") {
                        clicked = Some(LinkClick::File(hex.to_string()));
                    } else {
                        o.commands.push(cmd);
                    }
                }
                _ => o.commands.push(cmd),
            }
        }
    });
    clicked
}

// ── browser state (absorbed into WikiViewer) ─────────────────────────

/// An open canonical Wiki revision.
struct OpenPage {
    revision_id: Id,
}

fn render_diagnostic(ui: &mut egui::Ui, message: &str) {
    let color = egui::Color32::from_rgb(0xcc, 0x0a, 0x17);
    egui::Frame::NONE
        .stroke(egui::Stroke::new(1.0, color))
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("INVALID WIKI SNAPSHOT · {message}"))
                    .monospace()
                    .small()
                    .strong()
                    .color(color),
            );
        });
}

// ── widget ───────────────────────────────────────────────────────────

/// GORBIE-embeddable wiki viewer.
///
/// Holds pure UI state plus a cached query snapshot. The wiki dataset
/// (and optionally a files dataset, for `files:` link resolution) are
/// passed in at render time; the viewer refreshes its cached fact space
/// whenever either dataset revision advances.
///
/// ```ignore
/// let mut viewer = WikiViewer::default();
/// // Inside a GORBIE card, with `wiki_view` and optional `files_view`:
/// viewer.render(ctx, wiki_view, files_view);
/// ```
#[derive(Default)]
pub struct WikiViewer {
    search_query: String,
    /// Last search miss (for the "no match" chip). Cleared whenever
    /// the query text is edited.
    search_miss: Option<String>,
    /// Rebuilt when the wiki or files dataset revision changes.
    live: Option<WikiLive>,
    /// Missing maintained indexes are rendered instead of panicking.
    error: Option<((DatasetRevision, Option<DatasetRevision>), String)>,
    /// Lazily-initialized once `live` is populated (needs queries to
    /// build). Dropped whenever `live` is rebuilt.
    graph: Option<WikiGraph>,
    open_pages: Vec<OpenPage>,
}

impl WikiViewer {
    /// Build a viewer with no cached state. State will be populated on
    /// the first `render` call.
    pub fn new() -> Self {
        Self::default()
    }

    /// Render the viewer into a GORBIE card context. `wiki_view` is the
    /// wiki dataset; `files_view` is optional — when provided, the
    /// viewer will resolve `files:<selector>` links and open the resulting
    /// blobs via the platform `open` command.
    pub fn render(
        &mut self,
        ctx: &mut CardCtx<'_>,
        wiki_view: DatasetView<'_>,
        files_view: Option<DatasetView<'_>>,
    ) {
        let wiki_reader = wiki_view.reader;
        ctx.section("Wiki", |ctx| {
        // Refresh cached spaces if either revision changed since the last frame.
        let wiki_revision = wiki_view.revision;
        let files_revision = files_view.map(|view| view.revision);
        let need_refresh = match self.live.as_ref() {
            None => self
                .error
                .as_ref()
                .is_none_or(|(revisions, _)| *revisions != (wiki_revision, files_revision)),
            Some(l) => {
                l.cached_revision != wiki_revision
                    || l.files_cached_revision != files_revision
            }
        };
        if need_refresh {
            match WikiLive::refresh(wiki_view, files_view) {
                Ok(live) => {
                    self.live = Some(live);
                    self.error = None;
                }
                Err(error) => {
                    self.live = None;
                    self.error = Some(((wiki_revision, files_revision), error));
                }
            }
            // A failed refresh has no dataset to read, so the graph goes; a
            // successful one keeps it and retargets below.
            if self.error.is_some() {
                self.graph = None;
            }
        }

        if let Some((_, error)) = self.error.as_ref() {
            render_diagnostic(ctx.ui_mut(), error);
            return;
        }

        if self.live.is_none() {
            return;
        }

        // Search-bar UI is overlaid inside the graph viewport —
        // rendered after graph.show below using the viewport rect.
        let mut submit_query: Option<String> = None;

        // ── force-directed graph ─────────────────────────────────────
        match self.graph.as_mut() {
            None => self.graph = Some(WikiGraph::from_wiki(wiki_view)),
            Some(graph) if need_refresh => graph.refresh(wiki_view),
            Some(_) => {}
        }
        // Empty state when the Wiki collection has no live entries —
        // otherwise the graph is a blank canvas.
        let graph_is_empty = self
            .graph
            .as_ref()
            .map(|g| g.node_count() == 0)
            .unwrap_or(true);
        if graph_is_empty {
            let ui = ctx.ui_mut();
            ui.add_space(16.0);
            ui.vertical_centered(|ui| {
                let muted = egui::Color32::from_rgb(0x8a, 0x8a, 0x8a);
                ui.label(egui::RichText::new("\u{1f4d6}").size(28.0).color(muted));
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new("No live entries in this Wiki collection")
                        .monospace()
                        .small()
                        .strong()
                        .color(muted),
                );
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(
                        "Create one via `wiki create` and reopen the pile.",
                    )
                    .small()
                    .color(muted),
                );
            });
            ui.add_space(16.0);
        }
        if let Some(graph) = self.graph.as_mut() {
            if graph.node_count() == 0 {
                return;
            }
            // Advance the force layout every frame. The meta info is
            // overlaid inside the viewport itself — see WikiGraph::show.
            let stats = graph.step();
            // Graph is rendered OUTSIDE the grid so it uses the full
            // section width without the grid cell's edge padding —
            // visually the force-directed view becomes edge-to-edge
            // like the timeline viewport.
            let mut search = ctx.search();
            let (clicked_node, graph_rect) =
                graph.show(ctx.ui_mut(), &mut search);
            if let Some(revision_id) = clicked_node {
                if !self
                    .open_pages
                    .iter()
                    .any(|page| page.revision_id == revision_id)
                {
                    self.open_pages.push(OpenPage { revision_id });
                }
            }
            // Repaint only while something is moving. This ran unconditionally
            // every frame, so a settled graph burned a core at display rate
            // forever; `quiet` is a repaint gate and deliberately not a claim
            // that the layout converged.
            if !stats.quiet {
                ctx.ctx().request_repaint();
            }

            // ── Search-bar overlay in the top-left of the graph.
            // No FIND label — the empty field's hint_text and the
            // sibling GO button make intent clear enough. Uses
            // scope_builder with an explicit max_rect so interactive
            // widgets land on top of the painted graph (later-added
            // widgets win egui's hit-test). Top offset uses GORBIE's
            // GRID_ROW_MODULE so the bar aligns with the rest of the
            // notebook's vertical rhythm.
            {
                let module = GORBIE::card_ctx::GRID_ROW_MODULE;
                let bar_top = graph_rect.top() + module;
                let bar_left = graph_rect.left() + module;
                let bar_width = (graph_rect.width() * 0.5).clamp(240.0, 420.0);
                let bar_height = 3.0 * module;
                let bar_rect = egui::Rect::from_min_size(
                    egui::pos2(bar_left, bar_top),
                    egui::vec2(bar_width, bar_height),
                );
                let ui = ctx.ui_mut();
                ui.scope_builder(
                    egui::UiBuilder::new().max_rect(bar_rect),
                    |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 6.0;
                            let go_enabled =
                                !self.search_query.trim().is_empty();
                            // Place GO on the right; field fills
                            // whatever's left.
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .add_enabled(
                                            go_enabled,
                                            GORBIE::widgets::Button::new("GO"),
                                        )
                                        .on_hover_text(
                                            "Open revision/legacy selector by hex prefix or title (Enter)",
                                        )
                                        .clicked()
                                    {
                                        submit_query = Some(
                                            self.search_query.trim().to_string(),
                                        );
                                    }
                                    ui.with_layout(
                                        egui::Layout::left_to_right(
                                            egui::Align::Center,
                                        ),
                                        |ui| {
                                            // GORBIE LCD-style field;
                                            // auto-sizes to the
                                            // available width. No
                                            // hint_text (GORBIE's
                                            // field doesn't support
                                            // one) — the GO button
                                            // next to it signals
                                            // intent.
                                            let resp = ui.add(
                                                GORBIE::widgets::TextField::singleline(
                                                    &mut self.search_query,
                                                ),
                                            );
                                            if resp.changed() {
                                                self.search_miss = None;
                                            }
                                            if resp.lost_focus()
                                                && ui.input(|i| {
                                                    i.key_pressed(egui::Key::Enter)
                                                })
                                                && !self
                                                    .search_query
                                                    .trim()
                                                    .is_empty()
                                            {
                                                submit_query = Some(
                                                    self.search_query
                                                        .trim()
                                                        .to_string(),
                                                );
                                            }
                                        },
                                    );
                                },
                            );
                        });
                    },
                );
            }
        }

        // Search-submit handling (the overlay above populates
        // `submit_query` on GO click or Enter). Resolves hex prefixes
        // against canonical selectors or falls back to title-substring
        // search; opens every matching fork/legacy-selector target, shows a
        // "No match" banner under the viewport on miss.
        if let Some(q) = submit_query {
            let is_hex = !q.is_empty() && q.chars().all(|c| c.is_ascii_hexdigit());
            let mut found = if is_hex {
                WikiLive::resolve_prefix(wiki_view.facts, &q).unwrap_or_default()
            } else {
                let q_lower = q.to_lowercase();
                WikiLive::visible_heads(wiki_view)
                    .into_iter()
                    .filter(|head| {
                        WikiLive::title(wiki_view.facts, wiki_reader, head.revision_id)
                            .to_lowercase()
                            .contains(&q_lower)
                    })
                    .map(|head| head.revision_id)
                    .collect()
            };
            found.sort_unstable();
            found.dedup();
            if !found.is_empty() {
                for revision_id in found {
                    self.open_pages
                        .retain(|page| page.revision_id != revision_id);
                    self.open_pages.push(OpenPage { revision_id });
                }
                self.search_query.clear();
                self.search_miss = None;
            } else {
                self.search_miss = Some(q);
            }
        }

        // Search miss banner — muted warn style, auto-dismisses on
        // the user's next edit or successful search.
        if let Some(miss) = self.search_miss.clone() {
            let ui = ctx.ui_mut();
            let warn_fg = egui::Color32::from_rgb(0xf7, 0xba, 0x0b);
            egui::Frame::NONE
                .stroke(egui::Stroke::new(1.0, warn_fg))
                .corner_radius(egui::CornerRadius::same(3))
                .inner_margin(egui::Margin::symmetric(8, 3))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;
                        ui.label(
                            egui::RichText::new("\u{26a0}").small().color(warn_fg),
                        );
                        ui.label(
                            egui::RichText::new(format!(
                                "No match for \"{miss}\""
                            ))
                            .monospace()
                            .small()
                            .color(warn_fg),
                        );
                    });
                });
        }

        // ── floating wiki page cards ─────────────────────────────────
        let open_snapshot: Vec<Id> = self
            .open_pages
            .iter()
            .map(|page| page.revision_id)
            .collect();
        let mut to_close: Vec<Id> = Vec::new();
        let mut to_open_from_link: Vec<(Id, bool)> = Vec::new();
        let mut to_open_file: Vec<String> = Vec::new();

        for revision_id in open_snapshot {
            let revision_bytes: &[u8] = revision_id.as_ref();
            let mut revision_key = [0u8; 16];
            revision_key.copy_from_slice(revision_bytes);

            let revision = WikiLive::revision(wiki_view.facts, revision_id);
            let entry = revision.as_ref().and_then(|_| {
                wiki_view
                    .latest_index(metadata::supersedes.id())
                    .and_then(|order| crate::wiki::entry(wiki_view.facts, order, revision_id))
            });
            let title = WikiLive::title(wiki_view.facts, wiki_reader, revision_id);
            let content = WikiLive::content(wiki_view.facts, wiki_reader, revision_id);
            let entry_key = entry
                .as_ref()
                .and_then(WikiLive::entry_key)
                .unwrap_or(revision_id);
            let color = frag_color(entry_key);
            let frontier_position = entry.as_ref().and_then(|entry| {
                entry
                    .frontier
                    .iter()
                    .position(|head| head.id == revision_id)
            });
            let state_label = match (entry.as_ref(), frontier_position) {
                (Some(entry), Some(index)) if entry.frontier.len() > 1 => {
                    format!("FORK HEAD {}/{}", index + 1, entry.frontier.len())
                }
                (Some(_), Some(_)) => "HEAD".to_owned(),
                (Some(_), None) => "HISTORICAL".to_owned(),
                (None, _) => "MISSING".to_owned(),
            };
            let archived = revision
                .as_ref()
                .is_some_and(|row| row.tags.contains(&TAG_ARCHIVED_ID));

            ctx.push_id(revision_key, |ctx| {
                let resp = ctx.float(|ctx| {
                    ctx.grid(|g| {
                        if revision.is_none() {
                            g.full(|ctx| {
                                ctx.add(
                                    egui::Label::new(
                                        egui::RichText::new("Link target not found").heading(),
                                    )
                                    .wrap(),
                                );
                            });
                            g.full(|ctx| {
                                ctx.label(
                                    egui::RichText::new(format!("wiki:{revision_id:x}"))
                                        .monospace()
                                        .small()
                                        .color(color),
                                );
                            });
                            g.full(|ctx| { ctx.separator(); });
                            g.full(|ctx| {
                                ctx.label(
                                    "This link points to an ID that doesn't exist in the wiki. \
                                     The target may have been deleted, or the link may contain a typo.",
                                );
                            });
                            return;
                        }

                        // Heading row: identity-colored dot swatch + title.
                        g.full(|ctx| {
                            ctx.ui_mut().horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 8.0;
                                let (dot_rect, _) = ui.allocate_exact_size(
                                    egui::vec2(10.0, 10.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().circle_filled(
                                    dot_rect.center(),
                                    5.0,
                                    color,
                                );
                                ui.add(
                                    egui::Label::new(egui::RichText::new(&title).heading())
                                        .wrap(),
                                );
                            });
                        });

                        // A revision DAG has no honest scalar "latest" or
                        // prev/next order. Show the exact revision and its
                        // causal/frontier role instead of reintroducing a
                        // timestamp winner through navigation chrome.
                        g.place(8, |ctx| {
                            ctx.label(
                                egui::RichText::new(format!("wiki:{revision_id:x}"))
                                    .monospace()
                                    .small()
                                    .color(color),
                            );
                        });
                        g.place(4, |ctx| {
                            ctx.ui_mut().with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    let mut label = state_label.clone();
                                    if archived {
                                        label.push_str(" · ARCHIVED");
                                    }
                                    ui.label(
                                        egui::RichText::new(label)
                                            .monospace()
                                            .small()
                                            .strong(),
                                    );
                                },
                            );
                        });

                        g.full(|ctx| { ctx.separator(); });

                        g.full(|ctx| {
                            match render_wiki_content(ctx, &content) {
                                Some(LinkClick::Wiki(id)) => {
                                    to_open_from_link.push((id, false))
                                }
                                Some(LinkClick::WikiEntry(id)) => {
                                    to_open_from_link.push((id, true))
                                }
                                Some(LinkClick::File(hex)) => to_open_file.push(hex),
                                None => {}
                            }
                        });
                    });
                });
                if resp.closed {
                    to_close.push(revision_id);
                }
            });
        }

        for id in to_close {
            self.open_pages.retain(|page| page.revision_id != id);
        }
        for (selector, follow_entry) in to_open_from_link {
            let mut revisions = if follow_entry {
                WikiLive::resolve_entry_selector(wiki_view, selector)
            } else {
                WikiLive::resolve_selector(wiki_view.facts, selector)
            };
            if revisions.is_empty() {
                revisions.push(selector);
            }
            for revision_id in revisions {
                // Move to top if already open, otherwise open new. A
                // set-valued legacy fragment therefore opens every head.
                self.open_pages
                    .retain(|page| page.revision_id != revision_id);
                self.open_pages.push(OpenPage { revision_id });
            }
        }
        for hex in to_open_file {
            WikiLive::open_file(files_view, &hex);
        }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::schemas::wiki::{attrs, KIND_VERSION_ID};
    use crate::wiki::{self, RevisionDraft};
    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::metadata;
    use triblespace::macros::{find, pattern};
    use triblespace::prelude::*;

    fn at(seconds: f64) -> wiki::IntervalValue {
        let instant = Epoch::from_tai_seconds(seconds);
        (instant, instant).try_to_inline().unwrap()
    }

    fn revision(
        output: &mut Fragment,
        author: Id,
        title: &str,
        tags: &[Id],
        parents: &[Id],
        seconds: f64,
    ) -> Id {
        let (fragment, revision) = wiki::revision_record(RevisionDraft {
            title: title.to_owned(),
            content: format!("content for {title}"),
            tags: tags.iter().copied().collect(),
            predecessors: parents.iter().copied().collect(),
            author,
            authored_at: at(seconds),
        })
        .unwrap();
        *output += fragment;
        revision
    }

    #[test]
    fn canonical_projection_keeps_every_fork_head_visible() {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let (mut fragment, author) = wiki::author_record(&signer.verifying_key());

        let base = revision(&mut fragment, author, "base", &[], &[], 1.0);
        let left = revision(&mut fragment, author, "left", &[], &[base], 2.0);
        let right = revision(&mut fragment, author, "right", &[], &[base], 3.0);
        let independent = revision(&mut fragment, author, "independent", &[], &[], 4.0);
        let archived_root = revision(&mut fragment, author, "archived root", &[], &[], 5.0);
        let live = revision(&mut fragment, author, "live", &[], &[archived_root], 6.0);
        let archived = revision(
            &mut fragment,
            author,
            "archived",
            &[TAG_ARCHIVED_ID],
            &[archived_root],
            7.0,
        );

        let derived = triblespace::core::collection::latest::derive_element(
            &fragment.facts().clone().to_blob(),
            metadata::supersedes.id(),
        )
        .unwrap();
        let order = triblespace::core::collection::latest::LatestIndex::decode(&derived).unwrap();
        let projected = WikiLive::projected_heads(fragment.facts(), &order);
        let by_revision: BTreeMap<_, _> = projected
            .iter()
            .map(|head| (head.revision_id, *head))
            .collect();

        assert_eq!(projected.len(), 5);
        assert_eq!(
            projected
                .iter()
                .map(|head| head.entry_key)
                .collect::<BTreeSet<_>>()
                .len(),
            3,
            "independent roots remain distinct entries"
        );
        assert_eq!(by_revision[&left].fork_width, 2);
        assert_eq!(by_revision[&right].fork_width, 2);
        assert_eq!(by_revision[&live].fork_width, 2);
        assert_eq!(by_revision[&archived].fork_width, 2);
        assert!(by_revision[&archived].archived);
        assert!(!by_revision[&live].archived);
        assert!(by_revision.contains_key(&independent));
        assert_eq!(
            WikiLive::resolve_selector(fragment.facts(), left),
            vec![left],
            "an intrinsic revision selector stays exact"
        );

        assert_eq!(
            WikiLive::resolve_entry_selector_with_order(fragment.facts(), &order, base),
            vec![left, right],
            "an entry-qualified root selector follows the complete frontier"
        );
    }

    #[test]
    fn typed_wiki_links_distinguish_live_entries_from_exact_edges() {
        let id = Id::new([0xab; 16]).unwrap();
        let hex = format!("{id:x}");
        assert_eq!(parse_wiki_link_target(&hex), Some((id, false)));
        assert_eq!(
            parse_wiki_link_target(&format!("reviews:{hex}")),
            Some((id, false)),
            "ordinary typed edges still cite an exact revision"
        );
        assert_eq!(
            parse_wiki_link_target(&format!("entry:{hex}")),
            Some((id, true)),
            "entry is the one explicit follow-frontier link kind"
        );
    }

    /// A legacy anchor id names nothing. Its facts stay in the store — the
    /// fixture writes them — but the viewer resolves revisions only, so an
    /// anchor click opens no pane instead of silently opening today's text.
    #[test]
    fn a_legacy_anchor_selector_resolves_to_nothing() {
        let fragment_id = Id::new([0xa1; 16]).unwrap();
        let first = Id::new([0xb1; 16]).unwrap();
        let second = Id::new([0xb2; 16]).unwrap();
        let mut fragment = Fragment::empty();
        let title = fragment.put::<UTF8String, _>("legacy title".to_owned());
        let content = fragment.put::<UTF8String, _>("legacy content".to_owned());
        fragment += entity! { ExclusiveId::force_ref(&first) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: fragment_id,
            attrs::title: title,
            attrs::content: content,
            metadata::created_at: at(1.0),
        };
        fragment += entity! { ExclusiveId::force_ref(&second) @
            metadata::tag: &KIND_VERSION_ID,
            attrs::fragment: fragment_id,
            attrs::title: title,
            attrs::content: content,
            metadata::created_at: at(2.0),
        };

        assert_eq!(
            WikiLive::resolve_selector(fragment.facts(), first),
            vec![first],
            "a revision id still resolves to itself"
        );
        assert_eq!(
            WikiLive::resolve_selector(fragment.facts(), second),
            vec![second]
        );
        assert!(
            WikiLive::resolve_selector(fragment.facts(), fragment_id).is_empty(),
            "an anchor id resolves to nothing"
        );
    }

    #[test]
    fn shared_file_bytes_use_the_digest_instead_of_a_name_winner() {
        let first = crate::files::stage(b"shared".to_vec(), "alpha.txt", "text/plain").unwrap();
        let content = find!(
            value: crate::files::ContentHandle,
            pattern!(&first, [{ _?file @ file_attrs::content: ?value }])
        )
        .next()
        .unwrap();
        let second = crate::files::stage(b"shared".to_vec(), "beta.txt", "text/plain").unwrap();
        let mut fragment = first;
        fragment += second;
        let mut blobs = fragment.blobs().clone();
        let reader = blobs.snapshot().unwrap();
        let catalog = crate::files::load_catalog(&reader, fragment.facts()).unwrap();
        let resolved = catalog
            .resolve_file(&crate::files::content_hash_hex(content))
            .unwrap();

        assert_eq!(resolved.names, ["alpha.txt", "beta.txt"]);
        assert_eq!(
            resolved_file_name(&resolved),
            crate::files::content_hash_hex(content)
        );
    }
}
