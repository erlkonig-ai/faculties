//! Full-featured GORBIE-embeddable wiki viewer.
//!
//! Renders the canonical Wiki revision collection from a triblespace pile. The widget holds only
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
//!   derived from immutable content (GPU,
//!   with optional FDEB edge bundling)
//! - Floating wiki-page cards that open when the user clicks a node, a
//!   `wiki:<hex>` link in typst content, or a file entry
//! - Fork-visible revision cards without inventing a scalar latest state
//! - `files:` link handling — resolves the shared file selector language to a
//!   file blob (against the optional files dataset),
//!   writes it to `$TMPDIR/faculties-files/`, and opens it via the platform
//!   `open` command.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use cubecl::prelude::*;
use cubecl::wgpu::{WgpuDevice, WgpuRuntime};
use triblespace::core::blob::Blob;
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::Inline;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::blobencodings::{LongString, RawBytes};
use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;

use crate::schemas::wiki::{extract_link_targets, TAG_ARCHIVED_ID};
use crate::widgets::storage::{DatasetRevision, DatasetView};
use crate::wiki::{EntryRecord, RevisionRecord, WikiCatalog};

/// Handle to a long-string blob living in a pile.
type TextHandle = Inline<Handle<LongString>>;

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

/// Cached canonical Wiki projection + file facts and revision markers.
/// Rebuilt when either input dataset changes.
struct WikiLive {
    catalog: WikiCatalog,
    files_catalog: Option<crate::files::FilesCatalog>,
    cached_revision: DatasetRevision,
    files_cached_revision: Option<DatasetRevision>,
}

impl WikiLive {
    /// Refresh cached fact spaces from the provided immutable dataset views.
    fn refresh(wiki: DatasetView<'_>, files: Option<DatasetView<'_>>) -> Result<Self, String> {
        let (files_catalog, files_cached_revision) = match files {
            Some(files) => {
                let catalog = crate::files::load_catalog(files.reader, files.facts)
                    .map_err(|error| format!("validate Files collection for Wiki: {error:#}"))?;
                (Some(catalog), Some(files.revision))
            }
            None => (None, None),
        };

        Ok(WikiLive {
            // Storage normally admits this exact snapshot first, but the
            // widget remains a safe embedding boundary on its own: structural
            // corruption and missing text blobs become visible diagnostics.
            catalog: crate::wiki::validate_catalog(wiki.reader, wiki.facts)
                .map_err(|error| format!("validate Wiki collection: {error:#}"))?,
            files_catalog,
            cached_revision: wiki.revision,
            files_cached_revision,
        })
    }

    fn text(&self, reader: &PileReader, h: TextHandle) -> String {
        crate::wiki::read_text(reader, h).unwrap_or_default()
    }

    // ── canonical revision/entry projection ──────────────────────────

    fn entry_key(entry: &EntryRecord) -> Id {
        *entry
            .legacy_fragments
            .first()
            .or_else(|| entry.roots.first())
            .expect("validated Wiki entries always have a selector")
    }

    fn revision(&self, revision: Id) -> Option<&RevisionRecord> {
        self.catalog.revisions.revision(revision)
    }

    fn title(&self, wiki_reader: &PileReader, revision: Id) -> String {
        self.revision(revision)
            .map(|row| self.text(wiki_reader, row.title))
            .unwrap_or_default()
    }

    fn content(&self, wiki_reader: &PileReader, revision: Id) -> String {
        self.revision(revision)
            .map(|row| self.text(wiki_reader, row.content))
            .unwrap_or_default()
    }

    /// Complete frontiers of every entry which has at least one live head.
    ///
    /// An archived/live fork keeps both heads visible: hiding the archived
    /// side would falsely present a resolved state. Entries whose complete
    /// frontier is archived are absent from the default graph.
    fn projected_heads(catalog: &WikiCatalog) -> Vec<VisibleHead> {
        let mut heads = Vec::new();
        for entry in catalog.revisions.list_entries() {
            let entry_key = Self::entry_key(&entry);
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

    fn visible_heads(&self, wiki_reader: &PileReader) -> Vec<VisibleHead> {
        let mut heads = Self::projected_heads(&self.catalog);
        heads.sort_by(|left, right| {
            self.title(wiki_reader, left.revision_id)
                .to_lowercase()
                .cmp(&self.title(wiki_reader, right.revision_id).to_lowercase())
                .then_with(|| left.entry_key.cmp(&right.entry_key))
                .then_with(|| left.revision_id.cmp(&right.revision_id))
        });
        heads
    }

    fn all_selectors(&self) -> BTreeSet<Id> {
        self.catalog
            .revisions
            .revision_records()
            .map(|revision| revision.id)
            .chain(
                self.catalog
                    .revisions
                    .all_entries()
                    .into_iter()
                    .flat_map(|entry| entry.legacy_fragments),
            )
            .collect()
    }

    /// Resolve one full selector without collapsing its legitimate frontier.
    fn resolve_catalog_selector(catalog: &WikiCatalog, selector: Id) -> Vec<Id> {
        if catalog.revisions.revision(selector).is_some() {
            vec![selector]
        } else if let Some(revisions) = catalog.revisions.legacy_fragment_frontier(selector) {
            revisions.to_vec()
        } else {
            Vec::new()
        }
    }

    fn resolve_selector(&self, selector: Id) -> Vec<Id> {
        Self::resolve_catalog_selector(&self.catalog, selector)
    }

    /// Resolve a selector as a live entry reference. Unlike an immutable
    /// revision link, this deliberately follows the selected revision's
    /// connected component to its complete current frontier.
    fn resolve_catalog_entry_selector(catalog: &WikiCatalog, selector: Id) -> Vec<Id> {
        let mut heads = BTreeSet::new();
        for revision in Self::resolve_catalog_selector(catalog, selector) {
            if let Some(entry) = catalog.revisions.entry_containing(revision) {
                heads.extend(entry.frontier.iter().map(|head| head.id));
            }
        }
        heads.into_iter().collect()
    }

    fn resolve_entry_selector(&self, selector: Id) -> Vec<Id> {
        Self::resolve_catalog_entry_selector(&self.catalog, selector)
    }

    /// Resolve a hex prefix to the set-valued result of its unique selector.
    /// No timestamp, fact order, or lowest-id winner resolves ambiguity.
    fn resolve_prefix(&self, prefix: &str) -> Option<Vec<Id>> {
        let needle = prefix.trim().to_lowercase();
        if needle.is_empty()
            || needle.len() > 32
            || !needle.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        let mut matches = self
            .all_selectors()
            .into_iter()
            .filter(|id| format!("{id:x}").starts_with(&needle));
        let selector = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        let resolved = self.resolve_selector(selector);
        (!resolved.is_empty()).then_some(resolved)
    }

    /// Resolve links parsed from immutable revision content.
    fn links(&self, wiki_reader: &PileReader, revision: Id) -> Vec<Id> {
        let mut links = BTreeSet::new();
        for raw in extract_link_targets(&self.content(wiki_reader, revision)) {
            if let Some(selector) = Id::from_hex(&raw) {
                links.extend(self.resolve_selector(selector));
            }
        }
        links.into_iter().collect()
    }

    /// Convert a link's exact revision targets into the current entry
    /// frontiers used by the graph. This changes only graph topology; opening
    /// the link still shows every exact set-valued target.
    fn graph_link_targets(&self, wiki_reader: &PileReader, revision: Id) -> Vec<Id> {
        let mut heads = BTreeSet::new();
        for target in self.links(wiki_reader, revision) {
            if let Some(entry) = self.catalog.revisions.entry_containing(target) {
                heads.extend(entry.frontier.iter().map(|head| head.id));
            }
        }
        heads.into_iter().collect()
    }

    // ── file resolution ──────────────────────────────────────────────

    /// Resolve a `files:<selector>` URL fragment through the canonical file
    /// selector semantics. Shared bytes keep every filename variant in the
    /// catalog; when there is no unique name, the content digest itself is the
    /// neutral output name.
    fn resolve_file(&self, hex: &str) -> Result<(FileHandle, String), String> {
        let catalog = self
            .files_catalog
            .as_ref()
            .ok_or_else(|| "no Files dataset available".to_owned())?;
        let resolved = catalog
            .resolve_file(hex)
            .map_err(|error| format!("resolve files:{hex}: {error:#}"))?;
        let name = resolved_file_name(&resolved);
        Ok((resolved.content, name))
    }

    /// Resolve `files:<selector>`, write the blob to `$TMPDIR/faculties-files/<name>`,
    /// and fire `open` on it. Logs errors to stderr rather than surfacing
    /// them through the UI (this is a best-effort side channel).
    fn open_file(&self, files_reader: Option<&PileReader>, hex: &str) {
        let Some(reader) = files_reader else {
            eprintln!("[files] no files dataset available");
            return;
        };
        let (handle, name) = match self.resolve_file(hex) {
            Ok(resolved) => resolved,
            Err(error) => {
                eprintln!("[files] {error}");
                return;
            }
        };

        let result = (|| -> Result<std::path::PathBuf, String> {
            let blob: Blob<RawBytes> =
                reader.get(handle).map_err(|e| format!("get blob: {e:?}"))?;
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

// ── GPU force-directed layout kernel ──────────────────────────────────

#[cube(launch)]
fn force_step_kernel(
    pos: &Array<f32>,
    vel: &mut Array<f32>,
    edges: &Array<u32>,
    // Per-node degree (1.0 + incident edge count), used for the
    // SYMMETRIC attraction weight below. Precomputed on the CPU so
    // the kernel can look up the *other* endpoint's degree, not just
    // its own.
    degrees: &Array<f32>,
    node_count: u32,
    edge_count: u32,
    pos_out: &mut Array<f32>,
) {
    let i = ABSOLUTE_POS as u32;
    if i < node_count {
        // Calmer layout. `damping` is a velocity *retention* factor
        // applied every step — at 0.75 a node kept 75% of its
        // momentum, so attract/repel pairs orbited each other forever
        // (the energy sink was too weak to ever let them settle).
        // 0.45 bleeds momentum off fast, so orbital motion decays into
        // a resting layout. This is the only lever that drains the
        // *pairwise* orbital energy — the global anti-rotation pass
        // only removes the whole cloud's average spin, not relative
        // orbits between node pairs.
        // `attraction` is the spring constant: 0.3 → 0.15 makes edges
        // softer (less stiff), so connected nodes ease together rather
        // than snapping taut and overshooting. `max_force` caps the
        // per-step impulse — halved so a big push moves gently.
        // Repulsion eased so the initial expansion is less explosive.
        let repulsion = 140000.0f32;
        let attraction = 0.15f32;
        let damping = 0.45f32;
        let max_force = 15.0f32;
        let gravity = 0.001f32;

        let ix = (i * 2) as usize;
        let iy = ix + 1;
        let px = pos[ix];
        let py = pos[iy];

        let mut fx = f32::new(0.0);
        let mut fy = f32::new(0.0);

        for j in 0..node_count {
            if j != i {
                let jx = (j * 2) as usize;
                let dx = px - pos[jx];
                let dy = py - pos[jx + 1];
                let dist_sq = (dx * dx + dy * dy).max(1.0f32);
                let dist = dist_sq.sqrt().max(0.001f32);
                let f = repulsion / dist_sq;
                fx += (dx / dist) * f;
                fy += (dy / dist) * f;
            }
        }

        // Attraction with a SYMMETRIC degree weight. The old code
        // scaled each endpoint's pull by 1/degree(self), so a hub
        // linked to a leaf pulled the leaf hard (small leaf degree)
        // but the leaf barely pulled the hub (large hub degree) —
        // unequal magnitudes on the same edge, which violates
        // Newton's 3rd law and continuously injects net linear AND
        // angular momentum (the source of the never-ending spin/drift
        // that damping could never overcome). The weight
        // `attraction / sqrt(deg_i * deg_o)` is symmetric in the two
        // endpoints, so both feel the same magnitude → equal and
        // opposite → momentum is conserved and the layout can settle.
        // It still relieves hubs (the anti-collapse benefit).
        let deg_i = degrees[i as usize];
        for e in 0..edge_count {
            let ea = edges[(e * 2) as usize];
            let eb = edges[(e * 2 + 1) as usize];
            if ea == i {
                let deg_o = degrees[eb as usize];
                let w = attraction / (deg_i * deg_o).sqrt();
                let bx = (eb * 2) as usize;
                fx += (pos[bx] - px) * w;
                fy += (pos[bx + 1] - py) * w;
            }
            if eb == i {
                let deg_o = degrees[ea as usize];
                let w = attraction / (deg_i * deg_o).sqrt();
                let ax = (ea * 2) as usize;
                fx += (pos[ax] - px) * w;
                fy += (pos[ax + 1] - py) * w;
            }
        }

        fx -= px * gravity;
        fy -= py * gravity;

        let fmag = (fx * fx + fy * fy).sqrt();
        if fmag > max_force {
            let scale = max_force / fmag;
            fx *= scale;
            fy *= scale;
        }

        let vx = (vel[ix] + fx) * damping;
        let vy = (vel[iy] + fy) * damping;
        vel[ix] = vx;
        vel[iy] = vy;
        pos_out[ix] = px + vx;
        pos_out[iy] = py + vy;
    }
}

// ── FDEB (force-directed edge bundling) kernel ────────────────────────

#[cube(launch)]
fn fdeb_step_kernel(
    points: &Array<f32>,
    points_out: &mut Array<f32>,
    edge_count: u32,
    k: u32,
    step_size: f32,
    spring_k: f32,
) {
    let tid = ABSOLUTE_POS as u32;
    let total = edge_count * k;
    if tid < total {
        let e = tid / k;
        let p = tid % k;
        let ix = (tid * 2) as usize;
        let px = points[ix];
        let py = points[ix + 1];

        if p == 0u32 || p == k - 1u32 {
            points_out[ix] = px;
            points_out[ix + 1] = py;
        } else {
            let my0 = (e * k * 2) as usize;
            let my1 = ((e * k + k - 1u32) * 2) as usize;
            let my_p0x = points[my0];
            let my_p0y = points[my0 + 1];
            let my_p1x = points[my1];
            let my_p1y = points[my1 + 1];
            let my_dx = my_p1x - my_p0x;
            let my_dy = my_p1y - my_p0y;
            let my_len = (my_dx * my_dx + my_dy * my_dy).sqrt().max(1.0f32);
            let my_mx = (my_p0x + my_p1x) * 0.5f32;
            let my_my = (my_p0y + my_p1y) * 0.5f32;

            // Smoothing spring: penalizes curvature (local).
            let prev_ix = ((e * k + p - 1u32) * 2) as usize;
            let next_ix = ((e * k + p + 1u32) * 2) as usize;
            let fx_smooth = ((points[prev_ix] - px) + (points[next_ix] - px)) * spring_k;
            let fy_smooth = ((points[prev_ix + 1] - py) + (points[next_ix + 1] - py)) * spring_k;

            // Straight-line restoring: pulls back toward the unbent
            // position on the original edge (global shape anchor).
            let t = p as f32 / (k - 1u32) as f32;
            let sx = my_p0x + (my_p1x - my_p0x) * t;
            let sy = my_p0y + (my_p1y - my_p0y) * t;
            let straighten = 0.03f32;
            let fx_straight = (sx - px) * straighten;
            let fy_straight = (sy - py) * straighten;

            // Electrostatic: unit-vector pull toward corresponding
            // point on each compatible edge, averaged over compatible
            // count so total magnitude is bounded ≤ 1.
            let mut fx_elec = f32::new(0.0);
            let mut fy_elec = f32::new(0.0);

            for other in 0u32..edge_count {
                if other != e {
                    let o0 = (other * k * 2) as usize;
                    let o1 = ((other * k + k - 1u32) * 2) as usize;
                    let o_p0x = points[o0];
                    let o_p0y = points[o0 + 1];
                    let o_p1x = points[o1];
                    let o_p1y = points[o1 + 1];
                    let o_dx = o_p1x - o_p0x;
                    let o_dy = o_p1y - o_p0y;
                    let o_len = (o_dx * o_dx + o_dy * o_dy).sqrt().max(1.0f32);
                    let o_mx = (o_p0x + o_p1x) * 0.5f32;
                    let o_my = (o_p0y + o_p1y) * 0.5f32;

                    let dot = my_dx * o_dx + my_dy * o_dy;
                    let cos_a = dot / (my_len * o_len);
                    let c_angle = cos_a * cos_a;

                    let lavg = (my_len + o_len) * 0.5f32;
                    let lmin = my_len.min(o_len);
                    let lmax = my_len.max(o_len);
                    let c_scale = 2.0f32 / (lavg / lmin + lmax / lavg);

                    let mdx = my_mx - o_mx;
                    let mdy = my_my - o_my;
                    let mdist = (mdx * mdx + mdy * mdy).sqrt();
                    let c_pos = lavg / (lavg + mdist);

                    let compat = c_angle * c_scale * c_pos;

                    if compat > 0.2f32 {
                        let corr_p = if dot >= 0.0f32 { p } else { k - 1u32 - p };
                        let other_ix = ((other * k + corr_p) * 2) as usize;
                        let ox = points[other_ix];
                        let oy = points[other_ix + 1];
                        let ddx = ox - px;
                        let ddy = oy - py;
                        let d = (ddx * ddx + ddy * ddy).sqrt().max(0.1f32);
                        fx_elec += (ddx / d) * compat;
                        fy_elec += (ddy / d) * compat;
                    }
                }
            }

            // Cap electrostatic magnitude so it can't overwhelm
            // the straight-line restoring force.
            let elec_mag = (fx_elec * fx_elec + fy_elec * fy_elec).sqrt();
            let max_elec = 3.0f32;
            if elec_mag > max_elec {
                let s = max_elec / elec_mag;
                fx_elec *= s;
                fy_elec *= s;
            }

            let fx = fx_smooth + fx_straight + fx_elec;
            let fy = fy_smooth + fy_straight + fy_elec;
            points_out[ix] = px + fx * step_size;
            points_out[ix + 1] = py + fy * step_size;
        }
    }
}

// ── force-directed graph ──────────────────────────────────────────────

struct WikiGraph {
    nodes: Vec<GraphNode>,
    edges: Vec<(usize, usize)>,
    gpu: Option<GpuForceState>,
    /// Bundled polylines per edge (world coords). `None` = draw straight.
    polylines: Option<Vec<Vec<egui::Vec2>>>,
}

struct GpuForceState {
    client: ComputeClient<WgpuRuntime>,
    pos_handle: cubecl::server::Handle,
    vel_handle: cubecl::server::Handle,
    edges_handle: cubecl::server::Handle,
    /// Per-node degree (1.0 + incident edges), immutable across steps.
    degrees_handle: cubecl::server::Handle,
    pos_out_handle: cubecl::server::Handle,
    node_count: u32,
    edge_count: u32,
}

struct GraphNode {
    revision_id: Id,
    entry_key: Id,
    archived: bool,
    label: String,
    pos: egui::Vec2,
    /// Total incident edges (in + out). Used to scale the node
    /// radius so hub revisions visually dominate.
    degree: u32,
}

impl WikiGraph {
    fn from_wiki(live: &WikiLive, wiki_reader: &PileReader) -> Self {
        let heads = live.visible_heads(wiki_reader);
        let mut revision_to_idx = BTreeMap::new();
        let mut nodes = Vec::new();

        let n = heads.len().max(1) as f32;
        for (i, head) in heads.iter().enumerate() {
            let angle = (i as f32 / n) * std::f32::consts::TAU;
            let radius = 200.0 + n * 5.0;
            let title = live.title(wiki_reader, head.revision_id);
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
                pos: egui::vec2(angle.cos() * radius, angle.sin() * radius),
                degree: 0,
            });
        }

        let mut seen = HashSet::new();
        let mut edges = Vec::new();
        let mut unresolved = 0usize;
        for head in &heads {
            let from = revision_to_idx[&head.revision_id];
            for target in live.graph_link_targets(wiki_reader, head.revision_id) {
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

        // Compute per-node degree for size scaling in the render pass.
        for &(from, to) in &edges {
            nodes[from].degree = nodes[from].degree.saturating_add(1);
            nodes[to].degree = nodes[to].degree.saturating_add(1);
        }

        let gpu = Self::init_gpu(&nodes, &edges);
        WikiGraph {
            nodes,
            edges,
            gpu,
            polylines: None,
        }
    }

    fn init_gpu(nodes: &[GraphNode], edges: &[(usize, usize)]) -> Option<GpuForceState> {
        let device = WgpuDevice::default();
        let client = WgpuRuntime::client(&device);
        let n = nodes.len();

        let mut pos_flat: Vec<f32> = Vec::with_capacity(n * 2);
        let vel_flat: Vec<f32> = vec![0.0; n * 2];
        for node in nodes {
            pos_flat.push(node.pos.x);
            pos_flat.push(node.pos.y);
        }

        let edges_flat: Vec<u32> = edges
            .iter()
            .flat_map(|&(a, b)| [a as u32, b as u32])
            .collect();

        // Per-node degree for the symmetric attraction weight. Base of
        // 1.0 (matches the old `degree` starting value) keeps isolated
        // nodes at deg=1 and avoids a divide-by-zero in sqrt(deg*deg).
        let degrees_flat: Vec<f32> = nodes.iter().map(|nd| 1.0 + nd.degree as f32).collect();

        let pos_handle = client.create_from_slice(f32::as_bytes(&pos_flat));
        let vel_handle = client.create_from_slice(f32::as_bytes(&vel_flat));
        let edges_handle = if edges_flat.is_empty() {
            client.create_from_slice(u32::as_bytes(&[0u32; 2]))
        } else {
            client.create_from_slice(u32::as_bytes(&edges_flat))
        };
        let degrees_handle = if degrees_flat.is_empty() {
            client.create_from_slice(f32::as_bytes(&[1.0f32]))
        } else {
            client.create_from_slice(f32::as_bytes(&degrees_flat))
        };
        let pos_out_handle = client.empty(n * 2 * std::mem::size_of::<f32>());

        Some(GpuForceState {
            client,
            pos_handle,
            vel_handle,
            edges_handle,
            degrees_handle,
            pos_out_handle,
            node_count: n as u32,
            edge_count: edges.len() as u32,
        })
    }

    fn step(&mut self) {
        let Some(gpu) = &mut self.gpu else { return };
        let n = gpu.node_count as usize;
        if n == 0 {
            return;
        }

        unsafe {
            force_step_kernel::launch::<WgpuRuntime>(
                &gpu.client,
                CubeCount::new_1d(((n as u32) + 255) / 256),
                CubeDim::new_1d(256),
                ArrayArg::from_raw_parts(gpu.pos_handle.clone(), n * 2),
                ArrayArg::from_raw_parts(gpu.vel_handle.clone(), n * 2),
                ArrayArg::from_raw_parts(
                    gpu.edges_handle.clone(),
                    gpu.edge_count.max(1) as usize * 2,
                ),
                ArrayArg::from_raw_parts(gpu.degrees_handle.clone(), n),
                gpu.node_count,
                gpu.edge_count,
                ArrayArg::from_raw_parts(gpu.pos_out_handle.clone(), n * 2),
            );
        }

        std::mem::swap(&mut gpu.pos_handle, &mut gpu.pos_out_handle);

        let bytes = gpu
            .client
            .read_one(gpu.pos_handle.clone())
            .expect("gpu readback");
        let positions: &[f32] = f32::from_bytes(&bytes);

        // Compute center of mass and average angular velocity,
        // then subtract to kill collective rotation.
        let mut cx = 0.0f32;
        let mut cy = 0.0f32;
        for i in 0..n {
            cx += positions[i * 2];
            cy += positions[i * 2 + 1];
        }
        cx /= n as f32;
        cy /= n as f32;

        // Compute average angular momentum around center of mass.
        let mut angular = 0.0f32;
        let mut inertia = 0.0f32;
        for (i, node) in self.nodes.iter().enumerate() {
            let px = positions[i * 2];
            let py = positions[i * 2 + 1];
            let dx = px - cx;
            let dy = py - cy;
            let vx = px - node.pos.x;
            let vy = py - node.pos.y;
            let r_sq = dx * dx + dy * dy;
            angular += dx * vy - dy * vx; // cross product = angular contribution
            inertia += r_sq;
        }
        let omega = if inertia > 1.0 {
            angular / inertia
        } else {
            0.0
        };

        // Read back velocities up-front so we can compute the mean
        // (= the system's linear momentum / mass) alongside the
        // angular correction.
        let vel_bytes = gpu
            .client
            .read_one(gpu.vel_handle.clone())
            .expect("gpu readback");
        let velocities: &[f32] = f32::from_bytes(&vel_bytes);
        let mut mean_vx = 0.0f32;
        let mut mean_vy = 0.0f32;
        for i in 0..n {
            mean_vx += velocities[i * 2];
            mean_vy += velocities[i * 2 + 1];
        }
        mean_vx /= n as f32;
        mean_vy /= n as f32;

        // Corrections fed back to the GPU each frame:
        //
        // - Position: pin the centroid at the world origin (positions
        //   ← positions − centroid). Pure translation of the frame —
        //   norm-preserving, never distorts the layout.
        // - Velocity: remove the net linear (mean) and net angular
        //   (omega × r) components. Both are momentum-removal that is
        //   a no-op at rest (omega, mean → 0) and only bleeds off any
        //   residual global drift/spin from initial conditions or
        //   numerical noise during settling.
        //
        // We deliberately do NOT shear positions by `omega × r` any
        // more. That was a small-angle approximation of a rotation —
        // not norm-preserving — and it wrote into `node.pos`, which is
        // also the baseline for next frame's velocity estimate, so it
        // closed a feedback loop that could *sustain* rotation. With
        // the attraction now momentum-conserving (symmetric weight)
        // there is no torque source, so global angular momentum stays
        // ~0 on its own and the velocity-only removal is all the
        // insurance we need.
        let mut corrected_pos: Vec<f32> = Vec::with_capacity(n * 2);
        let mut corrected_vel: Vec<f32> = Vec::with_capacity(n * 2);
        for (i, node) in self.nodes.iter_mut().enumerate() {
            let dx = positions[i * 2] - cx;
            let dy = positions[i * 2 + 1] - cy;
            node.pos = egui::vec2(dx, dy);
            corrected_pos.push(dx);
            corrected_pos.push(dy);
            corrected_vel.push(velocities[i * 2] - mean_vx + omega * dy);
            corrected_vel.push(velocities[i * 2 + 1] - mean_vy - omega * dx);
        }

        // Replace GPU buffers — `create_from_slice` is the only public
        // update path in cubecl 0.9; the old handles drop and the
        // runtime's allocator reclaims their slots.
        gpu.pos_handle = gpu.client.create_from_slice(f32::as_bytes(&corrected_pos));
        gpu.vel_handle = gpu.client.create_from_slice(f32::as_bytes(&corrected_vel));
    }

    #[allow(dead_code)]
    fn is_bundled(&self) -> bool {
        self.polylines.is_some()
    }

    fn node_count(&self) -> usize {
        self.nodes.len()
    }

    #[allow(dead_code)]
    fn edge_count(&self) -> usize {
        self.edges.len()
    }

    #[allow(dead_code)]
    fn clear_bundling(&mut self) {
        self.polylines = None;
    }

    /// Force-Directed Edge Bundling (Holten & Van Wijk 2009) on GPU.
    /// Edges subdivide into K control points; each non-endpoint point
    /// is pulled by spring forces from its polyline neighbors and by
    /// electrostatic attraction from *compatible* edges (matching
    /// angle, scale, and midpoint proximity). Compatibility prevents
    /// edges from detouring through unrelated bundles.
    #[allow(dead_code)]
    fn bundle_edges(&mut self) {
        const K: u32 = 17;
        const CYCLES: usize = 5;
        const ITERATIONS_START: usize = 50;
        const SPRING_K: f32 = 0.1;

        if self.edges.is_empty() {
            self.polylines = Some(Vec::new());
            return;
        }

        let e = self.edges.len() as u32;
        let total = e * K;
        let total_floats = (total * 2) as usize;

        let mut flat: Vec<f32> = Vec::with_capacity(total_floats);
        for &(a, b) in &self.edges {
            let p0 = self.nodes[a].pos;
            let p1 = self.nodes[b].pos;
            for i in 0..K {
                let t = i as f32 / (K - 1) as f32;
                let p = p0 + (p1 - p0) * t;
                flat.push(p.x);
                flat.push(p.y);
            }
        }

        // Average edge length — sets step scale so forces move control
        // points a sensible fraction of a typical edge per iteration.
        let mut len_sum = 0.0f32;
        for &(a, b) in &self.edges {
            len_sum += (self.nodes[a].pos - self.nodes[b].pos).length();
        }
        let avg_len = (len_sum / e as f32).max(1.0);
        // Step in world units. Electrostatic force is a unit vector
        // (bounded ≤ 1 after averaging), so step_size controls the
        // max displacement per iteration. Segment length ≈ avg_len/16;
        // move at most ~1/3 of a segment per step for stability.
        let segment_len = avg_len / (K - 1) as f32;
        let mut step_size = segment_len * 0.15;

        let device = WgpuDevice::default();
        let client = WgpuRuntime::client(&device);
        let mut pts_handle = client.create_from_slice(f32::as_bytes(&flat));
        let mut pts_out_handle = client.empty(total_floats * std::mem::size_of::<f32>());

        let mut iterations = ITERATIONS_START;
        for _cycle in 0..CYCLES {
            for _ in 0..iterations {
                unsafe {
                    fdeb_step_kernel::launch::<WgpuRuntime>(
                        &client,
                        CubeCount::new_1d((total + 255) / 256),
                        CubeDim::new_1d(256),
                        ArrayArg::from_raw_parts(pts_handle.clone(), total_floats),
                        ArrayArg::from_raw_parts(pts_out_handle.clone(), total_floats),
                        e,
                        K,
                        step_size,
                        SPRING_K,
                    );
                }
                std::mem::swap(&mut pts_handle, &mut pts_out_handle);
            }
            step_size *= 0.5;
            iterations = (iterations * 2 / 3).max(10);
        }

        let bytes = client.read_one(pts_handle).expect("gpu readback");
        let result: &[f32] = f32::from_bytes(&bytes);

        let mut polylines = Vec::with_capacity(self.edges.len());
        for ei in 0..self.edges.len() {
            let mut poly = Vec::with_capacity(K as usize);
            for pi in 0..K as usize {
                let ix = (ei * K as usize + pi) * 2;
                poly.push(egui::vec2(result[ix], result[ix + 1]));
            }
            polylines.push(poly);
        }
        self.polylines = Some(polylines);
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
        let center = rect.center();

        let view_id = ui.id().with("wiki_graph_view");
        let pan_id = view_id.with("pan");
        let zoom_id = view_id.with("zoom");

        let mut pan: egui::Vec2 = ui.ctx().memory_mut(|m| {
            *m.data
                .get_temp_mut_or_insert_with(pan_id, || egui::Vec2::ZERO)
        });
        let mut zoom: f32 = ui
            .ctx()
            .memory_mut(|m| *m.data.get_temp_mut_or_insert_with(zoom_id, || 1.0f32));

        // Direct rect-contains-pointer hover check — the outer
        // notebook ScrollArea otherwise claims hover priority and
        // `response.hovered()` returns false, so wheel events fall
        // through to the notebook instead of the graph.
        let pointer_in_graph = ui
            .input(|i| i.pointer.hover_pos())
            .map(|p| rect.contains(p))
            .unwrap_or(false);
        if pointer_in_graph {
            // Pinch-to-zoom (trackpad native) or cmd/ctrl + scroll
            // (mouse wheel). Plain vertical/horizontal scroll is NOT
            // consumed — it falls through to the outer notebook
            // ScrollArea. Previously we zoomed on `smooth_scroll_delta.x`
            // alone, which caught trackpad sideways drift on every
            // scroll and made the graph zoom when the user just wanted
            // to scroll the page.
            let (pinch, scroll_y, ctrl) = ui.input(|i| {
                (
                    i.zoom_delta(),
                    i.smooth_scroll_delta.y,
                    i.modifiers.command || i.modifiers.ctrl,
                )
            });
            let zoom_factor = if pinch != 1.0 {
                pinch
            } else if ctrl && scroll_y != 0.0 {
                (1.0 + scroll_y * 0.004).clamp(0.85, 1.15)
            } else {
                1.0
            };
            if zoom_factor != 1.0 {
                let old_zoom = zoom;
                zoom = (zoom * zoom_factor).clamp(0.05, 10.0);
                if let Some(hp) = response.hover_pos() {
                    let cursor_offset = hp - center - pan;
                    pan -= cursor_offset * (zoom / old_zoom - 1.0);
                }
                ui.ctx().memory_mut(|m| {
                    m.data.insert_temp(zoom_id, zoom);
                    m.data.insert_temp(pan_id, pan);
                });
                // Only consume the scroll delta we actually used.
                if ctrl && scroll_y != 0.0 {
                    ui.ctx().input_mut(|i| i.smooth_scroll_delta.y = 0.0);
                }
            }
        }

        // Drag-to-pan via egui's z-aware drag sense — `drag_delta()`
        // only fires when the press started on this widget AND no
        // higher-z widget is on top, so floats dragged across the
        // viewport don't steal pans (or pan-and-drag in lockstep).
        let drag_delta = response.drag_delta();
        if drag_delta != egui::Vec2::ZERO {
            pan += drag_delta;
            ui.ctx().memory_mut(|m| m.data.insert_temp(pan_id, pan));
        }

        let to_screen =
            |world: egui::Vec2| center + pan + egui::vec2(world.x * zoom, world.y * zoom);

        let node_radius = 6.0 * zoom.max(0.3);
        let edge_color = ui.visuals().weak_text_color();
        let node_match_fill = GORBIE::themes::ral(1003);
        let needle_lower = search.query().to_lowercase();
        let node_stroke = ui.visuals().widgets.noninteractive.bg_stroke;
        let label_color = ui.visuals().text_color();
        let font_id = egui::TextStyle::Small.resolve(ui.style());

        let edge_stroke = egui::Stroke::new(0.5, edge_color);
        for (e_idx, &(a, b)) in self.edges.iter().enumerate() {
            let p1 = to_screen(self.nodes[a].pos);
            let p2 = to_screen(self.nodes[b].pos);
            if !(rect.expand(50.0).contains(p1) || rect.expand(50.0).contains(p2)) {
                continue;
            }
            match &self.polylines {
                Some(polys) => {
                    let pts: Vec<egui::Pos2> = polys[e_idx].iter().map(|&p| to_screen(p)).collect();
                    painter.add(egui::Shape::line(pts, edge_stroke));
                }
                None => {
                    painter.line_segment([p1, p2], edge_stroke);
                }
            }
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
        for node in &self.nodes {
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

            let pos = to_screen(node.pos);
            if !rect.expand(20.0).contains(pos) {
                continue;
            }

            // Scale node radius by degree: isolated nodes at the base
            // size, hub revisions grow logarithmically. Caps at 3×.
            let deg_scale = (1.0 + (node.degree as f32 + 1.0).ln() * 0.4).min(3.0);
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
            painter.circle(pos, r, fill, node_stroke);
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
    /// Strict projection failures are rendered instead of panicking or
    /// falling back to legacy-shaped facts.
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
        let files_reader = files_view.map(|view| view.reader);
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
            self.graph = None;
        }

        if let Some((_, error)) = self.error.as_ref() {
            render_diagnostic(ctx.ui_mut(), error);
            return;
        }

        let live = match self.live.as_ref() {
            Some(l) => l,
            None => return,
        };

        // Search-bar UI is overlaid inside the graph viewport —
        // rendered after graph.show below using the viewport rect.
        let mut submit_query: Option<String> = None;

        // ── force-directed graph ─────────────────────────────────────
        if self.graph.is_none() {
            self.graph = Some(WikiGraph::from_wiki(live, wiki_reader));
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
            // Advance the force layout every frame. Bundle toggle is
            // gone (graph.bundle_edges / clear_bundling are still
            // available for a future reintroduction); the meta info
            // is overlaid inside the viewport itself — see
            // WikiGraph::show.
            graph.step();
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
            ctx.ctx().request_repaint();

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
                live.resolve_prefix(&q).unwrap_or_default()
            } else {
                let q_lower = q.to_lowercase();
                live.visible_heads(wiki_reader)
                    .into_iter()
                    .filter(|head| {
                        live.title(wiki_reader, head.revision_id)
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

            let revision = live.revision(revision_id);
            let entry = revision.and_then(|_| live.catalog.revisions.entry_containing(revision_id));
            let title = live.title(wiki_reader, revision_id);
            let content = live.content(wiki_reader, revision_id);
            let entry_key = entry.map(WikiLive::entry_key).unwrap_or(revision_id);
            let color = frag_color(entry_key);
            let frontier_position = entry.and_then(|entry| {
                entry
                    .frontier
                    .iter()
                    .position(|head| head.id == revision_id)
            });
            let state_label = match (entry, frontier_position) {
                (Some(entry), Some(index)) if entry.frontier.len() > 1 => {
                    format!("FORK HEAD {}/{}", index + 1, entry.frontier.len())
                }
                (Some(_), Some(_)) => "HEAD".to_owned(),
                (Some(_), None) => "HISTORICAL".to_owned(),
                (None, _) => "MISSING".to_owned(),
            };
            let archived = revision.is_some_and(|row| row.tags.contains(&TAG_ARCHIVED_ID));

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

                        if let Some(entry) = entry.filter(|entry| entry.legacy_fragments.len() > 1) {
                            g.full(|ctx| {
                                let weak = ctx.ctx().global_style().visuals.weak_text_color();
                                ctx.label(
                                    egui::RichText::new(format!(
                                        "{} legacy aliases name this entry",
                                        entry.legacy_fragments.len()
                                    ))
                                    .monospace()
                                    .small()
                                    .color(weak),
                                );
                            });
                        }

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
                live.resolve_entry_selector(selector)
            } else {
                live.resolve_selector(selector)
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
            live.open_file(files_reader, &hex);
        }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::schemas::files::file as file_attrs;
    use crate::schemas::wiki::{attrs, KIND_VERSION_ID};
    use crate::wiki::{self, RevisionDraft};
    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::metadata;
    use triblespace::core::repo::BlobStore;
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

        let catalog = wiki::load_catalog(fragment.facts()).unwrap();
        let projected = WikiLive::projected_heads(&catalog);
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
            WikiLive::resolve_catalog_selector(&catalog, left),
            vec![left],
            "an intrinsic revision selector stays exact"
        );

        assert_eq!(
            WikiLive::resolve_catalog_entry_selector(&catalog, base),
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

    #[test]
    fn legacy_fragment_selector_returns_its_complete_frontier() {
        let fragment_id = Id::new([0xa1; 16]).unwrap();
        let first = Id::new([0xb1; 16]).unwrap();
        let second = Id::new([0xb2; 16]).unwrap();
        let mut fragment = Fragment::empty();
        let title = fragment.put::<LongString, _>("legacy title".to_owned());
        let content = fragment.put::<LongString, _>("legacy content".to_owned());
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

        let catalog = wiki::load_catalog(fragment.facts()).unwrap();
        assert_eq!(
            WikiLive::resolve_catalog_selector(&catalog, fragment_id),
            vec![first, second],
            "the alias is set-valued; time does not arbitrate the fork"
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
        let reader = blobs.reader().unwrap();
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
