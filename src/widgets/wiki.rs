//! Full-featured GORBIE-embeddable wiki viewer.
//!
//! Renders wiki fragments from a triblespace pile. The widget holds only
//! UI state plus cached query results; the host is responsible for
//! pulling the wiki branch (and optionally a files branch) and passing
//! the workspaces in at render time:
//!
//! ```ignore
//! let mut viewer = WikiViewer::default();
//! // Inside a GORBIE card, with `wiki_ws` and optional `files_ws`:
//! viewer.render(ctx, wiki_ws, files_ws);
//! ```
//!
//! Features:
//! - Search bar at the top
//! - A force-directed graph of fragments + their `links_to` edges (GPU,
//!   with optional FDEB edge bundling)
//! - Floating wiki-page cards that open when the user clicks a node, a
//!   `wiki:<hex>` link in typst content, or a file entry
//! - Version navigation (prev/next/latest) on fragments with history
//! - `files:` link handling — resolves a 32-char entity id or 64-char
//!   content hash to a file blob (against the optional files workspace),
//!   writes it to `$TMPDIR/liora-files/`, and opens it via the platform
//!   `open` command.

use std::collections::{BTreeMap, HashSet};

use cubecl::prelude::*;
use cubecl::wgpu::{WgpuDevice, WgpuRuntime};
use GORBIE::prelude::CardCtx;
use GORBIE::themes::colorhash;
use triblespace::core::blob::Blob;
use triblespace::core::id::Id;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{CommitHandle, Workspace};
use triblespace::core::trible::TribleSet;
use triblespace::core::inline::encodings::hash::{Blake3, Handle};
use triblespace::core::inline::{TryToInline, Inline};
use triblespace::macros::{find, pattern};
use triblespace::prelude::blobencodings::{RawBytes, LongString};
use triblespace::prelude::View;

use crate::schemas::files::{file, KIND_FILE};
use crate::schemas::wiki::{attrs as wiki, KIND_VERSION_ID, TAG_ARCHIVED_ID};

/// Handle to a long-string blob living in a pile.
type TextHandle = Inline<Handle<LongString>>;

/// Handle to a file-bytes blob living in a pile.
type FileHandle = Inline<Handle<RawBytes>>;

/// Format an Id as a lowercase hex string.
fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// Deterministic per-fragment color via GORBIE's colorhash palette.
/// Gives each wiki fragment a stable identity color so the same
/// fragment shows up consistently across open pages.
fn frag_color(id: Id) -> egui::Color32 {
    colorhash::ral_categorical(id.as_ref())
}

// ── cached wiki query state ──────────────────────────────────────────

/// Cached fact spaces + head marker. Rebuilt when the wiki workspace's
/// head advances past `cached_head` (i.e. we pushed something, or the
/// host re-pulled after an external write).
struct WikiLive {
    wiki_space: TribleSet,
    files_space: TribleSet,
    cached_head: Option<CommitHandle>,
    files_cached_head: Option<CommitHandle>,
}

impl WikiLive {
    /// Refresh cached fact spaces from the provided workspaces. Pulls
    /// fresh `TribleSet`s via `checkout(..)`.
    fn refresh(
        wiki_ws: &mut Workspace<Pile>,
        files_ws: Option<&mut Workspace<Pile>>,
    ) -> Self {
        let wiki_space = wiki_ws
            .checkout(..)
            .map(|co| co.into_facts())
            .unwrap_or_else(|e| {
                eprintln!("[wiki] checkout: {e:?}");
                TribleSet::new()
            });
        let cached_head = wiki_ws.head();

        let (files_space, files_cached_head) = match files_ws {
            Some(ws) => {
                let head = ws.head();
                let space = ws
                    .checkout(..)
                    .map(|co| co.into_facts())
                    .unwrap_or_else(|e| {
                        eprintln!("[files] checkout: {e:?}");
                        TribleSet::new()
                    });
                (space, head)
            }
            None => (TribleSet::new(), None),
        };

        WikiLive {
            wiki_space,
            files_space,
            cached_head,
            files_cached_head,
        }
    }

    fn text(&self, ws: &mut Workspace<Pile>, h: TextHandle) -> String {
        ws.get::<View<str>, LongString>(h)
            .map(|v| {
                let s: &str = v.as_ref();
                s.to_string()
            })
            .unwrap_or_default()
    }

    fn file_text(
        &self,
        files_ws: Option<&mut Workspace<Pile>>,
        h: TextHandle,
    ) -> String {
        files_ws
            .and_then(|ws| ws.get::<View<str>, LongString>(h).ok())
            .map(|v| {
                let s: &str = v.as_ref();
                s.to_string()
            })
            .unwrap_or_default()
    }

    // ── queries (all on-demand via find!) ─────────────────────────────

    /// Resolve a hex prefix to a fragment ID. Matches both version and
    /// fragment IDs. Returns None if no match or ambiguous.
    fn resolve_prefix(&self, prefix: &str) -> Option<Id> {
        let needle = prefix.trim().to_lowercase();
        let mut matches = Vec::new();
        let mut seen_frags = HashSet::new();
        for (vid, frag) in find!(
            (vid: Id, frag: Id),
            pattern!(&self.wiki_space, [{
                ?vid @ metadata::tag: &KIND_VERSION_ID, wiki::fragment: ?frag
            }])
        ) {
            if format!("{vid:x}").starts_with(&needle) {
                matches.push(frag); // resolve version to its fragment
            }
            if seen_frags.insert(frag) && format!("{frag:x}").starts_with(&needle) {
                matches.push(frag);
            }
        }
        matches.sort();
        matches.dedup();
        if matches.len() == 1 {
            Some(matches[0])
        } else {
            None
        }
    }

    /// Resolve an ID that might be a version or a fragment to its fragment.
    fn to_fragment(&self, id: Id) -> Option<Id> {
        if self.latest_version(id).is_some() {
            return Some(id);
        }
        find!(frag: Id, pattern!(&self.wiki_space, [{ id @ wiki::fragment: ?frag }])).next()
    }

    /// All versions of a fragment, sorted newest-first.
    fn version_history(&self, fragment_id: Id) -> Vec<Id> {
        let mut versions: Vec<(Id, i128)> = find!(
            (vid: Id, ts: (i128, i128)),
            pattern!(&self.wiki_space, [{
                ?vid @
                metadata::tag: &KIND_VERSION_ID,
                wiki::fragment: &fragment_id,
                metadata::created_at: ?ts,
            }])
        )
        .map(|(vid, ts)| (vid, ts.0))
        .collect();
        versions.sort_by(|a, b| b.1.cmp(&a.1)); // newest first
        versions.into_iter().map(|(vid, _)| vid).collect()
    }

    /// Find the latest version id for a given fragment id.
    fn latest_version(&self, fragment_id: Id) -> Option<Id> {
        find!(
            (vid: Id, ts: (i128, i128)),
            pattern!(&self.wiki_space, [{
                ?vid @
                metadata::tag: &KIND_VERSION_ID,
                wiki::fragment: &fragment_id,
                metadata::created_at: ?ts,
            }])
        )
        .max_by_key(|(_, ts)| ts.0)
        .map(|(vid, _)| vid)
    }

    fn title(&self, wiki_ws: &mut Workspace<Pile>, vid: Id) -> String {
        find!(h: TextHandle, pattern!(&self.wiki_space, [{ vid @ wiki::title: ?h }]))
            .next()
            .map(|h| self.text(wiki_ws, h))
            .unwrap_or_default()
    }

    fn content(&self, wiki_ws: &mut Workspace<Pile>, vid: Id) -> String {
        find!(h: TextHandle, pattern!(&self.wiki_space, [{ vid @ wiki::content: ?h }]))
            .next()
            .map(|h| self.text(wiki_ws, h))
            .unwrap_or_default()
    }

    fn tags(&self, vid: Id) -> Vec<Id> {
        find!(tag: Id, pattern!(&self.wiki_space, [{ vid @ metadata::tag: ?tag }]))
            .filter(|t| *t != KIND_VERSION_ID)
            .collect()
    }

    fn is_archived(&self, vid: Id) -> bool {
        self.tags(vid).contains(&TAG_ARCHIVED_ID)
    }

    fn links(&self, vid: Id) -> Vec<Id> {
        find!(
            target: Id,
            pattern!(&self.wiki_space, [{ vid @ wiki::links_to: ?target }])
        )
        .collect()
    }

    /// Latest non-archived (fragment_id, version_id) pairs sorted by title.
    fn fragments_sorted(&self, wiki_ws: &mut Workspace<Pile>) -> Vec<(Id, Id)> {
        let mut latest: BTreeMap<Id, (Id, i128)> = BTreeMap::new();
        for (vid, frag, ts) in find!(
            (vid: Id, frag: Id, ts: (i128, i128)),
            pattern!(&self.wiki_space, [{
                ?vid @
                metadata::tag: &KIND_VERSION_ID,
                wiki::fragment: ?frag,
                metadata::created_at: ?ts,
            }])
        ) {
            let replace = match latest.get(&frag) {
                None => true,
                Some((_, prev_key)) => ts.0 > *prev_key,
            };
            if replace {
                latest.insert(frag, (vid, ts.0));
            }
        }
        let mut entries: Vec<(Id, Id)> = latest
            .into_iter()
            .map(|(frag, (vid, _))| (frag, vid))
            .filter(|(_, vid)| !self.is_archived(*vid))
            .collect();
        entries.sort_by(|a, b| {
            self.title(wiki_ws, a.1)
                .to_lowercase()
                .cmp(&self.title(wiki_ws, b.1).to_lowercase())
        });
        entries
    }

    // ── file resolution ──────────────────────────────────────────────

    /// Resolve a `files:<hex>` URL fragment. `hex` must be either a
    /// 32-char file-entity id or a 64-char blake3 content hash. Returns
    /// the blob handle and a file name (or "file" if none is known).
    fn resolve_file(
        &self,
        files_ws: Option<&mut Workspace<Pile>>,
        hex: &str,
    ) -> Option<(FileHandle, String)> {
        let (entity_id, handle) = if hex.len() == 32 {
            let eid = Id::from_hex(hex)?;
            let h = find!(
                h: FileHandle,
                pattern!(&self.files_space, [{
                    eid @ metadata::tag: &KIND_FILE, file::content: ?h,
                }])
            )
            .next()?;
            (eid, h)
        } else if hex.len() == 64 {
            let hash_str = format!("blake3:{hex}");
            let hash_value: Inline<triblespace::core::inline::encodings::hash::Hash<Blake3>> =
                hash_str.as_str().try_to_inline().ok()?;
            let content_handle: FileHandle = hash_value.into();
            let eid = find!(
                eid: Id,
                pattern!(&self.files_space, [{
                    ?eid @ metadata::tag: &KIND_FILE, file::content: &content_handle,
                }])
            )
            .next()?;
            (eid, content_handle)
        } else {
            return None;
        };

        let name = find!(
            h: TextHandle,
            pattern!(&self.files_space, [{ entity_id @ file::name: ?h }])
        )
        .next()
        .map(|h| self.file_text(files_ws, h))
        .unwrap_or_else(|| "file".to_string());

        Some((handle, name))
    }

    /// Resolve `files:<hex>`, write the blob to `$TMPDIR/liora-files/<name>`,
    /// and fire `open` on it. Logs errors to stderr rather than surfacing
    /// them through the UI (this is a best-effort side channel).
    fn open_file(&self, files_ws: Option<&mut Workspace<Pile>>, hex: &str) {
        let Some(ws) = files_ws else {
            eprintln!("[files] no files workspace available");
            return;
        };
        // Resolve using a re-borrow so we can still use the workspace for
        // the blob read below.
        let Some((handle, name)) = self.resolve_file(Some(&mut *ws), hex) else {
            eprintln!("[files] could not resolve files:{hex}");
            return;
        };

        let result = (|| -> Result<std::path::PathBuf, String> {
            let blob: Blob<RawBytes> = ws.get(handle).map_err(|e| format!("get blob: {e:?}"))?;
            let tmp_dir = std::env::temp_dir().join("liora-files");
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
    node_count: u32,
    edge_count: u32,
    pos_out: &mut Array<f32>,
) {
    let i = ABSOLUTE_POS as u32;
    if i < node_count {
        let repulsion = 200000.0f32;
        let attraction = 0.3f32;
        let damping = 0.75f32;
        let max_force = 30.0f32;
        let gravity = 0.001f32;

        let ix = (i * 2) as usize;
        let iy = ix + 1;
        let px = pos[ix];
        let py = pos[iy];

        let mut fx = 0.0f32;
        let mut fy = 0.0f32;

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

        // Count degree to normalize attraction (high-degree nodes
        // don't collapse into a ball).
        let mut degree = 1.0f32;
        for e in 0..edge_count {
            let ea = edges[(e * 2) as usize];
            let eb = edges[(e * 2 + 1) as usize];
            if ea == i || eb == i {
                degree += 1.0f32;
            }
        }
        let norm_attraction = attraction / degree;

        for e in 0..edge_count {
            let ea = edges[(e * 2) as usize];
            let eb = edges[(e * 2 + 1) as usize];
            if ea == i {
                let bx = (eb * 2) as usize;
                fx += (pos[bx] - px) * norm_attraction;
                fy += (pos[bx + 1] - py) * norm_attraction;
            }
            if eb == i {
                let ax = (ea * 2) as usize;
                fx += (pos[ax] - px) * norm_attraction;
                fy += (pos[ax + 1] - py) * norm_attraction;
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
            let mut fx_elec = 0.0f32;
            let mut fy_elec = 0.0f32;

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
    pos_out_handle: cubecl::server::Handle,
    node_count: u32,
    edge_count: u32,
}

struct GraphNode {
    frag_id: Id,
    label: String,
    pos: egui::Vec2,
    /// Total incident edges (in + out). Used to scale the node
    /// radius so hub fragments visually dominate.
    degree: u32,
}

impl WikiGraph {
    fn from_wiki(live: &WikiLive, wiki_ws: &mut Workspace<Pile>) -> Self {
        let fragments = live.fragments_sorted(wiki_ws);
        let mut frag_to_idx = BTreeMap::new();
        let mut nodes = Vec::new();

        let n = fragments.len().max(1) as f32;
        for (i, &(frag_id, vid)) in fragments.iter().enumerate() {
            let angle = (i as f32 / n) * std::f32::consts::TAU;
            let radius = 200.0 + n * 5.0;
            let title = live.title(wiki_ws, vid);
            frag_to_idx.insert(frag_id, i);
            nodes.push(GraphNode {
                frag_id,
                label: if title.is_empty() {
                    fmt_id(frag_id)
                } else {
                    title
                },
                pos: egui::vec2(angle.cos() * radius, angle.sin() * radius),
                degree: 0,
            });
        }

        let mut seen = HashSet::new();
        let mut edges = Vec::new();
        let mut unresolved = 0usize;
        for &(frag_id, vid) in &fragments {
            let from = frag_to_idx[&frag_id];
            for target in live.links(vid) {
                let frag_target = if frag_to_idx.contains_key(&target) {
                    Some(target)
                } else {
                    find!(
                        frag: Id,
                        pattern!(&live.wiki_space, [{ target @ wiki::fragment: ?frag }])
                    )
                    .next()
                };
                if let Some(frag) = frag_target {
                    if let Some(&to) = frag_to_idx.get(&frag) {
                        if from != to && seen.insert((from, to)) {
                            edges.push((from, to));
                        }
                    } else {
                        unresolved += 1;
                    }
                } else {
                    unresolved += 1;
                }
            }
        }
        if unresolved > 0 {
            eprintln!(
                "[wiki] graph: {unresolved} link targets could not be resolved to fragments"
            );
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

        let pos_handle = client.create_from_slice(f32::as_bytes(&pos_flat));
        let vel_handle = client.create_from_slice(f32::as_bytes(&vel_flat));
        let edges_handle = if edges_flat.is_empty() {
            client.create_from_slice(u32::as_bytes(&[0u32; 2]))
        } else {
            client.create_from_slice(u32::as_bytes(&edges_flat))
        };
        let pos_out_handle = client.empty(n * 2 * std::mem::size_of::<f32>());

        Some(GpuForceState {
            client,
            pos_handle,
            vel_handle,
            edges_handle,
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
            let _ = force_step_kernel::launch::<WgpuRuntime>(
                &gpu.client,
                CubeCount::new_1d(((n as u32) + 255) / 256),
                CubeDim::new_1d(256),
                ArrayArg::from_raw_parts::<f32>(&gpu.pos_handle, n * 2, 1),
                ArrayArg::from_raw_parts::<f32>(&gpu.vel_handle, n * 2, 1),
                ArrayArg::from_raw_parts::<u32>(
                    &gpu.edges_handle,
                    gpu.edge_count.max(1) as usize * 2,
                    1,
                ),
                ScalarArg::new(gpu.node_count),
                ScalarArg::new(gpu.edge_count),
                ArrayArg::from_raw_parts::<f32>(&gpu.pos_out_handle, n * 2, 1),
            );
        }

        std::mem::swap(&mut gpu.pos_handle, &mut gpu.pos_out_handle);

        let bytes = gpu.client.read_one(gpu.pos_handle.clone());
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
        let omega = if inertia > 1.0 { angular / inertia } else { 0.0 };

        for (i, node) in self.nodes.iter_mut().enumerate() {
            let px = positions[i * 2] - cx;
            let py = positions[i * 2 + 1] - cy;
            // Subtract rigid rotation: v_rot = omega × r = (-omega*y, omega*x)
            node.pos = egui::vec2(
                positions[i * 2] + omega * py,
                positions[i * 2 + 1] - omega * px,
            );
        }
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
                    let _ = fdeb_step_kernel::launch::<WgpuRuntime>(
                        &client,
                        CubeCount::new_1d((total + 255) / 256),
                        CubeDim::new_1d(256),
                        ArrayArg::from_raw_parts::<f32>(&pts_handle, total_floats, 1),
                        ArrayArg::from_raw_parts::<f32>(&pts_out_handle, total_floats, 1),
                        ScalarArg::new(e),
                        ScalarArg::new(K),
                        ScalarArg::new(step_size),
                        ScalarArg::new(SPRING_K),
                    );
                }
                std::mem::swap(&mut pts_handle, &mut pts_out_handle);
            }
            step_size *= 0.5;
            iterations = (iterations * 2 / 3).max(10);
        }

        let bytes = client.read_one(pts_handle);
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
        let (response, painter) = ui.allocate_painter(
            egui::vec2(available.x, h),
            egui::Sense::click_and_drag(),
        );
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
        let node_fill = GORBIE::themes::ral(5005);
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
                    let pts: Vec<egui::Pos2> =
                        polys[e_idx].iter().map(|&p| to_screen(p)).collect();
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
            // counter. We use `frag_id.with("graph_node")` as the
            // match id to avoid colliding with text-level matches for
            // the same fragment (e.g. wiki:id in a meta row).
            let is_match = !needle_lower.is_empty()
                && node.label.to_lowercase().contains(&needle_lower);
            let _match_info = if is_match {
                let frag_bytes: &[u8] = node.frag_id.as_ref();
                let id = egui::Id::new(("wiki_graph_node", frag_bytes));
                Some(search.report(id))
            } else {
                None
            };

            let pos = to_screen(node.pos);
            if !rect.expand(20.0).contains(pos) {
                continue;
            }

            // Scale node radius by degree: isolated nodes at the base
            // size, hub fragments grow logarithmically. Caps at 3×.
            let deg_scale = (1.0 + (node.degree as f32 + 1.0).ln() * 0.4).min(3.0);
            let r = node_radius * deg_scale;
            // Matching nodes paint in RAL 1003 (signal yellow) — same
            // color GORBIE uses for word-level search underlines, so
            // the graph and the floats highlight in lock-step.
            let fill = if is_match { node_match_fill } else { node_fill };
            painter.circle(pos, r, fill, node_stroke);
            if show_labels {
                // Measure the label first so we know whether it fits
                // on the right. If painting to the right of the node
                // would clip past the viewport, flip to the left side
                // instead — keeps labels on-screen and reduces the
                // "labels all pile up at the right edge" look on
                // dense graphs.
                let galley = painter.layout_no_wrap(
                    node.label.clone(),
                    font_id.clone(),
                    label_color,
                );
                let right_anchor = pos + egui::vec2(r + 4.0, 0.0);
                let right_rect = egui::Align2::LEFT_CENTER.anchor_rect(
                    egui::Rect::from_min_size(right_anchor, galley.size()),
                );
                let label_rect = if right_rect.right() <= rect.right() - 2.0 {
                    right_rect
                } else {
                    // `Align2::RIGHT_CENTER.anchor_rect(rect)` already
                    // positions the result so its right-center sits at
                    // `rect.min`; passing `left_anchor` directly puts
                    // the label's right edge just left of the node.
                    let left_anchor = pos - egui::vec2(r + 4.0, 0.0);
                    egui::Align2::RIGHT_CENTER.anchor_rect(
                        egui::Rect::from_min_size(left_anchor, galley.size()),
                    )
                };
                painter.rect_filled(
                    label_rect.expand2(egui::vec2(3.0, 1.0)),
                    2.0,
                    label_bg,
                );
                painter.galley(label_rect.min, galley, label_color);
            }

            if let Some(hp) = hover_pos {
                if (hp - pos).length() < r + 8.0 {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    if response.clicked() {
                        clicked = Some(node.frag_id);
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
            let hint_galley =
                painter.layout_no_wrap(hint_label.to_string(), hint_font, hint_color);
            let meta_galley =
                painter.layout_no_wrap(meta_label, meta_font, meta_color);
            let hint_pos = egui::pos2(right - hint_galley.size().x, top);
            painter.galley(hint_pos, hint_galley, hint_color);
            let meta_pos = egui::pos2(
                hint_pos.x - gap - meta_galley.size().x,
                top,
            );
            painter.galley(meta_pos, meta_galley, meta_color);
        }

        (clicked, rect)
    }
}

// ── link interception ────────────────────────────────────────────────

/// A clicked URL in a rendered typst fragment that the viewer should
/// handle internally (rather than letting egui open it in a browser).
enum LinkClick {
    /// `wiki:<hex>` link — `Id` is either a fragment or a version id.
    Wiki(Id),
    /// `files:<hex>` link — `String` is the 32/64-char hex payload.
    File(String),
}

/// Render typst `content` into `ctx` and intercept any `wiki:` / `files:`
/// URL open commands it emitted. Returns the last click seen (or `None`).
///
/// Egui emits link clicks as `OutputCommand::OpenUrl` entries on its
/// output queue; we peek at the commands added during `ctx.typst(…)`,
/// keep the non-matching ones (so e.g. `https:` links still open the
/// browser), and pull out the `wiki:` / `files:` ones as `LinkClick`s.
fn render_wiki_content(ctx: &mut CardCtx<'_>, content: &str) -> Option<LinkClick> {
    let cmd_count_before = ctx.ctx().output(|o| o.commands.len());
    ctx.typst(content);

    let mut clicked = None;
    ctx.ctx().output_mut(|o| {
        let new_commands: Vec<egui::OutputCommand> =
            o.commands.drain(cmd_count_before..).collect();
        for cmd in new_commands {
            match &cmd {
                egui::OutputCommand::OpenUrl(open_url) => {
                    if let Some(hex) = open_url.url.strip_prefix("wiki:") {
                        if let Some(id) = Id::from_hex(hex) {
                            clicked = Some(LinkClick::Wiki(id));
                        } else {
                            eprintln!(
                                "[wiki] link click: wiki:{hex} ({} chars) → failed to parse as Id (expected 32 hex chars)",
                                hex.len()
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

/// An open wiki page — tracks which version is being viewed.
struct OpenPage {
    frag_id: Id,
    /// `None` = show latest version.
    pinned_version: Option<Id>,
}

// ── widget ───────────────────────────────────────────────────────────

/// GORBIE-embeddable wiki viewer.
///
/// Holds pure UI state plus a cached query snapshot. The wiki workspace
/// (and optionally a files workspace, for `files:` link resolution) are
/// passed in at render time; the viewer refreshes its cached fact space
/// whenever the wiki workspace's head advances.
///
/// ```ignore
/// let mut viewer = WikiViewer::default();
/// // Inside a GORBIE card, with `wiki_ws` and optional `files_ws`:
/// viewer.render(ctx, wiki_ws, files_ws);
/// ```
#[derive(Default)]
pub struct WikiViewer {
    search_query: String,
    /// Last search miss (for the "no match" chip). Cleared whenever
    /// the query text is edited.
    search_miss: Option<String>,
    /// Rebuilt when the wiki workspace's head advances.
    live: Option<WikiLive>,
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

    /// Render the viewer into a GORBIE card context. `wiki_ws` must point
    /// at the wiki branch; `files_ws` is optional — when provided, the
    /// viewer will resolve `files:<hex>` links and open the resulting
    /// blobs via the platform `open` command.
    pub fn render(
        &mut self,
        ctx: &mut CardCtx<'_>,
        wiki_ws: &mut Workspace<Pile>,
        mut files_ws: Option<&mut Workspace<Pile>>,
    ) {
        ctx.section("Wiki", |ctx| {
        // Refresh cached spaces if the wiki head has advanced since the
        // last frame (push happened, external write, or first render).
        let wiki_head = wiki_ws.head();
        let files_head = files_ws.as_ref().and_then(|ws| ws.head());
        let need_refresh = match self.live.as_ref() {
            None => true,
            Some(l) => l.cached_head != wiki_head || l.files_cached_head != files_head,
        };
        if need_refresh {
            self.live = Some(WikiLive::refresh(
                wiki_ws,
                files_ws.as_mut().map(|w| &mut **w),
            ));
            self.graph = None;
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
            self.graph = Some(WikiGraph::from_wiki(live, wiki_ws));
        }
        // Empty state when the wiki branch has no fragments at all —
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
                    egui::RichText::new("No fragments in this wiki branch")
                        .monospace()
                        .small()
                        .strong()
                        .color(muted),
                );
                ui.add_space(2.0);
                ui.label(
                    egui::RichText::new(
                        "Create one via `faculties/wiki.rs create` and reopen the pile.",
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
            if let Some(frag_id) = clicked_node {
                if !self.open_pages.iter().any(|p| p.frag_id == frag_id) {
                    self.open_pages.push(OpenPage {
                        frag_id,
                        pinned_version: None,
                    });
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
                                            "Open fragment by hex prefix or title (Enter)",
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
        // against the wiki index or falls back to title-substring
        // search; opens a floating page on match, shows a
        // "No match" banner under the viewport on miss.
        if let Some(q) = submit_query {
            let is_hex = !q.is_empty() && q.chars().all(|c| c.is_ascii_hexdigit());
            let found = if is_hex {
                live.resolve_prefix(&q)
            } else {
                let q_lower = q.to_lowercase();
                let frags = live.fragments_sorted(wiki_ws);
                frags
                    .iter()
                    .find(|(_, vid)| live.title(wiki_ws, *vid).to_lowercase().contains(&q_lower))
                    .map(|(frag_id, _)| *frag_id)
            };
            if let Some(frag_id) = found {
                if !self.open_pages.iter().any(|p| p.frag_id == frag_id) {
                    self.open_pages.push(OpenPage {
                        frag_id,
                        pinned_version: None,
                    });
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
        let open_snapshot: Vec<(Id, Option<Id>)> = self
            .open_pages
            .iter()
            .map(|p| (p.frag_id, p.pinned_version))
            .collect();
        let mut to_close: Vec<Id> = Vec::new();
        let mut to_open_from_link: Vec<Id> = Vec::new();
        let mut to_open_file: Vec<String> = Vec::new();
        let mut version_nav: Option<(Id, Option<Id>)> = None; // (frag_id, new_pinned)

        for (frag_id, pinned) in open_snapshot.into_iter() {
            let frag_bytes: &[u8] = frag_id.as_ref();
            let mut frag_key = [0u8; 16];
            frag_key.copy_from_slice(frag_bytes);

            let history = live.version_history(frag_id);
            let vid = pinned.or_else(|| live.latest_version(frag_id));
            let title = vid.map(|v| live.title(wiki_ws, v)).unwrap_or_default();
            let content = vid.map(|v| live.content(wiki_ws, v)).unwrap_or_default();
            let current_idx = vid.and_then(|v| history.iter().position(|&h| h == v));
            let n_versions = history.len();

            ctx.push_id(frag_key, |ctx| {
                let resp = ctx.float(|ctx| {
                    ctx.grid(|g| {
                        if vid.is_none() {
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
                                    egui::RichText::new(format!("wiki:{frag_id:x}"))
                                        .monospace()
                                        .small()
                                        .color(frag_color(frag_id)),
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
                        let frag_col = frag_color(frag_id);

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
                                    frag_col,
                                );
                                ui.add(
                                    egui::Label::new(egui::RichText::new(&title).heading())
                                        .wrap(),
                                );
                            });
                        });

                        // Meta row: multi-cell grid split. (DIAGNOSTIC)
                        if n_versions <= 1 {
                            g.full(|ctx| {
                                ctx.label(
                                    egui::RichText::new(format!("wiki:{frag_id:x}"))
                                        .monospace()
                                        .small()
                                        .color(frag_col),
                                );
                            });
                        } else {
                            let vi = current_idx.unwrap_or(0);
                            let at_latest = pinned.is_none();
                            let back_enabled = vi + 1 < n_versions;
                            let fwd_enabled = vi > 0 || pinned.is_some();
                            let ver_label = if pinned.is_some() {
                                format!("v{}/{}", n_versions - vi, n_versions)
                            } else {
                                format!("v{} · LATEST", n_versions)
                            };

                            g.place(6, |ctx| {
                                ctx.label(
                                    egui::RichText::new(format!("wiki:{frag_id:x}"))
                                        .monospace()
                                        .small()
                                        .color(frag_col),
                                );
                            });
                            g.place(3, |ctx| {
                                // Right-align so the label sits flush against
                                // the ◀ button across just one gutter, with
                                // vertical centering against the taller
                                // button cells in the same row. The grid's
                                // frame-delayed row sizing bounds the cell
                                // height to the row's actual height, so the
                                // `Center` cross-align doesn't drift.
                                ctx.ui_mut().with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            egui::RichText::new(ver_label)
                                                .monospace()
                                                .small()
                                                .strong(),
                                        );
                                    },
                                );
                            });
                            g.place(1, |ctx| {
                                if ctx
                                    .ui_mut()
                                    .add_enabled(
                                        back_enabled,
                                        GORBIE::widgets::Button::new("◀").columns(1),
                                    )
                                    .on_hover_text("Older version")
                                    .clicked()
                                {
                                    version_nav =
                                        Some((frag_id, Some(history[vi + 1])));
                                }
                            });
                            g.place(1, |ctx| {
                                if ctx
                                    .ui_mut()
                                    .add_enabled(
                                        fwd_enabled,
                                        GORBIE::widgets::Button::new("▶").columns(1),
                                    )
                                    .on_hover_text("Newer version")
                                    .clicked()
                                {
                                    if vi > 0 {
                                        version_nav =
                                            Some((frag_id, Some(history[vi - 1])));
                                    } else {
                                        version_nav = Some((frag_id, None));
                                    }
                                }
                            });
                            g.place(1, |ctx| {
                                if ctx
                                    .ui_mut()
                                    .add_enabled(
                                        !at_latest,
                                        GORBIE::widgets::Button::new("↻").columns(1),
                                    )
                                    .on_hover_text("Jump to latest")
                                    .clicked()
                                {
                                    version_nav = Some((frag_id, None));
                                }
                            });
                        }

                        g.full(|ctx| { ctx.separator(); });

                        g.full(|ctx| {
                            match render_wiki_content(ctx, &content) {
                                Some(LinkClick::Wiki(id)) => to_open_from_link.push(id),
                                Some(LinkClick::File(hex)) => to_open_file.push(hex),
                                None => {}
                            }
                        });
                    });
                });
                if resp.closed {
                    to_close.push(frag_id);
                }
            });
        }

        for id in to_close {
            self.open_pages.retain(|p| p.frag_id != id);
        }
        if let Some((frag_id, new_pinned)) = version_nav {
            if let Some(page) = self.open_pages.iter_mut().find(|p| p.frag_id == frag_id) {
                page.pinned_version = new_pinned;
            }
        }
        for id in to_open_from_link {
            let frag = live.to_fragment(id).unwrap_or(id);
            // Move to top if already open, otherwise open new.
            self.open_pages.retain(|p| p.frag_id != frag);
            self.open_pages.push(OpenPage {
                frag_id: frag,
                pinned_version: None,
            });
        }
        for hex in to_open_file {
            live.open_file(files_ws.as_mut().map(|w| &mut **w), &hex);
        }
        });
    }
}
