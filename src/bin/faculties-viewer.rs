//! GORBIE-backed viewer for a faculties pile.
//!
//! Composes the `wiki`, `compass`, `local-messages`, and activity-
//! timeline widgets against a single shared pile — the GUI
//! counterpart to the CLI faculties in the repo root.
//!
//! Usage:
//! ```sh
//! cargo install faculties --features widgets
//! faculties-viewer ./self.pile
//! # or set PILE=./self.pile in the environment; anything passed
//! # on the command line (--pile <path> or positional) beats it
//! ```
//!
//! This mirrors `examples/pile_inspector.rs`; the example is kept as
//! a source reference for library users composing their own
//! notebook layouts.

use std::path::PathBuf;

use faculties::widgets::{
    AtlasViewer, BranchTimeline, CompassBoard, DecidePanel, DiscordViewer, FilesViewer,
    GaugeViewer, HeadspaceViewer, MailViewer, MemoryViewer, MessagesPanel, PlannerViewer,
    RelationsViewer, StorageState, TeamsViewer, TimelineSource, TriageViewer, WikiViewer,
};
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::Workspace;
use triblespace::core::inline::encodings::hash::Blake3;
use GORBIE::notebook;
use GORBIE::prelude::*;

fn resolve_pile_path() -> PathBuf {
    // Precedence: --pile > positional > PILE env > ./self.pile —
    // anything explicit on the command line beats the ambient env.
    // The scan skips the values of value-taking flags (#[notebook]'s
    // `--out-dir <path>`, etc.) so they can't be misread as the
    // positional pile path.
    const VALUE_FLAGS: &[&str] = &[
        "--pile",
        "--out-dir",
        "--export-dir",
        "--scale",
        "--headless-wait-ms",
    ];
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut flagged = None;
    let mut positional = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--pile" {
            flagged = args.get(i + 1).cloned();
            i += 2;
            continue;
        }
        if VALUE_FLAGS.contains(&a) {
            i += 2; // skip the flag's value token
            continue;
        }
        if !a.starts_with("--") && positional.is_none() {
            positional = Some(args[i].clone());
        }
        i += 1;
    }
    flagged
        .or(positional)
        .or_else(|| std::env::var("PILE").ok())
        .unwrap_or_else(|| "./self.pile".to_owned())
        .into()
}

#[notebook]
fn main(nb: &mut NotebookCtx) {
    let path = resolve_pile_path();

    let storage = nb.state("storage", StorageState::new(path), |ctx, st| {
        // Dashboard-style notebook: every widget section starts
        // collapsed so the initial view is a scannable list of
        // section headers instead of kilometres of open cards. A
        // user's toggle is persisted per section and wins over this
        // default on subsequent runs. (The *-capture bins don't set
        // this, so headless screenshots still render open.)
        GORBIE::card_ctx::set_default_section_open(ctx.ctx(), false);
        st.top_bar(ctx);
    });

    nb.state("headspace", HeadspaceViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("config") else { return };
        panel.render(ctx, &mut ws);
        st.push(&mut ws);
    });

    nb.state(
        "timeline",
        BranchTimeline::multi(vec![
            TimelineSource::Compass {
                label: "goals".to_owned(),
            },
            TimelineSource::LocalMessages {
                label: "local".to_owned(),
            },
            TimelineSource::Wiki {
                label: "wiki".to_owned(),
            },
            TimelineSource::Reason {
                label: "reason".to_owned(),
            },
            TimelineSource::Archive {
                label: "archive".to_owned(),
            },
        ]),
        move |ctx, tl| {
            let mut st = storage.read_mut(ctx);
            // Branches are positional w.r.t. the TimelineSource vec
            // above. Missing branches at the tail are handled cleanly
            // by MultiLive (workspaces.get_mut(idx) returning None
            // → the corresponding source is skipped for the frame),
            // so e.g. an empty archive branch produces no archive
            // events without breaking the others.
            let branch_names: &[&str] =
                &["compass", "local-messages", "wiki", "cognition", "archive"];
            let mut pulled: Vec<(&str, Workspace<Pile>)> =
                Vec::with_capacity(branch_names.len());
            for name in branch_names {
                if let Some(ws) = st.workspace(name) {
                    pulled.push((*name, ws));
                }
            }
            let mut slots: Vec<(&str, &mut Workspace<Pile>)> =
                pulled.iter_mut().map(|(n, ws)| (*n, ws)).collect();
            tl.render(ctx, slots.as_mut_slice());
        },
    );

    nb.state("gauge", GaugeViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("wiki") else { return };
        panel.render(ctx, &mut ws);
        st.push(&mut ws);
    });

    nb.state("wiki", WikiViewer::default(), move |ctx, wiki| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("wiki") else { return };
        let mut files = st.workspace("files");
        wiki.render(ctx, &mut ws, files.as_mut());
        st.push(&mut ws);
    });

    nb.state("compass", CompassBoard::default(), move |ctx, compass| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("compass") else { return };
        compass.render(ctx, &mut ws);
        st.push(&mut ws);
    });

    nb.state("decide", DecidePanel::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("decide") else { return };
        panel.render(ctx, &mut ws);
        st.push(&mut ws);
    });

    nb.state("mail", MailViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("mail") else { return };
        let mut relations = st.workspace("relations");
        panel.render(ctx, &mut ws, relations.as_mut());
        st.push(&mut ws);
    });

    nb.state("planner", PlannerViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("planner") else { return };
        let mut relations = st.workspace("relations");
        panel.render(ctx, &mut ws, relations.as_mut());
        st.push(&mut ws);
    });

    nb.state("messages", MessagesPanel::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("local-messages") else { return };
        let mut relations = st.workspace("relations");
        panel.render(ctx, &mut ws, relations.as_mut());
        st.push(&mut ws);
    });

    nb.state("discord", DiscordViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("discord") else { return };
        panel.render(ctx, &mut ws);
        st.push(&mut ws);
    });

    nb.state("teams", TeamsViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("teams") else { return };
        panel.render(ctx, &mut ws);
        st.push(&mut ws);
    });

    nb.state("relations", RelationsViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("relations") else { return };
        panel.render(ctx, &mut ws);
        st.push(&mut ws);
    });

    nb.state("memory", MemoryViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        // Try the canonical `memory` branch first; fall back to
        // `cognition` for piles seeded before memory split out.
        let ws = st.workspace("memory").or_else(|| st.workspace("cognition"));
        let Some(mut ws) = ws else { return };
        panel.render(ctx, &mut ws);
        st.push(&mut ws);
    });

    nb.state("files", FilesViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("files") else { return };
        panel.render(ctx, &mut ws);
        st.push(&mut ws);
    });

    nb.state("triage", TriageViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("cognition") else { return };
        panel.render(ctx, &mut ws);
        st.push(&mut ws);
    });

    nb.state("atlas", AtlasViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("atlas") else { return };
        panel.render(ctx, &mut ws);
        st.push(&mut ws);
    });
}
