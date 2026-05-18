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
//! # or set PILE=./self.pile in the environment
//! ```
//!
//! This mirrors `examples/pile_inspector.rs`; the example is kept as
//! a source reference for library users composing their own
//! notebook layouts.

use std::path::PathBuf;

use faculties::widgets::{
    BranchTimeline, CompassBoard, DecidePanel, MailViewer, MessagesPanel, PlannerViewer,
    RelationsViewer, StorageState, TimelineSource, WikiViewer,
};
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::Workspace;
use triblespace::core::inline::encodings::hash::Blake3;
use GORBIE::notebook;
use GORBIE::prelude::*;

fn resolve_pile_path() -> PathBuf {
    std::env::args()
        .nth(1)
        .or_else(|| std::env::var("PILE").ok())
        .unwrap_or_else(|| "./self.pile".to_owned())
        .into()
}

#[notebook]
fn main(nb: &mut NotebookCtx) {
    let path = resolve_pile_path();

    let storage = nb.state("storage", StorageState::new(path), |ctx, st| {
        st.top_bar(ctx);
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
        ]),
        move |ctx, tl| {
            let mut st = storage.read_mut(ctx);
            let branch_names: &[&str] = &["compass", "local-messages", "wiki"];
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

    nb.state("relations", RelationsViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("relations") else { return };
        panel.render(ctx, &mut ws);
        st.push(&mut ws);
    });
}
