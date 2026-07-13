//! Unified pile inspector: composes all four faculty widgets with a
//! single shared pile-path selector via `StorageState`.
//!
//! Run against a pile that has a `wiki`, `compass`, and `message`
//! branch:
//!
//! ```ignore
//! cargo run --example pile_inspector --features widgets -- ./self.pile
//! ```
//!
//! Or set `PILE=./self.pile` in the environment.

use std::path::PathBuf;

use faculties::widgets::{
    BranchTimeline, CompassBoard, MessagesPanel, StorageState, TimelineSource, WikiViewer,
};
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::Workspace;
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
            // Pull a fresh workspace per source each frame.
            let branch_names: &[&str] = &["compass", "message", "wiki"];
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

    nb.state("messages", MessagesPanel::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("message") else { return };
        let mut relations = st.workspace("relations");
        panel.render(ctx, &mut ws, relations.as_mut());
        st.push(&mut ws);
    });
}
