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
    BranchTimeline, CompassBoard, MessagesPanel, SourceKey, StorageState, TimelineSource,
    WikiViewer,
};
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
                key: SourceKey::Compass,
                label: "goals".to_owned(),
            },
            TimelineSource::LocalMessages {
                key: SourceKey::Messages,
                label: "local".to_owned(),
            },
            TimelineSource::Wiki {
                key: SourceKey::Wiki,
                label: "wiki".to_owned(),
            },
        ]),
        move |ctx, tl| {
            let mut st = storage.read_mut(ctx);
            let sources = st.context();
            tl.render(ctx, &sources);
        },
    );

    nb.state("wiki", WikiViewer::default(), move |ctx, wiki| {
        let mut st = storage.read_mut(ctx);
        let sources = st.context();
        let Some(view) = sources.dataset(SourceKey::Wiki) else {
            return;
        };
        wiki.render(ctx, view, sources.dataset(SourceKey::Files));
    });

    nb.state("compass", CompassBoard::default(), move |ctx, compass| {
        let mut st = storage.read_mut(ctx);
        let Some(view) = st.context().dataset(SourceKey::Compass) else {
            return;
        };
        compass.render(ctx, view);
    });

    nb.state("messages", MessagesPanel::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let sources = st.context();
        let Some(view) = sources.dataset(SourceKey::Messages) else {
            return;
        };
        panel.render(ctx, view, sources.dataset(SourceKey::Relations));
    });
}
