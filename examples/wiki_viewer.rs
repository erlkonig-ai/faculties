//! Minimal GORBIE notebook that embeds `faculties::widgets::WikiViewer`.
//!
//! Run against a pile that has a `wiki` branch:
//!
//! ```ignore
//! cargo run --example wiki_viewer --features widgets -- ./self.pile
//! ```
//!
//! Or set `PILE=./self.pile` in the environment.

use std::path::PathBuf;

use faculties::widgets::{StorageState, WikiViewer};
use GORBIE::notebook;
use GORBIE::prelude::*;

#[notebook]
fn main(nb: &mut NotebookCtx) {
    let pile_path: PathBuf = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("PILE").ok())
        .unwrap_or_else(|| "./self.pile".to_owned())
        .into();

    let storage = nb.state("storage", StorageState::new(pile_path), |ctx, st| {
        st.top_bar(ctx);
    });

    nb.view(|ctx| {
        ctx.grid(|g| {
            g.full(|ctx| {
                ctx.markdown("# Wiki Viewer\nBrowse wiki fragments stored in a TribleSpace pile.");
            });
        });
    });

    nb.state("wiki", WikiViewer::default(), move |ctx, viewer| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("wiki") else {
            return;
        };
        let files = st.files_view();
        viewer.render(ctx, &mut ws, files);
        st.push(&mut ws);
    });
}
