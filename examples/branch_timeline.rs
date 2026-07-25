//! Minimal GORBIE notebook that embeds `faculties::widgets::BranchTimeline`.
//!
//! Run against a pile with a named branch:
//!
//! ```ignore
//! cargo run --example branch_timeline --features widgets -- ./self.pile wiki
//! ```
//!
//! Or set `PILE=./self.pile` and `BRANCH=wiki` in the environment.

use std::path::PathBuf;

use faculties::widgets::{BranchTimeline, StorageState};
use GORBIE::notebook;
use GORBIE::prelude::*;

#[notebook]
fn main(nb: &mut NotebookCtx) {
    let mut args = std::env::args().skip(1);
    let pile_path: PathBuf = args
        .next()
        .or_else(|| std::env::var("PILE").ok())
        .unwrap_or_else(|| "./self.pile".to_owned())
        .into();
    let branch = args
        .next()
        .or_else(|| std::env::var("BRANCH").ok())
        .unwrap_or_else(|| "wiki".to_owned());

    let storage = nb.state("storage", StorageState::new(pile_path), |ctx, st| {
        st.top_bar(ctx);
    });

    nb.view(|ctx| {
        ctx.grid(|g| {
            g.full(|ctx| {
                ctx.markdown("# Branch Timeline\nPan/zoom time axis of commits on a pile branch.");
            });
        });
    });

    let branch_for_render = branch.clone();
    nb.state("timeline", BranchTimeline::new(branch), move |ctx, tl| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace(&branch_for_render) else {
            return;
        };
        tl.render(ctx, &mut [(branch_for_render.as_str(), &mut ws)]);
    });
}
