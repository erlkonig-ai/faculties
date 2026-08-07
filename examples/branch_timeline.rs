//! Minimal GORBIE notebook that embeds `faculties::widgets::BranchTimeline`.
//!
//! Run against a pile whose viewer catalog provides the wiki dataset:
//!
//! ```ignore
//! cargo run --example branch_timeline --features widgets -- ./self.pile
//! ```
//!
//! Or set `PILE=./self.pile` in the environment.

use std::path::PathBuf;

use faculties::widgets::{BranchTimeline, SourceKey, StorageState, TimelineSource};
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
    let storage = nb.state("storage", StorageState::new(pile_path), |ctx, st| {
        st.top_bar(ctx);
    });

    nb.view(|ctx| {
        ctx.grid(|g| {
            g.full(|ctx| {
                ctx.markdown("# Activity Timeline\nPan/zoom time axis of semantic pile data.");
            });
        });
    });

    nb.state(
        "timeline",
        BranchTimeline::multi(vec![TimelineSource::Wiki {
            key: SourceKey::Wiki,
            label: "wiki".into(),
        }]),
        move |ctx, tl| {
            let mut st = storage.read_mut(ctx);
            tl.render(ctx, &st.context());
        },
    );
}
