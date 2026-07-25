//! Minimal GORBIE notebook that embeds `faculties::widgets::CompassBoard`.
//!
//! Run against a pile that has a `compass` branch:
//!
//! ```ignore
//! cargo run --example compass_board --features widgets -- ./self.pile
//! ```
//!
//! Or set `PILE=./self.pile` in the environment. A non-default branch name
//! can be passed as the second positional argument or via `BRANCH=<name>`.

use std::path::PathBuf;

use faculties::widgets::{CompassBoard, StorageState};
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
        .unwrap_or_else(|| "compass".to_owned());

    let storage = nb.state("storage", StorageState::new(pile_path), |ctx, st| {
        st.top_bar(ctx);
    });

    nb.view(|ctx| {
        ctx.grid(|g| {
            g.full(|ctx| {
                ctx.markdown("# Compass Board\nKanban view of goals on a pile's compass branch.");
            });
        });
    });

    nb.state("compass", CompassBoard::default(), move |ctx, board| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace(&branch) else {
            return;
        };
        board.render(ctx, &mut ws);
        st.push(&mut ws);
    });
}
