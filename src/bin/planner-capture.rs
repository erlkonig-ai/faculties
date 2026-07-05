//! Minimal capture target for iterating on the planner widget in
//! isolation. The full `faculties-viewer` pulls in the wiki widget
//! which initialises its own cubecl/wgpu GPU context — that collides
//! with the headless wgpu renderer on some platforms and produces
//! 2-pixel-tall stub PNGs for every card after wiki.
//!
//! Usage:
//! ```sh
//! cargo build --release --bin planner-capture --features widgets
//! PILE=./self.pile target/release/planner-capture --headless \
//!   --out-dir /tmp/planner-capture --scale 2 --headless-wait-ms 2000
//! ```

use std::path::PathBuf;

use faculties::widgets::{PlannerViewer, StorageState};
use GORBIE::notebook;
use GORBIE::prelude::*;

fn resolve_pile_path() -> PathBuf {
    // Handled before anything else so `--version` works without a pile or a
    // display. Prints crate version + baked git hash (the stale-binary question).
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!(
            "{} {} ({})",
            env!("CARGO_BIN_NAME"),
            env!("CARGO_PKG_VERSION"),
            env!("FACULTIES_GIT_VERSION"),
        );
        std::process::exit(0);
    }
    std::env::var("PILE")
        .ok()
        .or_else(|| {
            std::env::args()
                .skip(1)
                .find(|a| !a.starts_with("--"))
        })
        .unwrap_or_else(|| "./self.pile".to_owned())
        .into()
}

#[notebook]
fn main(nb: &mut NotebookCtx) {
    let path = resolve_pile_path();

    let storage = nb.state("storage", StorageState::new(path), |ctx, st| {
        st.top_bar(ctx);
    });

    nb.state("planner", PlannerViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("planner") else { return };
        let mut relations = st.workspace("relations");
        panel.render(ctx, &mut ws, relations.as_mut());
        st.push(&mut ws);
    });
}
