//! Minimal capture target for iterating on the discord widget.

use std::path::PathBuf;

use faculties::widgets::{DiscordViewer, SourceKey, StorageState};
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
    faculties::widgets::resolve_pile_path(std::env::args().skip(1), std::env::var("PILE").ok())
}

#[notebook]
fn main(nb: &mut NotebookCtx) {
    let path = resolve_pile_path();

    let storage = nb.state(
        "storage",
        StorageState::for_sources(path, [SourceKey::Discord]),
        |ctx, st| {
            st.top_bar(ctx);
        },
    );

    nb.state("discord", DiscordViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(view) = st.context().dataset(SourceKey::Discord) else {
            return;
        };
        panel.render(ctx, view);
    });
}
