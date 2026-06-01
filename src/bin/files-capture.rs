//! Minimal capture target for iterating on the files widget.

use std::path::PathBuf;

use faculties::widgets::{FilesViewer, StorageState};
use GORBIE::notebook;
use GORBIE::prelude::*;

fn resolve_pile_path() -> PathBuf {
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

    nb.state("files", FilesViewer::default(), move |ctx, panel| {
        let mut st = storage.read_mut(ctx);
        let Some(mut ws) = st.workspace("files") else { return };
        panel.render(ctx, &mut ws);
        st.push(&mut ws);
    });
}
