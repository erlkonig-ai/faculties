//! GORBIE-backed viewer for a faculties pile.
//!
//! Composes the faculty dashboard widgets against a single shared
//! pile — the GUI counterpart to the CLI faculties in the repo root.
//!
//! Usage:
//! ```sh
//! cargo install faculties --features widgets
//! viewer ./self.pile
//! # or set PILE=./self.pile in the environment; anything passed
//! # on the command line (--pile <path> or positional) beats it
//! ```
//!
//! `examples/pile_inspector.rs` is a smaller source reference for
//! library users composing their own notebook layouts.

fn main() -> anyhow::Result<()> {
    faculties::viewer::cli::run(env!("CARGO_BIN_NAME"), notebook)
}

#[GORBIE::notebook]
fn notebook(nb: &mut GORBIE::NotebookCtx) {
    faculties::viewer::compose(
        nb,
        &faculties::viewer::cli::configuration_from_env(),
        faculties::viewer::Target::Dashboard,
    );
}
