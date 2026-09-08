//! Minimal capture target for iterating on the discord widget.

fn main() -> anyhow::Result<()> {
    faculties::viewer::cli::run(env!("CARGO_BIN_NAME"), notebook)
}

#[GORBIE::notebook]
fn notebook(nb: &mut GORBIE::NotebookCtx) {
    faculties::viewer::compose(
        nb,
        &faculties::viewer::cli::configuration_from_env(),
        faculties::viewer::Target::Discord,
    );
}
