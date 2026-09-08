//! Minimal capture target for iterating on the planner widget in
//! isolation. The full `viewer` pulls in the wiki widget
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

fn main() -> anyhow::Result<()> {
    faculties::viewer::cli::run(env!("CARGO_BIN_NAME"), notebook)
}

#[GORBIE::notebook]
fn notebook(nb: &mut GORBIE::NotebookCtx) {
    faculties::viewer::compose(
        nb,
        &faculties::viewer::cli::configuration_from_env(),
        faculties::viewer::Target::Planner,
    );
}
