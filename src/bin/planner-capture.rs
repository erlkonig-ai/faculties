//! Minimal capture target for iterating on the planner widget in
//! isolation.
//!
//! It exists because the full `viewer` pulled in the wiki widget, which
//! initialised its own cubecl/wgpu GPU context — that collided with the
//! headless wgpu renderer on some platforms and produced 2-pixel-tall stub
//! PNGs for every card after wiki. **That context is gone**: the graph layout
//! moved to the CPU in `GORBIE::graph`, so the wiki widget no longer opens a
//! device of its own and the collision has no cause left. Whether the full
//! viewer now captures cleanly has not been re-run; if it does, this target is
//! redundant except as a faster loop on one widget.
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
