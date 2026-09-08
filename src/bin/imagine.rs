//! Image-generation CLI; native operations and MCP live in the library.
fn main() -> anyhow::Result<()> {
    faculties::imagine::cli::run()
}
