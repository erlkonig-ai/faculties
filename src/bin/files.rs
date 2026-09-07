use anyhow::Result;

use faculties::files::cli::{execute, SPEC};

fn main() -> Result<()> {
    faculties::cli::run(&SPEC, execute)
}
