use anyhow::Result;

use faculties::atlas::cli::{execute, SPEC};

fn main() -> Result<()> {
    faculties::cli::run(&SPEC, execute)
}
