use anyhow::Result;

use faculties::atlas::command::{execute, SPEC};

fn main() -> Result<()> {
    faculties::cli::run(&SPEC, execute)
}
