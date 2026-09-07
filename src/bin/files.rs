use anyhow::Result;

use faculties::files::command::{execute_cli, SPEC};

fn main() -> Result<()> {
    faculties::cli::run(&SPEC, execute_cli)
}
