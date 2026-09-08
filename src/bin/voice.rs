//! Voice CLI; synthesis, policy, and explicit host playback live in the library.
fn main() -> anyhow::Result<()> {
    faculties::voice::cli::run()
}
