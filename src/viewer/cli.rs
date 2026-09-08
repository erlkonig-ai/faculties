//! CLI-only notebook harness integration. GORBIE's macro remains in each thin
//! binary so its per-binary native/window/headless/web-export UX is preserved.
//! Help and version are handled before starting any window or GPU context.

use std::io::Write;

use anyhow::Result;

pub fn information(binary: &str, args: &[String]) -> Option<String> {
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        return Some(format!(
            "{} {} ({})\n",
            binary,
            env!("CARGO_PKG_VERSION"),
            env!("FACULTIES_GIT_VERSION")
        ));
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return Some(format!(
            "Usage: {binary} [PILE] [OPTIONS]\n\n\
             Open the shared faculty notebook; PILE defaults to $PILE or ./self.pile.\n\n\
             --pile PATH              Override positional/environment pile\n\
             --headless               Write PNG card captures instead of opening a window\n\
             --out-dir PATH           Capture directory (default gorbie_capture)\n\
             --scale NUMBER           Pixels per point (default 2)\n\
             --headless-wait-ms MS     Settle timeout per layout pass (default 2000)\n\
             --export                 Explicit web export (requires web-export feature)\n\
             --export-dir PATH        Explicit web export destination\n\
             -h, --help               Show this help without opening the pile or GPU\n\
             -V, --version            Show version without opening the pile or GPU\n"
        ));
    }
    None
}

/// The only global argument/terminal boundary; native operations do not call
/// this. The supplied notebook wrapper owns GORBIE's existing harness syntax.
pub fn run(binary: &str, notebook: impl FnOnce()) -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if let Some(info) = information(binary, &args) {
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(info.as_bytes())?;
        stdout.flush()?;
    } else {
        notebook();
    }
    Ok(())
}

#[cfg(feature = "widgets")]
pub fn configuration_from_env() -> super::Viewer {
    super::Viewer::new(
        crate::widgets::resolve_pile_path(std::env::args().skip(1), std::env::var("PILE").ok()),
        None,
    )
}
