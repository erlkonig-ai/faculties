use super::{operations::remember_range, Imagine, ModelSources, Options, Variant};
use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version = crate::GIT_VERSION, name = "imagine", about = "Generate an image with the local FLUX.2 pipeline")]
struct Cli {
    /// Literal prompt, @file, @- stdin, or @@escaped leading at-sign.
    prompt: Option<String>,
    #[arg(long, conflicts_with = "dev")]
    klein: bool,
    #[arg(long)]
    dev: bool,
    #[arg(long)]
    steps: Option<usize>,
    #[arg(long, default_value_t = 0)]
    seed: u64,
    #[arg(long, default_value_t = 1024)]
    width: usize,
    #[arg(long, default_value_t = 1024)]
    height: usize,
    #[arg(long, default_value_t = 4.0)]
    guidance: f32,
    /// Save original PNG here; otherwise /tmp/imagine/<timestamp>_<seed>.png.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Explicit TAI timestamp or from..to Memory range; requires a configured pile.
    #[arg(long)]
    remember: Option<String>,
    #[arg(long, env = "PILE")]
    pile: Option<PathBuf>,
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
}
pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let Some(prompt) = cli.prompt else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };
    // A disabled generator must not acquire a file or wait for stdin first.
    anyhow::ensure!(
        cfg!(feature = "imagine"),
        "image generation requires a build with the `imagine` feature"
    );
    let options = Options {
        prompt: crate::text_arg(&prompt, "image prompt")?,
        variant: if cli.dev {
            Variant::Dev
        } else {
            Variant::Klein
        },
        steps: cli.steps,
        seed: cli.seed,
        width: cli.width,
        height: cli.height,
        guidance: cli.guidance,
    };
    options.validate()?;
    let remember = cli
        .remember
        .as_deref()
        .map(|raw| {
            let pile = cli
                .pile
                .clone()
                .context("--remember requires --pile or PILE")?;
            Ok::<_, anyhow::Error>((
                crate::memory::Memory::new(pile, cli.key.clone()),
                remember_range(raw)?,
            ))
        })
        .transpose()?;
    let generated = Imagine::new(ModelSources::from_environment()).generate(&options)?;
    let path = match cli.out {
        Some(path) => path,
        None => PathBuf::from(format!(
            "/tmp/imagine/{}_{}.png",
            crate::clock::tai_nanoseconds_now()?,
            cli.seed
        )),
    };
    generated.save(&path)?;
    eprintln!("imagine: {}", generated.diagnostic());
    crate::cli::with_output("imagine", |out| {
        // Plain CLI keeps its useful readable artifact path; a configured Drive
        // receives the actual image as well as the saved-file receipt.
        if std::env::var_os("DRIVE_ENDPOINT").is_some() {
            out.image(generated.png.clone(), "image/png")?;
        }
        out.line(path.display().to_string())
    })?;
    if let Some((memory, range)) = remember {
        let receipt = memory
            .image(generated.png.as_ref(), range)
            .with_context(|| {
                format!(
                    "remembering failed; generated PNG remains at {}",
                    path.display()
                )
            })?;
        crate::cli::with_output("imagine", |out| receipt.emit(out))?;
    }
    Ok(())
}
