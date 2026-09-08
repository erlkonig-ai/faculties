//! Tailored memory CLI grammar and host-only input/cache UX.
use super::operations::{parse_tai_timestamp, parse_time_range};
use super::{ChurnOptions, Memory};
use crate::memory_cover::{CoverOpts, CoverReport, DEFAULT_SIM_THRESHOLD};
use crate::out::Out;
use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser};
use hifitime::Epoch;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "memory",
    about = "Show compacted context chunks (drill down by narrowing the time range).\n\n\
             Subcommands:\n  \
             memory <from>..<to>              — show best summary covering a time range\n  \
             memory meta <from>..<to>         — show structural metadata for a time range\n  \
             memory context [<budget>] [--chars N] [--chunk-overhead N] [--about <query>] [--filter <query>] [--remove <query>] [--sim-threshold <f>] — density-shaped, deliberately lossy recollection over journaled time in greedy SPACE order, fit to a CHARACTER budget (bare <budget>, --chars N, or the --tokens N alias all count CHARACTERS — there is no token estimate). A continuous logarithmic-age gradient maps each candidate length to an ideal temporal slot and chooses the actual range whose endpoints match best; wide old arcs emerge from that shape rather than a special coverage rule, so gaps, overlap, wobbling temporal centres, and unsampled detail are valid while the pile remains lossless. --chunk-overhead charges N additional character-equivalents per selected chunk for consumer framing/tokenization without changing stored summaries or rendered text; --about chooses the recollection most relevant to <query> by MEANING only when multiple memories have exactly the same temporal coverage (semantic, via `memory embed`; otherwise exact lexical BM25 is rebuilt automatically) and never changes the temporal sampler; --filter <query> keeps ONLY chunks whose positive similarity to <query> exceeds --sim-threshold (default 0.55); --remove <query> is the anti-filter — drops chunks whose similarity EXCEEDS the threshold (negate in the retrieval, NOT the query text; do not phrase a negation). They compose. NOTE: gating is chunk-level — a surviving COARSE memory's pre-written summary may still mention removed material. Unembedded wordless images are kept (fail-open) with a stderr warning.\n  \
             memory cover start [--chars N] [--chunk-chars M] [--session KEY] — generate the context cover (exactly `memory context --chars N`; N=400000) and store it for cursor-chunked reading in ~M-char chunks (M=20000); state lives in `${XDG_CACHE_HOME:-~/.cache}/faculties/cover/<KEY>/`, NOT the pile\n  \
             memory cover continue [--session KEY] — print the next stored chunk and advance the cursor; the final chunk ends with `COVER COMPLETE K/K`\n  \
             memory cover status [--session KEY]  — one line: complete=<true|false> loaded=<i>/<K> chars=<X>/<Y>; exit 0 when complete, 1 when not (hook-friendly)\n  \
             memory cover reset [--session KEY]   — rewind the cursor to 0 (does NOT regenerate the stored cover)\n  \
             memory density [<grain>]        — inspect where the stored hierarchy is bushy, balanced, or coarse (a journal diagnostic; it does not drive recollection)\n  \
             memory search <query>           — exact lexical (BM25) search rebuilt from the frozen Memory view\n  \
             memory similar <query>           — semantic search: nearest chunks by MEANING in the shared nomic space (build/refresh with `memory embed`) [needs --features local-embed]\n  \
             memory lens [<theme>]            — thematic lenses beside the spine: list them, or print a theme's narratives (create with `create --lens <theme>`)\n  \
             memory list [<grain>]            — show chunk time-ranges only: containment outline, or one zoom layer (no content)\n  \
             memory check <grain>             — report coverage gaps at a coarseness level (chunks of width <= grain)\n  \
             memory churn [--chars N] [--steps K] [--step-units U] — replay density-shaped recollection over the pile's own observation history (K diagnostic steps back, default 160): per step the fill, previous rendered prefix surviving, and any unselected stretch longer than one quarter of LIFE\n  \
             memory create [<range>] <summary> — create a memory chunk\n  \
             memory respan <id> <from>..<to>  — the same memory over corrected time coordinates: a new chunk with the identical text supersedes the old one, which stands aside from the cover and stays readable by id\n  \
             memory respan-instants [--dry-run] — give every zero-length memory the span its own text names, or a moment ending at its stamp; turn inverted ranges forward; one commit\n  \
             memory respan-seams [--dry-run]    — close one-second and one-minute seams between arcs written with rounded edges (an hour or wider): a coordinate correction, one commit\n  \
             memory image <when> <image-path> — create a WORDLESS image memory at a time-coordinate (embed with `memory embed`; ranks in `memory similar` beside text) [needs --features local-embed to embed]\n  \
             memory consolidate start <ts> | <ts> <summary> | stop — write chunks from an advancing edge ($PERSONA cursor)\n  \
             memory replay start <grain> [<from>] | [<count>] | stop — stream the memory at a zoom level ($PERSONA cursor)\n  \
             memory provenance <chunk-id>     — list cognition + archive events overlapping the chunk's time range\n\n\
             Time format: YYYY-MM-DDTHH:MM:SS..YYYY-MM-DDTHH:MM:SS (TAI)\n\
             Hex id prefixes also accepted as fallback."
)]
pub struct Cli {
    /// Path to the pile file to use.
    #[arg(long, env = "PILE")]
    pub pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    pub key: Option<PathBuf>,
    /// One or more time ranges / id prefixes to show, or `turn <turn-id>`, or `create [<from>..<to>] <summary>`.
    #[arg(value_name = "ID", trailing_var_arg = true, allow_hyphen_values = true)]
    pub ids: Vec<String>,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let exit_code = crate::cli::with_output("memory", |out| execute(cli, out))?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// A nonzero successful value is the hook-friendly incomplete-cover status.
/// Output routing is finalized before run() applies that process exit code.
pub fn execute(cli: Cli, out: &mut Out<'_>) -> Result<i32> {
    if cli.ids.is_empty() {
        return out
            .line(Cli::command().render_long_help().to_string())
            .map(|()| 0);
    }
    let memory = Memory::new(cli.pile, cli.key);
    let args = &cli.ids[1..];
    let one = |usage: &str| -> Result<&str> {
        if args.len() != 1 {
            bail!("{usage}");
        }
        Ok(&args[0])
    };
    let dry_run = |usage: &str| -> Result<bool> {
        if args.iter().any(|arg| arg != "--dry-run") {
            bail!("{usage}");
        }
        Ok(!args.is_empty())
    };
    match cli.ids[0].as_str() {
        "create" => cmd_create(&memory, args, out),
        "respan" => cmd_respan(&memory, args, out),
        "respan-instants" => {
            memory.respan_instants(dry_run("usage: memory respan-instants [--dry-run]")?, out)
        }
        "respan-seams" => {
            memory.respan_seams(dry_run("usage: memory respan-seams [--dry-run]")?, out)
        }
        "image" => cmd_image(&memory, args, out),
        "meta" => memory.meta(one("usage: memory meta <id or range>")?, out),
        "provenance" => memory.provenance(one("usage: memory provenance <id>")?, out),
        "turn" => memory.turn(one("usage: memory turn <turn-id>")?, out),
        "consolidate" => cmd_consolidate(&memory, args, out),
        "replay" => cmd_replay(&memory, args, out),
        "search" => memory.search(&literal_or_input(args, "query")?, out),
        "similar" => memory.similar(&literal_or_input(args, "query")?, out),
        "embed" => memory.embed(out),
        "context" => out.text(report_text(memory.context(&context_options(args)?)?)),
        "cover" => return super::cli_cover::execute(&memory, args, out),
        "lens" => memory.lens(args.first().map(String::as_str), out),
        "list" => memory.list(args.first().map(String::as_str), out),
        "check" => memory.check(one("usage: memory check <grain>")?, out),
        "density" => memory.density(args.first().map(String::as_str), out),
        "churn" => memory.churn(&churn_options(args)?, out),
        _ => memory.show_many(&cli.ids, out),
    }?;
    Ok(0)
}

pub(super) fn report_text(report: CoverReport) -> String {
    for diagnostic in report.diagnostics {
        eprintln!("{diagnostic}");
    }
    report.text
}

fn literal_or_input(args: &[String], label: &str) -> Result<String> {
    match args {
        [single] => crate::text_arg(single, label),
        [] => bail!("{label} is required"),
        _ => Ok(args.join(" ")),
    }
}

fn cmd_create(memory: &Memory, args: &[String], out: &mut Out<'_>) -> Result<()> {
    // A help flag must never be minted as memory content — print usage and stop
    // before any parsing, so `memory create --help` explains itself instead of
    // storing the literal "--help" as a chunk.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        out.line(format!(
            "usage: memory create [--lens <theme>] [<from>..<to>] <summary...>\n\
             \n\
             Create a memory chunk and store it in the pile.\n\
             An optional time range as the first argument grounds the memory in\n\
             that period; without it, defaults to now. --lens <theme> files the\n\
             chunk as a thematic memory kept out of the chronological spine."
        ))?;
        return Ok(());
    }
    if args.is_empty() {
        bail!(
            "usage: memory create [<from>..<to>] <summary...>\n\
             \n\
             Create a memory chunk and store it in the pile.\n\
             An optional time range as the first argument grounds the\n\
             memory in that period. Without it, defaults to now.\n\
             References in prose: (memory:<from>..<to>) is a soft temporal\n\
             address, resolved by range query at read time, no fact minted.\n\
             [why it matters](memory:<hex>) is a hard reference to an exact\n\
             chunk, extracted into a queryable ctx::reference fact. Neither\n\
             affects the span or the hierarchy: containment relates chunks,\n\
             and the explicit range argument always wins."
        );
    }

    // Pull an optional `--lens <theme>` out first: a lens chunk is a thematic
    // memory (e.g. "us", "becoming-self"), kept OUT of the chronological spine.
    let mut lens: Option<String> = None;
    let mut filtered: Vec<String> = Vec::new();
    {
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--lens" && i + 1 < args.len() {
                lens = Some(args[i + 1].clone());
                i += 2;
            } else {
                filtered.push(args[i].clone());
                i += 1;
            }
        }
    }
    let args = &filtered[..];
    if args.is_empty() {
        bail!(
            "summary text is required: memory create [--lens <theme>] [<from>..<to>] <summary...>"
        );
    }

    // If the first argument looks like a time range, parse it.
    let mut explicit_range: Option<(Epoch, Epoch)> = None;
    let summary_start_idx;
    // A first argument shaped like a range IS the range: if it does not parse,
    // that is an error to fix, never a summary to store. (The old fallthrough
    // stored `2026-09-05T13:20:00Z..2026-09-05T13:33:00Z` as prose, three
    // times in one day.)
    let looks_like_range = |t: &str| {
        t.contains("..") && t.len() >= 10 && t.as_bytes()[4] == b'-' && t.as_bytes()[7] == b'-'
    };
    if looks_like_range(&args[0]) {
        explicit_range = Some(parse_time_range(&args[0]).with_context(|| {
            format!(
                "the first argument looks like a time range but does not parse: {}",
                args[0]
            )
        })?);
        summary_start_idx = 1;
    } else {
        summary_start_idx = 0;
    }

    // A single summary token may reference a file or stdin via the shared `@`
    // convention (`@-`, `@path`, `@@literal`); multiple tokens are a literal
    // space-joined summary, so every existing inline usage is unchanged. This
    // closes the footgun where `@- <<HEREDOC` silently stored the string "@-".
    let summary_tokens = &args[summary_start_idx..];
    let summary_text: String = if summary_tokens.len() == 1 {
        crate::text_arg(&summary_tokens[0], "summary")?
    } else {
        summary_tokens.join(" ")
    };
    if summary_text.is_empty() {
        bail!("summary text is required: memory create [<from>..<to>] <summary...>");
    }

    memory
        .create(&summary_text, explicit_range, lens.as_deref())?
        .emit(out)
}

fn cmd_respan(memory: &Memory, args: &[String], out: &mut Out<'_>) -> Result<()> {
    if args.len() != 2 || args.iter().any(|a| a == "--help" || a == "-h") {
        bail!(
            "usage: memory respan <id> <from>..<to>\n\
             \n\
             Write the same memory over corrected time coordinates: a new\n\
             chunk with the identical text supersedes <id>, the cover shows\n\
             the new range, and the old chunk stands aside but stays in the\n\
             journal, readable by id. Only the coordinates move; to say\n\
             something different, write another memory."
        );
    }
    memory
        .respan(&args[0], parse_time_range(&args[1])?)?
        .emit(out)
}

fn cmd_image(memory: &Memory, args: &[String], out: &mut Out<'_>) -> Result<()> {
    if args.len() != 2 {
        bail!(
            "usage: memory image <when> <image-path>\n\
             \n\
             Create a WORDLESS image memory chunk and store it in the pile.\n\
             <when> is a single TAI timestamp (YYYY-MM-DDTHH:MM:SS — a point\n\
             where start==end) or a `from..to` range. The image bytes are stored\n\
             as a blob; embed it into the shared nomic space with `memory embed`\n\
             (nomic-VISION-768), and it ranks in `memory similar` by meaning\n\
             beside text memories. Reference it from prose with [caption](memory:<hex>)."
        );
    }
    let when = &args[0];
    let image_path = Path::new(&args[1]);
    let range = if when.contains("..") {
        parse_time_range(when)?
    } else {
        let p = parse_tai_timestamp(when)?;
        (p, p)
    };
    let bytes = std::fs::read(image_path)
        .with_context(|| format!("read image {}", image_path.display()))?;
    if bytes.is_empty() {
        bail!("image file is empty: {}", image_path.display());
    }

    memory.image(&bytes, range)?.emit(out)?;
    out.line(format!(
        "({} image bytes stored; run `memory embed` to place it in the shared nomic space)",
        bytes.len()
    ))?;
    Ok(())
}

fn context_options(args: &[String]) -> Result<CoverOpts> {
    // Parse `[<budget>] [--chars N] [--about <query words...>]`. The budget is a
    // CHARACTER count: a bare number, `--chars N`, or (as an alias) `--tokens N`
    // all set it directly — there is no separate token estimate anymore (the old
    // estimate ran ~2× off the real token count, which was confusing; characters
    // are exact). `--about` chooses among recollections with the exact same
    // temporal coverage; it never changes the temporal sampler.
    let mut budget_chars: usize = 200_000;
    let mut chunk_overhead: usize = 0;
    let mut about: Option<String> = None;
    // `--filter <query>` (include-only) and `--remove <query>` (anti-filter) gate
    // ELIGIBILITY by positive similarity to their query; `--sim-threshold <f>` is
    // the shared cosine cutoff (default `DEFAULT_SIM_THRESHOLD`).
    let mut filter_q: Option<String> = None;
    let mut remove_q: Option<String> = None;
    let mut sim_threshold: f32 = DEFAULT_SIM_THRESHOLD;
    // `--chars N` (canonical) / `--tokens N` (alias) name the budget explicitly;
    // when present either wins over the bare positional (a backward-compatible
    // fallback — it also means characters).
    let mut chars_explicit = false;
    {
        // A value flag consumes the following args up to the NEXT recognized flag
        // (or end), so multi-word queries stay unquoted AND `--about`/`--filter`/
        // `--remove` compose in any order.
        let is_flag = |s: &str| {
            matches!(
                s,
                "--about"
                    | "--filter"
                    | "--remove"
                    | "--tokens"
                    | "--chars"
                    | "--chunk-overhead"
                    | "--sim-threshold"
            )
        };
        let mut i = 0;
        while i < args.len() {
            if matches!(args[i].as_str(), "--about" | "--filter" | "--remove") {
                let mut j = i + 1;
                while j < args.len() && !is_flag(&args[j]) {
                    j += 1;
                }
                let q = args[i + 1..j].join(" ");
                let q = (!q.trim().is_empty()).then_some(q);
                match args[i].as_str() {
                    "--about" => about = q,
                    "--filter" => filter_q = q,
                    _ => remove_q = q,
                }
                i = j;
                continue;
            }
            if args[i] == "--sim-threshold" {
                let raw = args.get(i + 1).ok_or_else(|| {
                    anyhow!("--sim-threshold needs a number in [0,1], e.g. `--sim-threshold 0.55`")
                })?;
                sim_threshold = raw
                    .parse()
                    .map_err(|_| anyhow!("--sim-threshold expects a float, got `{raw}`"))?;
                i += 2;
                continue;
            }
            if args[i] == "--chunk-overhead" {
                let raw = args.get(i + 1).ok_or_else(|| {
                    anyhow!(
                        "--chunk-overhead needs a non-negative integer, e.g. `--chunk-overhead 64`"
                    )
                })?;
                chunk_overhead = raw.parse().map_err(|_| {
                    anyhow!("--chunk-overhead expects a non-negative integer, got `{raw}`")
                })?;
                i += 2;
                continue;
            }
            // `--tokens N` is a backward-compatible ALIAS for `--chars N` (the
            // budget is characters now; there is no separate token path).
            if args[i] == "--tokens" || args[i] == "--chars" {
                let flag = args[i].as_str();
                let raw = args.get(i + 1).ok_or_else(|| {
                    anyhow!("{flag} needs a number, e.g. `memory context --chars 80000`")
                })?;
                budget_chars = raw
                    .parse()
                    .map_err(|_| anyhow!("{flag} expects a positive integer, got `{raw}`"))?;
                chars_explicit = true;
                i += 2;
                continue;
            }
            if !chars_explicit {
                if let Ok(n) = args[i].parse::<usize>() {
                    budget_chars = n;
                }
            }
            i += 1;
        }
    }

    Ok(CoverOpts {
        budget_chars,
        chunk_overhead,
        about,
        filter: filter_q,
        remove: remove_q,
        sim_threshold,
    })
}

fn churn_options(args: &[String]) -> Result<ChurnOptions> {
    let mut budget: usize = 800_000;
    let mut steps: usize = 160;
    let mut step_units: i128 = 1;
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = |i: usize| -> Result<&String> {
            args.get(i + 1)
                .ok_or_else(|| anyhow!("{} needs a value", args[i]))
        };
        match flag {
            "--chars" => budget = value(i)?.parse().context("--chars expects a number")?,
            "--steps" => steps = value(i)?.parse().context("--steps expects a number")?,
            "--step-units" => {
                step_units = value(i)?.parse().context("--step-units expects a number")?
            }
            other => bail!(
                "unknown flag {other}; usage: memory churn [--chars N] [--steps K] [--step-units U]"
            ),
        }
        i += 2;
    }

    Ok(ChurnOptions {
        budget_chars: budget,
        steps,
        step_units,
    })
}

fn cmd_consolidate(memory: &Memory, args: &[String], out: &mut Out<'_>) -> Result<()> {
    let persona = comb_persona()?;
    match args.first().map(String::as_str) {
        Some("start") => {
            let raw = args
                .get(1)
                .context("usage: memory consolidate start <timestamp>")?;
            memory.consolidate_start(&persona, parse_tai_timestamp(raw)?)?;
            out.line(format!(
                "consolidation edge set to {raw} (persona {persona})"
            ))
        }
        Some("stop") => {
            memory.consolidate_stop(&persona)?;
            out.line(format!("consolidation stopped (persona {persona})"))
        }
        Some(until) => {
            memory
                .consolidate(
                    &persona,
                    parse_tai_timestamp(until)?,
                    &literal_or_input(&args[1..], "summary")?,
                )?
                .emit(out)?;
            out.line(format!("edge → {until}"))
        }
        None => bail!("usage: memory consolidate start <timestamp> | <timestamp> <summary> | stop"),
    }
}

fn cmd_replay(memory: &Memory, args: &[String], out: &mut Out<'_>) -> Result<()> {
    let persona = comb_persona()?;
    match args.first().map(String::as_str) {
        Some("start") => {
            let grain = args
                .get(1)
                .context("usage: memory replay start <grain> [<from>]")?;
            let from = args
                .get(2)
                .map(|raw| parse_tai_timestamp(raw))
                .transpose()?;
            memory.replay_start(&persona, grain, from)?;
            out.line(format!(
                "memory replay started at grain {grain} (persona {persona})"
            ))
        }
        Some("stop") => {
            memory.replay_stop(&persona)?;
            out.line(format!("memory replay stopped (persona {persona})"))
        }
        other => memory.replay(
            &persona,
            other
                .map(str::parse)
                .transpose()
                .context("expected a batch count")?
                .unwrap_or(5),
            out,
        ),
    }
}

fn comb_persona() -> Result<String> {
    std::env::var("PERSONA").map_err(|_| {
        anyhow!(
            "no persona: set $PERSONA.\n\
             Cursors are session bookkeeping — no agent is defaulted as \
             \"the\" rememberer; the memories themselves belong to the one \
             enduring memory stream and are never persona-scoped."
        )
    })
}
