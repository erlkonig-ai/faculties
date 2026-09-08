//! CLI-only cache state. This ephemeral harness UX is never exposed as MCP
//! paths or tool arguments; memory_context is the resident-memory API.
use super::Memory;
use crate::clock;
use crate::memory_cover::{fmt_epoch, CoverOpts};
use crate::out::Out;
use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

const COVER_DEFAULT_CHARS: usize = 400_000;
/// Default chunk size — sized so a chunk printed to stdout survives
/// tool-result truncation in one piece.
const COVER_DEFAULT_CHUNK_CHARS: usize = 20_000;
const COVER_TEXT_FILE: &str = "cover.txt";
const COVER_CURSOR_FILE: &str = "cursor.json";

/// The cursor half of the cover state: how far `cover continue` has read into
/// the stored cover, in CHARACTERS (the same unit as the context budget — no
/// byte/char ambiguity, and chunk boundaries can never split a multi-byte
/// character).
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct CoverCursor {
    /// Characters of the stored cover already emitted.
    pub(super) offset: usize,
    /// Chunk size in characters, fixed at `cover start`.
    pub(super) chunk_chars: usize,
    /// Total characters of the stored cover.
    pub(super) total_chars: usize,
    /// When the cover was generated (TAI, the clock every chunk uses).
    pub(super) generated_at: String,
}

/// State directory for one cover session:
/// `${XDG_CACHE_HOME:-$HOME/.cache}/faculties/cover/<key>`. The key becomes a
/// directory name, so path-shaped keys are rejected outright.
pub(super) fn cover_session_dir(key: &str) -> Result<PathBuf> {
    if key.is_empty() || key == "." || key == ".." || key.contains('/') || key.contains('\\') {
        bail!("invalid session key `{key}` (it becomes a directory name)");
    }
    let base = match std::env::var_os("XDG_CACHE_HOME") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => {
            let home = std::env::var_os("HOME")
                .ok_or_else(|| anyhow!("neither XDG_CACHE_HOME nor HOME is set"))?;
            PathBuf::from(home).join(".cache")
        }
    };
    Ok(base.join("faculties").join("cover").join(key))
}

/// How many chunks a cover of `total_chars` splits into at `chunk_chars`.
pub(super) fn cover_chunk_count(total_chars: usize, chunk_chars: usize) -> usize {
    total_chars.div_ceil(chunk_chars)
}

/// Byte index of the `chars`-th character of `text` (`text.len()` past the
/// end), so chunk slicing lands on character boundaries, never mid-codepoint.
pub(super) fn cover_byte_of_char(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map(|(byte, _)| byte)
        .unwrap_or(text.len())
}

pub(super) fn cover_save_cursor(dir: &Path, cursor: &CoverCursor) -> Result<()> {
    let path = dir.join(COVER_CURSOR_FILE);
    let json = serde_json::to_string_pretty(cursor).context("encode cover cursor")?;
    std::fs::write(&path, json).with_context(|| format!("write {}", path.display()))
}

/// Store a freshly generated cover with a zeroed cursor. Returns
/// `(chunk_count, total_chars)`.
pub(super) fn cover_write_state(
    dir: &Path,
    cover: &str,
    chunk_chars: usize,
    generated_at: String,
) -> Result<(usize, usize)> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create cover state dir {}", dir.display()))?;
    let text_path = dir.join(COVER_TEXT_FILE);
    std::fs::write(&text_path, cover).with_context(|| format!("write {}", text_path.display()))?;
    let total_chars = cover.chars().count();
    let cursor = CoverCursor {
        offset: 0,
        chunk_chars,
        total_chars,
        generated_at,
    };
    cover_save_cursor(dir, &cursor)?;
    Ok((cover_chunk_count(total_chars, chunk_chars), total_chars))
}

/// Load `(cover text, cursor)` from a session dir; `None` when no cover has
/// been started there.
pub(super) fn cover_read_state(dir: &Path) -> Result<Option<(String, CoverCursor)>> {
    let text_path = dir.join(COVER_TEXT_FILE);
    let cursor_path = dir.join(COVER_CURSOR_FILE);
    if !text_path.exists() || !cursor_path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&text_path)
        .with_context(|| format!("read {}", text_path.display()))?;
    let raw = std::fs::read_to_string(&cursor_path)
        .with_context(|| format!("read {}", cursor_path.display()))?;
    let cursor: CoverCursor =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", cursor_path.display()))?;
    if cursor.chunk_chars == 0 {
        bail!(
            "corrupt cover cursor {} (chunk_chars is 0) — rerun `memory cover start`",
            cursor_path.display()
        );
    }
    Ok(Some((text, cursor)))
}

/// One `cover continue` step: the emitted chunk with its coordinates, or the
/// already-complete marker. Separated from printing so tests can walk the
/// chunks and prove reassembly equals the stored cover byte-for-byte.
pub(super) enum CoverStep {
    AlreadyComplete {
        chunks: usize,
    },
    Chunk {
        index: usize,
        chunks: usize,
        start_char: usize,
        end_char: usize,
        text: String,
        complete: bool,
    },
}

/// Advance the cover cursor in `dir` by one chunk and persist the new offset.
pub(super) fn cover_advance(dir: &Path) -> Result<CoverStep> {
    let Some((text, mut cursor)) = cover_read_state(dir)? else {
        bail!(
            "no cover in {} — run `memory cover start` first",
            dir.display()
        );
    };
    let chunks = cover_chunk_count(cursor.total_chars, cursor.chunk_chars);
    if cursor.offset >= cursor.total_chars {
        return Ok(CoverStep::AlreadyComplete { chunks });
    }
    let start_char = cursor.offset;
    let end_char = (start_char + cursor.chunk_chars).min(cursor.total_chars);
    let chunk = text[cover_byte_of_char(&text, start_char)..cover_byte_of_char(&text, end_char)]
        .to_string();
    cursor.offset = end_char;
    cover_save_cursor(dir, &cursor)?;
    Ok(CoverStep::Chunk {
        index: start_char / cursor.chunk_chars + 1,
        chunks,
        start_char,
        end_char,
        text: chunk,
        complete: end_char >= cursor.total_chars,
    })
}

/// The `cover status` line plus completeness. A missing state reads as an
/// empty, INCOMPLETE cover, so a session-start hook treats "never started" and
/// "not done yet" the same way: block until a start + full walk has happened.
pub(super) fn cover_status_line(dir: &Path) -> Result<(String, bool)> {
    let Some((_, cursor)) = cover_read_state(dir)? else {
        return Ok(("complete=false loaded=0/0 chars=0/0".to_string(), false));
    };
    let chunks = cover_chunk_count(cursor.total_chars, cursor.chunk_chars);
    let complete = cursor.offset >= cursor.total_chars;
    let loaded = if complete {
        chunks
    } else {
        cursor.offset / cursor.chunk_chars
    };
    Ok((
        format!(
            "complete={complete} loaded={loaded}/{chunks} chars={}/{}",
            cursor.offset, cursor.total_chars
        ),
        complete,
    ))
}

/// Rewind the cursor to 0; the stored cover is untouched (reset never
/// regenerates). Returns the number of chunks now pending.
pub(super) fn cover_reset_cursor(dir: &Path) -> Result<usize> {
    let Some((_, mut cursor)) = cover_read_state(dir)? else {
        bail!(
            "no cover in {} — run `memory cover start` first",
            dir.display()
        );
    };
    cursor.offset = 0;
    cover_save_cursor(dir, &cursor)?;
    Ok(cover_chunk_count(cursor.total_chars, cursor.chunk_chars))
}

/// `memory cover start|continue|status|reset` — the cursor state machine a
/// harness hook drives to force complete ingestion of the context cover:
/// reset (or start) on session start, block turn-end until `status` exits 0.
pub(super) fn execute(memory: &Memory, args: &[String], out: &mut Out<'_>) -> Result<i32> {
    let usage = "usage: memory cover start [--chars N] [--chunk-chars M] [--session KEY]\n\
                 \x20      memory cover continue [--session KEY]\n\
                 \x20      memory cover status [--session KEY]\n\
                 \x20      memory cover reset [--session KEY]";
    let Some(verb) = args.first().map(String::as_str) else {
        bail!("{usage}");
    };
    if matches!(verb, "--help" | "-h") {
        out.line(format!("{usage}"))?;
        return Ok(0);
    }
    let mut budget_chars: usize = COVER_DEFAULT_CHARS;
    let mut chunk_chars: usize = COVER_DEFAULT_CHUNK_CHARS;
    let mut session = "default".to_string();
    {
        let mut i = 1;
        while i < args.len() {
            let flag = args[i].as_str();
            match flag {
                "--chars" | "--chunk-chars" | "--session" => {
                    let raw = args
                        .get(i + 1)
                        .ok_or_else(|| anyhow!("{flag} needs a value\n{usage}"))?;
                    match flag {
                        "--session" => session = raw.clone(),
                        _ => {
                            let n: usize = raw.parse().map_err(|_| {
                                anyhow!("{flag} expects a positive integer, got `{raw}`")
                            })?;
                            if n == 0 {
                                bail!("{flag} must be positive");
                            }
                            if flag == "--chars" {
                                budget_chars = n;
                            } else {
                                chunk_chars = n;
                            }
                        }
                    }
                    i += 2;
                }
                other => bail!("unknown argument `{other}`\n{usage}"),
            }
        }
    }
    let dir = cover_session_dir(&session)?;

    match verb {
        "start" => {
            let cover = super::cli::report_text(memory.context(&CoverOpts::plain(budget_chars))?);
            let now = clock::now().context("generate cover state timestamp")?;
            let (chunks, total) = cover_write_state(&dir, &cover, chunk_chars, fmt_epoch(now))?;
            out.line(format!(
                "cover: generated {chunks} chunks (~{chunk_chars} chars each, {total} chars total); run 'memory cover continue'"
            ))?;
            Ok(0)
        }
        "continue" => match cover_advance(&dir)? {
            CoverStep::AlreadyComplete { chunks } => {
                out.line(format!("COVER COMPLETE {chunks}/{chunks} (nothing to do)"))?;
                Ok(0)
            }
            CoverStep::Chunk {
                index,
                chunks,
                start_char,
                end_char,
                text,
                complete,
            } => {
                out.line(format!(
                    "COVER CHUNK {index}/{chunks} (chars {start_char}..{end_char})"
                ))?;
                // The chunk itself, verbatim; a bare newline is appended only
                // when the chunk does not end on one, to keep the following
                // line (or the shell prompt) off the chunk's last line. The
                // stored cover is untouched by this — reassembly from state is
                // byte-exact.
                out.text(format!("{text}"))?;
                if !text.ends_with('\n') {
                    out.line("")?;
                }
                if complete {
                    out.line(format!("COVER COMPLETE {chunks}/{chunks}"))?;
                }
                Ok(0)
            }
        },
        "status" => {
            let (line, complete) = cover_status_line(&dir)?;
            out.line(format!("{line}"))?;
            // Hook-friendly: the exit code IS the answer (0 complete, 1 not).
            if !complete {
                return Ok(1);
            }
            Ok(0)
        }
        "reset" => {
            let chunks = cover_reset_cursor(&dir)?;
            out.line(format!("cover: cursor reset ({chunks} chunks pending)"))?;
            Ok(0)
        }
        other => bail!("unknown cover subcommand `{other}`\n{usage}"),
    }
}
