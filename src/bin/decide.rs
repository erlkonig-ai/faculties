//! `decide` — deliberation primitive.
//!
//! Append-only pros/cons tracking with a resolution step that itself
//! enforces "≥1 pro AND ≥1 con" (with `--force` as the explicit
//! bypass). Downstream faculties gate their high-stakes actions on
//! the *existence* of a resolved decision — the deliberation rule
//! lives here, the trust contract is "is it resolved?" lives there.

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::schemas::decide::{
    DEFAULT_BRANCH, KIND_CON, KIND_DECISION, KIND_PRO, decide as decide_attrs, factor,
};
use hifitime::Epoch;
use rand_core::OsRng;
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::*;

type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

// ── CLI ───────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "decide", about = "Deliberation primitive — pros, cons, resolution")]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    #[arg(long)]
    branch_id: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Propose a new decision. Title is required; optional context
    /// (long-form description) and `--about <entity-id>` (link to
    /// whatever the decision is concerned with — a mail draft, a
    /// compass goal, anything).
    Propose {
        /// Short one-liner naming the decision.
        title: String,
        /// Optional long-form context. `@path` / `@-` for stdin.
        #[arg(long)]
        context: Option<String>,
        /// Optional pointer to the entity this decision is about.
        #[arg(long)]
        about: Option<String>,
    },
    /// Add a "for" factor — a reason to take the decided action.
    Pro {
        /// Full 32-char hex decision id.
        decision: String,
        /// Factor text. `@path` / `@-` accepted.
        text: String,
    },
    /// Add an "against" factor — a reason not to, or a risk.
    Con {
        /// Full 32-char hex decision id.
        decision: String,
        /// Factor text. `@path` / `@-` accepted.
        text: String,
    },
    /// Resolve a decision with a free-form outcome.
    ///
    /// Refuses unless the decision has ≥1 pro AND ≥1 con factor.
    /// Use `--force` to bypass — a resolved decision with missing
    /// factors is by definition forced, no further flag is recorded.
    Resolve {
        /// Full 32-char hex decision id.
        decision: String,
        /// Free-form outcome text. `@path` / `@-` accepted.
        outcome: String,
        /// Bypass the ≥1 pro AND ≥1 con check. The absence of
        /// factors is the trace of the bypass; review forced
        /// resolutions later with `decide list --forced`.
        #[arg(long)]
        force: bool,
    },
    /// List unresolved decisions (most recent first).
    List {
        /// Include resolved decisions too.
        #[arg(long)]
        all: bool,
        /// Show only decisions resolved with `--force` (no factors).
        #[arg(long)]
        forced: bool,
    },
    /// Show one decision with pros, cons, and outcome.
    Show {
        /// Full 32-char hex decision id.
        decision: String,
    },
    /// Resolve a hex prefix to a full 32-char decision id.
    ResolveId {
        prefix: String,
    },
}

// ── helpers ───────────────────────────────────────────────────────────────

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn instant_interval(at: Epoch) -> IntervalValue {
    (at, at).try_to_inline().unwrap()
}

fn unpack_interval(iv: IntervalValue) -> (Epoch, Epoch) {
    iv.try_from_inline().unwrap()
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// Resolve a decision id, accepting either a full 32-char hex or a
/// shorter prefix. Scans `KIND_DECISION` entities for matches.
fn resolve_decision_id(space: &TribleSet, input: &str) -> Result<Id> {
    let candidates = find!(d: Id, pattern!(space, [{ ?d @ metadata::tag: KIND_DECISION }]));
    faculties::resolve_id_prefix(input, candidates)
}

fn load_value_or_file(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_string())
}

fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile = Pile::open(path)
        .map_err(|e| anyhow::anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.refresh() {
        let _ = pile.close();
        return Err(match err {
            triblespace::core::repo::pile::ReadError::CorruptPile { valid_length } => anyhow::anyhow!(
                "pile corrupt at byte {valid_length}: refusing to auto-repair (a stale binary \
                 could truncate newer data). If, and only if, the tail is a genuinely torn write, truncate it explicitly (DESTRUCTIVE) with: trible pile amputate {}",
                path.display()
            ),
            other => anyhow::anyhow!("refresh pile {}: {other:?}", path.display()),
        });
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))
}

fn with_repo<T>(
    pile: &Path,
    f: impl FnOnce(&mut Repository<Pile>) -> Result<T>,
) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let result = f(&mut repo);
    let close_res = repo
        .close()
        .map_err(|e| anyhow::anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, blobencodings::LongString>(h)
        .ok()
        .map(|view| view.to_string())
}

// ── queries ───────────────────────────────────────────────────────────────

fn count_factors(space: &TribleSet, decision_id: Id, factor_kind: Id) -> usize {
    find!(
        f: Id,
        pattern!(space, [{
            ?f @
                metadata::tag: factor_kind,
                factor::about_decision: decision_id,
        }])
    )
    .count()
}

/// A resolved decision has BOTH `metadata::finished_at` and a
/// non-empty `decide::outcome`. We treat absence-of-either as
/// "still open."
fn is_resolved(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    decision_id: Id,
) -> bool {
    let has_finished_at = find!(
        f: IntervalValue,
        pattern!(space, [{ decision_id @ metadata::finished_at: ?f }])
    )
    .next()
    .is_some();
    let has_outcome = find!(
        o: TextHandle,
        pattern!(space, [{ decision_id @ decide_attrs::outcome: ?o }])
    )
    .next()
    .and_then(|h| read_text(ws, h))
    .map(|s| !s.trim().is_empty())
    .unwrap_or(false);
    has_finished_at && has_outcome
}

fn decision_title(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
    decision_id: Id,
) -> String {
    find!(
        h: TextHandle,
        pattern!(space, [{ decision_id @ metadata::name: ?h }])
    )
    .next()
    .and_then(|h| read_text(ws, h))
    .unwrap_or_else(|| "(untitled)".into())
}

fn decision_created_at(space: &TribleSet, decision_id: Id) -> Option<Epoch> {
    find!(
        c: IntervalValue,
        pattern!(space, [{ decision_id @ metadata::created_at: ?c }])
    )
    .next()
    .map(|iv| unpack_interval(iv).0)
}

// ── kind entities ─────────────────────────────────────────────────────────

fn ensure_kind_entities(ws: &mut Workspace<Pile>) -> Result<TribleSet> {
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let existing: HashSet<Id> = find!(
        (k: Id),
        pattern!(&space, [{ ?k @ metadata::name: _?handle }])
    )
    .map(|(k,)| k)
    .collect();
    let mut change = TribleSet::new();
    let label = |id: Id| -> &'static str {
        if id == KIND_DECISION {
            "decide-decision"
        } else if id == KIND_PRO {
            "decide-pro"
        } else {
            "decide-con"
        }
    };
    for kind in [KIND_DECISION, KIND_PRO, KIND_CON] {
        if !existing.contains(&kind) {
            let name = ws.put(label(kind));
            change += entity! { ExclusiveId::force_ref(&kind) @
                metadata::name: name,
            };
        }
    }
    Ok(change)
}

// ── commands ──────────────────────────────────────────────────────────────

fn cmd_propose(
    pile: &Path,
    branch_id: Id,
    title: String,
    context: Option<String>,
    about: Option<String>,
) -> Result<()> {
    if title.trim().is_empty() {
        bail!("title must not be empty");
    }
    // `about` can reference any entity across faculties (a compass goal,
    // a mail draft, a wiki fragment, etc.); we don't have a single
    // KIND to scope a prefix search against, so it stays strict — pass
    // a full 32-char id.
    let about_id = about
        .as_deref()
        .map(|raw| {
            Id::from_hex(raw.trim()).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --about id '{}': expected a full 32-char hex id \
                     (cross-faculty linker, no prefix expansion)",
                    raw.trim()
                )
            })
        })
        .transpose()?;
    let context_text = context.as_deref().map(|s| load_value_or_file(s, "context")).transpose()?;

    let decision_ref = with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let decision_id = ufoid();
        let decision_ref = decision_id.id;
        let now = instant_interval(now_epoch());
        let title_handle = ws.put(title.clone());
        let context_handle: Option<TextHandle> = context_text.as_deref().map(|c| ws.put(c.to_string()));

        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &decision_id @
            metadata::tag: &KIND_DECISION,
            metadata::created_at: now,
            metadata::name: title_handle,
            metadata::description?: context_handle.as_ref(),
            decide_attrs::about?: about_id.as_ref(),
        };
        ws.commit(change, "decide: propose");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
        Ok(decision_ref)
    })?;
    println!("Proposed decision {}", fmt_id(decision_ref));
    Ok(())
}

fn cmd_factor(
    pile: &Path,
    branch_id: Id,
    decision_hex: String,
    text: String,
    kind: Id,
) -> Result<()> {
    let body = load_value_or_file(&text, "factor text")?;
    if body.trim().is_empty() {
        bail!("factor text must not be empty");
    }
    let decision_id = with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        // Sanity-check the decision exists and isn't already resolved.
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let decision_id = resolve_decision_id(&space, &decision_hex)?;
        let exists = find!(
            d: Id,
            pattern!(&space, [{ ?d @ metadata::tag: KIND_DECISION }])
        )
        .any(|d| d == decision_id);
        if !exists {
            bail!("no decision with id {decision_id:x}");
        }
        if is_resolved(&mut ws, &space, decision_id) {
            bail!(
                "decision {decision_id:x} is already resolved — append a new \
                 decision to reconsider instead of mutating a closed one"
            );
        }

        let factor_id = ufoid();
        let now = instant_interval(now_epoch());
        let body_handle: TextHandle = ws.put(body.clone());
        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &factor_id @
            metadata::tag: &kind,
            metadata::created_at: now,
            metadata::name: body_handle,
            factor::about_decision: &decision_id,
        };
        ws.commit(
            change,
            if kind == KIND_PRO { "decide: pro" } else { "decide: con" },
        );
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
        Ok(decision_id)
    })?;
    let side = if kind == KIND_PRO { "pro" } else { "con" };
    println!("Added {side} to decision {}", fmt_id(decision_id));
    Ok(())
}

fn cmd_resolve(
    pile: &Path,
    branch_id: Id,
    decision_hex: String,
    outcome: String,
    force: bool,
) -> Result<()> {
    let outcome_text = load_value_or_file(&outcome, "outcome")?;
    if outcome_text.trim().is_empty() {
        bail!("outcome must not be empty (use @- to pipe in stdin)");
    }
    let decision_id = with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let decision_id = resolve_decision_id(&space, &decision_hex)?;
        let exists = find!(
            d: Id,
            pattern!(&space, [{ ?d @ metadata::tag: KIND_DECISION }])
        )
        .any(|d| d == decision_id);
        if !exists {
            bail!("no decision with id {decision_id:x}");
        }
        if is_resolved(&mut ws, &space, decision_id) {
            bail!("decision {decision_id:x} is already resolved");
        }

        // The deliberation gate. `--force` bypasses; absence of
        // factors is the trace.
        if !force {
            let pros = count_factors(&space, decision_id, KIND_PRO);
            let cons = count_factors(&space, decision_id, KIND_CON);
            if pros == 0 || cons == 0 {
                bail!(
                    "cannot resolve: needs ≥1 pro AND ≥1 con (have {pros} pro, {cons} con). \
                     Add factors with `decide pro <id>` / `decide con <id>`, or pass --force \
                     if this genuinely doesn't merit deliberation."
                );
            }
        }

        let now = instant_interval(now_epoch());
        let outcome_handle: TextHandle = ws.put(outcome_text.clone());
        let mut change = TribleSet::new();
        change += entity! { ExclusiveId::force_ref(&decision_id) @
            metadata::finished_at: now,
            decide_attrs::outcome: outcome_handle,
        };
        ws.commit(change, "decide: resolve");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
        Ok(decision_id)
    })?;
    println!("Resolved decision {}", fmt_id(decision_id));
    Ok(())
}

struct DecisionRow {
    id: Id,
    title: String,
    created_at: Option<Epoch>,
    resolved: bool,
    pros: usize,
    cons: usize,
    outcome_preview: Option<String>,
}

fn collect_decisions(
    ws: &mut Workspace<Pile>,
    space: &TribleSet,
) -> Vec<DecisionRow> {
    let ids: Vec<Id> = find!(
        d: Id,
        pattern!(space, [{ ?d @ metadata::tag: KIND_DECISION }])
    )
    .collect();
    let mut rows: Vec<DecisionRow> = ids
        .into_iter()
        .map(|id| {
            let title = decision_title(ws, space, id);
            let created_at = decision_created_at(space, id);
            let resolved = is_resolved(ws, space, id);
            let pros = count_factors(space, id, KIND_PRO);
            let cons = count_factors(space, id, KIND_CON);
            let outcome_preview = if resolved {
                find!(
                    h: TextHandle,
                    pattern!(space, [{ id @ decide_attrs::outcome: ?h }])
                )
                .next()
                .and_then(|h| read_text(ws, h))
                .map(|s| s.lines().next().unwrap_or("").trim().to_string())
            } else {
                None
            };
            DecisionRow {
                id,
                title,
                created_at,
                resolved,
                pros,
                cons,
                outcome_preview,
            }
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.created_at.map(|e| e.to_tai_seconds() as i128).unwrap_or(0)));
    rows
}

fn cmd_list(pile: &Path, branch_id: Id, all: bool, forced_only: bool) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let rows = collect_decisions(&mut ws, &space);
        let filtered: Vec<&DecisionRow> = rows
            .iter()
            .filter(|r| {
                if forced_only {
                    r.resolved && (r.pros == 0 || r.cons == 0)
                } else if all {
                    true
                } else {
                    !r.resolved
                }
            })
            .collect();
        if filtered.is_empty() {
            println!("(no decisions)");
        } else {
            for r in filtered {
                let status = if r.resolved {
                    if r.pros == 0 || r.cons == 0 {
                        "resolved [forced]"
                    } else {
                        "resolved"
                    }
                } else {
                    "open"
                };
                print!(
                    "  {} [{status}] +{}/-{} {}",
                    &fmt_id(r.id)[..8],
                    r.pros,
                    r.cons,
                    r.title,
                );
                if let Some(o) = &r.outcome_preview {
                    print!("  → {}", truncate(o, 60));
                }
                println!();
            }
        }
        Ok(())
    })
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let trimmed: String = s.chars().take(max - 1).collect();
        format!("{trimmed}…")
    }
}

fn cmd_show(pile: &Path, branch_id: Id, decision_hex: String) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let decision_id = resolve_decision_id(&space, &decision_hex)?;

        let title = decision_title(&mut ws, &space, decision_id);
        println!("decision {}", fmt_id(decision_id));
        println!("  title:   {title}");
        let context_handle: Option<TextHandle> = find!(
            h: TextHandle,
            pattern!(&space, [{ decision_id @ metadata::description: ?h }])
        )
        .next();
        if let Some(h) = context_handle {
            if let Some(c) = read_text(&mut ws, h) {
                println!("  context:");
                for line in c.lines() {
                    println!("    {line}");
                }
            }
        }
        let about: Option<Id> = find!(
            a: Id,
            pattern!(&space, [{ decision_id @ decide_attrs::about: ?a }])
        )
        .next();
        if let Some(a) = about {
            println!("  about:   {}", fmt_id(a));
        }

        let pros: Vec<Id> = find!(
            p: Id,
            pattern!(&space, [{
                ?p @ metadata::tag: KIND_PRO, factor::about_decision: decision_id
            }])
        )
        .collect();
        let cons: Vec<Id> = find!(
            c: Id,
            pattern!(&space, [{
                ?c @ metadata::tag: KIND_CON, factor::about_decision: decision_id
            }])
        )
        .collect();

        println!("  pros ({}):", pros.len());
        for p in pros {
            let text = find!(
                h: TextHandle,
                pattern!(&space, [{ p @ metadata::name: ?h }])
            )
            .next()
            .and_then(|h| read_text(&mut ws, h))
            .unwrap_or_default();
            println!("    + {text}");
        }
        println!("  cons ({}):", cons.len());
        for c in cons {
            let text = find!(
                h: TextHandle,
                pattern!(&space, [{ c @ metadata::name: ?h }])
            )
            .next()
            .and_then(|h| read_text(&mut ws, h))
            .unwrap_or_default();
            println!("    - {text}");
        }

        if is_resolved(&mut ws, &space, decision_id) {
            let outcome = find!(
                h: TextHandle,
                pattern!(&space, [{ decision_id @ decide_attrs::outcome: ?h }])
            )
            .next()
            .and_then(|h| read_text(&mut ws, h))
            .unwrap_or_default();
            println!("  outcome:");
            for line in outcome.lines() {
                println!("    {line}");
            }
        } else {
            println!("  outcome: (unresolved)");
        }
        Ok(())
    })
}

fn cmd_resolve_id(pile: &Path, branch_id: Id, prefix: String) -> Result<()> {
    let needle = prefix.trim().to_ascii_lowercase();
    if needle.is_empty() {
        bail!("empty prefix");
    }
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let matches: Vec<Id> = find!(
            d: Id,
            pattern!(&space, [{ ?d @ metadata::tag: KIND_DECISION }])
        )
        .filter(|d| fmt_id(*d).starts_with(&needle))
        .collect();
        match matches.len() {
            0 => bail!("no decision id starts with '{}'", needle),
            1 => {
                println!("{}", fmt_id(matches[0]));
                Ok(())
            }
            n => bail!("{n} matches; provide a longer prefix"),
        }
    })
}

// ── main ──────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cmd = cli.command.unwrap_or(Command::List { all: false, forced: false });
    let branch_id_hex = cli.branch_id.as_deref();
    let branch_id = with_repo(&cli.pile, |repo| {
        if let Some(hex) = branch_id_hex {
            // Branch ids aren't enumerable by content kind, so no prefix
            // expansion — pass a full 32-char hex.
            Id::from_hex(hex.trim()).ok_or_else(|| {
                anyhow::anyhow!("invalid --branch-id '{}': expected 32-char hex", hex.trim())
            })
        } else {
            repo.ensure_branch(&cli.branch, None)
                .map_err(|e| anyhow::anyhow!("ensure branch '{}': {e:?}", cli.branch))
        }
    })?;

    match cmd {
        Command::Propose { title, context, about } => {
            cmd_propose(&cli.pile, branch_id, title, context, about)
        }
        Command::Pro { decision, text } => {
            cmd_factor(&cli.pile, branch_id, decision, text, KIND_PRO)
        }
        Command::Con { decision, text } => {
            cmd_factor(&cli.pile, branch_id, decision, text, KIND_CON)
        }
        Command::Resolve { decision, outcome, force } => {
            cmd_resolve(&cli.pile, branch_id, decision, outcome, force)
        }
        Command::List { all, forced } => cmd_list(&cli.pile, branch_id, all, forced),
        Command::Show { decision } => cmd_show(&cli.pile, branch_id, decision),
        Command::ResolveId { prefix } => cmd_resolve_id(&cli.pile, branch_id, prefix),
    }
}
