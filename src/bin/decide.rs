//! `decide` — a fork-visible deliberation ledger over one union collection.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use faculties::clock;
use faculties::collection_names::open_configured;
use faculties::decide::{
    self, DecisionGenesis, FactorRecord, FactorSide, IntervalValue, Resolution, ResolutionSnapshot,
};
use faculties::schemas::decide::DEFAULT_SCOPE_ID;
use faculties::storage::{load_signer, open_pile_strict, FactArchive};
use hifitime::Epoch;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{Collection, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "decide",
    about = "A fork-visible TribleSpace deliberation ledger"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Propose a stable decision with one immutable genesis.
    Propose {
        #[arg(help = "Decision title. Use @path for file input or @- for stdin.")]
        title: String,
        #[arg(
            long,
            help = "Optional context. Use @path for file input or @- for stdin."
        )]
        context: Option<String>,
        /// Optional exact 32-character id of the entity this concerns.
        #[arg(long, value_parser = parse_id_arg)]
        about: Option<Id>,
    },
    /// Add one independent pro factor while the decision is unresolved.
    Pro {
        decision: String,
        #[arg(help = "Factor text. Use @path for file input or @- for stdin.")]
        text: String,
    },
    /// Add one independent con factor while the decision is unresolved.
    Con {
        decision: String,
        #[arg(help = "Factor text. Use @path for file input or @- for stdin.")]
        text: String,
    },
    /// Resolve an open decision. Ordinary resolution is allowed only while its
    /// resolution track is Missing.
    Resolve {
        decision: String,
        #[arg(help = "Outcome text. Use @path for file input or @- for stdin.")]
        outcome: String,
        /// Machine-readable result, alongside the outcome prose. The outcome
        /// is for a reader and may say anything; this is the only part a gate
        /// is allowed to act on, so reasoning and clearance stop competing for
        /// one field.
        #[arg(long, value_parser = parse_result_arg)]
        result: Option<Id>,
        /// Explicitly bypass the pro-and-con evidence gate.
        #[arg(long)]
        force: bool,
    },
    /// Reconcile a genuinely divergent resolution fork, citing every current
    /// head. Agreement is already semantically resolved and cannot use this.
    Reconcile {
        decision: String,
        #[arg(help = "Reconciled outcome. Use @path for file input or @- for stdin.")]
        outcome: String,
        /// Machine-readable result for the reconciled head. See `resolve`.
        #[arg(long, value_parser = parse_result_arg)]
        result: Option<Id>,
        /// Explicitly bypass the pro-and-con evidence gate.
        #[arg(long)]
        force: bool,
    },
    /// List unresolved and diagnostically unsettled decisions.
    List {
        /// Include uniquely resolved and agreeing decisions too.
        #[arg(long)]
        all: bool,
        /// Show only semantically resolved decisions whose explicit forced bit
        /// is true.
        #[arg(long)]
        forced: bool,
    },
    /// Show one decision, factors, and every live resolution head.
    Show { decision: String },
    /// Resolve an unambiguous decision id prefix.
    ResolveId { prefix: String },
}

#[derive(Clone, Copy)]
struct DecideStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

struct CollectionView {
    facts: FactArchive,
    reader: PileSnapshot,
}

impl DecideStorage<'_> {
    fn with_store<T>(
        &self,
        operation: impl FnOnce(
            &mut Pile,
            Collection<SimpleArchive>,
            &ed25519_dalek::SigningKey,
            &CollectionView,
        ) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let collection = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
            let descriptor_snapshot = pile.snapshot()?;
            let policy = collection.policy(&descriptor_snapshot)?;
            drop(descriptor_snapshot);
            let maintained_succinct =
                pile.derive::<SuccinctArchiveBlob>(collection, (), policy.clone())?;
            let maintained_rank9 = pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(
                maintained_succinct,
                (),
                policy,
            )?;
            let store_snapshot = pollster::block_on(async {
                drop(pile.ensure(collection).await?);
                drop(pile.maintain(maintained_succinct).await?);
                pile.maintain(maintained_rank9).await
            })
            .context("maintain Decide fact collection")?;
            let facts = store_snapshot
                .collection(maintained_rank9)
                .context("observe maintained Decide fact collection")?
                .view::<FactArchive>()
                .context("read maintained Decide fact collection")?;
            operation(
                &mut pile,
                collection,
                &signer,
                &CollectionView {
                    facts,
                    reader: store_snapshot,
                },
            )
        })();
        finish_pile(pile, result)
    }

    fn with_view<T>(&self, operation: impl FnOnce(&CollectionView) -> Result<T>) -> Result<T> {
        self.with_store(|_, _, _, view| operation(view))
    }

    fn update<T>(
        &self,
        description: &'static str,
        operation: impl FnOnce(&CollectionView) -> Result<(Fragment, T)>,
    ) -> Result<T> {
        self.with_store(|pile, collection, signer, view| {
            let (mut fragment, value) = operation(view)?;
            fragment.describe_with(entity! { metadata::description: description });
            pile.commit(collection, signer, fragment)
                .context("commit authored Decide fragment")?;
            Ok(value)
        })
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close Decide pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Decide pile also failed: {close_error}")))
        }
    }
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
}

/// A result tag, by name or by exact id. Names keep the common case typable;
/// the raw id keeps the vocabulary open, since a tag another tool minted must
/// be recordable without this binary having to learn it first.
fn parse_result_arg(raw: &str) -> std::result::Result<Id, String> {
    let raw = raw.trim();
    if let Some(id) = decide::result_tag(raw) {
        return Ok(id);
    }
    Id::from_hex(raw).ok_or_else(|| {
        format!(
            "unknown result '{raw}'; expected a 32-character id or one of: {}",
            decide::RESULT_TAGS
                .iter()
                .map(|(label, _)| *label)
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

fn fmt_result(id: Id) -> String {
    match decide::result_name(id) {
        Some(name) => format!("{name} ({id:x})"),
        None => format!("{id:x}"),
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn now_epoch() -> Result<Epoch> {
    clock::now()
}

fn epoch_interval(epoch: Epoch) -> IntervalValue {
    (epoch, epoch)
        .try_to_inline()
        .expect("valid point interval")
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval
        .try_from_inline()
        .expect("validated point interval");
    lower
}

fn format_interval(interval: IntervalValue) -> String {
    let (lower, _): (Epoch, Epoch) = interval
        .try_from_inline()
        .expect("validated point interval");
    format!("{lower}")
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_owned()
    } else {
        format!(
            "{}…",
            value
                .chars()
                .take(max.saturating_sub(1))
                .collect::<String>()
        )
    }
}

fn resolve_decision(input: &str, facts: &FactArchive) -> Result<Id> {
    faculties::resolve_id_prefix(input, decide::decision_anchors(facts))
}

fn ensure_missing(state: &Resolution, action: &str, decision: Id) -> Result<()> {
    match state {
        Resolution::Missing => Ok(()),
        Resolution::Unique(snapshot) => {
            bail!(
                "decision {decision:x} is already resolved at head {:x}; cannot {action}",
                snapshot.id
            )
        }
        Resolution::Agreed(snapshots) => bail!(
            "decision {decision:x} is already resolved by {} agreeing heads; cannot {action}",
            snapshots.len()
        ),
        Resolution::Forked(snapshots) => bail!(
            "decision {decision:x} has {} divergent resolution heads; use `decide reconcile`",
            snapshots.len()
        ),
        Resolution::Invalid(reason) => {
            bail!("decision {decision:x} resolution is invalid: {reason}")
        }
    }
}

fn reconciliation_heads(state: Resolution, decision: Id) -> Result<Vec<Id>> {
    match state {
        Resolution::Forked(snapshots) => {
            Ok(snapshots.into_iter().map(|snapshot| snapshot.id).collect())
        }
        Resolution::Missing => bail!("decision {decision:x} is unresolved; use `decide resolve`"),
        Resolution::Unique(snapshot) => bail!(
            "decision {decision:x} has one closed resolution head {:x}; there is no fork to reconcile",
            snapshot.id
        ),
        Resolution::Agreed(snapshots) => bail!(
            "decision {decision:x} is already semantically resolved by {} agreeing heads",
            snapshots.len()
        ),
        Resolution::Invalid(reason) => bail!("decision {decision:x} resolution is invalid: {reason}"),
    }
}

fn evidence(facts: &FactArchive, decision: Id, forced: bool) -> Result<Vec<Id>> {
    let factors = decide::factors_for_decision(facts, decision)?;
    let pros = factors
        .iter()
        .filter(|factor| factor.side == FactorSide::Pro)
        .count();
    let cons = factors
        .iter()
        .filter(|factor| factor.side == FactorSide::Con)
        .count();
    if !forced && (pros == 0 || cons == 0) {
        bail!(
            "cannot resolve without force: exact evidence needs at least one pro and one con (have {pros} pro, {cons} con)"
        );
    }
    Ok(factors.into_iter().map(|factor| factor.id).collect())
}

fn cmd_propose(
    storage: DecideStorage<'_>,
    title: String,
    context: Option<String>,
    about: Option<Id>,
) -> Result<()> {
    let decision_id = genid().id;
    storage.update("propose Decide decision", |_| {
        let (fragment, _) = decide::decision_fragment(
            decision_id,
            title,
            context,
            about,
            epoch_interval(now_epoch()?),
        )?;
        Ok((fragment, ()))
    })?;
    println!("Proposed decision {decision_id:x}");
    Ok(())
}

fn cmd_factor(
    storage: DecideStorage<'_>,
    input: String,
    text: String,
    side: FactorSide,
) -> Result<()> {
    let description = match side {
        FactorSide::Pro => "add Decide pro factor",
        FactorSide::Con => "add Decide con factor",
    };
    let (decision_id, factor_id) = storage.update(description, |view| {
        let decision_id = resolve_decision(&input, &view.facts)?;
        ensure_missing(
            &decide::resolution(&view.facts, decision_id),
            "add a factor",
            decision_id,
        )?;
        let (fragment, factor_id) = decide::factor_fragment(
            genid().id,
            decision_id,
            side,
            text,
            epoch_interval(now_epoch()?),
        )?;
        Ok((fragment, (decision_id, factor_id)))
    })?;
    println!(
        "Added {} factor {factor_id:x} to {decision_id:x}",
        side.label()
    );
    Ok(())
}

fn cmd_resolve(
    storage: DecideStorage<'_>,
    input: String,
    outcome: String,
    result: Option<Id>,
    forced: bool,
) -> Result<()> {
    let (decision_id, snapshot_id) = storage.update("resolve Decide decision", |view| {
        let decision_id = resolve_decision(&input, &view.facts)?;
        ensure_missing(
            &decide::resolution(&view.facts, decision_id),
            "resolve it again",
            decision_id,
        )?;
        let evidence = evidence(&view.facts, decision_id, forced)?;
        let (fragment, snapshot_id) = decide::resolution_fragment(
            decision_id,
            outcome,
            result,
            forced,
            &evidence,
            &[],
            epoch_interval(now_epoch()?),
        )?;
        Ok((fragment, (decision_id, snapshot_id)))
    })?;
    println!("Resolved decision {decision_id:x} at {snapshot_id:x}");
    match result {
        Some(result) => println!("Result: {}", fmt_result(result)),
        None => println!("Result: none — no gate will read this outcome"),
    }
    if forced {
        println!("Resolution is explicitly forced");
    }
    Ok(())
}

fn cmd_reconcile(
    storage: DecideStorage<'_>,
    input: String,
    outcome: String,
    result: Option<Id>,
    forced: bool,
) -> Result<()> {
    let (decision_id, snapshot_id, predecessors) =
        storage.update("reconcile Decide resolution fork", |view| {
            let decision_id = resolve_decision(&input, &view.facts)?;
            let predecessors =
                reconciliation_heads(decide::resolution(&view.facts, decision_id), decision_id)?;
            let evidence = evidence(&view.facts, decision_id, forced)?;
            let (fragment, snapshot_id) = decide::resolution_fragment(
                decision_id,
                outcome,
                result,
                forced,
                &evidence,
                &predecessors,
                epoch_interval(now_epoch()?),
            )?;
            Ok((fragment, (decision_id, snapshot_id, predecessors)))
        })?;
    println!(
        "Reconciled {} resolution heads for {decision_id:x} at {snapshot_id:x}",
        predecessors.len()
    );
    match result {
        Some(result) => println!("Result: {}", fmt_result(result)),
        None => println!("Result: none — no gate will read this outcome"),
    }
    if forced {
        println!("Reconciliation is explicitly forced");
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct DecisionRow {
    id: Id,
    genesis: DecisionGenesis,
    pros: usize,
    cons: usize,
    resolution: Resolution,
}

fn collect_decisions(view: &CollectionView) -> Result<Vec<DecisionRow>> {
    let mut rows = Vec::new();
    for id in decide::decision_anchors(&view.facts) {
        let genesis = decide::genesis_for_decision(&view.facts, id)?
            .ok_or_else(|| anyhow!("decision {id:x} has no genesis"))?;
        let factors = decide::factors_for_decision(&view.facts, id)?;
        rows.push(DecisionRow {
            id,
            genesis,
            pros: factors
                .iter()
                .filter(|factor| factor.side == FactorSide::Pro)
                .count(),
            cons: factors
                .iter()
                .filter(|factor| factor.side == FactorSide::Con)
                .count(),
            resolution: decide::resolution(&view.facts, id),
        });
    }
    rows.sort_by_key(|row| std::cmp::Reverse((interval_key(row.genesis.created_at), row.id)));
    Ok(rows)
}

fn common_snapshot(resolution: &Resolution) -> Option<&ResolutionSnapshot> {
    match resolution {
        Resolution::Unique(snapshot) => Some(snapshot),
        Resolution::Agreed(snapshots) => snapshots.first(),
        Resolution::Missing | Resolution::Forked(_) | Resolution::Invalid(_) => None,
    }
}

fn list_status(resolution: &Resolution) -> String {
    match resolution {
        Resolution::Missing => "open".to_owned(),
        Resolution::Unique(snapshot) if snapshot.forced => "resolved [forced]".to_owned(),
        Resolution::Unique(_) => "resolved".to_owned(),
        Resolution::Agreed(snapshots) if snapshots[0].forced => {
            format!("resolved [forced agreement: {} heads]", snapshots.len())
        }
        Resolution::Agreed(snapshots) => {
            format!("resolved [agreement: {} heads]", snapshots.len())
        }
        Resolution::Forked(snapshots) => format!("FORKED: {} divergent heads", snapshots.len()),
        Resolution::Invalid(reason) => format!("INVALID: {reason}"),
    }
}

fn cmd_list(storage: DecideStorage<'_>, all: bool, forced_only: bool) -> Result<()> {
    storage.with_view(|view| {
        let rows = collect_decisions(view)?;
        let rows: Vec<_> = rows
            .iter()
            .filter(|row| {
                if forced_only {
                    common_snapshot(&row.resolution).is_some_and(|snapshot| snapshot.forced)
                } else if all {
                    true
                } else {
                    matches!(
                        row.resolution,
                        Resolution::Missing | Resolution::Forked(_) | Resolution::Invalid(_)
                    )
                }
            })
            .collect();
        if rows.is_empty() {
            println!("(no decisions)");
            return Ok(());
        }
        for row in rows {
            let title = decide::read_text(&view.reader, row.genesis.title)?;
            print!(
                "  {} [{}] +{}/-{} {}",
                &fmt_id(row.id)[..8],
                list_status(&row.resolution),
                row.pros,
                row.cons,
                title
            );
            if let Some(snapshot) = common_snapshot(&row.resolution) {
                let outcome = decide::read_text(&view.reader, snapshot.outcome)?;
                // The result tag prints ahead of the prose because it is the
                // part with consequences; a reader scanning the list should
                // never have to infer clearance from a sentence.
                if let Some(result) = snapshot.result {
                    print!(
                        "  → [{}]",
                        decide::result_name(result)
                            .map(str::to_owned)
                            .unwrap_or_else(|| format!("{result:x}"))
                    );
                } else {
                    print!("  →");
                }
                print!(" {}", truncate(outcome.lines().next().unwrap_or(""), 60));
            }
            println!();
        }
        Ok(())
    })
}

fn print_factor(view: &CollectionView, factor: &FactorRecord) -> Result<()> {
    let text = decide::read_text(&view.reader, factor.text)?;
    let sign = match factor.side {
        FactorSide::Pro => '+',
        FactorSide::Con => '-',
    };
    println!(
        "    {sign} [{}] {} ({})",
        fmt_id(factor.id),
        text,
        format_interval(factor.created_at)
    );
    Ok(())
}

fn print_snapshot(
    view: &CollectionView,
    snapshot: &ResolutionSnapshot,
    indent: &str,
) -> Result<()> {
    let outcome = decide::read_text(&view.reader, snapshot.outcome)?;
    println!("{indent}head {}", fmt_id(snapshot.id));
    println!(
        "{indent}  result: {}",
        snapshot
            .result
            .map(fmt_result)
            .unwrap_or_else(|| "(none - prose only, no gate reads it)".to_owned())
    );
    println!("{indent}  forced: {}", snapshot.forced);
    println!(
        "{indent}  finished: {}",
        format_interval(snapshot.finished_at)
    );
    println!(
        "{indent}  evidence: {}",
        if snapshot.evidence.is_empty() {
            "(none)".to_owned()
        } else {
            snapshot
                .evidence
                .iter()
                .map(|id| fmt_id(*id))
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    if !snapshot.predecessors.is_empty() {
        println!(
            "{indent}  supersedes: {}",
            snapshot
                .predecessors
                .iter()
                .map(|id| fmt_id(*id))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!("{indent}  outcome:");
    for line in outcome.lines() {
        println!("{indent}    {line}");
    }
    Ok(())
}

fn cmd_show(storage: DecideStorage<'_>, input: String) -> Result<()> {
    storage.with_view(|view| {
        let decision_id = resolve_decision(&input, &view.facts)?;
        let genesis = decide::genesis_for_decision(&view.facts, decision_id)?
            .ok_or_else(|| anyhow!("decision {decision_id:x} has no genesis"))?;
        println!("decision {decision_id:x}");
        println!(
            "  title: {}",
            decide::read_text(&view.reader, genesis.title)?
        );
        println!("  created: {}", format_interval(genesis.created_at));
        if let Some(context) = genesis.context {
            println!("  context:");
            for line in decide::read_text(&view.reader, context)?.lines() {
                println!("    {line}");
            }
        }
        if let Some(about) = genesis.about {
            println!("  about: {about:x}");
        }

        let factors = decide::factors_for_decision(&view.facts, decision_id)?;
        let pros: Vec<_> = factors
            .iter()
            .filter(|factor| factor.side == FactorSide::Pro)
            .collect();
        let cons: Vec<_> = factors
            .iter()
            .filter(|factor| factor.side == FactorSide::Con)
            .collect();
        println!("  pros ({}):", pros.len());
        for factor in pros {
            print_factor(view, factor)?;
        }
        println!("  cons ({}):", cons.len());
        for factor in cons {
            print_factor(view, factor)?;
        }

        match decide::resolution(&view.facts, decision_id) {
            Resolution::Missing => println!("  resolution: MISSING (open)"),
            Resolution::Unique(snapshot) => {
                println!("  resolution: UNIQUE");
                print_snapshot(view, &snapshot, "    ")?;
            }
            Resolution::Agreed(snapshots) => {
                println!(
                    "  resolution: AGREED ({} concurrent heads; all remain join obligations)",
                    snapshots.len()
                );
                for snapshot in snapshots {
                    print_snapshot(view, &snapshot, "    ")?;
                }
            }
            Resolution::Forked(snapshots) => {
                println!(
                    "  resolution: FORKED ({} divergent heads; no outcome selected)",
                    snapshots.len()
                );
                for snapshot in snapshots {
                    print_snapshot(view, &snapshot, "    ")?;
                }
            }
            Resolution::Invalid(reason) => println!("  resolution: INVALID ({reason})"),
        }
        Ok(())
    })
}

fn cmd_resolve_id(storage: DecideStorage<'_>, prefix: String) -> Result<()> {
    storage.with_view(|view| {
        println!("{:x}", resolve_decision(&prefix, &view.facts)?);
        Ok(())
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };
    let storage = DecideStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };
    match command {
        Command::Propose {
            title,
            context,
            about,
        } => cmd_propose(
            storage,
            faculties::text_arg(&title, "decision title")?,
            context
                .as_deref()
                .map(|value| faculties::text_arg(value, "decision context"))
                .transpose()?,
            about,
        ),
        Command::Pro { decision, text } => cmd_factor(
            storage,
            decision,
            faculties::text_arg(&text, "pro factor")?,
            FactorSide::Pro,
        ),
        Command::Con { decision, text } => cmd_factor(
            storage,
            decision,
            faculties::text_arg(&text, "con factor")?,
            FactorSide::Con,
        ),
        Command::Resolve {
            decision,
            outcome,
            result,
            force,
        } => cmd_resolve(
            storage,
            decision,
            faculties::text_arg(&outcome, "resolution outcome")?,
            result,
            force,
        ),
        Command::Reconcile {
            decision,
            outcome,
            result,
            force,
        } => cmd_reconcile(
            storage,
            decision,
            faculties::text_arg(&outcome, "reconciled outcome")?,
            result,
            force,
        ),
        Command::List { all, forced } => cmd_list(storage, all, forced),
        Command::Show { decision } => cmd_show(storage, decision),
        Command::ResolveId { prefix } => cmd_resolve_id(storage, prefix),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(id: Id, outcome: decide::TextHandle, forced: bool) -> ResolutionSnapshot {
        ResolutionSnapshot {
            id,
            decision: genid().id,
            outcome,
            result: None,
            forced,
            evidence: Vec::new(),
            predecessors: Vec::new(),
            finished_at: epoch_interval(Epoch::from_unix_seconds(1.0)),
        }
    }

    #[test]
    fn ordinary_actions_accept_only_missing_resolution() {
        let decision = genid().id;
        assert!(ensure_missing(&Resolution::Missing, "act", decision).is_ok());
        assert!(ensure_missing(&Resolution::Invalid("bad".into()), "act", decision).is_err());
    }

    #[test]
    fn reconciliation_accepts_only_genuine_forks_and_keeps_every_head() {
        let decision = genid().id;
        let first = genid().id;
        let second = genid().id;
        let handle = Inline::new([0x11; 32]);
        let heads = reconciliation_heads(
            Resolution::Forked(vec![
                snapshot(first, handle, false),
                snapshot(second, handle, true),
            ]),
            decision,
        )
        .unwrap();
        assert_eq!(heads, vec![first, second]);
        assert!(reconciliation_heads(
            Resolution::Agreed(vec![
                snapshot(first, handle, false),
                snapshot(second, handle, false),
            ]),
            decision,
        )
        .is_err());
    }
}
