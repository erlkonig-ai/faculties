//! `linkedin` — import conduit from LinkedIn into the shared substrate.
//!
//! LinkedIn is not a silo here. Connections flow into the `relations`
//! faculty as first-class people (same `KIND_PERSON_ID` entities `mail`
//! and `relations add` produce), so a LinkedIn contact, a booth lead, and
//! a mail sender that are the same human converge on one entity. Only
//! genuinely LinkedIn-shaped data with no other home (e.g. "posts we're
//! mentioned in") would live under a linkedin-specific schema later.
//!
//! Source data comes from the LinkedIn DMA Member Data Portability API
//! (the ban-safe, member-consented export — not scraping), pulled to a
//! JSON snapshot at the network boundary, then ingested here in Rust.
//!
//! ## Entity resolution (non-destructive)
//!
//! An append-only pile can't merge entities irreversibly, so identity is
//! modelled as edges, never a destructive merge:
//!   * deterministic key match (same `profile_url`, or same `email` as an
//!     existing person) → the row enriches that existing entity in place;
//!   * a name-only collision → a NEW distinct person plus a
//!     `review_candidate` edge to the lookalike, queued for an agent to
//!     adjudicate with common-sense reasoning;
//!   * `linkedin review` lists the open candidates; `linkedin resolve A B
//!     --same | --distinct` records the verdict as `same_as` /
//!     `distinct_from` (both correctable later by superseding).
//!
//! Commands:
//!   linkedin import <snapshot.json> [--dry-run]
//!   linkedin review [--limit N]
//!   linkedin resolve <id-a> <id-b> --same | --distinct

use anyhow::{Result, anyhow, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::schemas::relations::{DEFAULT_BRANCH, KIND_PERSON_ID, relations};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

// ── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "linkedin", about = "LinkedIn → relations import conduit")]
struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name for relations data (imports land here)
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Ingest a LinkedIn snapshot JSON (CONNECTIONS export) into relations.
    Import {
        /// Path to the snapshot JSON (array of connection records).
        snapshot: PathBuf,
        /// Resolve and report, but commit nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Pull a snapshot from the LinkedIn DMA Member Data Portability API.
    ///
    /// Token is a secret — pass via the LINKEDIN_TOKEN env var (preferred,
    /// not visible in `ps`) or --token. Never piled or committed.
    Pull {
        /// OAuth access token (scope r_dma_portability_self_serve).
        #[arg(long, env = "LINKEDIN_TOKEN", hide_env_values = true)]
        token: String,
        /// Snapshot domain (CONNECTIONS, PROFILE, …).
        #[arg(long, default_value = "CONNECTIONS")]
        domain: String,
        /// Linkedin-Version header — the app's PINNED product version.
        #[arg(long, default_value = "202312")]
        api_version: String,
        /// Write the raw snapshot JSON here (default /tmp/linkedin_<DOMAIN>.json).
        #[arg(long)]
        out: Option<PathBuf>,
        /// After pulling, ingest straight into relations (full automation).
        #[arg(long)]
        import: bool,
        /// With --import, resolve and report but commit nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// List open identity-resolution candidates (name collisions to adjudicate).
    Review {
        /// Max pairs to show.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Record an identity verdict between two people.
    Resolve {
        /// First person id (hex or unambiguous prefix).
        id_a: String,
        /// Second person id (hex or unambiguous prefix).
        id_b: String,
        /// They are the same individual (assert `same_as`).
        #[arg(long, conflicts_with = "distinct")]
        same: bool,
        /// They are different individuals (assert `distinct_from`).
        #[arg(long, conflicts_with = "same")]
        distinct: bool,
    },
}

// ── snapshot record ─────────────────────────────────────────────────────────

#[derive(Deserialize, Serialize, Default, Clone)]
struct Conn {
    #[serde(rename = "First Name", default)]
    first: String,
    #[serde(rename = "Last Name", default)]
    last: String,
    #[serde(rename = "Company", default)]
    company: String,
    #[serde(rename = "Position", default)]
    position: String,
    #[serde(rename = "URL", default)]
    url: String,
    #[serde(rename = "Email Address", default)]
    email: String,
}

impl Conn {
    fn full_name(&self) -> String {
        format!("{} {}", self.first.trim(), self.last.trim())
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }
    fn email_key(&self) -> Option<String> {
        let e = self.email.trim().to_ascii_lowercase();
        if e.is_empty() { None } else { Some(e) }
    }
    fn url_key(&self) -> Option<String> {
        normalize_url(&self.url)
    }
}

// ── normalization ───────────────────────────────────────────────────────────

/// Canonical key for a LinkedIn profile URL: lowercase, scheme/host/`www`
/// stripped, no trailing slash. `https://www.linkedin.com/in/jane-doe/`
/// and `linkedin.com/in/jane-doe` collapse to the same key.
fn normalize_url(url: &str) -> Option<String> {
    let mut s = url.trim().to_ascii_lowercase();
    if s.is_empty() {
        return None;
    }
    for pfx in ["https://", "http://"] {
        if let Some(rest) = s.strip_prefix(pfx) {
            s = rest.to_string();
        }
    }
    if let Some(rest) = s.strip_prefix("www.") {
        s = rest.to_string();
    }
    let trimmed = s.trim_end_matches('/').to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

fn name_key(name: &str) -> Option<String> {
    let k = name.trim().to_ascii_lowercase();
    if k.is_empty() { None } else { Some(k) }
}

// ── repo plumbing (mirrors mail.rs / relations.rs) ──────────────────────────

fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile =
        Pile::open(path).map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        let _ = pile.close();
        return Err(anyhow!("restore pile {}: {err:?}", path.display()));
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|e| anyhow!("create repository: {e:?}"))
}

fn with_repo<T>(pile: &Path, f: impl FnOnce(&mut Repository<Pile>) -> Result<T>) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let result = f(&mut repo);
    let close = repo.close().map_err(|e| anyhow!("close pile: {e:?}"));
    if let Err(err) = close {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn read_text(ws: &mut Workspace<Pile>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, blobencodings::LongString>(h)
        .ok()
        .map(|v| v.to_string())
}

// ── existing-people lookup maps ─────────────────────────────────────────────

struct Lookup {
    by_url: HashMap<String, Id>,
    by_email: HashMap<String, Id>,
    by_name: HashMap<String, Vec<Id>>,
}

fn build_lookup(ws: &mut Workspace<Pile>, space: &TribleSet) -> Lookup {
    let mut by_url = HashMap::new();
    let mut by_email = HashMap::new();
    let mut by_name: HashMap<String, Vec<Id>> = HashMap::new();

    // email + label_norm live inline, so one pass over people.
    for (id, email) in find!(
        (id: Id, e: String),
        pattern!(space, [{ ?id @ metadata::tag: KIND_PERSON_ID, relations::email: ?e }])
    ) {
        if let Some(k) = name_key(&email) {
            by_email.insert(k, id);
        }
    }
    for (id, norm) in find!(
        (id: Id, n: String),
        pattern!(space, [{ ?id @ metadata::tag: KIND_PERSON_ID, relations::label_norm: ?n }])
    ) {
        if let Some(k) = name_key(&norm) {
            by_name.entry(k).or_default().push(id);
        }
    }
    // profile_url is a LongString handle → resolve each blob.
    let url_handles: Vec<(Id, TextHandle)> = find!(
        (id: Id, h: TextHandle),
        pattern!(space, [{ ?id @ metadata::tag: KIND_PERSON_ID, relations::profile_url: ?h }])
    )
    .collect();
    for (id, h) in url_handles {
        if let Some(url) = read_text(ws, h) {
            if let Some(k) = normalize_url(&url) {
                by_url.insert(k, id);
            }
        }
    }

    Lookup { by_url, by_email, by_name }
}

// ── emitting person facts ───────────────────────────────────────────────────

/// Append the LinkedIn-sourced facts for `conn` onto person `id`. When
/// `core` is set (a brand-new entity) we also stamp the canonical identity
/// fields (`tag`, `name`, `label_norm`, first/last/display); enrichment of
/// an existing person only adds the contact/provenance facts so we never
/// clobber a hand-curated label with two competing display names.
fn emit_person(ws: &mut Workspace<Pile>, change: &mut TribleSet, id: Id, conn: &Conn, core: bool) {
    if let Some(url) = conn.url_key().map(|_| conn.url.trim().to_string()) {
        if !url.is_empty() {
            let h = ws.put(url);
            *change += entity! { ExclusiveId::force_ref(&id) @ relations::profile_url: h };
        }
    }
    if !conn.company.trim().is_empty() {
        let h = ws.put(conn.company.trim().to_string());
        *change += entity! { ExclusiveId::force_ref(&id) @ relations::company: h };
    }
    if !conn.position.trim().is_empty() {
        let h = ws.put(conn.position.trim().to_string());
        *change += entity! { ExclusiveId::force_ref(&id) @ relations::position: h };
    }
    *change += entity! { ExclusiveId::force_ref(&id) @ relations::source: "linkedin" };
    if let Some(email) = conn.email_key() {
        if email.len() <= 32 {
            *change += entity! { ExclusiveId::force_ref(&id) @ relations::email: email.as_str() };
        }
    }

    if core {
        let name = conn.full_name();
        if !name.is_empty() {
            let h = ws.put(name.clone());
            *change += entity! { ExclusiveId::force_ref(&id) @
                metadata::tag: &KIND_PERSON_ID,
                metadata::name: h,
            };
            let norm = name.to_ascii_lowercase();
            if norm.len() <= 32 {
                *change += entity! { ExclusiveId::force_ref(&id) @ relations::label_norm: norm.as_str() };
            }
            let dh = ws.put(name);
            *change += entity! { ExclusiveId::force_ref(&id) @ relations::display_name: dh };
        }
        if !conn.first.trim().is_empty() {
            let h = ws.put(conn.first.trim().to_string());
            *change += entity! { ExclusiveId::force_ref(&id) @ relations::first_name: h };
        }
        if !conn.last.trim().is_empty() {
            let h = ws.put(conn.last.trim().to_string());
            *change += entity! { ExclusiveId::force_ref(&id) @ relations::last_name: h };
        }
    }
}

// ── import ──────────────────────────────────────────────────────────────────

fn cmd_import(pile: &Path, branch_id: Id, snapshot: &Path, dry_run: bool) -> Result<()> {
    let raw = std::fs::read_to_string(snapshot)
        .map_err(|e| anyhow!("read snapshot {}: {e}", snapshot.display()))?;
    let conns: Vec<Conn> =
        serde_json::from_str(&raw).map_err(|e| anyhow!("parse snapshot JSON: {e}"))?;
    println!("Read {} connection records from {}", conns.len(), snapshot.display());
    ingest(pile, branch_id, &conns, dry_run)
}

/// Resolve every connection against existing relations and (unless
/// `dry_run`) commit. Shared by `import <file>` and `pull --import`.
fn ingest(pile: &Path, branch_id: Id, conns: &[Conn], dry_run: bool) -> Result<()> {
    let (created, enriched_url, merged_email, skipped, ambiguous_pairs, committed) =
        with_repo(pile, |repo| {
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull relations: {e:?}"))?;
            let space = ws.checkout(..).map_err(|e| anyhow!("checkout relations: {e:?}"))?;
            let mut look = build_lookup(&mut ws, &space);

            let mut change = TribleSet::new();
            let mut created = 0usize;
            let mut enriched_url = 0usize;
            let mut merged_email = 0usize;
            let mut skipped = 0usize;
            let mut ambiguous: Vec<(Id, Id, String)> = Vec::new();

            for conn in conns {
                let url_k = conn.url_key();
                let email_k = conn.email_key();
                let name = conn.full_name();
                let name_k = name_key(&name);

                // skip identity-less junk rows (empty export records) — they
                // carry no key, so they'd mint a fresh ghost on every import.
                if url_k.is_none() && email_k.is_none() && name_k.is_none() {
                    skipped += 1;
                    continue;
                }

                // 1. deterministic: same profile_url → idempotent enrich.
                if let Some(uk) = &url_k {
                    if let Some(&id) = look.by_url.get(uk) {
                        emit_person(&mut ws, &mut change, id, conn, false);
                        enriched_url += 1;
                        continue;
                    }
                }
                // 2. deterministic: same email → cross-source merge (mail/booth).
                if let Some(ek) = &email_k {
                    if let Some(&id) = look.by_email.get(ek) {
                        emit_person(&mut ws, &mut change, id, conn, false);
                        if let Some(uk) = &url_k {
                            look.by_url.insert(uk.clone(), id);
                        }
                        merged_email += 1;
                        continue;
                    }
                }
                // 3. name-only collision → distinct person + review candidate.
                let collision = name_k
                    .as_ref()
                    .and_then(|nk| look.by_name.get(nk))
                    .and_then(|ids| ids.first().copied());

                let new_id = ufoid().id;
                emit_person(&mut ws, &mut change, new_id, conn, true);
                if let Some(existing) = collision {
                    change += entity! { ExclusiveId::force_ref(&new_id) @
                        relations::review_candidate: existing,
                    };
                    ambiguous.push((new_id, existing, name.clone()));
                }
                created += 1;

                // index the new person so later rows in this same import dedup.
                if let Some(uk) = url_k {
                    look.by_url.insert(uk, new_id);
                }
                if let Some(ek) = email_k {
                    look.by_email.insert(ek, new_id);
                }
                if let Some(nk) = name_k {
                    look.by_name.entry(nk).or_default().push(new_id);
                }
            }

            let committed = if dry_run || change.is_empty() {
                false
            } else {
                ws.commit(change, "linkedin: import connections");
                repo.push(&mut ws).map_err(|e| anyhow!("push relations: {e:?}"))?;
                true
            };
            Ok((created, enriched_url, merged_email, skipped, ambiguous, committed))
        })?;

    println!();
    println!("  new people:        {created}");
    println!("  merged by email:   {merged_email}   (enriched existing mail/booth contacts)");
    println!("  matched by url:    {enriched_url}   (idempotent re-import)");
    println!("  needs review:      {}   (name collision, kept distinct)", ambiguous_pairs.len());
    if skipped > 0 {
        println!("  skipped:           {skipped}   (identity-less junk rows)");
    }
    if !ambiguous_pairs.is_empty() {
        println!("\nReview candidates (run `linkedin review` to adjudicate):");
        for (new_id, existing, name) in &ambiguous_pairs {
            println!("  {} ~ {}   {name}", fmt_id(*new_id), fmt_id(*existing));
        }
    }
    if dry_run {
        println!("\n(dry run — nothing committed)");
    } else if committed {
        println!("\nCommitted to relations.");
    } else {
        println!("\nNothing to commit.");
    }
    Ok(())
}

// ── pull ────────────────────────────────────────────────────────────────────

const SNAPSHOT_BASE: &str = "https://api.linkedin.com/rest/memberSnapshotData";

/// Fetch a Member Snapshot domain, paginating via `paging.links` rel=next.
/// Mirrors the contract the bootstrap puller proved: q=criteria, the app's
/// pinned Linkedin-Version, `start` advancing one page at a time.
fn fetch_snapshot(token: &str, domain: &str, api_version: &str) -> Result<Vec<Conn>> {
    let client = reqwest::blocking::Client::new();
    let mut rows: Vec<Conn> = Vec::new();
    let mut start = 0u32;
    loop {
        let url = format!("{SNAPSHOT_BASE}?q=criteria&domain={domain}&start={start}");
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Linkedin-Version", api_version)
            .header("Content-Type", "application/json")
            .send()
            .map_err(|e| anyhow!("request {domain} start={start}: {e}"))?;
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        if status.as_u16() == 404 || body.contains("No data found") {
            break;
        }
        if !status.is_success() {
            bail!(
                "LinkedIn API {status} at start={start}: {}",
                &body[..body.len().min(300)]
            );
        }
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| anyhow!("parse page {start}: {e}"))?;
        for el in v["elements"].as_array().into_iter().flatten() {
            for item in el["snapshotData"].as_array().into_iter().flatten() {
                match serde_json::from_value::<Conn>(item.clone()) {
                    Ok(c) => rows.push(c),
                    Err(e) => eprintln!("[linkedin] skip malformed record: {e}"),
                }
            }
        }
        let has_next = v["paging"]["links"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|l| l["rel"] == "next");
        if !has_next {
            break;
        }
        start += 1;
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    Ok(rows)
}

#[allow(clippy::too_many_arguments)]
fn cmd_pull(
    pile: &Path,
    branch_id: Id,
    token: &str,
    domain: &str,
    api_version: &str,
    out: Option<PathBuf>,
    import: bool,
    dry_run: bool,
) -> Result<()> {
    println!("Pulling {domain} (Linkedin-Version {api_version})…");
    let conns = fetch_snapshot(token, domain, api_version)?;
    println!("Fetched {} {domain} record(s).", conns.len());

    let out = out.unwrap_or_else(|| PathBuf::from(format!("/tmp/linkedin_{domain}.json")));
    let json = serde_json::to_string_pretty(&conns).map_err(|e| anyhow!("serialize: {e}"))?;
    std::fs::write(&out, json).map_err(|e| anyhow!("write {}: {e}", out.display()))?;
    println!("Wrote snapshot → {}", out.display());

    if import {
        println!();
        ingest(pile, branch_id, &conns, dry_run)?;
    } else {
        println!("(run `linkedin import {}` to ingest into relations)", out.display());
    }
    Ok(())
}

// ── review ──────────────────────────────────────────────────────────────────

fn describe(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> String {
    let name = find!(
        h: TextHandle,
        pattern!(space, [{ id @ metadata::name: ?h }])
    )
    .next()
    .and_then(|h| read_text(ws, h))
    .unwrap_or_else(|| "(no name)".into());
    let company = find!(
        h: TextHandle,
        pattern!(space, [{ id @ relations::company: ?h }])
    )
    .next()
    .and_then(|h| read_text(ws, h));
    let position = find!(
        h: TextHandle,
        pattern!(space, [{ id @ relations::position: ?h }])
    )
    .next()
    .and_then(|h| read_text(ws, h));
    let email = find!(
        e: String,
        pattern!(space, [{ id @ relations::email: ?e }])
    )
    .next();
    let url = find!(
        h: TextHandle,
        pattern!(space, [{ id @ relations::profile_url: ?h }])
    )
    .next()
    .and_then(|h| read_text(ws, h));
    let sources: Vec<String> = find!(
        s: String,
        pattern!(space, [{ id @ relations::source: ?s }])
    )
    .collect();

    let mut parts = vec![format!("{}  {name}", fmt_id(id))];
    if let Some(p) = position {
        parts.push(format!("    position: {p}"));
    }
    if let Some(c) = company {
        parts.push(format!("    company:  {c}"));
    }
    if let Some(e) = email {
        parts.push(format!("    email:    {e}"));
    }
    if let Some(u) = url {
        parts.push(format!("    url:      {u}"));
    }
    if !sources.is_empty() {
        parts.push(format!("    source:   {}", sources.join(", ")));
    }
    parts.join("\n")
}

fn edge_exists(space: &TribleSet, a: Id, b: Id) -> bool {
    let has = |x: Id, y: Id| {
        find!((), pattern!(space, [{ x @ relations::same_as: y }])).next().is_some()
            || find!((), pattern!(space, [{ x @ relations::distinct_from: y }])).next().is_some()
    };
    has(a, b) || has(b, a)
}

fn cmd_review(pile: &Path, branch_id: Id, limit: usize) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull relations: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout relations: {e:?}"))?;

        let pairs: Vec<(Id, Id)> = find!(
            (a: Id, b: Id),
            pattern!(&space, [{ ?a @ relations::review_candidate: ?b }])
        )
        .filter(|(a, b)| !edge_exists(&space, *a, *b))
        .collect();

        if pairs.is_empty() {
            println!("No open review candidates. 🎉");
            return Ok(());
        }
        println!("{} open review candidate(s):\n", pairs.len());
        for (i, (a, b)) in pairs.iter().take(limit).enumerate() {
            println!("[{}] ─────────────────────────────────────", i + 1);
            println!("{}", describe(&mut ws, &space, *a));
            println!("    ~ same person? ~");
            println!("{}", describe(&mut ws, &space, *b));
            println!(
                "  → linkedin resolve {} {} --same | --distinct\n",
                fmt_id(*a),
                fmt_id(*b)
            );
        }
        if pairs.len() > limit {
            println!("(+{} more; raise --limit)", pairs.len() - limit);
        }
        Ok(())
    })
}

// ── resolve ─────────────────────────────────────────────────────────────────

fn resolve_person_id(space: &TribleSet, raw: &str) -> Result<Id> {
    let prefix = raw.trim().to_lowercase();
    if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("person id must be hex (got '{raw}')");
    }
    let mut matches = Vec::new();
    for (id,) in find!(
        (id: Id),
        pattern!(space, [{ ?id @ metadata::tag: &KIND_PERSON_ID }])
    ) {
        let hex = format!("{id:x}");
        if hex == prefix || (prefix.len() < 32 && hex.starts_with(&prefix)) {
            matches.push(id);
        }
    }
    match matches.len() {
        0 => bail!("no person matches '{raw}'"),
        1 => Ok(matches[0]),
        _ => bail!("ambiguous person prefix '{raw}'"),
    }
}

fn cmd_resolve(
    pile: &Path,
    branch_id: Id,
    id_a: &str,
    id_b: &str,
    same: bool,
    distinct: bool,
) -> Result<()> {
    if same == distinct {
        bail!("pass exactly one of --same / --distinct");
    }
    with_repo(pile, |repo| {
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull relations: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout relations: {e:?}"))?;
        let a = resolve_person_id(&space, id_a)?;
        let b = resolve_person_id(&space, id_b)?;
        if a == b {
            bail!("both ids resolve to the same person {}", fmt_id(a));
        }
        let mut change = TribleSet::new();
        if same {
            // symmetric assertion: identity is the connected component.
            change += entity! { ExclusiveId::force_ref(&a) @ relations::same_as: b };
            change += entity! { ExclusiveId::force_ref(&b) @ relations::same_as: a };
        } else {
            change += entity! { ExclusiveId::force_ref(&a) @ relations::distinct_from: b };
            change += entity! { ExclusiveId::force_ref(&b) @ relations::distinct_from: a };
        }
        let verdict = if same { "same_as" } else { "distinct_from" };
        ws.commit(change, "linkedin: identity verdict");
        repo.push(&mut ws).map_err(|e| anyhow!("push relations: {e:?}"))?;
        println!("Recorded {verdict}: {} ↔ {}", fmt_id(a), fmt_id(b));
        Ok(())
    })
}

// ── main ────────────────────────────────────────────────────────────────────

fn resolve_branch(repo: &mut Repository<Pile>, name: &str) -> Result<Id> {
    repo.ensure_branch(name, None)
        .map_err(|e| anyhow!("ensure branch '{name}': {e:?}"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let branch_id = with_repo(&cli.pile, |repo| resolve_branch(repo, &cli.branch))?;

    match cli.command {
        Command::Import { snapshot, dry_run } => {
            cmd_import(&cli.pile, branch_id, &snapshot, dry_run)
        }
        Command::Pull { token, domain, api_version, out, import, dry_run } => cmd_pull(
            &cli.pile,
            branch_id,
            &token,
            &domain,
            &api_version,
            out,
            import,
            dry_run,
        ),
        Command::Review { limit } => cmd_review(&cli.pile, branch_id, limit),
        Command::Resolve { id_a, id_b, same, distinct } => {
            cmd_resolve(&cli.pile, branch_id, &id_a, &id_b, same, distinct)
        }
    }
}
