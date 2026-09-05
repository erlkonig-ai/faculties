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
//! This is a conservative adapter from one external snapshot into authored
//! Relations state, not a source-observation ledger. Before consulting current
//! state, it treats input rows as a set and closes them under shared canonical
//! URL/email keys. Identity remains monotone evidence, never a destructive
//! merge:
//!   * deterministic key matches enrich every anchor in the one settled
//!     same-person component; distinct, forked, or contradictory evidence
//!     fails closed;
//!   * a previously unseen stable URL/email derives the person anchor from a
//!     domain-separated canonical key, so identical imports converge;
//!   * a genuinely name-only row has no honest stable identity key and mints a
//!     fresh anchor (a dry-run reports that such ids are provisional);
//!   * same-label review pairs are a derived view over current Relations
//!     profiles and identity verdicts, not another persisted ontology;
//!   * `linkedin review` lists those derived pairs; `linkedin resolve A B
//!     --same | --distinct` records a fork-visible identity verdict (either
//!     outcome remains correctable by an explicit successor).
//!
//! Commands:
//!   linkedin import <snapshot.json> [--dry-run]
//!   linkedin review [--limit N]
//!   linkedin resolve <id-a> <id-b> --same | --distinct

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use faculties::collection_names::open_configured;
use faculties::relations::{self, Head, ProfileInput};
use faculties::schemas::linkedin;
use faculties::schemas::relations::DEFAULT_SCOPE_ID;
#[cfg(test)]
use faculties::storage;
use faculties::storage::{load_signer, open_pile_strict, FactArchive, FactCollection};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::collection::{Collection, CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::macros::entity;
use triblespace::prelude::*;

// ── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "linkedin", about = "LinkedIn → relations import conduit")]
struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
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
    /// Pull connections from the LinkedIn DMA Member Data Portability API
    /// straight into relations. The snapshot's home is the substrate, not a
    /// JSON file — there is no intermediate dump.
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
        /// Resolve and report but commit nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Derive unresolved same-label identity pairs from current Relations state.
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

#[derive(Deserialize, Default, Clone)]
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
    fn email_key(&self) -> Option<String> {
        let e = self.email.trim().to_ascii_lowercase();
        if e.is_empty() {
            None
        } else {
            Some(e)
        }
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
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn name_key(name: &str) -> Option<String> {
    let k = name.trim().to_ascii_lowercase();
    if k.is_empty() {
        None
    } else {
        Some(k)
    }
}

// ── collection access ───────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct RelationsStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

#[derive(Clone)]
struct RelationsView {
    facts: FactArchive,
    reader: PileSnapshot,
}

impl RelationsStorage<'_> {
    /// Maintain and attach one immutable Relations view before planning. No
    /// repository workspace, branch head, CAS cell, or reopen sits between the
    /// semantic decision and its signed collection commit.
    fn with_store<T>(
        &self,
        operation: impl FnOnce(
            &mut Pile,
            Collection<SimpleArchive>,
            &ed25519_dalek::SigningKey,
            &RelationsView,
        ) -> Result<T>,
    ) -> Result<T> {
        let signer = load_signer(self.pile, self.key)?;
        let mut pile = open_pile_strict(self.pile)?;
        let result = pollster::block_on(async {
            let collection = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
            let maintained = FactCollection::new(&mut pile, collection)
                .context("register maintained Relations fact collection")?;
            let store_snapshot = maintained
                .maintain(&mut pile)
                .await
                .context("maintain Relations fact collection")?;
            let observed = store_snapshot
                .collection(maintained.rank9())
                .context("observe Relations Rank9 projection")?;
            let facts = observed
                .view::<FactArchive>()
                .context("read Relations Rank9 projection")?;
            operation(
                &mut pile,
                maintained.source(),
                &signer,
                &RelationsView {
                    facts,
                    reader: store_snapshot,
                },
            )
        });
        finish_pile(pile, result)
    }

    fn with_view<T>(&self, operation: impl FnOnce(&RelationsView) -> Result<T>) -> Result<T> {
        self.with_store(|_, _, _, view| operation(view))
    }

    /// Publish at most one complete, locally constructed Relations fragment.
    fn update<T>(
        &self,
        description: &'static str,
        operation: impl FnOnce(&RelationsView) -> Result<(Option<Fragment>, T)>,
    ) -> Result<T> {
        self.with_store(|pile, collection, signer, view| {
            let (fragment, value) = operation(view)?;
            if let Some(mut fragment) = fragment {
                fragment.describe_with(entity! { metadata::description: description });
                pile.commit(collection, signer, fragment)
                    .context("commit authored Relations fragment")?;
            }
            Ok(value)
        })
    }

    #[cfg(test)]
    fn view(&self) -> Result<RelationsView> {
        self.with_view(|view| Ok(view.clone()))
    }

    #[cfg(test)]
    fn publish(&self, fragment: Fragment) -> Result<()> {
        self.update("test relations input", |_| Ok((Some(fragment), ())))
    }

    #[cfg(test)]
    fn commit_count(&self) -> Result<usize> {
        let signer = load_signer(self.pile, self.key)?;
        let author = signer.verifying_key().to_bytes();
        let mut pile = open_pile_strict(self.pile)?;
        let result = (|| {
            let collection = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())?;
            let store_snapshot = pile.snapshot()?;
            let cover = collection.admitted(&store_snapshot)?;
            Ok(cover
                .commits(&store_snapshot)?
                .iter()
                .filter(|commit| commit.public_key().raw == author)
                .count())
        })();
        finish_pile(pile, result)
    }
}

fn finish_pile<T>(pile: Pile, result: Result<T>) -> Result<T> {
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close LinkedIn Relations pile")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing LinkedIn Relations pile also failed: {close_error}"
        ))),
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

// ── batch-local planning over the maintained Relations view ─────────────────

#[derive(Clone)]
struct PlannedProfile {
    predecessor: Option<Id>,
    value: ProfileInput,
    dirty: bool,
}

/// Input-shaped projection of the existing Relations view. It retains only
/// keys which this batch actually asks about, never complete profiles or an
/// independently validated catalog.
#[derive(Default)]
struct ImportProjection {
    by_url: BTreeMap<String, BTreeSet<Id>>,
    by_email: BTreeMap<String, BTreeSet<Id>>,
    by_label: BTreeMap<String, BTreeSet<Id>>,
    matching_forks: BTreeSet<Id>,
}

fn index_requested_key(
    index: &mut BTreeMap<String, BTreeSet<Id>>,
    requested: &BTreeSet<String>,
    key: Option<String>,
    person: Id,
) -> bool {
    let Some(key) = key.filter(|key| requested.contains(key)) else {
        return false;
    };
    index.entry(key).or_default().insert(person);
    true
}

fn index_requested_profile_keys(
    projection: &mut ImportProjection,
    requested_urls: &BTreeSet<String>,
    requested_emails: &BTreeSet<String>,
    person: Id,
    profile: &ProfileInput,
) -> bool {
    let mut matched = false;
    for url in &profile.profile_urls {
        matched |= index_requested_key(
            &mut projection.by_url,
            requested_urls,
            normalize_url(url),
            person,
        );
    }
    for email in &profile.emails {
        matched |= index_requested_key(
            &mut projection.by_email,
            requested_emails,
            name_key(email),
            person,
        );
    }
    matched
}

/// Query current profile tracks once for the exact URL, email, and label keys
/// present in this import. Historical profiles which are no longer heads
/// cannot match, and unrelated malformed or forked anchors stay outside the
/// projection.
fn import_projection(
    view: &RelationsView,
    components: &[ImportComponent],
) -> Result<ImportProjection> {
    let requested_urls: BTreeSet<String> = components
        .iter()
        .flat_map(|component| component.urls.iter().cloned())
        .collect();
    let requested_emails: BTreeSet<String> = components
        .iter()
        .flat_map(|component| component.emails.iter().cloned())
        .collect();
    let requested_labels: BTreeSet<String> = components
        .iter()
        .filter_map(|component| component.name.as_ref())
        .map(|name| relations::lookup_key(&name.full))
        .collect();
    let mut projection = ImportProjection::default();
    for person in relations::person_anchors(&view.facts) {
        match relations::profile_head(&view.facts, person)? {
            Head::Missing => {}
            Head::Unique(id) => {
                let snapshot = relations::profile_snapshot(&view.facts, id)?;
                let profile = relations::profile_input(&view.reader, &snapshot)?;
                index_requested_profile_keys(
                    &mut projection,
                    &requested_urls,
                    &requested_emails,
                    person,
                    &profile,
                );
                for label in std::iter::once(&profile.label).chain(profile.aliases.iter()) {
                    let key = relations::lookup_key(label);
                    if requested_labels.contains(&key) {
                        projection.by_label.entry(key).or_default().insert(person);
                    }
                }
            }
            Head::Forked(heads) => {
                let mut matched = false;
                for id in heads {
                    let snapshot = relations::profile_snapshot(&view.facts, id)?;
                    let profile = relations::profile_input(&view.reader, &snapshot)?;
                    matched |= index_requested_profile_keys(
                        &mut projection,
                        &requested_urls,
                        &requested_emails,
                        person,
                        &profile,
                    );
                }
                if matched {
                    projection.matching_forks.insert(person);
                }
            }
        }
    }
    Ok(projection)
}

fn profile_for_planning(view: &RelationsView, person: Id) -> Result<Option<PlannedProfile>> {
    match relations::profile_head(&view.facts, person)? {
        Head::Missing => Ok(None),
        Head::Unique(id) => {
            let snapshot = relations::profile_snapshot(&view.facts, id)?;
            Ok(Some(PlannedProfile {
                predecessor: Some(id),
                value: relations::profile_input(&view.reader, &snapshot)?,
                dirty: false,
            }))
        }
        Head::Forked(heads) => bail!(
            "LinkedIn match expands to same-person anchor {} whose profile is forked across {} heads",
            fmt_id(person),
            heads.len()
        ),
    }
}

fn matched_anchors(
    index: &BTreeMap<String, BTreeSet<Id>>,
    keys: &BTreeSet<String>,
) -> BTreeSet<Id> {
    keys.iter()
        .filter_map(|key| index.get(key))
        .flatten()
        .copied()
        .collect()
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CanonicalName {
    full: String,
    first: String,
    last: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CanonicalRow {
    name: Option<CanonicalName>,
    company: Option<String>,
    position: Option<String>,
    url: Option<String>,
    email: Option<String>,
}

fn trimmed(raw: &str) -> Option<String> {
    let value = raw.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn normalized_words(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl CanonicalRow {
    fn from_conn(conn: &Conn) -> Option<Self> {
        let first = normalized_words(&conn.first);
        let last = normalized_words(&conn.last);
        let full = [first.as_str(), last.as_str()]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let name = (!full.is_empty()).then_some(CanonicalName { full, first, last });
        let url = conn.url_key();
        let email = conn.email_key();
        if name.is_none() && url.is_none() && email.is_none() {
            return None;
        }
        Some(Self {
            name,
            company: trimmed(&conn.company),
            position: trimmed(&conn.position),
            url,
            email,
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ImportComponent {
    urls: BTreeSet<String>,
    emails: BTreeSet<String>,
    name: Option<CanonicalName>,
    company: Option<String>,
    position: Option<String>,
}

#[derive(Debug)]
struct CanonicalInput {
    components: Vec<ImportComponent>,
    skipped: usize,
}

struct Dsu {
    parent: Vec<usize>,
}

impl Dsu {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
        }
    }

    fn root(&mut self, mut index: usize) -> usize {
        while self.parent[index] != index {
            let parent = self.parent[index];
            self.parent[index] = self.parent[parent];
            index = self.parent[index];
        }
        index
    }

    fn union(&mut self, first: usize, second: usize) {
        let first = self.root(first);
        let second = self.root(second);
        if first == second {
            return;
        }
        let (low, high) = if first < second {
            (first, second)
        } else {
            (second, first)
        };
        self.parent[high] = low;
    }
}

fn one_value(values: BTreeSet<String>, field: &str, component: &str) -> Result<Option<String>> {
    match values.into_iter().collect::<Vec<_>>().as_slice() {
        [] => Ok(None),
        [value] => Ok(Some(value.clone())),
        values => bail!(
            "LinkedIn component {component} has conflicting {field} observations: {}",
            values.join(" / ")
        ),
    }
}

fn component_description(
    urls: &BTreeSet<String>,
    emails: &BTreeSet<String>,
    names: &BTreeMap<String, BTreeSet<CanonicalName>>,
) -> String {
    urls.iter()
        .next()
        .map(|value| format!("url:{value}"))
        .or_else(|| emails.iter().next().map(|value| format!("email:{value}")))
        .or_else(|| {
            names
                .values()
                .next()
                .and_then(|values| values.iter().next())
                .map(|value| format!("name:{}", value.full))
        })
        .unwrap_or_else(|| "<empty>".to_owned())
}

fn canonical_input(conns: &[Conn]) -> Result<CanonicalInput> {
    let mut rows = BTreeSet::new();
    let mut skipped = 0;
    for conn in conns {
        if let Some(row) = CanonicalRow::from_conn(conn) {
            rows.insert(row);
        } else {
            skipped += 1;
        }
    }
    let rows: Vec<CanonicalRow> = rows.into_iter().collect();
    let mut dsu = Dsu::new(rows.len());
    let mut owners: BTreeMap<String, usize> = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        for key in row
            .url
            .iter()
            .map(|value| format!("url:{value}"))
            .chain(row.email.iter().map(|value| format!("email:{value}")))
        {
            if let Some(&other) = owners.get(&key) {
                dsu.union(index, other);
            } else {
                owners.insert(key, index);
            }
        }
    }

    let mut groups: BTreeMap<usize, Vec<CanonicalRow>> = BTreeMap::new();
    for (index, row) in rows.into_iter().enumerate() {
        let root = dsu.root(index);
        groups.entry(root).or_default().push(row);
    }

    let mut components = Vec::new();
    for rows in groups.into_values() {
        let mut urls = BTreeSet::new();
        let mut emails = BTreeSet::new();
        let mut names = BTreeMap::new();
        let mut companies = BTreeSet::new();
        let mut positions = BTreeSet::new();
        for row in rows {
            urls.extend(row.url);
            emails.extend(row.email);
            if let Some(name) = row.name {
                names
                    .entry(relations::lookup_key(&name.full))
                    .or_insert_with(BTreeSet::new)
                    .insert(name);
            }
            companies.extend(row.company);
            positions.extend(row.position);
        }
        let description = component_description(&urls, &emails, &names);
        let name_groups: Vec<BTreeSet<CanonicalName>> = names.into_values().collect();
        let name = match name_groups.as_slice() {
            [] => None,
            [variants] => {
                let partitions: BTreeSet<(String, String)> = variants
                    .iter()
                    .map(|name| {
                        (
                            relations::lookup_key(&name.first),
                            relations::lookup_key(&name.last),
                        )
                    })
                    .collect();
                if partitions.len() > 1 {
                    bail!(
                        "LinkedIn component {description} has conflicting first/last name partitions: {}",
                        variants
                            .iter()
                            .map(|name| format!("'{}' | '{}'", name.first, name.last))
                            .collect::<Vec<_>>()
                            .join(" / ")
                    );
                }
                variants.iter().next().cloned()
            }
            groups => bail!(
                "LinkedIn component {description} has conflicting full-name observations: {}",
                groups
                    .iter()
                    .flat_map(|names| names.iter().map(|name| name.full.as_str()))
                    .collect::<Vec<_>>()
                    .join(" / ")
            ),
        };
        components.push(ImportComponent {
            urls,
            emails,
            name,
            company: one_value(companies, "company", &description)?,
            position: one_value(positions, "position", &description)?,
        });
    }
    components.sort();
    Ok(CanonicalInput {
        components,
        skipped,
    })
}

fn stable_person_id(component: &ImportComponent) -> Option<Id> {
    let key = component
        .urls
        .iter()
        .next()
        .map(|key| format!("url:{key}"))
        .or_else(|| {
            component
                .emails
                .iter()
                .next()
                .map(|key| format!("email:{key}"))
        })?;
    entity! { linkedin::person_key: key }.root()
}

fn new_profile(component: &ImportComponent) -> ProfileInput {
    let label = component
        .name
        .as_ref()
        .map(|name| name.full.clone())
        .or_else(|| component.emails.iter().next().cloned())
        .or_else(|| component.urls.iter().next().cloned())
        .expect("an import component has a name or stable key");
    ProfileInput {
        label,
        first_name: component
            .name
            .as_ref()
            .filter(|name| !name.first.is_empty())
            .map(|name| name.first.clone()),
        last_name: component
            .name
            .as_ref()
            .filter(|name| !name.last.is_empty())
            .map(|name| name.last.clone()),
        display_name: component.name.as_ref().map(|name| name.full.clone()),
        emails: component.emails.iter().cloned().collect(),
        company: component.company.clone(),
        position: component.position.clone(),
        profile_urls: component.urls.iter().cloned().collect(),
        ..ProfileInput::default()
    }
}

fn canonical_profile_emails(values: &[String]) -> BTreeSet<String> {
    values.iter().filter_map(|value| name_key(value)).collect()
}

fn canonical_profile_urls(values: &[String]) -> BTreeSet<String> {
    values
        .iter()
        .filter_map(|value| normalize_url(value))
        .collect()
}

fn merge_scalar(
    target: &mut Option<String>,
    incoming: Option<&String>,
    label: &str,
) -> Result<bool> {
    let Some(incoming) = incoming else {
        return Ok(false);
    };
    match target {
        None => {
            *target = Some(incoming.clone());
            Ok(true)
        }
        Some(existing) if existing == incoming => Ok(false),
        Some(existing) => bail!(
            "LinkedIn {label} '{incoming}' conflicts with current Relations value '{existing}'"
        ),
    }
}

fn enrich_profile(planned: &mut PlannedProfile, component: &ImportComponent) -> Result<()> {
    let profile = &mut planned.value;
    let mut email_keys = canonical_profile_emails(&profile.emails);
    for email in &component.emails {
        if email_keys.insert(email.clone()) {
            profile.emails.push(email.clone());
            planned.dirty = true;
        }
    }
    let mut url_keys = canonical_profile_urls(&profile.profile_urls);
    for url in &component.urls {
        if url_keys.insert(url.clone()) {
            profile.profile_urls.push(url.clone());
            planned.dirty = true;
        }
    }
    planned.dirty |= merge_scalar(&mut profile.company, component.company.as_ref(), "company")?;
    planned.dirty |= merge_scalar(
        &mut profile.position,
        component.position.as_ref(),
        "position",
    )?;
    if let Some(name) = &component.name {
        let key = relations::lookup_key(&name.full);
        let already_named = relations::lookup_key(&profile.label) == key
            || profile
                .aliases
                .iter()
                .any(|alias| relations::lookup_key(alias) == key);
        if !already_named {
            profile.aliases.push(name.full.clone());
            planned.dirty = true;
        }
    }
    Ok(())
}

fn settled_identity_component(
    view: &RelationsView,
    identities: &relations::IdentityComponents,
    raw: &BTreeSet<Id>,
    matching_forks: &BTreeSet<Id>,
) -> Result<BTreeSet<Id>> {
    let first = *raw.iter().next().expect("called only for matched anchors");
    for person in raw {
        if matching_forks.contains(person) {
            let Head::Forked(heads) = relations::profile_head(&view.facts, *person)? else {
                unreachable!("matching fork was observed from the same immutable view")
            };
            bail!(
                "LinkedIn key matches person {} whose profile is forked across {} heads",
                fmt_id(*person),
                heads.len()
            );
        }
    }
    let component = identities.component(first).with_context(|| {
        format!("LinkedIn key match touches unsettled identity around {first:x}")
    })?;
    if identities
        .mixed_forked_pairs()
        .iter()
        .any(|(low, high)| component.contains(low) || component.contains(high))
    {
        bail!(
            "LinkedIn key match touches an identity component with a mixed same/distinct verdict fork"
        );
    }
    for &person in raw.iter().skip(1) {
        let other = identities.component(person).with_context(|| {
            format!("LinkedIn key match touches unsettled identity around {person:x}")
        })?;
        if other != component {
            bail!(
                "LinkedIn URL/email keys match distinct identity components: {}",
                raw.iter()
                    .map(|id| fmt_id(*id))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    let mut usable = BTreeSet::new();
    for person in &component {
        match relations::profile_head(&view.facts, *person)? {
            Head::Missing => {
                // An anchor without the typed profile projection this reader
                // understands is simply outside the writable view.
            }
            Head::Unique(_) => {
                usable.insert(*person);
            }
            Head::Forked(heads) => bail!(
                "LinkedIn match expands to same-person anchor {} whose profile is forked across {} heads",
                fmt_id(*person),
                heads.len()
            ),
        }
    }
    Ok(usable)
}

// ── import ──────────────────────────────────────────────────────────────────

struct IngestPlan {
    fragment: Fragment,
    created: usize,
    matched_by_url: usize,
    matched_by_email: usize,
    skipped: usize,
    name_only: usize,
    prospective_collisions: Vec<(Id, Id, String)>,
}

struct IngestReport {
    created: usize,
    matched_by_url: usize,
    matched_by_email: usize,
    skipped: usize,
    name_only: usize,
    prospective_collisions: Vec<(Id, Id, String)>,
    committed: bool,
}

fn ordered_pair(first: Id, second: Id) -> (Id, Id) {
    if first < second {
        (first, second)
    } else {
        (second, first)
    }
}

fn index_profile_labels(
    labels: &mut BTreeMap<String, BTreeSet<Id>>,
    person: Id,
    profile: &ProfileInput,
) {
    for label in std::iter::once(&profile.label).chain(profile.aliases.iter()) {
        labels
            .entry(relations::lookup_key(label))
            .or_default()
            .insert(person);
    }
}

fn plan_import(view: &RelationsView, conns: &[Conn]) -> Result<IngestPlan> {
    let CanonicalInput {
        components,
        skipped,
    } = canonical_input(conns)?;
    // Existing Relations facts stay in their maintained query representation.
    // This map contains only profiles the input batch actually touches.
    let mut profiles = BTreeMap::new();
    let mut projection = import_projection(view, &components)?;
    let identities = relations::IdentityComponents::from_facts(&view.facts)?;

    let mut created = 0;
    let mut matched_by_url = 0;
    let mut matched_by_email = 0;
    let mut name_only = 0;
    let mut prospective_collisions = BTreeSet::new();

    for component in components {
        let url_matches = matched_anchors(&projection.by_url, &component.urls);
        let email_matches = matched_anchors(&projection.by_email, &component.emails);
        let raw_matches: BTreeSet<Id> = url_matches.union(&email_matches).copied().collect();

        if !raw_matches.is_empty() {
            matched_by_url += usize::from(!url_matches.is_empty());
            matched_by_email += usize::from(!email_matches.is_empty());
            let settled = settled_identity_component(
                view,
                &identities,
                &raw_matches,
                &projection.matching_forks,
            )?;
            for person in settled {
                if !profiles.contains_key(&person) {
                    let Some(profile) = profile_for_planning(view, person)? else {
                        continue;
                    };
                    profiles.insert(person, profile);
                }
                let profile = profiles
                    .get_mut(&person)
                    .expect("profile was inserted above");
                enrich_profile(profile, &component)
                    .with_context(|| format!("enrich Relations person {}", fmt_id(person)))?;
            }
            continue;
        }

        let person = match stable_person_id(&component) {
            Some(person) => person,
            None => {
                name_only += 1;
                genid().id
            }
        };

        let value = new_profile(&component);
        if component.name.is_some() {
            let label_key = relations::lookup_key(&value.label);
            for existing in projection
                .by_label
                .get(&label_key)
                .into_iter()
                .flatten()
                .copied()
            {
                if existing == person {
                    continue;
                }
                let (first, second) = ordered_pair(person, existing);
                prospective_collisions.insert((first, second, value.label.clone()));
            }
        }
        index_profile_labels(&mut projection.by_label, person, &value);
        profiles.insert(
            person,
            PlannedProfile {
                predecessor: None,
                value,
                dirty: true,
            },
        );
        created += 1;
    }

    let mut fragment = Fragment::empty();
    for (person, planned) in profiles {
        if !planned.dirty {
            continue;
        }
        if let Some(predecessor) = planned.predecessor {
            fragment += relations::profile_fragment(person, planned.value, &[predecessor])?;
        } else {
            fragment += relations::person_fragment(person, planned.value)?.0;
        }
    }

    Ok(IngestPlan {
        fragment,
        created,
        matched_by_url,
        matched_by_email,
        skipped,
        name_only,
        prospective_collisions: prospective_collisions.into_iter().collect(),
    })
}

fn cmd_import(storage: RelationsStorage<'_>, snapshot: &Path, dry_run: bool) -> Result<()> {
    let raw = std::fs::read_to_string(snapshot)
        .map_err(|e| anyhow!("read snapshot {}: {e}", snapshot.display()))?;
    let conns: Vec<Conn> =
        serde_json::from_str(&raw).map_err(|e| anyhow!("parse snapshot JSON: {e}"))?;
    println!(
        "Read {} connection records from {}",
        conns.len(),
        snapshot.display()
    );
    ingest(storage, &conns, dry_run)
}

/// Resolve every connection against existing relations and (unless
/// `dry_run`) commit. Shared by `import <file>` and `pull --import`.
fn ingest(storage: RelationsStorage<'_>, conns: &[Conn], dry_run: bool) -> Result<()> {
    let report = storage.update("linkedin: import connections", |view| {
        let IngestPlan {
            fragment,
            created,
            matched_by_url,
            matched_by_email,
            skipped,
            name_only,
            prospective_collisions,
        } = plan_import(view, conns)?;
        let committed = !dry_run && !fragment.facts().is_empty();
        Ok((
            committed.then_some(fragment),
            IngestReport {
                created,
                matched_by_url,
                matched_by_email,
                skipped,
                name_only,
                prospective_collisions,
                committed,
            },
        ))
    })?;

    println!();
    println!("  new people:        {}", report.created);
    println!(
        "  matched by email:  {}   (components with existing email evidence)",
        report.matched_by_email
    );
    println!(
        "  matched by url:    {}   (components with existing profile-URL evidence)",
        report.matched_by_url
    );
    println!(
        "  prospective review:{}   (same current label, kept distinct)",
        report.prospective_collisions.len()
    );
    if report.skipped > 0 {
        println!(
            "  skipped:           {}   (identity-less junk rows)",
            report.skipped
        );
    }
    if report.name_only > 0 {
        let qualification = if dry_run {
            "fresh provisional dry-run anchors; no stable upstream key"
        } else {
            "fresh anchors; no stable upstream key"
        };
        println!(
            "  name-only rows:     {}   ({qualification})",
            report.name_only
        );
    }
    if !report.prospective_collisions.is_empty() {
        println!("\nProspective name collisions (derived, not persisted):");
        for (new_id, existing, name) in &report.prospective_collisions {
            println!("  {} ~ {}   {name}", fmt_id(*new_id), fmt_id(*existing));
        }
    }
    if dry_run {
        println!("\n(dry run — nothing committed)");
    } else if report.committed {
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

fn cmd_pull(
    storage: RelationsStorage<'_>,
    token: &str,
    domain: &str,
    api_version: &str,
    dry_run: bool,
) -> Result<()> {
    println!("Pulling {domain} (Linkedin-Version {api_version})…");
    let conns = fetch_snapshot(token, domain, api_version)?;
    println!("Fetched {} {domain} record(s).", conns.len());
    println!();
    ingest(storage, &conns, dry_run)
}

// ── review ──────────────────────────────────────────────────────────────────

fn describe(view: &RelationsView, id: Id) -> Result<String> {
    let snapshot = relations::current_profile(&view.facts, id)?;
    let profile = relations::profile_input(&view.reader, &snapshot)?;
    let mut parts = vec![format!("{}  {}", fmt_id(id), profile.label)];
    if let Some(p) = profile.position {
        parts.push(format!("    position: {p}"));
    }
    if let Some(c) = profile.company {
        parts.push(format!("    company:  {c}"));
    }
    for e in profile.emails {
        parts.push(format!("    email:    {e}"));
    }
    for u in profile.profile_urls {
        parts.push(format!("    url:      {u}"));
    }
    Ok(parts.join("\n"))
}

fn direct_verdict_is_mixed(facts: &FactArchive, first: Id, second: Id) -> Result<bool> {
    let Head::Forked(heads) = relations::identity_head(facts, first, second)? else {
        return Ok(false);
    };
    let values: BTreeSet<bool> = heads
        .into_iter()
        .map(|id| Ok(relations::identity_verdict(facts, id)?.same))
        .collect::<Result<_>>()?;
    Ok(values.len() > 1)
}

fn derived_review_pairs(view: &RelationsView) -> Result<Vec<(Id, Id)>> {
    let identities = relations::IdentityComponents::from_facts(&view.facts)?;
    let mut labels: BTreeMap<String, BTreeSet<Id>> = BTreeMap::new();
    for person in relations::person_anchors(&view.facts) {
        let Head::Unique(profile) = relations::profile_head(&view.facts, person)? else {
            continue;
        };
        let snapshot = relations::profile_snapshot(&view.facts, profile)?;
        let profile = relations::profile_input(&view.reader, &snapshot)?;
        index_profile_labels(&mut labels, person, &profile);
    }

    let mut pairs = BTreeSet::new();
    for people in labels.into_values() {
        let people: Vec<Id> = people.into_iter().collect();
        for (index, &first) in people.iter().enumerate() {
            for &second in &people[index + 1..] {
                match identities.relation(first, second) {
                    Ok(relations::IdentityRelation::Same)
                    | Ok(relations::IdentityRelation::Distinct) => {}
                    Ok(relations::IdentityRelation::Unknown) => {
                        pairs.insert((first, second));
                    }
                    Err(_) if direct_verdict_is_mixed(&view.facts, first, second)? => {
                        pairs.insert((first, second));
                    }
                    Err(_) => {}
                }
            }
        }
    }
    Ok(pairs.into_iter().collect())
}

fn cmd_review(storage: RelationsStorage<'_>, limit: usize) -> Result<()> {
    storage.with_view(|view| {
        let pairs = derived_review_pairs(view)?;

        if pairs.is_empty() {
            println!("No open review candidates. 🎉");
            return Ok(());
        }
        println!("{} open review candidate(s):\n", pairs.len());
        for (i, (a, b)) in pairs.iter().take(limit).enumerate() {
            println!("[{}] ─────────────────────────────────────", i + 1);
            println!("{}", describe(view, *a)?);
            println!("    ~ same person? ~");
            println!("{}", describe(view, *b)?);
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

fn resolve_person_id(space: &FactArchive, raw: &str) -> Result<Id> {
    let prefix = raw.trim().to_lowercase();
    if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("person id must be hex (got '{raw}')");
    }
    let mut matches = Vec::new();
    for id in relations::person_anchors(space) {
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
    storage: RelationsStorage<'_>,
    id_a: &str,
    id_b: &str,
    same: bool,
    distinct: bool,
) -> Result<()> {
    if same == distinct {
        bail!("pass exactly one of --same / --distinct");
    }
    enum Outcome {
        Already(Id),
        Recorded { first: Id, second: Id, id: Id },
    }
    let outcome = storage.update("linkedin: identity verdict", |view| {
        let a = resolve_person_id(&view.facts, id_a)?;
        let b = resolve_person_id(&view.facts, id_b)?;
        if a == b {
            bail!("both ids resolve to the same person {}", fmt_id(a));
        }
        let predecessors = match relations::identity_head(&view.facts, a, b)? {
            Head::Missing => Vec::new(),
            Head::Unique(id) => {
                if relations::identity_verdict(&view.facts, id)?.same == same {
                    return Ok((None, Outcome::Already(id)));
                }
                vec![id]
            }
            Head::Forked(ids) => ids,
        };
        let fragment = relations::identity_verdict_fragment(a, b, same, &predecessors)?;
        let successor = fragment.root().expect("identity verdict root");
        Ok((
            Some(fragment),
            Outcome::Recorded {
                first: a,
                second: b,
                id: successor,
            },
        ))
    })?;
    match outcome {
        Outcome::Already(id) => println!("Identity verdict is already settled at {}.", fmt_id(id)),
        Outcome::Recorded { first, second, id } => {
            let verdict = if same { "same_as" } else { "distinct_from" };
            println!(
                "Recorded {verdict}: {} ↔ {} ({})",
                fmt_id(first),
                fmt_id(second),
                fmt_id(id)
            );
        }
    }
    Ok(())
}

// ── main ────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = RelationsStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };

    match cli.command {
        Command::Import { snapshot, dry_run } => cmd_import(storage, &snapshot, dry_run),
        Command::Pull {
            token,
            domain,
            api_version,
            dry_run,
        } => cmd_pull(storage, &token, &domain, &api_version, dry_run),
        Command::Review { limit } => cmd_review(storage, limit),
        Command::Resolve {
            id_a,
            id_b,
            same,
            distinct,
        } => cmd_resolve(storage, &id_a, &id_b, same, distinct),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("linkedin.pile");
            let key = directory.path().join("linkedin.key");
            File::create(&pile).unwrap();
            storage::initialize_signer(&pile, Some(&key)).unwrap();
            Self {
                _directory: directory,
                pile,
                key,
            }
        }

        fn storage(&self) -> RelationsStorage<'_> {
            RelationsStorage {
                pile: &self.pile,
                key: Some(&self.key),
            }
        }

        fn view(&self) -> RelationsView {
            self.storage().view().unwrap()
        }

        fn publish(&self, fragment: Fragment) {
            self.storage().publish(fragment).unwrap();
        }

        fn commit_count(&self) -> usize {
            self.storage().commit_count().unwrap()
        }
    }

    fn connection(name: &str, url: &str, email: &str) -> Conn {
        let mut names = name.splitn(2, ' ');
        Conn {
            first: names.next().unwrap_or_default().to_owned(),
            last: names.next().unwrap_or_default().to_owned(),
            url: url.to_owned(),
            email: email.to_owned(),
            ..Conn::default()
        }
    }

    fn person(label: &str, url: &str, email: &str) -> (Id, Fragment) {
        let id = genid().id;
        let profile = ProfileInput {
            label: label.to_owned(),
            emails: (!email.is_empty())
                .then(|| email.to_owned())
                .into_iter()
                .collect(),
            profile_urls: (!url.is_empty())
                .then(|| url.to_owned())
                .into_iter()
                .collect(),
            ..ProfileInput::default()
        };
        (id, relations::person_fragment(id, profile).unwrap().0)
    }

    fn person_with_aliases(label: &str, aliases: &[&str]) -> (Id, Fragment) {
        let id = genid().id;
        let profile = ProfileInput {
            label: label.to_owned(),
            aliases: aliases.iter().map(|alias| (*alias).to_owned()).collect(),
            ..ProfileInput::default()
        };
        (id, relations::person_fragment(id, profile).unwrap().0)
    }

    fn one_component(rows: &[Conn]) -> ImportComponent {
        let mut input = canonical_input(rows).unwrap();
        assert_eq!(input.components.len(), 1);
        input.components.pop().unwrap()
    }

    fn fork_profile(fixture: &Fixture, person: Id) -> String {
        let view = fixture.view();
        let current = relations::current_profile(&view.facts, person).unwrap();
        let base = relations::profile_input(&view.reader, &current).unwrap();
        let alternate = "linkedin.com/in/fork-alternate".to_owned();
        let mut left = base.clone();
        left.company = Some("Left".to_owned());
        left.profile_urls.push(alternate.clone());
        let mut right = base;
        right.company = Some("Right".to_owned());
        let fork = relations::profile_fragment(person, left, &[current.id]).unwrap()
            + relations::profile_fragment(person, right, &[current.id]).unwrap();
        fixture.publish(fork);
        alternate
    }

    #[test]
    fn stable_anchor_uses_canonical_url_then_email() {
        let first = one_component(&[connection(
            "Ada Lovelace",
            "https://www.linkedin.com/in/ada/",
            "ada@first.test",
        )]);
        let same_url = one_component(&[connection(
            "Ada Lovelace",
            "LINKEDIN.COM/in/ada",
            "ada@second.test",
        )]);
        assert_eq!(stable_person_id(&first), stable_person_id(&same_url));

        let first_email = one_component(&[connection("Ada", "", "ADA@example.test")]);
        let same_email = one_component(&[connection("Ada", "", "ada@example.test")]);
        assert_eq!(
            stable_person_id(&first_email),
            stable_person_id(&same_email)
        );
        let name_only = one_component(&[connection("Ada", "", "")]);
        assert!(stable_person_id(&name_only).is_none());
    }

    #[test]
    fn row_permutations_with_a_bridge_produce_the_same_fragment() {
        let fixture = Fixture::new();
        let rows = [
            connection("Ada Lovelace", "linkedin.com/in/ada", ""),
            connection("Ada Lovelace", "", "ada@example.test"),
            connection(
                "Ada Lovelace",
                "https://www.linkedin.com/in/ada/",
                "ADA@example.test",
            ),
        ];
        let orders = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        let mut expected = None;
        for order in orders {
            let permutation = order.map(|index| rows[index].clone());
            let plan = plan_import(&fixture.view(), &permutation).unwrap();
            assert_eq!(plan.created, 1);
            if let Some(expected) = &expected {
                assert_eq!(&plan.fragment, expected);
            } else {
                expected = Some(plan.fragment);
            }
        }
    }

    #[test]
    fn three_rows_close_transitively_under_shared_keys() {
        let rows = [
            connection("Ada Lovelace", "linkedin.com/in/one", "one@example.test"),
            connection("Ada Lovelace", "linkedin.com/in/one", "two@example.test"),
            connection("Ada Lovelace", "linkedin.com/in/two", "two@example.test"),
        ];
        let component = one_component(&rows);
        assert_eq!(component.urls.len(), 2);
        assert_eq!(component.emails.len(), 2);

        let fixture = Fixture::new();
        let plan = plan_import(&fixture.view(), &rows).unwrap();
        assert_eq!(plan.created, 1);
        assert_eq!(relations::person_anchors(plan.fragment.facts()).len(), 1);
        let first_key = one_component(&[connection(
            "Ada Lovelace",
            "linkedin.com/in/one",
            "ignored@example.test",
        )]);
        assert_eq!(
            stable_person_id(&component),
            stable_person_id(&first_key),
            "the lexicographically first URL, not an email, names the component"
        );
    }

    #[test]
    fn duplicate_import_is_a_no_op_and_url_spelling_is_canonical() {
        let fixture = Fixture::new();
        let row = connection(
            "Ada Lovelace",
            "https://WWW.LinkedIn.com/in/Ada/",
            "ada@example.test",
        );
        let person = stable_person_id(&one_component(std::slice::from_ref(&row))).unwrap();
        ingest(fixture.storage(), std::slice::from_ref(&row), false).unwrap();
        let first = fixture.view();
        let first_head = relations::current_profile(&first.facts, person).unwrap().id;
        let first_commits = fixture.commit_count();
        let profile = relations::current_profile(&first.facts, person).unwrap();
        let profile = relations::profile_input(&first.reader, &profile).unwrap();
        assert_eq!(profile.profile_urls, ["linkedin.com/in/ada"]);

        let canonical = connection("Ada Lovelace", "linkedin.com/in/ada", "ADA@example.test");
        ingest(fixture.storage(), &[canonical], false).unwrap();
        let second = fixture.view();
        assert_eq!(
            relations::current_profile(&second.facts, person)
                .unwrap()
                .id,
            first_head
        );
        assert_eq!(fixture.commit_count(), first_commits);
    }

    #[test]
    fn unrelated_anchor_without_a_profile_does_not_block_import() {
        let fixture = Fixture::new();
        let unrelated = genid().id;
        fixture.publish(entity! { ExclusiveId::force_ref(&unrelated) @
            metadata::tag: &faculties::schemas::relations::KIND_PERSON_ID,
        });

        let row = connection("Ada Lovelace", "linkedin.com/in/ada", "");
        ingest(fixture.storage(), &[row], false).unwrap();

        let view = fixture.view();
        let anchors = relations::person_anchors(&view.facts);
        assert_eq!(anchors.len(), 2);
        assert!(anchors.contains(&unrelated));
        assert!(matches!(
            relations::profile_head(&view.facts, unrelated).unwrap(),
            Head::Missing
        ));
    }

    #[test]
    fn repeated_multi_key_import_does_not_depend_on_handle_order() {
        let fixture = Fixture::new();
        let rows = [
            connection("Ada Lovelace", "linkedin.com/in/one", "one@example.test"),
            connection("Ada Lovelace", "linkedin.com/in/one", "two@example.test"),
            connection("Ada Lovelace", "linkedin.com/in/two", "two@example.test"),
        ];
        let person = stable_person_id(&one_component(&rows)).unwrap();
        ingest(fixture.storage(), &rows, false).unwrap();
        let first = fixture.view();
        let head = relations::current_profile(&first.facts, person).unwrap().id;
        let commits = fixture.commit_count();

        ingest(fixture.storage(), &rows, false).unwrap();
        let second = fixture.view();
        assert_eq!(
            relations::current_profile(&second.facts, person)
                .unwrap()
                .id,
            head
        );
        assert_eq!(fixture.commit_count(), commits);
    }

    #[test]
    fn equivalent_keys_preserve_existing_generic_values_byte_for_byte() {
        let fixture = Fixture::new();
        let exact_url = "https://Example.com/CaseSensitive";
        let exact_email = "Exact.Case@Example.test";
        let (person, fragment) = person("Exact Person", exact_url, exact_email);
        fixture.publish(fragment);
        let before = fixture.view();
        let head = relations::current_profile(&before.facts, person)
            .unwrap()
            .id;
        let commits = fixture.commit_count();

        let equivalent = connection(
            "Exact Person",
            "http://www.EXAMPLE.com/CaseSensitive/",
            "exact.case@example.test",
        );
        ingest(fixture.storage(), &[equivalent], false).unwrap();

        let after = fixture.view();
        assert_eq!(
            relations::current_profile(&after.facts, person).unwrap().id,
            head
        );
        assert_eq!(fixture.commit_count(), commits);
        let snapshot = relations::current_profile(&after.facts, person).unwrap();
        let value = relations::profile_input(&after.reader, &snapshot).unwrap();
        assert_eq!(value.profile_urls, [exact_url]);
        assert_eq!(value.emails, [exact_email]);
    }

    #[test]
    fn dry_run_publishes_no_collection_commit() {
        let fixture = Fixture::new();
        let before = fixture.commit_count();
        let row = connection(
            "Ada Lovelace",
            "https://linkedin.com/in/ada",
            "ada@example.test",
        );

        ingest(fixture.storage(), &[row], true).unwrap();

        assert_eq!(fixture.commit_count(), before);
        assert!(relations::person_anchors(&fixture.view().facts).is_empty());
    }

    #[test]
    fn distinct_url_and_email_matches_fail_closed() {
        let fixture = Fixture::new();
        let (_, url_person) = person("URL Person", "linkedin.com/in/url", "");
        fixture.publish(url_person);
        let (_, email_person) = person("Email Person", "", "shared@example.test");
        fixture.publish(email_person);

        let row = connection(
            "Conflict Person",
            "linkedin.com/in/url",
            "shared@example.test",
        );
        let error = ingest(fixture.storage(), &[row], true).unwrap_err();
        assert!(error.to_string().contains("distinct identity components"));
    }

    #[test]
    fn a_settled_same_person_bridge_enriches_every_anchor() {
        let fixture = Fixture::new();
        let (url_person, url_fragment) = person("URL Person", "linkedin.com/in/url", "");
        let (email_person, email_fragment) = person("Email Person", "", "shared@example.test");
        fixture.publish(url_fragment + email_fragment);
        fixture.publish(
            relations::identity_verdict_fragment(url_person, email_person, true, &[]).unwrap(),
        );

        let mut row = connection(
            "Combined Person",
            "https://www.linkedin.com/in/url/",
            "SHARED@example.test",
        );
        row.company = "Analytical Engines".to_owned();
        ingest(fixture.storage(), &[row], false).unwrap();

        let view = fixture.view();
        for person in [url_person, email_person] {
            let current = relations::current_profile(&view.facts, person).unwrap();
            let value = relations::profile_input(&view.reader, &current).unwrap();
            assert_eq!(value.emails, ["shared@example.test"]);
            assert_eq!(value.profile_urls, ["linkedin.com/in/url"]);
            assert_eq!(value.company.as_deref(), Some("Analytical Engines"));
            assert!(value.aliases.contains(&"Combined Person".to_owned()));
        }
    }

    #[test]
    fn an_unrelated_profile_fork_does_not_block_but_a_matching_fork_does() {
        let fixture = Fixture::new();
        let (forked, fragment) = person("Forked", "linkedin.com/in/fork", "");
        fixture.publish(fragment);
        let alternate = fork_profile(&fixture, forked);

        let unrelated = connection("Ada Lovelace", "linkedin.com/in/ada", "");
        ingest(fixture.storage(), &[unrelated], true).unwrap();

        let matching = connection("Forked", &alternate, "");
        let error = ingest(fixture.storage(), &[matching], true).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("profile is forked"), "{message}");
        assert!(message.contains(&fmt_id(forked)), "{message}");
    }

    #[test]
    fn current_scalar_conflict_fails_without_appending() {
        let fixture = Fixture::new();
        let mut row = connection("Ada Lovelace", "linkedin.com/in/ada", "");
        row.company = "Analytical Engines".to_owned();
        ingest(fixture.storage(), std::slice::from_ref(&row), false).unwrap();
        let before = fixture.commit_count();

        ingest(fixture.storage(), std::slice::from_ref(&row), false).unwrap();
        assert_eq!(fixture.commit_count(), before);

        row.company = "Difference Engines".to_owned();
        let error = ingest(fixture.storage(), &[row], false).unwrap_err();
        assert!(format!("{error:#}").contains("company"));
        assert_eq!(fixture.commit_count(), before);
    }

    #[test]
    fn conflicting_observations_inside_a_new_component_fail() {
        let fixture = Fixture::new();
        let mut first = connection("Ada Lovelace", "linkedin.com/in/ada", "");
        first.company = "Analytical Engines".to_owned();
        let mut second = connection("Ada Lovelace", "linkedin.com/in/ada", "");
        second.company = "Difference Engines".to_owned();
        let error = ingest(fixture.storage(), &[first, second], true).unwrap_err();
        assert!(error
            .to_string()
            .contains("conflicting company observations"));

        let first = connection("Ada Lovelace", "linkedin.com/in/ada", "");
        let second = connection("Grace Hopper", "linkedin.com/in/ada", "");
        let error = ingest(fixture.storage(), &[first, second], true).unwrap_err();
        assert!(error
            .to_string()
            .contains("conflicting full-name observations"));

        let first = Conn {
            first: "Mary Ann".to_owned(),
            last: "Smith".to_owned(),
            url: "linkedin.com/in/mary".to_owned(),
            ..Conn::default()
        };
        let second = Conn {
            first: "Mary".to_owned(),
            last: "Ann Smith".to_owned(),
            url: "linkedin.com/in/mary".to_owned(),
            ..Conn::default()
        };
        let error = ingest(fixture.storage(), &[first, second], true).unwrap_err();
        assert!(error
            .to_string()
            .contains("conflicting first/last name partitions"));
        assert!(relations::person_anchors(&fixture.view().facts).is_empty());
    }

    #[test]
    fn differing_existing_name_becomes_an_alias() {
        let fixture = Fixture::new();
        let (person, fragment) = person("Augusta Ada King", "linkedin.com/in/ada", "");
        fixture.publish(fragment);
        ingest(
            fixture.storage(),
            &[connection("Ada Lovelace", "linkedin.com/in/ada", "")],
            false,
        )
        .unwrap();
        let view = fixture.view();
        let profile = relations::current_profile(&view.facts, person).unwrap();
        let profile = relations::profile_input(&view.reader, &profile).unwrap();
        assert_eq!(profile.label, "Augusta Ada King");
        assert_eq!(profile.aliases, ["Ada Lovelace"]);
    }

    #[test]
    fn same_label_review_is_derived_and_respects_verdict_algebra() {
        let fixture = Fixture::new();
        let (first, first_fragment) = person("Ada Lovelace", "", "");
        let (second, second_fragment) = person("ada lovelace", "", "");
        fixture.publish(first_fragment + second_fragment);
        let pair = ordered_pair(first, second);
        assert_eq!(derived_review_pairs(&fixture.view()).unwrap(), [pair]);

        fixture.publish(relations::identity_verdict_fragment(first, second, false, &[]).unwrap());
        assert!(derived_review_pairs(&fixture.view()).unwrap().is_empty());

        let view = fixture.view();
        let Head::Unique(predecessor) =
            relations::identity_head(&view.facts, first, second).unwrap()
        else {
            panic!("expected one direct verdict head")
        };
        let mixed = relations::identity_verdict_fragment(first, second, true, &[predecessor])
            .unwrap()
            + relations::identity_verdict_fragment(first, second, false, &[predecessor]).unwrap();
        fixture.publish(mixed);
        assert_eq!(derived_review_pairs(&fixture.view()).unwrap(), [pair]);
    }

    #[test]
    fn review_suppresses_distinctness_propagated_through_same_identity() {
        let fixture = Fixture::new();
        let (first, first_fragment) = person("Shared Label", "", "");
        let (bridge, bridge_fragment) = person("Bridge", "", "");
        let (same_as_bridge, same_fragment) = person("shared label", "", "");
        fixture.publish(first_fragment + bridge_fragment + same_fragment);
        fixture.publish(relations::identity_verdict_fragment(first, bridge, false, &[]).unwrap());
        fixture.publish(
            relations::identity_verdict_fragment(bridge, same_as_bridge, true, &[]).unwrap(),
        );

        assert!(derived_review_pairs(&fixture.view()).unwrap().is_empty());
    }

    #[test]
    fn review_suppresses_same_identity_reached_transitively() {
        let fixture = Fixture::new();
        let (first, first_fragment) = person("Shared Label", "", "");
        let (bridge, bridge_fragment) = person("Bridge", "", "");
        let (same_as_first, same_fragment) = person("shared label", "", "");
        fixture.publish(first_fragment + bridge_fragment + same_fragment);
        fixture.publish(relations::identity_verdict_fragment(first, bridge, true, &[]).unwrap());
        fixture.publish(
            relations::identity_verdict_fragment(bridge, same_as_first, true, &[]).unwrap(),
        );

        assert!(derived_review_pairs(&fixture.view()).unwrap().is_empty());
    }

    #[test]
    fn review_suppresses_same_valued_verdict_forks() {
        let fixture = Fixture::new();
        let (same_a, same_a_fragment) = person("Same Pair", "", "");
        let (same_b, same_b_fragment) = person("same pair", "", "");
        let (distinct_a, distinct_a_fragment) = person("Distinct Pair", "", "");
        let (distinct_b, distinct_b_fragment) = person("distinct pair", "", "");
        fixture
            .publish(same_a_fragment + same_b_fragment + distinct_a_fragment + distinct_b_fragment);

        for (first, second, settled_value) in
            [(same_a, same_b, true), (distinct_a, distinct_b, false)]
        {
            let initial =
                relations::identity_verdict_fragment(first, second, settled_value, &[]).unwrap();
            let initial_id = initial.root().unwrap();
            fixture.publish(initial);
            fixture.publish(
                relations::identity_verdict_fragment(first, second, settled_value, &[initial_id])
                    .unwrap(),
            );
            let detour =
                relations::identity_verdict_fragment(first, second, !settled_value, &[initial_id])
                    .unwrap();
            let detour_id = detour.root().unwrap();
            fixture.publish(detour);
            fixture.publish(
                relations::identity_verdict_fragment(first, second, settled_value, &[detour_id])
                    .unwrap(),
            );
            assert!(matches!(
                relations::identity_head(&fixture.view().facts, first, second).unwrap(),
                Head::Forked(_)
            ));
        }

        assert!(derived_review_pairs(&fixture.view()).unwrap().is_empty());
    }

    #[test]
    fn review_indexes_primary_labels_and_aliases_and_deduplicates_pairs() {
        let fixture = Fixture::new();
        let (alias_person, alias_fragment) =
            person_with_aliases("First", &["Alias Meets Label", "Duplicate Key"]);
        let (label_person, label_fragment) =
            person_with_aliases("alias meets label", &["duplicate key"]);
        let (left_alias, left_fragment) = person_with_aliases("Left", &["Shared Alias"]);
        let (right_alias, right_fragment) = person_with_aliases("Right", &["shared alias"]);
        fixture.publish(alias_fragment + label_fragment + left_fragment + right_fragment);

        let expected: BTreeSet<(Id, Id)> = [
            ordered_pair(alias_person, label_person),
            ordered_pair(left_alias, right_alias),
        ]
        .into();
        assert_eq!(
            derived_review_pairs(&fixture.view())
                .unwrap()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            expected
        );
    }

    #[test]
    fn prospective_collision_index_includes_existing_aliases() {
        let fixture = Fixture::new();
        let (_, existing) = person_with_aliases("Augusta King", &["Ada Lovelace"]);
        fixture.publish(existing);
        let row = connection("ada lovelace", "linkedin.com/in/ada", "");

        let plan = plan_import(&fixture.view(), &[row]).unwrap();
        assert_eq!(plan.prospective_collisions.len(), 1);
    }

    #[test]
    fn transitive_contradiction_does_not_emit_an_unresolvable_pair() {
        let fixture = Fixture::new();
        let (first, first_fragment) = person("Shared", "", "");
        let (second, second_fragment) = person("shared", "", "");
        let (third, third_fragment) = person("Third", "", "");
        fixture.publish(first_fragment + second_fragment + third_fragment);
        fixture.publish(relations::identity_verdict_fragment(first, second, true, &[]).unwrap());
        fixture.publish(relations::identity_verdict_fragment(second, third, true, &[]).unwrap());
        fixture.publish(relations::identity_verdict_fragment(first, third, false, &[]).unwrap());

        assert!(derived_review_pairs(&fixture.view()).unwrap().is_empty());
    }

    #[test]
    fn a_mixed_fork_elsewhere_does_not_mislabel_a_name_pair() {
        let fixture = Fixture::new();
        let (first, first_fragment) = person("Shared", "", "");
        let (second, second_fragment) = person("shared", "", "");
        let (same_as_second, third_fragment) = person("Third", "", "");
        fixture.publish(first_fragment + second_fragment + third_fragment);
        fixture.publish(
            relations::identity_verdict_fragment(second, same_as_second, true, &[]).unwrap(),
        );
        fixture.publish(
            relations::identity_verdict_fragment(first, same_as_second, true, &[]).unwrap(),
        );
        fixture.publish(
            relations::identity_verdict_fragment(first, same_as_second, false, &[]).unwrap(),
        );

        assert!(derived_review_pairs(&fixture.view()).unwrap().is_empty());
    }

    #[test]
    fn a_matching_mixed_identity_fork_fails_as_unsettled() {
        let fixture = Fixture::new();
        let (first, first_fragment) = person("First", "linkedin.com/in/first", "");
        let (second, second_fragment) = person("Second", "", "second@example.test");
        fixture.publish(first_fragment + second_fragment);
        let predecessor = relations::identity_verdict_fragment(first, second, false, &[]).unwrap();
        let predecessor_id = predecessor.root().unwrap();
        fixture.publish(predecessor);
        fixture.publish(
            relations::identity_verdict_fragment(first, second, true, &[predecessor_id]).unwrap()
                + relations::identity_verdict_fragment(first, second, false, &[predecessor_id])
                    .unwrap(),
        );

        let row = connection("First", "linkedin.com/in/first", "");
        let error = ingest(fixture.storage(), &[row], true).unwrap_err();
        assert!(format!("{error:#}").contains("mixed same/distinct verdict fork"));
    }
}
