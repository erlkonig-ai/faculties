
use anyhow::{Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::schemas::relations::{DEFAULT_BRANCH, KIND_PERSON_ID, relations};
use rand_core::OsRng;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::{find, pattern};
use triblespace::prelude::*;

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

#[derive(Parser)]
#[command(name = "relations", about = "Relationship/contacts faculty")]
struct Cli {
    /// Path to the pile file to use
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name for relations data
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    /// Branch id for relations data (hex). Overrides ensure_branch.
    #[arg(long)]
    branch_id: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add a person
    Add {
        /// Canonical short label
        label: String,
        /// Explicit person id (hex)
        #[arg(long)]
        id: Option<String>,
        /// First name
        #[arg(long)]
        first_name: Option<String>,
        /// Last name
        #[arg(long)]
        last_name: Option<String>,
        /// Display name
        #[arg(long)]
        display_name: Option<String>,
        /// Affinity / relationship note (short)
        #[arg(long)]
        affinity: Option<String>,
        /// Note (long)
        #[arg(long)]
        note: Option<String>,
        /// Alias (repeatable)
        #[arg(long)]
        alias: Vec<String>,
        /// Teams user id (GUID)
        #[arg(long)]
        teams_user_id: Option<String>,
        /// Email address
        #[arg(long)]
        email: Option<String>,
        /// Phone number
        #[arg(long)]
        phone: Option<String>,
        /// Company / organisation
        #[arg(long)]
        company: Option<String>,
        /// Role / job title
        #[arg(long)]
        position: Option<String>,
        /// Provenance ("summit" | "card" | "mail" | …)
        #[arg(long)]
        source: Option<String>,
        /// Create even if a relation with this label, alias, or email
        /// already exists. Without this flag, `relations add` refuses
        /// to mint a duplicate person entity — protects the knowledge
        /// base from accidental forks when the same person gets touched
        /// by multiple faculties (mail autoregister, manual add, etc.).
        #[arg(long)]
        force: bool,
    },
    /// Update a person
    Set {
        /// Person id (hex)
        id: String,
        /// New canonical short label
        #[arg(long)]
        label: Option<String>,
        /// First name
        #[arg(long)]
        first_name: Option<String>,
        /// Last name
        #[arg(long)]
        last_name: Option<String>,
        /// Display name
        #[arg(long)]
        display_name: Option<String>,
        /// Affinity / relationship note (short)
        #[arg(long)]
        affinity: Option<String>,
        /// Note (long)
        #[arg(long)]
        note: Option<String>,
        /// Alias (repeatable)
        #[arg(long)]
        alias: Vec<String>,
        /// Teams user id (GUID)
        #[arg(long)]
        teams_user_id: Option<String>,
        /// Email address
        #[arg(long)]
        email: Option<String>,
        /// Phone number
        #[arg(long)]
        phone: Option<String>,
        /// Company / organisation
        #[arg(long)]
        company: Option<String>,
        /// Role / job title
        #[arg(long)]
        position: Option<String>,
        /// Provenance ("summit" | "card" | "mail" | …)
        #[arg(long)]
        source: Option<String>,
    },
    /// List people
    List {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show a person
    Show { id: String },
}


fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn normalize_label(label: &str) -> Result<String> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        bail!("label is empty");
    }
    validate_short(trimmed, "label")?;
    Ok(trimmed.to_string())
}

/// ShortString fields live inline in the 32-byte value slot; anything
/// longer must go in `--note` (LongString). Bail with the limit named
/// instead of panicking in the encoder.
fn validate_short(value: &str, field: &str) -> Result<()> {
    let len = value.len();
    if len > 32 {
        bail!(
            "{field} is {len} bytes but ShortString fields hold at most 32 — \
             shorten it or move the detail into --note"
        );
    }
    if value.bytes().any(|b| b == 0) {
        bail!("{field} contains a NUL byte");
    }
    Ok(())
}

fn normalize_lookup_key(value: &str) -> Result<String> {
    Ok(normalize_label(value)?.to_ascii_lowercase())
}

fn normalize_aliases(aliases: Vec<String>) -> Vec<String> {
    aliases
        .into_iter()
        .map(|alias| alias.trim().to_string())
        .filter(|alias| !alias.is_empty())
        .collect()
}

fn normalize_alias_lookup_keys(aliases: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for alias in aliases {
        let key = alias.trim().to_ascii_lowercase();
        if key.is_empty() || !seen.insert(key.clone()) {
            continue;
        }
        out.push(key);
    }
    out
}

fn parse_hex_id(raw: &str, label: &str) -> Result<Id> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("{label} is empty");
    }
    Id::from_hex(trimmed).ok_or_else(|| anyhow!("invalid {label} {trimmed}"))
}

fn resolve_person_id(space: &TribleSet, raw: &str) -> Result<Id> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("person id is empty");
    }

    let prefix = trimmed.to_lowercase();
    if !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("person id must be hex (got '{trimmed}')");
    }

    if prefix.len() == 32 {
        let id = Id::from_hex(&prefix).ok_or_else(|| anyhow!("invalid person id {trimmed}"))?;
        for (person_id,) in find!(
            (person_id: Id),
            pattern!(&space, [{ ?person_id @ metadata::tag: &KIND_PERSON_ID }])
        ) {
            if person_id == id {
                return Ok(id);
            }
        }
        bail!("unknown person id {trimmed}");
    }

    let mut matches = Vec::new();
    for (person_id,) in find!(
        (person_id: Id),
        pattern!(&space, [{ ?person_id @ metadata::tag: &KIND_PERSON_ID }])
    ) {
        let hex = format!("{person_id:x}");
        if hex.starts_with(&prefix) {
            matches.push(person_id);
        }
    }

    match matches.len() {
        0 => bail!("no person id matches prefix '{trimmed}'"),
        1 => Ok(matches[0]),
        _ => bail!("multiple people match id prefix '{trimmed}'"),
    }
}

fn read_text(ws: &mut Workspace<Pile>, handle: TextHandle) -> Result<String> {
    let view: View<str> = ws
        .get(handle)
        .map_err(|e| anyhow!("load longstring: {e:?}"))?;
    Ok(view.to_string())
}

fn open_repo(path: &Path) -> Result<Repository<Pile>> {
    let mut pile = Pile::open(path)
        .map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        // Avoid Drop warnings on early errors.
        let _ = pile.close();
        return Err(anyhow!("restore pile {}: {err:?}", path.display()));
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow!("create repository: {err:?}"))
}

fn with_repo<T>(
    pile: &Path,
    f: impl FnOnce(&mut Repository<Pile>) -> Result<T>,
) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let result = f(&mut repo);
    let close_res = repo.close().map_err(|e| anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

fn ensure_kind_entities(ws: &mut Workspace<Pile>) -> Result<TribleSet> {
    let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
    let existing: HashMap<Id, TextHandle> = find!(
        (kind: Id, name: TextHandle),
        pattern!(&space, [{ ?kind @ metadata::name: ?name }])
    )
    .into_iter()
    .collect();
    let mut change = TribleSet::new();
    if !existing.contains_key(&KIND_PERSON_ID) {
        let name_handle = "person"
            .to_owned()
            .to_blob()
            .get_handle();
        change += entity! { ExclusiveId::force_ref(&KIND_PERSON_ID) @ metadata::name: name_handle };
    }
    Ok(change)
}

// ── on-demand person queries ─────────────────────────────────────────

fn person_label(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> Option<String> {
    find!(h: TextHandle, pattern!(space, [{ id @ metadata::name: ?h }]))
        .next().and_then(|h| read_text(ws, h).ok())
}

fn person_first_name(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> Option<String> {
    find!(h: TextHandle, pattern!(space, [{ id @ relations::first_name: ?h }]))
        .next().and_then(|h| read_text(ws, h).ok())
}

fn person_last_name(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> Option<String> {
    find!(h: TextHandle, pattern!(space, [{ id @ relations::last_name: ?h }]))
        .next().and_then(|h| read_text(ws, h).ok())
}

fn person_display_name(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> Option<String> {
    find!(h: TextHandle, pattern!(space, [{ id @ relations::display_name: ?h }]))
        .next().and_then(|h| read_text(ws, h).ok())
}

fn person_affinity(space: &TribleSet, id: Id) -> Option<String> {
    find!(v: String, pattern!(space, [{ id @ relations::affinity: ?v }])).next()
}

fn person_note(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> Option<String> {
    find!(h: TextHandle, pattern!(space, [{ id @ metadata::description: ?h }]))
        .next().and_then(|h| read_text(ws, h).ok())
}

fn person_teams_user_id(space: &TribleSet, id: Id) -> Option<String> {
    find!(v: String, pattern!(space, [{ id @ relations::teams_user_id: ?v }])).next()
}

fn person_email(space: &TribleSet, id: Id) -> Option<String> {
    find!(v: String, pattern!(space, [{ id @ relations::email: ?v }])).next()
}

fn person_phone(space: &TribleSet, id: Id) -> Option<String> {
    find!(v: String, pattern!(space, [{ id @ relations::phone: ?v }])).next()
}

fn person_aliases(space: &TribleSet, id: Id) -> Vec<String> {
    find!(v: String, pattern!(space, [{ id @ relations::alias: ?v }])).collect()
}

fn person_company(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> Option<String> {
    find!(h: TextHandle, pattern!(space, [{ id @ relations::company: ?h }]))
        .next().and_then(|h| read_text(ws, h).ok())
}

fn person_position(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> Option<String> {
    find!(h: TextHandle, pattern!(space, [{ id @ relations::position: ?h }]))
        .next().and_then(|h| read_text(ws, h).ok())
}

fn person_profile_url(ws: &mut Workspace<Pile>, space: &TribleSet, id: Id) -> Option<String> {
    find!(h: TextHandle, pattern!(space, [{ id @ relations::profile_url: ?h }]))
        .next().and_then(|h| read_text(ws, h).ok())
}

fn person_sources(space: &TribleSet, id: Id) -> Vec<String> {
    find!(v: String, pattern!(space, [{ id @ relations::source: ?v }])).collect()
}

fn person_same_as(space: &TribleSet, id: Id) -> Vec<Id> {
    find!(o: Id, pattern!(space, [{ id @ relations::same_as: ?o }])).collect()
}

fn all_person_ids(space: &TribleSet) -> Vec<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &KIND_PERSON_ID }])).collect()
}

fn find_people_by_lookup_key(space: &TribleSet, key: &str) -> HashSet<Id> {
    find!(
        person_id: Id,
        pattern!(space, [{ ?person_id @ metadata::tag: &KIND_PERSON_ID }])
    )
    .filter(|&person_id| {
        exists!(pattern!(space, [{ person_id @ relations::label_norm: key }]))
            || exists!(pattern!(space, [{ person_id @ relations::alias_norm: key }]))
    })
    .collect()
}

/// Find people whose `email` attribute matches `email_norm` (case-folded
/// comparison). Used by `relations add` to refuse minting a duplicate
/// person entity when the same email already lives on another relation —
/// otherwise mail autoregister + manual add ends up forking the same
/// person across two ids.
fn find_people_by_email_norm(space: &TribleSet, email_norm: &str) -> HashSet<Id> {
    find!(
        (person_id: Id, email: String),
        pattern!(space, [{ ?person_id @
            metadata::tag: &KIND_PERSON_ID,
            relations::email: ?email,
        }])
    )
    .filter(|(_, email)| email.to_ascii_lowercase() == email_norm)
    .map(|(id, _)| id)
    .collect()
}

fn cmd_add(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    label: String,
    id: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    display_name: Option<String>,
    affinity: Option<String>,
    note: Option<String>,
    aliases: Vec<String>,
    teams_user_id: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    company: Option<String>,
    position: Option<String>,
    source: Option<String>,
    force: bool,
) -> Result<()> {
    let label = normalize_label(&label)?;
    let label_lookup = normalize_lookup_key(&label)?;
    for (value, field) in [
        (affinity.as_deref(), "affinity"),
        (teams_user_id.as_deref(), "teams-user-id"),
        (email.as_deref(), "email"),
    ] {
        if let Some(v) = value {
            validate_short(v, field)?;
        }
    }
    for alias in &aliases {
        validate_short(alias, "alias")?;
    }
    let person_id = match id {
        Some(raw) => parse_hex_id(&raw, "person id")?,
        None => ufoid().id,
    };
    let email_norm = email
        .as_deref()
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty());

    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
        let mut change = ensure_kind_entities(&mut ws)?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;

        let aliases = normalize_aliases(aliases);
        let alias_lookup = normalize_alias_lookup_keys(&aliases);

        if !force {
            for existing in find_people_by_lookup_key(&space, &label_lookup) {
                if existing != person_id {
                    bail!(
                        "label/alias '{label_lookup}' already belongs to relation {} \
                         — use `relations set {} --label '{label}' …` to update it, \
                         or pass --force to mint a duplicate",
                        fmt_id(existing),
                        fmt_id(existing),
                    );
                }
            }
            for key in &alias_lookup {
                for existing in find_people_by_lookup_key(&space, key) {
                    if existing != person_id {
                        bail!(
                            "label/alias '{key}' already belongs to relation {} \
                             — use `relations set {} --alias '{key}' …` to update it, \
                             or pass --force to mint a duplicate",
                            fmt_id(existing),
                            fmt_id(existing),
                        );
                    }
                }
            }
            if let Some(email_norm) = &email_norm {
                for existing in find_people_by_email_norm(&space, email_norm) {
                    if existing != person_id {
                        bail!(
                            "email '{email_norm}' already belongs to relation {} \
                             — use `relations set {} --label '{label}' …` \
                             to attach this label to the existing entry, \
                             or pass --force to mint a duplicate",
                            fmt_id(existing),
                            fmt_id(existing),
                        );
                    }
                }
            }
        }

        if let Some(s) = source.as_deref() {
            validate_short(s, "source")?;
        }
        if let Some(p) = phone.as_deref() {
            validate_short(p, "phone")?;
        }
        let label_handle = ws.put(label.clone());
        let display_name_handle = display_name.map(|value| ws.put(value));
        let first_name_handle = first_name.map(|value| ws.put(value));
        let last_name_handle = last_name.map(|value| ws.put(value));
        let note_handle = note.map(|value| ws.put(value));
        let company_handle = company.map(|value| ws.put(value));
        let position_handle = position.map(|value| ws.put(value));
        change += entity! { ExclusiveId::force_ref(&person_id) @
            metadata::tag: &KIND_PERSON_ID,
            metadata::name: label_handle,
            relations::label_norm: label_lookup.as_str(),
            relations::display_name?: display_name_handle,
            relations::first_name?: first_name_handle,
            relations::last_name?: last_name_handle,
            relations::affinity?: affinity,
            metadata::description?: note_handle,
            relations::teams_user_id?: teams_user_id,
            relations::email?: email,
            relations::phone?: phone,
            relations::company?: company_handle,
            relations::position?: position_handle,
            relations::source?: source,
            relations::alias*: aliases.iter().map(String::as_str),
            relations::alias_norm*: alias_lookup.iter().map(String::as_str),
        };

        ws.commit(change, "relations add");
        repo.push(&mut ws)
            .map_err(|e| anyhow!("push person: {e:?}"))?;
        Ok(())
    })?;
    println!("Added {} ({label}).", format!("{person_id:x}"));
    Ok(())
}

fn cmd_set(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    id: String,
    label: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    display_name: Option<String>,
    affinity: Option<String>,
    note: Option<String>,
    aliases: Vec<String>,
    teams_user_id: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    company: Option<String>,
    position: Option<String>,
    source: Option<String>,
) -> Result<()> {
    let label = label.map(|l| normalize_label(&l)).transpose()?;
    let label_lookup = label.as_deref().map(normalize_lookup_key).transpose()?;
    for (value, field) in [
        (affinity.as_deref(), "affinity"),
        (teams_user_id.as_deref(), "teams-user-id"),
        (email.as_deref(), "email"),
        (phone.as_deref(), "phone"),
        (source.as_deref(), "source"),
    ] {
        if let Some(v) = value {
            validate_short(v, field)?;
        }
    }
    for alias in &aliases {
        validate_short(alias, "alias")?;
    }

    let person_id = with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
        let mut change = ensure_kind_entities(&mut ws)?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;

        let person_id = resolve_person_id(&space, &id)?;

        let aliases = normalize_aliases(aliases);
        let alias_lookup = normalize_alias_lookup_keys(&aliases);

        if let Some(key) = label_lookup.as_deref() {
            for existing in find_people_by_lookup_key(&space, key) {
                if existing != person_id {
                    bail!(
                        "lookup key '{key}' already belongs to person {}",
                        fmt_id(existing)
                    );
                }
            }
        }
        for key in &alias_lookup {
            for existing in find_people_by_lookup_key(&space, key) {
                if existing != person_id {
                    bail!(
                        "lookup key '{key}' already belongs to person {}",
                        fmt_id(existing)
                    );
                }
            }
        }

        let label_handle = label.map(|value| ws.put(value));
        let display_name_handle = display_name.map(|value| ws.put(value));
        let first_name_handle = first_name.map(|value| ws.put(value));
        let last_name_handle = last_name.map(|value| ws.put(value));
        let note_handle = note.map(|value| ws.put(value));
        let company_handle = company.map(|value| ws.put(value));
        let position_handle = position.map(|value| ws.put(value));
        let has_updates = label_handle.is_some()
            || label_lookup.is_some()
            || display_name_handle.is_some()
            || first_name_handle.is_some()
            || last_name_handle.is_some()
            || affinity.is_some()
            || note_handle.is_some()
            || teams_user_id.is_some()
            || email.is_some()
            || phone.is_some()
            || company_handle.is_some()
            || position_handle.is_some()
            || source.is_some()
            || !aliases.is_empty();

        if has_updates {
            change += entity! { ExclusiveId::force_ref(&person_id) @
                metadata::name?: label_handle,
                relations::label_norm?: label_lookup.as_deref(),
                relations::display_name?: display_name_handle,
                relations::first_name?: first_name_handle,
                relations::last_name?: last_name_handle,
                relations::affinity?: affinity,
                metadata::description?: note_handle,
                relations::teams_user_id?: teams_user_id,
                relations::email?: email,
                relations::phone?: phone,
                relations::company?: company_handle,
                relations::position?: position_handle,
                relations::source?: source,
                relations::alias*: aliases.iter().map(String::as_str),
                relations::alias_norm*: alias_lookup.iter().map(String::as_str),
            };
        }

        if !change.is_empty() {
            ws.commit(change, "relations set");
            repo.push(&mut ws)
                .map_err(|e| anyhow!("push person: {e:?}"))?;
        }
        Ok(person_id)
    })?;
    println!("Updated {}.", format!("{person_id:x}"));
    Ok(())
}

fn cmd_list(pile: &Path, _branch_name: &str, branch_id: Id, limit: usize) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;

        let mut ids: Vec<(Option<String>, Id)> = all_person_ids(&space)
            .into_iter()
            .map(|id| (person_label(&mut ws, &space, id), id))
            .collect();
        ids.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        if ids.is_empty() {
            println!("No people.");
        } else {
            for (label, id) in ids.into_iter().take(limit) {
                let label = label.as_deref().unwrap_or("<unnamed>");
                let mut line = format!("[{}] {}", fmt_id(id), label);
                let first = person_first_name(&mut ws, &space, id);
                let last = person_last_name(&mut ws, &space, id);
                let fallback_name = match (&first, &last) {
                    (Some(f), Some(l)) => Some(format!("{f} {l}")),
                    (Some(f), None) => Some(f.clone()),
                    (None, Some(l)) => Some(l.clone()),
                    (None, None) => None,
                };
                let display = person_display_name(&mut ws, &space, id).or(fallback_name);
                if let Some(display) = display {
                    line.push_str(&format!(" ({display})"));
                }
                if let Some(affinity) = person_affinity(&space, id) {
                    line.push_str(&format!(" [{affinity}]"));
                }
                println!("{line}");
            }
        }
        Ok(())
    })
}

fn cmd_show(pile: &Path, _branch_name: &str, branch_id: Id, id: String) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
        let person_id = resolve_person_id(&space, &id)?;

        println!("id: {:x}", person_id);
        if let Some(label) = person_label(&mut ws, &space, person_id) {
            println!("label: {label}");
        }
        if let Some(first) = person_first_name(&mut ws, &space, person_id) {
            println!("first_name: {first}");
        }
        if let Some(last) = person_last_name(&mut ws, &space, person_id) {
            println!("last_name: {last}");
        }
        if let Some(display) = person_display_name(&mut ws, &space, person_id) {
            println!("display_name: {display}");
        }
        if let Some(affinity) = person_affinity(&space, person_id) {
            println!("affinity: {affinity}");
        }
        if let Some(value) = person_teams_user_id(&space, person_id) {
            println!("teams_user_id: {value}");
        }
        if let Some(value) = person_email(&space, person_id) {
            println!("email: {value}");
        }
        if let Some(value) = person_phone(&space, person_id) {
            println!("phone: {value}");
        }
        if let Some(value) = person_position(&mut ws, &space, person_id) {
            println!("position: {value}");
        }
        if let Some(value) = person_company(&mut ws, &space, person_id) {
            println!("company: {value}");
        }
        if let Some(value) = person_profile_url(&mut ws, &space, person_id) {
            println!("profile_url: {value}");
        }
        let sources = person_sources(&space, person_id);
        if !sources.is_empty() {
            println!("source: {}", sources.join(", "));
        }
        let same_as = person_same_as(&space, person_id);
        if !same_as.is_empty() {
            println!("same_as:");
            for other in same_as {
                println!("- {}", fmt_id(other));
            }
        }
        let aliases = person_aliases(&space, person_id);
        if !aliases.is_empty() {
            println!("aliases:");
            for alias in aliases {
                println!("- {alias}");
            }
        }
        if let Some(note) = person_note(&mut ws, &space, person_id) {
            println!("note:");
            println!("{note}");
        }

        Ok(())
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(cmd) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    let branch_id = with_repo(&cli.pile, |repo| {
        if let Some(hex) = cli.branch_id.as_deref() {
            return Id::from_hex(hex.trim())
                .ok_or_else(|| anyhow!("invalid branch id '{hex}'"));
        }
        repo.ensure_branch(&cli.branch, None)
            .map_err(|e| anyhow!("ensure relations branch: {e:?}"))
    })?;

    match cmd {
        Command::Add {
            label,
            id,
            first_name,
            last_name,
            display_name,
            affinity,
            note,
            alias,
            teams_user_id,
            email,
            phone,
            company,
            position,
            source,
            force,
        } => cmd_add(
            &cli.pile,
            &cli.branch,
            branch_id,
            label,
            id,
            first_name,
            last_name,
            display_name,
            affinity,
            note,
            alias,
            teams_user_id,
            email,
            phone,
            company,
            position,
            source,
            force,
        ),
        Command::Set {
            id,
            label,
            first_name,
            last_name,
            display_name,
            affinity,
            note,
            alias,
            teams_user_id,
            email,
            phone,
            company,
            position,
            source,
        } => cmd_set(
            &cli.pile,
            &cli.branch,
            branch_id,
            id,
            label,
            first_name,
            last_name,
            display_name,
            affinity,
            note,
            alias,
            teams_user_id,
            email,
            phone,
            company,
            position,
            source,
        ),
        Command::List { limit } => cmd_list(&cli.pile, &cli.branch, branch_id, limit),
        Command::Show { id } => cmd_show(&cli.pile, &cli.branch, branch_id, id),
    }
}
