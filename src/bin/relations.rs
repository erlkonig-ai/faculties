
use anyhow::{Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::schemas::relations::{
    group_snapshot_fragment, resolve_group_head, DEFAULT_BRANCH, GroupHead, KIND_GROUP,
    KIND_PERSON_ID, KIND_RETIRE_ID, KIND_UNRETIRE_ID, group, head_members, head_snapshot_of,
    relations,
};
use hifitime::Epoch;
use rand_core::OsRng;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::{find, pattern};
use triblespace::prelude::*;

type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "relations", about = "Relationship/contacts faculty")]
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
        /// Include soft-retired relations (default hides them)
        #[arg(long)]
        all: bool,
        /// Show ONLY soft-retired relations
        #[arg(long, conflicts_with = "all")]
        retired: bool,
    },
    /// Show a person
    Show { id: String },
    /// Soft-retire a relation (label or id). Append-only: the person
    /// entity is never deleted — an "unretire"/"restore" reverses it and
    /// the entry stays recoverable in the pile. Default `list` hides it.
    Retire {
        /// Person label, alias, or id (hex / prefix)
        person: String,
    },
    /// Un-retire (restore) a soft-retired relation (label or id).
    #[command(alias = "restore")]
    Unretire {
        /// Person label, alias, or id (hex / prefix)
        person: String,
    },
    /// Manage groups (addressable sets of people, e.g. the colony)
    Group {
        #[command(subcommand)]
        command: GroupCmd,
    },
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Create a group
    Create {
        /// Canonical short label (e.g. "colony", "embodiment")
        name: String,
    },
    /// Add a person to a group
    Add {
        /// Group label or id
        group: String,
        /// Person label or id
        person: String,
    },
    /// Remove a person from a group
    Remove {
        /// Group label or id
        group: String,
        /// Person label or id
        person: String,
    },
    /// Rename a group
    Rename {
        /// Group label or id
        group: String,
        /// New canonical short label
        name: String,
    },
    /// One-time: give legacy anchor-direct groups their initial snapshot.
    Migrate,
    /// Heal a forked group: mint one child superseding every concurrent head,
    /// carrying the UNION of their members (edit down afterward if intended).
    Reconcile {
        /// Group label or id
        group: String,
        /// Name for the reconciled head. Required only when concurrent renames
        /// left the fork heads with different names; otherwise inherited.
        #[arg(long)]
        name: Option<String>,
    },
    /// List groups and their members
    List,
    /// Show a group's members
    Show {
        /// Group label or id
        group: String,
    },
}


fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> IntervalValue {
    (epoch, epoch).try_to_inline().unwrap()
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval.try_from_inline().unwrap();
    lower
}

/// People currently soft-retired: the latest retire/unretire event per
/// person wins (retire => retired, unretire => active). Monotonic and
/// invertible — mirrors compass prioritize/deprioritize. Default views
/// exclude these; `--all`/`--retired` reveal them.
fn retired_person_ids(space: &TribleSet) -> HashSet<Id> {
    let mut latest: HashMap<Id, (i128, bool)> = HashMap::new();
    for (person, at) in find!(
        (person: Id, at: IntervalValue),
        pattern!(space, [{
            _?evt @
            metadata::tag: &KIND_RETIRE_ID,
            relations::subject: ?person,
            metadata::created_at: ?at,
        }])
    ) {
        let key = interval_key(at);
        latest
            .entry(person)
            .and_modify(|(cur_key, cur_retired)| {
                if key >= *cur_key {
                    *cur_key = key;
                    *cur_retired = true;
                }
            })
            .or_insert((key, true));
    }
    for (person, at) in find!(
        (person: Id, at: IntervalValue),
        pattern!(space, [{
            _?evt @
            metadata::tag: &KIND_UNRETIRE_ID,
            relations::subject: ?person,
            metadata::created_at: ?at,
        }])
    ) {
        let key = interval_key(at);
        latest
            .entry(person)
            .and_modify(|(cur_key, cur_retired)| {
                if key > *cur_key {
                    *cur_key = key;
                    *cur_retired = false;
                }
            })
            .or_insert((key, false));
    }
    latest
        .into_iter()
        .filter(|(_, (_, retired))| *retired)
        .map(|(id, _)| id)
        .collect()
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
    if let Err(err) = pile.refresh() {
        // Avoid Drop warnings on early errors.
        let _ = pile.close();
        return Err(match err {
            triblespace::core::repo::pile::ReadError::CorruptPile { valid_length } => anyhow!(
                "pile corrupt at byte {valid_length}: refusing to auto-repair (a stale binary \
                 could truncate newer data). If, and only if, the tail is a genuinely torn write, truncate it explicitly (DESTRUCTIVE) with: trible pile amputate {}",
                path.display()
            ),
            other => anyhow!("refresh pile {}: {other:?}", path.display()),
        });
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

fn cmd_list(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    limit: usize,
    all: bool,
    retired_only: bool,
) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;

        let retired = retired_person_ids(&space);
        let mut ids: Vec<(Option<String>, Id)> = all_person_ids(&space)
            .into_iter()
            .filter(|id| {
                if retired_only {
                    retired.contains(id)
                } else {
                    all || !retired.contains(id)
                }
            })
            .map(|id| (person_label(&mut ws, &space, id), id))
            .collect();
        ids.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        if ids.is_empty() {
            println!("No people.");
        } else {
            for (label, id) in ids.into_iter().take(limit) {
                let label = label.as_deref().unwrap_or("<unnamed>");
                let mut line = format!("[{}] {}", fmt_id(id), label);
                if all && retired.contains(&id) {
                    line.push_str(" (retired)");
                }
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
        if retired_person_ids(&space).contains(&person_id) {
            println!("retired: true");
        }
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

/// Soft-retire (or restore) a relation by appending a retirement event.
/// `retired = true` appends a `KIND_RETIRE_ID` event; `false` appends a
/// `KIND_UNRETIRE_ID` event. Latest event by timestamp wins — see
/// `retired_person_ids`. The person entity is never mutated or deleted.
fn cmd_set_retired(
    pile: &Path,
    branch_id: Id,
    person: String,
    retired: bool,
) -> Result<(Id, Option<String>, bool)> {
    with_repo(pile, |repo| {
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
        let person_id = resolve_member_id(&space, &person)?;
        let label = person_label(&mut ws, &space, person_id);

        // No-op if already in the requested state — keeps the ledger free
        // of redundant events (and gives the caller a clear "already X").
        if retired_person_ids(&space).contains(&person_id) == retired {
            return Ok((person_id, label, false));
        }

        let now = epoch_interval(now_epoch());
        let evt_id = ufoid();
        let kind = if retired { &KIND_RETIRE_ID } else { &KIND_UNRETIRE_ID };
        let mut change = TribleSet::new();
        change += entity! { &evt_id @
            metadata::tag: kind,
            relations::subject: &person_id,
            metadata::created_at: now,
        };
        ws.commit(change, if retired { "relations retire" } else { "relations unretire" });
        repo.push(&mut ws).map_err(|e| anyhow!("push: {e:?}"))?;
        Ok((person_id, label, true))
    })
}

fn cmd_retire(pile: &Path, branch_id: Id, person: String) -> Result<()> {
    let (id, label, changed) = cmd_set_retired(pile, branch_id, person, true)?;
    let label = label.as_deref().unwrap_or("<unnamed>");
    if changed {
        println!("Retired {} ({label}).", fmt_id(id));
    } else {
        println!("{} ({label}) is already retired.", fmt_id(id));
    }
    Ok(())
}

fn cmd_unretire(pile: &Path, branch_id: Id, person: String) -> Result<()> {
    let (id, label, changed) = cmd_set_retired(pile, branch_id, person, false)?;
    let label = label.as_deref().unwrap_or("<unnamed>");
    if changed {
        println!("Restored {} ({label}).", fmt_id(id));
    } else {
        println!("{} ({label}) is not retired.", fmt_id(id));
    }
    Ok(())
}

// ── groups ──────────────────────────────────────────────────────────────────

fn resolve_group_id(space: &TribleSet, raw: &str) -> Result<Id> {
    let trimmed = raw.trim();
    if trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        if let Some(id) = Id::from_hex(&trimmed.to_lowercase()) {
            if exists!(pattern!(space, [{ id @ metadata::tag: &KIND_GROUP }])) {
                return Ok(id);
            }
        }
    }
    let key = normalize_lookup_key(trimmed)?;
    // Name lookup resolves through the head snapshot: an anchor matches when
    // its current (un-superseded) snapshot carries this label_norm. A rename
    // supersedes the old name, so only the current name resolves.
    let mut matches: Vec<Id> = find!(gid: Id, pattern!(space, [{ ?gid @ metadata::tag: &KIND_GROUP }]))
        .filter(|&gid| {
            head_snapshot_of(space, gid).is_some_and(|head| {
                exists!(pattern!(space, [{ head @ relations::label_norm: key.as_str() }]))
            })
        })
        .collect();
    matches.sort();
    matches.dedup();
    match matches.len() {
        0 => bail!("no group matches '{raw}'"),
        1 => Ok(matches[0]),
        _ => bail!("multiple groups match '{raw}'"),
    }
}

fn group_members(space: &TribleSet, group_id: Id) -> Vec<Id> {
    // Current members = the members of the anchor's head snapshot.
    let mut members: Vec<Id> = head_members(space, group_id).into_iter().collect();
    members.sort();
    members
}

/// Resolve a person by hex id (or prefix) OR by label/alias — `group add`
/// takes either, unlike `resolve_person_id` which is hex-only.
fn resolve_member_id(space: &TribleSet, raw: &str) -> Result<Id> {
    let trimmed = raw.trim();
    if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return resolve_person_id(space, trimmed);
    }
    let key = normalize_lookup_key(trimmed)?;
    let mut matches: Vec<Id> = find_people_by_lookup_key(space, &key).into_iter().collect();
    matches.sort();
    matches.dedup();
    match matches.len() {
        0 => bail!("no person matches '{raw}'"),
        1 => Ok(matches[0]),
        _ => bail!("multiple people match '{raw}'"),
    }
}

/// Mint a new group snapshot carrying the full `{name, label_norm, members}`
/// state, superseding `prior` (the previous head, if any). Returns the change
/// to commit and the new snapshot id. Every group edit (add/remove/rename,
/// and migration) goes through here so a snapshot is always a complete state.
/// The group's unique head snapshot + its members, failing CLOSED on a
/// Missing/Forked/Invalid group so no edit is built on an ambiguous state.
fn require_unique_head(space: &TribleSet, gid: Id) -> Result<(Id, Vec<Id>)> {
    match resolve_group_head(space, gid) {
        GroupHead::Unique(head) => {
            let mut members: Vec<Id> = head_members(space, gid).into_iter().collect();
            members.sort();
            Ok((head, members))
        }
        GroupHead::Missing => bail!(
            "group {} has no snapshot yet; run `relations group migrate`",
            fmt_id(gid)
        ),
        GroupHead::Forked(heads) => bail!(
            "group {} has {} concurrent heads (forked); reconcile before editing",
            fmt_id(gid),
            heads.len()
        ),
        GroupHead::Invalid(reason) => {
            bail!("group {} is invalid ({reason}); cannot edit", fmt_id(gid))
        }
    }
}

fn mint_group_snapshot(
    ws: &mut Workspace<Pile>,
    anchor: Id,
    members: &[Id],
    label: &str,
    key: &str,
    predecessors: &[Id],
) -> (TribleSet, Id) {
    let label_handle = ws.put(label.to_string());
    // Intrinsic content-sealed snapshot: id = hash of {anchor, name handle,
    // sorted members, sorted predecessor heads} — built through the single
    // `group_snapshot_fragment` authority the on-read validator also uses, so
    // mint and validation can never disagree. Identical content dedups; a
    // supersedes cycle is structurally impossible (an id depends on its
    // predecessors). label_norm + created_at are derived/exhaust and added as
    // separate facts outside the sealed identity.
    let sealed = group_snapshot_fragment(anchor, label_handle, members, predecessors);
    let snap = sealed
        .root()
        .expect("a group snapshot fragment has one intrinsic root");
    let now = epoch_interval(now_epoch());
    let mut change = TribleSet::new();
    change += sealed;
    change += entity! { ExclusiveId::force_ref(&snap) @
        relations::label_norm: key,
        metadata::created_at: now,
    };
    (change, snap)
}

fn cmd_group_create(pile: &Path, branch_id: Id, name: String) -> Result<()> {
    let label = normalize_label(&name)?;
    let key = normalize_lookup_key(&name)?;
    let group_id = with_repo(pile, |repo| {
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
        if let Ok(existing) = resolve_group_id(&space, &name) {
            bail!("group '{label}' already exists ({})", fmt_id(existing));
        }
        // Stable extrinsic anchor: pure identity. Name/members live on
        // intrinsic snapshots, so the current state is always the anchor's
        // unique head snapshot. A fresh group gets snapshot-0 (its name, no
        // members, no predecessors).
        let gid = ufoid().id;
        let mut change = TribleSet::new();
        change += entity! { ExclusiveId::force_ref(&gid) @ metadata::tag: &KIND_GROUP };
        let (snap_change, _) = mint_group_snapshot(&mut ws, gid, &[], &label, &key, &[]);
        change += snap_change;
        ws.commit(change, "relations group create");
        repo.push(&mut ws).map_err(|e| anyhow!("push: {e:?}"))?;
        Ok(gid)
    })?;
    println!("Created group {} ({label}).", fmt_id(group_id));
    Ok(())
}

fn cmd_group_add(pile: &Path, branch_id: Id, group: String, person: String) -> Result<()> {
    let (gid, pid, added) = with_repo(pile, |repo| {
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
        let gid = resolve_group_id(&space, &group)?;
        let pid = resolve_member_id(&space, &person)?;
        let (head, mut members) = require_unique_head(&space, gid)?;
        if members.contains(&pid) {
            return Ok((gid, pid, false));
        }
        members.push(pid);
        members.sort();
        let name = person_label(&mut ws, &space, head)
            .ok_or_else(|| anyhow!("group {} head snapshot has no name", fmt_id(gid)))?;
        let label = normalize_label(&name)?;
        let key = normalize_lookup_key(&name)?;
        let (change, _) = mint_group_snapshot(&mut ws, gid, &members, &label, &key, &[head]);
        ws.commit(change, "relations group add");
        repo.push(&mut ws).map_err(|e| anyhow!("push: {e:?}"))?;
        Ok((gid, pid, true))
    })?;
    if added {
        println!("Added {} to group {}.", fmt_id(pid), fmt_id(gid));
    } else {
        println!("{} already in group {}.", fmt_id(pid), fmt_id(gid));
    }
    Ok(())
}

fn cmd_group_remove(pile: &Path, branch_id: Id, group: String, person: String) -> Result<()> {
    let (gid, pid, removed) = with_repo(pile, |repo| {
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
        let gid = resolve_group_id(&space, &group)?;
        let pid = resolve_member_id(&space, &person)?;
        let (head, mut members) = require_unique_head(&space, gid)?;
        if !members.contains(&pid) {
            return Ok((gid, pid, false));
        }
        members.retain(|&m| m != pid);
        let name = person_label(&mut ws, &space, head)
            .ok_or_else(|| anyhow!("group {} head snapshot has no name", fmt_id(gid)))?;
        let label = normalize_label(&name)?;
        let key = normalize_lookup_key(&name)?;
        let (change, _) = mint_group_snapshot(&mut ws, gid, &members, &label, &key, &[head]);
        ws.commit(change, "relations group remove");
        repo.push(&mut ws).map_err(|e| anyhow!("push: {e:?}"))?;
        Ok((gid, pid, true))
    })?;
    if removed {
        println!("Removed {} from group {}.", fmt_id(pid), fmt_id(gid));
    } else {
        println!("{} is not in group {}.", fmt_id(pid), fmt_id(gid));
    }
    Ok(())
}

fn cmd_group_rename(pile: &Path, branch_id: Id, group: String, name: String) -> Result<()> {
    let label = normalize_label(&name)?;
    let key = normalize_lookup_key(&name)?;
    let gid = with_repo(pile, |repo| {
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
        let gid = resolve_group_id(&space, &group)?;
        if let Ok(other) = resolve_group_id(&space, &name) {
            if other != gid {
                bail!("group '{label}' already exists ({})", fmt_id(other));
            }
        }
        let (head, members) = require_unique_head(&space, gid)?;
        let (change, _) = mint_group_snapshot(&mut ws, gid, &members, &label, &key, &[head]);
        ws.commit(change, "relations group rename");
        repo.push(&mut ws).map_err(|e| anyhow!("push: {e:?}"))?;
        Ok(gid)
    })?;
    println!("Renamed group {} to {label}.", fmt_id(gid));
    Ok(())
}

fn cmd_group_migrate(pile: &Path, branch_id: Id) -> Result<()> {
    let migrated = with_repo(pile, |repo| {
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
        let anchors: Vec<Id> =
            find!(gid: Id, pattern!(&space, [{ ?gid @ metadata::tag: &KIND_GROUP }])).collect();
        let mut change = TribleSet::new();
        let mut count = 0usize;
        for gid in anchors {
            // Only a legacy anchor-direct group (no snapshots at all => Missing)
            // needs snapshot-0. Groups that already have any snapshot
            // (Unique/Forked/Invalid) are left untouched.
            if !matches!(resolve_group_head(&space, gid), GroupHead::Missing) {
                continue;
            }
            let mut members: Vec<Id> =
                find!(m: Id, pattern!(&space, [{ gid @ group::member: ?m }])).collect();
            members.sort();
            members.dedup();
            let name = person_label(&mut ws, &space, gid)
                .ok_or_else(|| anyhow!("legacy group {} has no name to migrate", fmt_id(gid)))?;
            let label = normalize_label(&name)?;
            let key = normalize_lookup_key(&name)?;
            let (snapshot, _) = mint_group_snapshot(&mut ws, gid, &members, &label, &key, &[]);
            change += snapshot;
            count += 1;
        }
        if count > 0 {
            ws.commit(change, "relations migrate groups to snapshots");
            repo.push(&mut ws).map_err(|e| anyhow!("push: {e:?}"))?;
        }
        Ok(count)
    })?;
    println!("Migrated {migrated} legacy group(s) to snapshot form.");
    Ok(())
}

fn cmd_group_reconcile(
    pile: &Path,
    branch_id: Id,
    group: String,
    name: Option<String>,
) -> Result<()> {
    let (gid, healed) = with_repo(pile, |repo| {
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
        let gid = resolve_group_id(&space, &group)?;
        let heads = match resolve_group_head(&space, gid) {
            GroupHead::Forked(heads) => heads,
            GroupHead::Unique(_) => return Ok((gid, false)),
            GroupHead::Missing => bail!(
                "group {} has no snapshot yet; run `relations group migrate`",
                fmt_id(gid)
            ),
            GroupHead::Invalid(reason) => bail!(
                "group {} is invalid ({reason}); a corrupt snapshot graph cannot be reconciled",
                fmt_id(gid)
            ),
        };
        // The UNION of every fork head's members: reconciliation drops no member
        // silently. Prune afterward with `group remove` if that was intended.
        let mut members: Vec<Id> = Vec::new();
        for &head in &heads {
            members.extend(find!(m: Id, pattern!(&space, [{ head @ group::member: ?m }])));
        }
        members.sort();
        members.dedup();
        // Name selection is EXPLICIT, never a silent content-hash pick. If the
        // fork heads agree on a name we adopt it; if concurrent renames diverged
        // we refuse until the operator chooses with `--name`.
        let chosen_name = match &name {
            Some(explicit) => explicit.clone(),
            None => {
                let mut names: Vec<String> = Vec::new();
                for &head in &heads {
                    match person_label(&mut ws, &space, head) {
                        Some(n) => names.push(n),
                        None => bail!("fork head {} has no name", fmt_id(head)),
                    }
                }
                names.sort();
                names.dedup();
                match names.as_slice() {
                    [single] => single.clone(),
                    _ => bail!(
                        "group {} fork heads disagree on name ({}); pass --name <name> to choose",
                        fmt_id(gid),
                        names.join(", ")
                    ),
                }
            }
        };
        let label = normalize_label(&chosen_name)?;
        let key = normalize_lookup_key(&chosen_name)?;
        // One intrinsic child superseding EVERY head => a single un-superseded head.
        let (change, _) = mint_group_snapshot(&mut ws, gid, &members, &label, &key, &heads);
        ws.commit(change, "relations group reconcile");
        repo.push(&mut ws).map_err(|e| anyhow!("push: {e:?}"))?;
        Ok((gid, true))
    })?;
    if healed {
        println!("Reconciled forked group {} into a single head.", fmt_id(gid));
    } else {
        println!("Group {} is not forked; nothing to reconcile.", fmt_id(gid));
    }
    Ok(())
}

fn cmd_group_list(pile: &Path, branch_id: Id) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
        let mut groups: Vec<Id> =
            find!(gid: Id, pattern!(&space, [{ ?gid @ metadata::tag: &KIND_GROUP }])).collect();
        groups.sort();
        groups.dedup();
        if groups.is_empty() {
            println!("No groups.");
            return Ok(());
        }
        for gid in groups {
            // Surface anomalies rather than reporting a broken group as an
            // empty one: an unmigrated legacy group, a fork, or a corrupt
            // snapshot must be VISIBLE so it gets reconciled, not silently
            // dropped from delivery/gating.
            match resolve_group_head(&space, gid) {
                GroupHead::Unique(head) => {
                    let label =
                        person_label(&mut ws, &space, head).unwrap_or_else(|| fmt_id(gid));
                    let members = group_members(&space, gid);
                    println!("[{}] {label} — {} member(s)", fmt_id(gid), members.len());
                }
                GroupHead::Missing => println!(
                    "[{}] !! unmigrated legacy group — run `relations group migrate`",
                    fmt_id(gid)
                ),
                GroupHead::Forked(heads) => println!(
                    "[{}] !! FORKED across {} heads — reconcile before use",
                    fmt_id(gid),
                    heads.len()
                ),
                GroupHead::Invalid(reason) => {
                    println!("[{}] !! INVALID: {reason}", fmt_id(gid))
                }
            }
        }
        Ok(())
    })
}

fn cmd_group_show(pile: &Path, branch_id: Id, group: String) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
        let gid = resolve_group_id(&space, &group)?;
        // Anomalies are surfaced explicitly: a broken group must never look
        // like a healthy empty one.
        let head = match resolve_group_head(&space, gid) {
            GroupHead::Unique(head) => head,
            GroupHead::Missing => bail!(
                "group {} is an unmigrated legacy group — run `relations group migrate`",
                fmt_id(gid)
            ),
            GroupHead::Forked(heads) => bail!(
                "group {} is FORKED across {} concurrent heads — reconcile before use",
                fmt_id(gid),
                heads.len()
            ),
            GroupHead::Invalid(reason) => {
                bail!("group {} is INVALID: {reason}", fmt_id(gid))
            }
        };
        let label = person_label(&mut ws, &space, head).unwrap_or_else(|| fmt_id(gid));
        println!("group: {label} ({})", fmt_id(gid));
        let members = group_members(&space, gid);
        if members.is_empty() {
            println!("- (no members)");
        }
        for m in members {
            let mlabel = person_label(&mut ws, &space, m).unwrap_or_else(|| fmt_id(m));
            println!("- {mlabel} ({})", fmt_id(m));
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
        Command::List { limit, all, retired } => {
            cmd_list(&cli.pile, &cli.branch, branch_id, limit, all, retired)
        }
        Command::Show { id } => cmd_show(&cli.pile, &cli.branch, branch_id, id),
        Command::Retire { person } => cmd_retire(&cli.pile, branch_id, person),
        Command::Unretire { person } => cmd_unretire(&cli.pile, branch_id, person),
        Command::Group { command } => match command {
            GroupCmd::Create { name } => cmd_group_create(&cli.pile, branch_id, name),
            GroupCmd::Add { group, person } => cmd_group_add(&cli.pile, branch_id, group, person),
            GroupCmd::Remove { group, person } => {
                cmd_group_remove(&cli.pile, branch_id, group, person)
            }
            GroupCmd::Rename { group, name } => cmd_group_rename(&cli.pile, branch_id, group, name),
            GroupCmd::Migrate => cmd_group_migrate(&cli.pile, branch_id),
            GroupCmd::Reconcile { group, name } => {
                cmd_group_reconcile(&cli.pile, branch_id, group, name)
            }
            GroupCmd::List => cmd_group_list(&cli.pile, branch_id),
            GroupCmd::Show { group } => cmd_group_show(&cli.pile, branch_id, group),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    struct TestPile(PathBuf);

    impl TestPile {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("faculties-relations-{}.pile", ufoid().id));
            File::create(&path).expect("create test pile");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestPile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn sorted(mut v: Vec<Id>) -> Vec<Id> {
        v.sort();
        v
    }

    fn branch(pile: &Path) -> Id {
        with_repo(pile, |repo| {
            repo.ensure_branch(DEFAULT_BRANCH, None)
                .map_err(|e| anyhow!("ensure branch: {e:?}"))
        })
        .expect("ensure relations branch")
    }

    fn seed_person(pile: &Path, branch_id: Id, id: Id, name: &str) {
        with_repo(pile, |repo| {
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
            let handle = ws.put(name.to_string());
            let mut change = TribleSet::new();
            change += entity! { ExclusiveId::force_ref(&id) @
                metadata::tag: &KIND_PERSON_ID,
                metadata::name: handle,
            };
            ws.commit(change, "seed person");
            repo.push(&mut ws).map_err(|e| anyhow!("push: {e:?}"))?;
            Ok(())
        })
        .expect("seed person");
    }

    /// Seed a legacy anchor-direct group: name + members live DIRECTLY on the
    /// anchor (the pre-snapshot model), with no snapshot entity at all. This is
    /// exactly the shape `group migrate` must promote.
    fn seed_legacy_group(
        pile: &Path,
        branch_id: Id,
        anchor: Id,
        name: Option<&str>,
        members: &[Id],
    ) {
        with_repo(pile, |repo| {
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
            let mut change = TribleSet::new();
            change += entity! { ExclusiveId::force_ref(&anchor) @ metadata::tag: &KIND_GROUP };
            if let Some(name) = name {
                let handle = ws.put(name.to_string());
                change += entity! { ExclusiveId::force_ref(&anchor) @ metadata::name: handle };
            }
            for m in members {
                change += entity! { ExclusiveId::force_ref(&anchor) @ group::member: m };
            }
            ws.commit(change, "seed legacy group");
            repo.push(&mut ws).map_err(|e| anyhow!("push: {e:?}"))?;
            Ok(())
        })
        .expect("seed legacy group");
    }

    fn head(pile: &Path, branch_id: Id, anchor: Id) -> GroupHead {
        with_repo(pile, |repo| {
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
            let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
            Ok(resolve_group_head(&space, anchor))
        })
        .expect("read head")
    }

    fn members(pile: &Path, branch_id: Id, anchor: Id) -> Vec<Id> {
        with_repo(pile, |repo| {
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
            let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
            Ok(group_members(&space, anchor))
        })
        .expect("read members")
    }

    fn resolve(pile: &Path, branch_id: Id, name: &str) -> Result<Id> {
        with_repo(pile, |repo| {
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
            let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;
            resolve_group_id(&space, name)
        })
    }

    #[test]
    fn migrate_promotes_legacy_groups_and_is_idempotent() {
        let pile = TestPile::new();
        let b = branch(pile.path());
        let mut anchors = Vec::new();
        for i in 0..4 {
            let anchor = ufoid().id;
            let m1 = ufoid().id;
            let m2 = ufoid().id;
            seed_legacy_group(pile.path(), b, anchor, Some(&format!("group-{i}")), &[m1, m2]);
            anchors.push((anchor, sorted(vec![m1, m2])));
        }
        // Before migration each is a VISIBLE unmigrated legacy group (Missing),
        // not a healthy-looking empty one.
        for (anchor, _) in &anchors {
            assert_eq!(head(pile.path(), b, *anchor), GroupHead::Missing);
        }
        cmd_group_migrate(pile.path(), b).expect("migrate");
        let heads: Vec<Id> = anchors
            .iter()
            .map(|(anchor, want)| match head(pile.path(), b, *anchor) {
                GroupHead::Unique(h) => {
                    assert_eq!(&members(pile.path(), b, *anchor), want);
                    h
                }
                other => panic!("expected Unique after migrate, got {other:?}"),
            })
            .collect();
        // Idempotent: a second migration re-mints nothing; every head is byte
        // -identical (migrate only touches Missing groups).
        cmd_group_migrate(pile.path(), b).expect("migrate idempotent");
        for ((anchor, _), h) in anchors.iter().zip(heads) {
            assert_eq!(head(pile.path(), b, *anchor), GroupHead::Unique(h));
        }
    }

    #[test]
    fn migrate_empty_legacy_group_yields_unique_empty_head() {
        let pile = TestPile::new();
        let b = branch(pile.path());
        let anchor = ufoid().id;
        seed_legacy_group(pile.path(), b, anchor, Some("empty"), &[]);
        cmd_group_migrate(pile.path(), b).expect("migrate");
        assert!(matches!(head(pile.path(), b, anchor), GroupHead::Unique(_)));
        assert!(members(pile.path(), b, anchor).is_empty());
    }

    #[test]
    fn migrate_malformed_legacy_group_without_name_fails_visible() {
        let pile = TestPile::new();
        let b = branch(pile.path());
        let anchor = ufoid().id;
        seed_legacy_group(pile.path(), b, anchor, None, &[ufoid().id]);
        // Fails LOUDLY rather than silently minting a nameless snapshot.
        let err = cmd_group_migrate(pile.path(), b).unwrap_err();
        assert!(err.to_string().contains("no name"), "unexpected error: {err}");
        // Still visibly un-migrated (Missing), never a healthy zero-member group.
        assert_eq!(head(pile.path(), b, anchor), GroupHead::Missing);
    }

    #[test]
    fn create_add_remove_rename_roundtrip() {
        let pile = TestPile::new();
        let b = branch(pile.path());
        let alice = ufoid().id;
        let bob = ufoid().id;
        seed_person(pile.path(), b, alice, "Alice");
        seed_person(pile.path(), b, bob, "Bob");

        cmd_group_create(pile.path(), b, "Crew".to_string()).expect("create");
        let anchor = resolve(pile.path(), b, "Crew").expect("resolve crew");
        // Fresh group: Unique head, zero members.
        assert!(matches!(head(pile.path(), b, anchor), GroupHead::Unique(_)));
        assert!(members(pile.path(), b, anchor).is_empty());

        cmd_group_add(pile.path(), b, "Crew".to_string(), fmt_id(alice)).expect("add alice");
        cmd_group_add(pile.path(), b, "Crew".to_string(), fmt_id(bob)).expect("add bob");
        assert_eq!(members(pile.path(), b, anchor), sorted(vec![alice, bob]));

        cmd_group_remove(pile.path(), b, "Crew".to_string(), fmt_id(alice)).expect("remove alice");
        assert_eq!(members(pile.path(), b, anchor), vec![bob]);

        // Rename: only the NEW name resolves; the anchor and membership persist.
        cmd_group_rename(pile.path(), b, "Crew".to_string(), "Squad".to_string()).expect("rename");
        assert!(resolve(pile.path(), b, "Crew").is_err());
        assert_eq!(resolve(pile.path(), b, "Squad").expect("resolve squad"), anchor);
        assert!(matches!(head(pile.path(), b, anchor), GroupHead::Unique(_)));
        assert_eq!(members(pile.path(), b, anchor), vec![bob]);
    }

    /// Commit one content-canonical snapshot of `anchor` (tagging the anchor).
    /// Two divergent no-predecessor snapshots of the same anchor produce a fork.
    fn seed_snapshot(pile: &Path, branch_id: Id, anchor: Id, name: &str, members: &[Id], preds: &[Id]) {
        with_repo(pile, |repo| {
            let mut ws = repo.pull(branch_id).map_err(|e| anyhow!("pull: {e:?}"))?;
            let handle = ws.put(name.to_string());
            let mut change = TribleSet::new();
            change += entity! { ExclusiveId::force_ref(&anchor) @ metadata::tag: &KIND_GROUP };
            change += group_snapshot_fragment(anchor, handle, members, preds);
            ws.commit(change, "seed snapshot");
            repo.push(&mut ws).map_err(|e| anyhow!("push: {e:?}"))?;
            Ok(())
        })
        .expect("seed snapshot");
    }

    #[test]
    fn reconcile_heals_a_fork_into_one_head_with_the_union_of_members() {
        let pile = TestPile::new();
        let b = branch(pile.path());
        let anchor = ufoid().id;
        let m1 = ufoid().id;
        let m2 = ufoid().id;
        // Two replicas edited the same anchor concurrently and divergently: two
        // un-superseded heads with different members => Forked.
        seed_snapshot(pile.path(), b, anchor, "crew", &[m1], &[]);
        seed_snapshot(pile.path(), b, anchor, "crew", &[m1, m2], &[]);
        assert!(matches!(head(pile.path(), b, anchor), GroupHead::Forked(_)));
        // While forked, ordinary edits fail closed.
        assert!(cmd_group_add(pile.path(), b, fmt_id(anchor), fmt_id(m2)).is_err());

        cmd_group_reconcile(pile.path(), b, fmt_id(anchor), None).expect("reconcile");
        assert!(matches!(head(pile.path(), b, anchor), GroupHead::Unique(_)));
        // The union of both heads' members survives (nothing silently dropped).
        assert_eq!(members(pile.path(), b, anchor), sorted(vec![m1, m2]));
        // Reconcile on a healthy group is a visible no-op.
        cmd_group_reconcile(pile.path(), b, fmt_id(anchor), None).expect("reconcile no-op");
        assert!(matches!(head(pile.path(), b, anchor), GroupHead::Unique(_)));
    }

    #[test]
    fn reconcile_refuses_divergent_names_without_an_explicit_choice() {
        let pile = TestPile::new();
        let b = branch(pile.path());
        let anchor = ufoid().id;
        let m1 = ufoid().id;
        // Concurrent renames: two heads with DIFFERENT names.
        seed_snapshot(pile.path(), b, anchor, "alpha", &[m1], &[]);
        seed_snapshot(pile.path(), b, anchor, "beta", &[m1], &[]);
        assert!(matches!(head(pile.path(), b, anchor), GroupHead::Forked(_)));
        // No --name => refuses rather than silently picking by content-hash order.
        let err = cmd_group_reconcile(pile.path(), b, fmt_id(anchor), None).unwrap_err();
        assert!(
            err.to_string().contains("disagree on name"),
            "unexpected error: {err}"
        );
        assert!(matches!(head(pile.path(), b, anchor), GroupHead::Forked(_)));
        // With an explicit name it heals to a single named head.
        cmd_group_reconcile(pile.path(), b, fmt_id(anchor), Some("gamma".to_string()))
            .expect("reconcile with explicit name");
        assert!(matches!(head(pile.path(), b, anchor), GroupHead::Unique(_)));
        assert_eq!(resolve(pile.path(), b, "gamma").expect("resolve gamma"), anchor);
    }
}
