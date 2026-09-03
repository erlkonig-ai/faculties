//! `mail` — collection-native RFC 5322 evidence, intent, and receipt faculty.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::clock;
use faculties::collection_names::open_configured;
use faculties::files;
use faculties::mail::{self, AccountConfigInput, DraftInput, Head, SendAttemptInput};
use faculties::mail_pop;
use faculties::relations;
use faculties::schemas::{
    decide as decide_schema, files as files_schema, mail as mail_schema,
    relations as relations_schema,
};
use faculties::secrets::storage as vaults;
use faculties::storage::{load_signer, open_pile_strict, FactArchive, FactCollection};
use lettre::address::{Address as SmtpAddress, Envelope as LettreEnvelope};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::prelude::*;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "mail", about = "Immutable email evidence, drafts, and delivery receipts")]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable collection signer. Ordinary commands never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage immutable full-state mail-account configurations.
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    /// Fetch every enabled account through UIDL-safe POP.
    Fetch,
    /// Create one immutable draft and its deterministic Decide proposal.
    Draft(DraftArgs),
    /// Create a reply draft from an inbound wire message.
    Reply(ReplyArgs),
    /// Submit one authorized draft under externally serialized execution.
    Send { draft: String },
    /// List immutable drafts and their delivery state.
    Outbox,
    /// List inbound projections for the configured persona.
    List {
        #[arg(long)]
        unread: bool,
        #[arg(long)]
        spam: bool,
    },
    /// Record intrinsic read evidence for one inbound wire message.
    Read { message: String },
    /// Show one inbound or outgoing wire message.
    Show { message: String },
    /// Case-insensitive substring search over projected subject and body.
    Search { query: String },
}

#[derive(Subcommand)]
enum AccountCommand {
    /// Add an account or append a full-state successor to an existing account.
    Set {
        /// Existing account id/address. Omit only when creating a new anchor.
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        address: String,
        #[arg(long)]
        display_name: String,
        /// Implicit-TLS endpoint as `host:port`.
        #[arg(long)]
        pop_endpoint: String,
        /// Implicit-TLS endpoint as `host:port`.
        #[arg(long)]
        smtp_endpoint: String,
        #[arg(long)]
        username: Option<String>,
        /// Mailbox secret. Prefer MAIL_PASS rather than a visible argv value.
        #[arg(long, env = "MAIL_PASS", hide_env_values = true, requires = "vault")]
        password: Option<String>,
        /// Exact existing Secrets version. This is the repair path when
        /// a Secrets-first account update was interrupted before Mail commit.
        #[arg(long, value_parser = parse_id, conflicts_with = "password")]
        credential_version: Option<Id>,
        /// Exact vault epoch receiving a newly sealed mailbox password.
        #[arg(long, value_parser = parse_id, requires = "password")]
        vault: Option<Id>,
        #[arg(long)]
        disabled: bool,
    },
    List,
}

#[derive(Args)]
struct DraftArgs {
    /// Account id/address; required even when only one account exists.
    #[arg(long)]
    account: String,
    #[arg(long, required = true)]
    to: Vec<String>,
    #[arg(long)]
    cc: Vec<String>,
    #[arg(long)]
    bcc: Vec<String>,
    #[arg(long)]
    subject: String,
    /// Literal text, `@path`, or `@-`.
    body: String,
    #[arg(long)]
    attach: Vec<PathBuf>,
}

#[derive(Args)]
struct ReplyArgs {
    message: String,
    #[arg(long)]
    account: String,
    /// Literal text, `@path`, or `@-`.
    body: String,
}

#[derive(Clone, Copy)]
struct Scopes {
    mail: Id,
    files: Id,
    decide: Id,
    relations: Id,
}

impl Scopes {
    const FIXED: Self = Self {
        mail: mail_schema::DEFAULT_SCOPE_ID,
        files: files_schema::DEFAULT_SCOPE_ID,
        decide: decide_schema::DEFAULT_SCOPE_ID,
        relations: relations_schema::DEFAULT_SCOPE_ID,
    };
}

struct CollectionView {
    facts: FactArchive,
    reader: PileSnapshot,
}

struct Views {
    mail: CollectionView,
    files: CollectionView,
    decide: CollectionView,
    relations: CollectionView,
    secrets: vaults::VaultDiscovery,
}

struct Storage<'a> {
    pile_path: &'a Path,
    pile: RefCell<Option<Pile>>,
    signer: SigningKey,
    scopes: Scopes,
}

impl Storage<'_> {
    fn open<'a>(pile_path: &'a Path, key: Option<&Path>, scopes: Scopes) -> Result<Storage<'a>> {
        let signer = load_signer(pile_path, key)?;
        let pile = open_pile_strict(pile_path)?;
        Ok(Storage {
            pile_path,
            pile: RefCell::new(Some(pile)),
            signer,
            scopes,
        })
    }

    fn views(&self) -> Result<Views> {
        let (mail_facts, files_facts, decide_facts, relations_facts, store_snapshot, secrets) = {
            let mut pile = self.pile.borrow_mut();
            let pile = pile
                .as_mut()
                .ok_or_else(|| anyhow!("Mail storage is already closed"))?;
            let mail_collection =
                open_configured(pile, self.scopes.mail, self.signer.verifying_key())?;
            let files_collection =
                open_configured(pile, self.scopes.files, self.signer.verifying_key())?;
            let decide_collection =
                open_configured(pile, self.scopes.decide, self.signer.verifying_key())?;
            let relations_collection =
                open_configured(pile, self.scopes.relations, self.signer.verifying_key())?;
            let mail = FactCollection::new(pile, mail_collection)
                .context("register maintained Mail fact collection")?;
            let files = FactCollection::new(pile, files_collection)
                .context("register maintained Files fact collection")?;
            let decide = FactCollection::new(pile, decide_collection)
                .context("register maintained Decide fact collection")?;
            let relations = FactCollection::new(pile, relations_collection)
                .context("register maintained Relations fact collection")?;
            let before = pile
                .snapshot()
                .context("freeze shared Mail pre-maintenance snapshot")?;
            let instant = clock::now()?;
            // One source watermark fixes every ordinary fact collection this
            // command may observe. Maintenance may append physical views, but
            // cannot move that semantic boundary independently per scope.
            let mail_support = before
                .collection_at(mail.source(), instant)
                .context("observe resident Mail collection")?
                .support()
                .clone();
            let files_support = before
                .collection_at(files.source(), instant)
                .context("observe resident Files collection")?
                .support()
                .clone();
            let decide_support = before
                .collection_at(decide.source(), instant)
                .context("observe resident Decide collection")?
                .support()
                .clone();
            let relations_support = before
                .collection_at(relations.source(), instant)
                .context("observe resident Relations collection")?
                .support()
                .clone();
            drop(before);
            drop(
                mail.maintain_exact(pile, &mail_support)
                    .context("maintain Mail fact collection")?,
            );
            drop(
                files
                    .maintain_exact(pile, &files_support)
                    .context("maintain Files fact collection")?,
            );
            drop(
                decide
                    .maintain_exact(pile, &decide_support)
                    .context("maintain Decide fact collection")?,
            );
            drop(
                relations
                    .maintain_exact(pile, &relations_support)
                    .context("maintain Relations fact collection")?,
            );

            let secrets = vaults::discover_local_vaults(&mut *pile, &self.signer)
                .context("discover local Secrets vault epochs")?;
            // Secrets discovery owns the final immutable pile snapshot. Attach
            // every exact maintained support through that same world so Mail
            // facts, file payloads, decisions, relations, and credentials can
            // never be assembled from different store prefixes.
            let store_snapshot = secrets.snapshot().store_snapshot().clone();
            let mail_facts = store_snapshot
                .collection_exact(mail.rank9(), &mail_support)
                .context("attach maintained Mail fact collection")?
                .view::<FactArchive>()
                .context("read maintained Mail fact collection")?;
            let files_facts = store_snapshot
                .collection_exact(files.rank9(), &files_support)
                .context("attach maintained Files fact collection")?
                .view::<FactArchive>()
                .context("read maintained Files fact collection")?;
            let decide_facts = store_snapshot
                .collection_exact(decide.rank9(), &decide_support)
                .context("attach maintained Decide fact collection")?
                .view::<FactArchive>()
                .context("read maintained Decide fact collection")?;
            let relations_facts = store_snapshot
                .collection_exact(relations.rank9(), &relations_support)
                .context("attach maintained Relations fact collection")?
                .view::<FactArchive>()
                .context("read maintained Relations fact collection")?;
            (
                mail_facts,
                files_facts,
                decide_facts,
                relations_facts,
                store_snapshot,
                secrets,
            )
        };
        Ok(Views {
            mail: CollectionView {
                facts: mail_facts,
                reader: store_snapshot.clone(),
            },
            files: CollectionView {
                facts: files_facts,
                reader: store_snapshot.clone(),
            },
            decide: CollectionView {
                facts: decide_facts,
                reader: store_snapshot.clone(),
            },
            relations: CollectionView {
                facts: relations_facts,
                reader: store_snapshot,
            },
            secrets,
        })
    }

    fn add_secret(&self, vault: Id, name: &str, plaintext: &[u8]) -> Result<Id> {
        let mut pile = self.pile.borrow_mut();
        let pile = pile
            .as_mut()
            .ok_or_else(|| anyhow!("Mail storage is already closed"))?;
        let discovery = vaults::discover_local_vaults(&mut *pile, &self.signer)
            .context("discover local Secrets vault epochs")?;
        let location = discovery
            .location(vault)
            .copied()
            .ok_or_else(|| anyhow!("vault {vault} is not ready for this node"))?;
        vaults::add_secret(
            &mut *pile,
            &self.signer,
            &location,
            discovery.snapshot(),
            name,
            plaintext,
            point_now()?,
        )
        .context("publish mailbox credential to exact vault epoch")
    }

    fn publish(&self, scope: Id, fragment: Fragment, description: &str) -> Result<()> {
        let mut fragment = fragment;
        fragment.describe_with(entity! { metadata::description: description.to_owned() });
        let mut pile = self.pile.borrow_mut();
        let pile = pile
            .as_mut()
            .ok_or_else(|| anyhow!("Mail storage is already closed"))?;
        let collection = open_configured(pile, scope, self.signer.verifying_key())?;
        pile.commit(collection, &self.signer, fragment)
            .with_context(|| format!("commit collection {scope:x}"))?;
        Ok(())
    }

    fn close(self) -> Result<()> {
        self.close_inner()
    }

    fn close_inner(&self) -> Result<()> {
        let Some(pile) = self.pile.borrow_mut().take() else {
            return Ok(());
        };
        pile.close()
            .with_context(|| format!("close Mail pile {}", self.pile_path.display()))
    }
}

impl Drop for Storage<'_> {
    fn drop(&mut self) {
        // Command dispatch reports close failures explicitly through `close`.
        // This fallback keeps early-returning tests and callers from silently
        // abandoning a live Pile handle.
        let _ = self.close_inner();
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn parse_id(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim())
        .ok_or_else(|| format!("'{raw}' is not one exact nonzero 32-digit hexadecimal id"))
}

fn point_now() -> Result<mail::IntervalValue> {
    clock::point_now()
}

fn persona_selector() -> Result<String> {
    std::env::var("PERSONA").context("PERSONA must select an active Relations person")
}

fn relation_persona(views: &Views) -> Result<Id> {
    let raw = persona_selector()?;
    relations::resolve_person(&views.relations.reader, &views.relations.facts, &raw, false)?
        .require_unique("active Relations person", &raw)
}

fn mailbox_secret_name(account: Id) -> String {
    format!("mail/{}", URL_SAFE_NO_PAD.encode(account.raw()))
}

fn resolve_account(views: &Views, input: &str) -> Result<Id> {
    let anchors = mail::account_anchors(&views.mail.facts);
    if let Some(id) = Id::from_hex(input.trim()) {
        if anchors.contains(&id) {
            return Ok(id);
        }
        bail!("unknown mail account {id:x}");
    }
    let lowered = input.trim().to_ascii_lowercase();
    let mut matches = BTreeSet::new();
    for anchor in anchors {
        if fmt_id(anchor).starts_with(&lowered) {
            matches.insert(anchor);
            continue;
        }
        let config = match mail::account_head(&views.mail.facts, anchor)? {
            Head::Unique(id) => mail::account_config(&views.mail.facts, id)?,
            Head::Missing | Head::Forked(_) => continue,
        };
        if mail::read_text(&views.mail.reader, config.address)?.eq_ignore_ascii_case(input.trim()) {
            matches.insert(anchor);
        }
    }
    match matches.len() {
        0 => bail!("no mail account matches {input:?}"),
        1 => Ok(matches.pop_first().unwrap()),
        count => bail!("{count} mail accounts match {input:?}"),
    }
}

fn resolve_draft<P>(facts: &P, input: &str) -> Result<Id>
where
    P: TriblePattern,
{
    let candidates: BTreeSet<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &mail_schema::KIND_DRAFT_INTENT }])
    )
    .collect();
    faculties::resolve_id_prefix(input, candidates)
}

fn wire_candidates<P>(facts: &P) -> BTreeSet<Id>
where
    P: TriblePattern,
{
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: &mail_schema::KIND_WIRE_MESSAGE }]))
        .collect()
}

fn resolve_wire<P>(facts: &P, input: &str) -> Result<Id>
where
    P: TriblePattern,
{
    faculties::resolve_id_prefix(input, wire_candidates(facts))
}

fn account_set(
    storage: &Storage<'_>,
    account_selector: Option<String>,
    address: String,
    display_name: String,
    pop_endpoint: String,
    smtp_endpoint: String,
    username: Option<String>,
    password: Option<String>,
    credential_version: Option<Id>,
    vault: Option<Id>,
    disabled: bool,
) -> Result<()> {
    let mut views = storage.views()?;
    let (anchor, predecessors, old_credential, replacing_fork) =
        if let Some(selector) = account_selector {
            let anchor = resolve_account(&views, &selector)?;
            match mail::account_head(&views.mail.facts, anchor)? {
                Head::Unique(head) => {
                    let config = mail::account_config(&views.mail.facts, head)?;
                    (anchor, vec![head], Some(config.credential), false)
                }
                Head::Missing => bail!("account {anchor:x} has no configuration"),
                // A complete new snapshot can reconcile every observed branch,
                // but no branch may be selected as the credential donor.
                Head::Forked(heads) => (anchor, heads, None, true),
            }
        } else {
            (genid().id, Vec::new(), None, false)
        };

    if let Some(id) = credential_version {
        if !views.secrets.snapshot().contains(id) {
            bail!("unknown Secrets credential version {id:x}");
        }
    }

    // Canonicalize every account field before a supplied password can cause
    // an immutable secret publication. The temporary credential is replaced
    // below; it does not escape this in-memory validation step.
    let username = username.unwrap_or_else(|| address.clone());
    let mut input = AccountConfigInput {
        address,
        display_name,
        pop_endpoint,
        smtp_endpoint,
        username,
        credential: credential_version.or(old_credential).unwrap_or(anchor),
        enabled: !disabled,
        predecessors,
    }
    .canonicalized()?;

    let credential_id = match (password, credential_version, old_credential, vault) {
        (None, None, Some(id), None) => id,
        (None, None, None, None) if replacing_fork => {
            bail!("--credential-version or MAIL_PASS/--password is required to reconcile a forked account")
        }
        (None, None, None, None) => {
            bail!("--credential-version or MAIL_PASS/--password is required for a new account")
        }
        (None, Some(id), _, None) => id,
        (Some(value), None, _, Some(vault)) => {
            let id = storage.add_secret(vault, &mailbox_secret_name(anchor), value.as_bytes())?;
            eprintln!(
                "Published mailbox credential {id:x} to vault {vault:x}; if Mail publication is interrupted, retry with --credential-version {id:x}"
            );
            views = storage.views()?;
            if !views.secrets.snapshot().contains(id) {
                bail!("published mailbox secret {id:x} did not materialize");
            }
            id
        }
        (Some(_), None, _, None) => {
            bail!("--vault is required when sealing a supplied --password")
        }
        (None, _, _, Some(_)) => bail!("--vault only applies when sealing a supplied --password"),
        (Some(_), Some(_), _, _) => {
            bail!("--password cannot be combined with --credential-version")
        }
    };
    input.credential = credential_id;
    if let [predecessor] = input.predecessors.as_slice() {
        let previous = mail::account_config(&views.mail.facts, *predecessor)?;
        let same = mail::read_text(&views.mail.reader, previous.address)? == input.address
            && mail::read_text(&views.mail.reader, previous.display_name)? == input.display_name
            && mail::read_text(&views.mail.reader, previous.pop_endpoint)? == input.pop_endpoint
            && mail::read_text(&views.mail.reader, previous.smtp_endpoint)? == input.smtp_endpoint
            && mail::read_text(&views.mail.reader, previous.username)? == input.username
            && previous.credential == input.credential
            && previous.enabled == input.enabled;
        if same {
            println!(
                "Account {} already has config {}",
                fmt_id(anchor),
                fmt_id(*predecessor)
            );
            return Ok(());
        }
    }

    let mut fragment = Fragment::empty();
    let (config_fragment, config_id) = mail::account_config_fragment(anchor, input)?;
    fragment += config_fragment;
    storage.publish(
        storage.scopes.mail,
        fragment,
        "mail: account full-state config",
    )?;
    println!("Account {} config {}", fmt_id(anchor), fmt_id(config_id));
    Ok(())
}

fn account_list(storage: &Storage<'_>) -> Result<()> {
    let views = storage.views()?;
    for anchor in mail::account_anchors(&views.mail.facts) {
        match mail::account_head(&views.mail.facts, anchor)? {
            Head::Missing => println!("{}  MISSING", fmt_id(anchor)),
            Head::Forked(ids) => println!("{}  FORKED {:?}", fmt_id(anchor), ids),
            Head::Unique(id) => {
                let config = mail::account_config(&views.mail.facts, id)?;
                let address = mail::read_text(&views.mail.reader, config.address)?;
                let state = if config.enabled {
                    "enabled"
                } else {
                    "disabled"
                };
                println!(
                    "{}  {}  {}  config={}",
                    fmt_id(anchor),
                    address,
                    state,
                    fmt_id(id)
                );
            }
        }
    }
    Ok(())
}

fn stage_attachments(paths: &[PathBuf]) -> Result<(Fragment, Vec<Id>)> {
    let mut fragment = Fragment::empty();
    let mut ids = Vec::new();
    for path in paths {
        let bytes =
            fs::read(path).with_context(|| format!("read attachment {}", path.display()))?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("attachment.bin");
        let file = files::stage(bytes, name, files::infer_media_type(path))?;
        ids.push(file.root().expect("canonical file root"));
        fragment += file;
    }
    Ok((fragment, ids))
}

#[allow(clippy::too_many_arguments)]
fn create_draft(
    storage: &Storage<'_>,
    views: &Views,
    account_selector: &str,
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    subject: String,
    body: String,
    attach: &[PathBuf],
    in_reply_to: Vec<Id>,
    references: Vec<Id>,
) -> Result<()> {
    let account_id = resolve_account(views, account_selector)?;
    let account = match mail::account_head(&views.mail.facts, account_id)? {
        Head::Unique(id) => mail::account_config(&views.mail.facts, id)?,
        Head::Missing => bail!("account {account_id:x} has no configuration"),
        Head::Forked(ids) => bail!("account {account_id:x} has forked configurations {ids:?}"),
    };
    if !account.enabled {
        bail!("account {account_id:x} is disabled");
    }
    let envelope_from = mail::read_text(&views.mail.reader, account.address)?;
    let (files_fragment, attachment_ids) = stage_attachments(attach)?;
    let draft = mail::draft_publication(DraftInput {
        nonce: genid().id,
        account: account_id,
        envelope_from,
        to,
        cc,
        bcc,
        subject,
        body,
        attachments: attachment_ids,
        in_reply_to,
        references,
        created_at: point_now()?,
    })?;
    if !files_fragment.facts().is_empty() {
        storage.publish(
            storage.scopes.files,
            files_fragment,
            "mail: draft attachments",
        )?;
    }
    storage.publish(
        storage.scopes.decide,
        draft.decide,
        "mail: draft send decision",
    )?;
    storage.publish(
        storage.scopes.mail,
        draft.mail,
        "mail: immutable draft intent",
    )?;
    println!("Draft {}", fmt_id(draft.draft));
    println!("Decision {}", fmt_id(draft.decision));
    Ok(())
}

fn cmd_draft(storage: &Storage<'_>, args: DraftArgs) -> Result<()> {
    let views = storage.views()?;
    create_draft(
        storage,
        &views,
        &args.account,
        args.to,
        args.cc,
        args.bcc,
        args.subject,
        faculties::text_arg(&args.body, "draft body")?,
        &args.attach,
        Vec::new(),
        Vec::new(),
    )
}

fn projection_for_wire(views: &Views, wire_id: Id) -> Result<mail::ProjectionView> {
    let ids: BTreeSet<Id> = find!(
        projection_id: Id,
        pattern!(&views.mail.facts, [
            { _?source @ observation::wire: &wire_id },
            { ?projection_id @ projection::source: _?source, projection::recipe: &mail_schema::RECIPE_RFC5322_V1 }
        ])
    )
    .collect();
    let candidates = ids
        .into_iter()
        .map(|id| mail::projection_view(&views.mail.reader, &views.mail.facts, id))
        .collect::<Result<Vec<_>>>()?;
    let Some(chosen) = candidates.first().cloned() else {
        bail!("wire message {wire_id:x} has no parser projection");
    };
    // Re-observing byte-identical mail creates another source/projection pair
    // but must not make the WireMessage unusable.  The source-local attachment
    // occurrence ids legitimately differ, so reply arbitration compares the
    // semantic fields a reply consumes and rejects only a real conflict.
    let agrees = |other: &mail::ProjectionView| {
        chosen.wire == other.wire
            && chosen.message_id == other.message_id
            && chosen.from == other.from
            && chosen.to == other.to
            && chosen.cc == other.cc
            && chosen.bcc == other.bcc
            && chosen.subject == other.subject
            && chosen.body == other.body
            && chosen.claimed_date == other.claimed_date
            && chosen.in_reply_to == other.in_reply_to
            && chosen.references == other.references
            && chosen.spam == other.spam
    };
    if candidates.iter().skip(1).all(agrees) {
        Ok(chosen)
    } else {
        bail!(
            "wire message {wire_id:x} has conflicting parser projections; choose an exact source before replying"
        )
    }
}

fn cmd_reply(storage: &Storage<'_>, args: ReplyArgs) -> Result<()> {
    let views = storage.views()?;
    let wire_id = resolve_wire(&views.mail.facts, &args.message)?;
    let parent = projection_for_wire(&views, wire_id)?;
    let recipient = parent
        .from
        .ok_or_else(|| anyhow!("parent message has no From mailbox claim"))?;
    let subject = if parent.subject.to_ascii_lowercase().starts_with("re:") {
        parent.subject
    } else {
        format!("Re: {}", parent.subject)
    };
    let mut references = parent.references;
    let in_reply_to = if parent.message_id.is_some() {
        references.push(wire_id);
        vec![wire_id]
    } else {
        // A digest-only parent did not claim an RFC Message-ID. It is a valid
        // local WireMessage identity, but cannot honestly appear in a remote
        // In-Reply-To or References header.
        Vec::new()
    };
    create_draft(
        storage,
        &views,
        &args.account,
        vec![recipient],
        Vec::new(),
        Vec::new(),
        subject,
        faculties::text_arg(&args.body, "reply body")?,
        &[],
        in_reply_to,
        references,
    )
}

struct LettreSubmit {
    transport: SmtpTransport,
}

impl mail::SmtpSubmit for LettreSubmit {
    fn submit(&mut self, envelope: &mail::SmtpEnvelope, raw: &[u8]) -> Result<mail::AcceptedReply> {
        let from: SmtpAddress = envelope.from.parse().context("parse SMTP reverse path")?;
        let recipients = envelope
            .recipients
            .iter()
            .map(|value| {
                value
                    .parse()
                    .with_context(|| format!("parse SMTP recipient {value:?}"))
            })
            .collect::<Result<Vec<SmtpAddress>>>()?;
        let envelope =
            LettreEnvelope::new(Some(from), recipients).context("construct SMTP envelope")?;
        let response = self
            .transport
            .send_raw(&envelope, raw)
            .context("SMTP submission is uncertain; the durable SendAttempt must not be retried")?;
        let code: u16 = response.code().into();
        let message = response.message().collect::<Vec<_>>().join(" ");
        Ok(mail::AcceptedReply {
            code,
            message: if message.is_empty() {
                code.to_string()
            } else {
                message
            },
        })
    }
}

fn endpoint<'a>(value: &'a str, label: &str) -> Result<(&'a str, u16)> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("{label} endpoint must be host:port"))?;
    if host.is_empty() {
        bail!("{label} endpoint has an empty host");
    }
    Ok((
        host,
        port.parse()
            .with_context(|| format!("parse {label} port"))?,
    ))
}

fn cmd_send(storage: &Storage<'_>, selector: &str) -> Result<()> {
    let views = storage.views()?;
    let draft_id = resolve_draft(&views.mail.facts, selector)?;
    let existing = mail::attempts_for_draft(&views.mail.facts, draft_id);
    if let Some(&attempt) = existing.first() {
        if mail::acceptances_for_attempt(&views.mail.facts, attempt).is_empty() {
            bail!("draft {draft_id:x} already has uncertain attempt {attempt:x}; never retry automatically");
        }
        println!(
            "Draft {} was already accepted (attempt {}).",
            fmt_id(draft_id),
            fmt_id(attempt)
        );
        return Ok(());
    }
    let record = mail::draft_value(&views.mail.facts, draft_id)?;
    let current_config = match mail::account_head(&views.mail.facts, record.account)? {
        Head::Unique(id) => mail::account_config(&views.mail.facts, id)?,
        Head::Missing => bail!("draft account {:x} has no configuration", record.account),
        Head::Forked(ids) => bail!(
            "draft account {:x} has forked configuration heads: {ids:?}",
            record.account
        ),
    };
    if !current_config.enabled {
        bail!("draft account {} is disabled", fmt_id(record.account));
    }
    let account = mail::open_account(
        &views.mail.reader,
        &views.mail.facts,
        views.secrets.snapshot(),
        record.account,
        &storage.signer,
    )?;
    let draft = mail::materialize_draft(
        &views.mail.reader,
        &views.mail.facts,
        &views.files.facts,
        draft_id,
    )?;
    let rendered = mail::render_draft(&draft, &account)?;
    let (decision, heads) =
        mail::authorized_send(&views.decide.reader, &views.decide.facts, draft_id)?;
    let prepared = mail::prepare_send(
        &views.mail.reader,
        &views.decide.reader,
        &views.mail.facts,
        &views.files.facts,
        &views.decide.facts,
        SendAttemptInput {
            draft: draft_id,
            config: account.config,
            decision,
            decision_heads: heads,
            raw: rendered.raw.clone(),
            envelope_from: draft.envelope_from.clone(),
            to: draft.to.clone(),
            cc: draft.cc.clone(),
            bcc: draft.bcc.clone(),
        },
    )?;
    let attempt_id = prepared.attempt_id();
    // Any Files evidence needed by the post-effect outgoing projection is
    // durable before SMTP. Most drafts reuse already-published file values.
    if !prepared.outgoing_files().facts().is_empty() {
        storage.publish(
            storage.scopes.files,
            prepared.outgoing_files().clone(),
            "mail: outgoing attachment evidence",
        )?;
    }
    let smtp_endpoint = account.smtp_endpoint.clone();
    let (host, port) = endpoint(&smtp_endpoint, "SMTP")?;
    let creds = Credentials::new(account.username.clone(), account.password.clone());
    let transport = SmtpTransport::relay(host)
        .with_context(|| format!("configure SMTP relay {host}"))?
        .port(port)
        .credentials(creds)
        .build();
    let mut submitter = LettreSubmit { transport };
    let response = mail::submit_once(
        &mut submitter,
        &prepared,
        |fragment| {
            storage.publish(
                storage.scopes.mail,
                fragment.clone(),
                "mail: send attempt before SMTP",
            )
        },
        |fragment| {
            storage.publish(
                storage.scopes.mail,
                fragment.clone(),
                "mail: SMTP acceptance and outgoing evidence",
            )
        },
    )?;
    println!(
        "Accepted draft {} as attempt {}: {} {}",
        fmt_id(draft_id),
        fmt_id(attempt_id),
        response.code,
        response.message
    );
    Ok(())
}

fn cmd_outbox(storage: &Storage<'_>) -> Result<()> {
    let views = storage.views()?;
    let drafts: BTreeSet<Id> = find!(
        id: Id,
        pattern!(&views.mail.facts, [{ ?id @ metadata::tag: &mail_schema::KIND_DRAFT_INTENT }])
    )
    .collect();
    for id in drafts {
        let draft = mail::materialize_draft(
            &views.mail.reader,
            &views.mail.facts,
            &views.files.facts,
            id,
        )?;
        let attempts = mail::attempts_for_draft(&views.mail.facts, id);
        let state = match attempts.as_slice() {
            [] => "pending".to_owned(),
            [attempt] if mail::acceptances_for_attempt(&views.mail.facts, *attempt).is_empty() => {
                format!("UNCERTAIN attempt={}", fmt_id(*attempt))
            }
            [attempt] => format!("accepted attempt={}", fmt_id(*attempt)),
            _ => "INVALID multiple attempts".to_owned(),
        };
        println!("{}  {}  {}", fmt_id(id), state, draft.subject);
    }
    Ok(())
}

fn cmd_list(storage: &Storage<'_>, unread_only: bool, spam_only: bool) -> Result<()> {
    let views = storage.views()?;
    let persona = relation_persona(&views)?;
    for row in mail::inbox_projection(&views.mail.facts, &views.relations.facts, persona)? {
        if unread_only && !row.unread {
            continue;
        }
        let view = mail::projection_view(&views.mail.reader, &views.mail.facts, row.projection)?;
        if spam_only && !view.spam {
            continue;
        }
        println!(
            "{}  {}{}  {}  {}",
            fmt_id(view.wire),
            if row.unread { "UNREAD" } else { "read" },
            if view.spam { "/spam" } else { "" },
            view.from.unwrap_or_else(|| "(no From)".into()),
            view.subject,
        );
    }
    Ok(())
}

fn cmd_read(storage: &Storage<'_>, selector: &str) -> Result<()> {
    let views = storage.views()?;
    let wire = resolve_wire(&views.mail.facts, selector)?;
    let reader = relation_persona(&views)?;
    let (fragment, id) = mail::read_observation_fragment(wire, reader);
    storage.publish(storage.scopes.mail, fragment, "mail: read observation")?;
    println!("Read {} ({})", fmt_id(wire), fmt_id(id));
    Ok(())
}

fn cmd_show(storage: &Storage<'_>, selector: &str) -> Result<()> {
    let views = storage.views()?;
    let wire = resolve_wire(&views.mail.facts, selector)?;
    let projections: BTreeSet<Id> = find!(
        id: Id,
        pattern!(&views.mail.facts, [
            { _?source @ observation::wire: &wire },
            { ?id @ projection::source: _?source, projection::recipe: &mail_schema::RECIPE_RFC5322_V1 }
        ])
    )
    .collect();
    if projections.is_empty() {
        bail!("wire message {wire:x} has no parser projection");
    }
    for id in projections {
        let view = mail::projection_view(&views.mail.reader, &views.mail.facts, id)?;
        println!("Wire: {}", fmt_id(view.wire));
        println!(
            "Message-ID: {}",
            view.message_id.as_deref().unwrap_or("(not claimed)")
        );
        println!("Source: {}", fmt_id(view.source));
        println!("From: {}", view.from.unwrap_or_default());
        println!("To: {}", view.to.join(", "));
        if !view.cc.is_empty() {
            println!("Cc: {}", view.cc.join(", "));
        }
        println!("Subject: {}", view.subject);
        println!();
        println!("{}", view.body);
        if !view.attachments.is_empty() {
            println!(
                "\nAttachment occurrences: {}",
                view.attachments
                    .iter()
                    .map(|id| fmt_id(*id))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    Ok(())
}

fn cmd_search(storage: &Storage<'_>, query: &str) -> Result<()> {
    let views = storage.views()?;
    let needle = query.to_lowercase();
    let projections: BTreeSet<Id> = find!(
        id: Id,
        pattern!(&views.mail.facts, [{ ?id @ metadata::tag: &mail_schema::KIND_PARSED_PROJECTION }])
    )
    .collect();
    for id in projections {
        let view = mail::projection_view(&views.mail.reader, &views.mail.facts, id)?;
        if view.subject.to_lowercase().contains(&needle)
            || view.body.to_lowercase().contains(&needle)
        {
            println!(
                "{}  {}  {}",
                fmt_id(view.wire),
                view.from.unwrap_or_default(),
                view.subject
            );
        }
    }
    Ok(())
}

#[cfg(test)]
fn fragment_is_materialized(facts: &FactArchive, fragment: &Fragment) -> bool {
    fragment
        .facts()
        .iter()
        .all(|expected| facts.iter().any(|actual| &actual == expected))
}

fn publish_pop_publication_with<P>(
    publication: &mail::SourcePublication,
    scopes: Scopes,
    mut publish: P,
) -> Result<()>
where
    P: FnMut(Id, Fragment, &str) -> Result<()>,
{
    // Both fragments were constructed locally by typed APIs. Publish Files
    // before Mail so every referenced attachment blob is durable before the
    // source observation that names it. Replaying either intrinsic fragment
    // is harmless and needs no derived-id lookup against the current union.
    if !publication.files.facts().is_empty() {
        publish(
            scopes.files,
            publication.files.clone(),
            "mail: POP attachment evidence",
        )?;
    }

    publish(
        scopes.mail,
        publication.mail.clone(),
        "mail: POP source evidence and parser projection",
    )?;

    Ok(())
}

fn cmd_fetch(storage: &Storage<'_>) -> Result<()> {
    let views = storage.views()?;
    let mut enabled_anchors = Vec::new();
    for anchor in mail::account_anchors(&views.mail.facts) {
        let config_id = match mail::account_head(&views.mail.facts, anchor)? {
            Head::Unique(id) => id,
            Head::Missing => bail!("mail account {anchor:x} has no configuration"),
            Head::Forked(ids) => {
                bail!("mail account {anchor:x} has forked configuration heads: {ids:?}")
            }
        };
        if mail::account_config(&views.mail.facts, config_id)?.enabled {
            enabled_anchors.push(anchor);
        }
    }
    if enabled_anchors.is_empty() {
        return Ok(());
    }

    let mut accounts = Vec::new();
    for anchor in enabled_anchors {
        let account = mail::open_account(
            &views.mail.reader,
            &views.mail.facts,
            views.secrets.snapshot(),
            anchor,
            &storage.signer,
        )
        .with_context(|| format!("open POP account {anchor:x}"))?;
        accounts.push(account);
    }
    drop(views);

    for account in accounts {
        let (host, port) = endpoint(&account.pop_endpoint, "POP")?;
        let session =
            mail_pop::connect_implicit_tls(host, port, &account.username, &account.password)
                .with_context(|| format!("connect POP account {}", account.address))?;
        let mut fetched = 0usize;
        mail::drain_pop(session, account.anchor, account.config, |publication| {
            publish_pop_publication_with(
                publication,
                storage.scopes,
                |scope, fragment, description| storage.publish(scope, fragment, description),
            )?;
            fetched += 1;
            Ok(())
        })
        .with_context(|| {
            format!(
                "drain POP account {}; a QUIT failure after DELE is an uncertain remote deletion transaction",
                account.address
            )
        })?;
        println!("{}: fetched {fetched} message(s)", account.address);
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let storage = Storage::open(&cli.pile, cli.key.as_deref(), Scopes::FIXED)?;
    let result = match cli.command {
        Command::Account { command } => match command {
            AccountCommand::Set {
                account,
                address,
                display_name,
                pop_endpoint,
                smtp_endpoint,
                username,
                password,
                credential_version,
                vault,
                disabled,
            } => account_set(
                &storage,
                account,
                address,
                display_name,
                pop_endpoint,
                smtp_endpoint,
                username,
                password,
                credential_version,
                vault,
                disabled,
            ),
            AccountCommand::List => account_list(&storage),
        },
        Command::Fetch => cmd_fetch(&storage),
        Command::Draft(args) => cmd_draft(&storage, args),
        Command::Reply(args) => cmd_reply(&storage, args),
        Command::Send { draft } => cmd_send(&storage, &draft),
        Command::Outbox => cmd_outbox(&storage),
        Command::List { unread, spam } => cmd_list(&storage, unread, spam),
        Command::Read { message } => cmd_read(&storage, &message),
        Command::Show { message } => cmd_show(&storage, &message),
        Command::Search { query } => cmd_search(&storage, &query),
    };
    let close = storage.close();
    match (result, close) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing Mail pile also failed: {close_error:#}")))
        }
    }
}

// Short aliases keep declarative query clauses readable without recreating a
// second ontology in the binary.
use faculties::schemas::mail::{observation, projection};

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs::File;
    use std::rc::Rc;

    use faculties::storage::{initialize_signer, publish_fragment};
    use triblespace::core::repo::StoreSnapshot;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn scopes() -> Scopes {
        Scopes {
            mail: mail_schema::DEFAULT_SCOPE_ID,
            files: files_schema::DEFAULT_SCOPE_ID,
            decide: decide_schema::DEFAULT_SCOPE_ID,
            relations: relations_schema::DEFAULT_SCOPE_ID,
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
        account: Id,
        config: Id,
        credential: Id,
        secret_vault: Id,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("mail-cli.pile");
            let key = directory.path().join("mail-cli.key");
            File::create(&pile).unwrap();
            initialize_signer(&pile, Some(&key)).unwrap();

            let account = id(70);
            let signer = load_signer(&pile, Some(&key)).unwrap();
            let mut store = open_pile_strict(&pile).unwrap();
            let secret_vault = id(120);
            vaults::create_vault(
                &mut store,
                &signer,
                secret_vault,
                "mail-test",
                point_now().unwrap(),
            )
            .unwrap();
            let discovery = vaults::discover_local_vaults(&mut store, &signer).unwrap();
            let location = *discovery.location(secret_vault).unwrap();
            let credential_id = vaults::add_secret(
                &mut store,
                &signer,
                &location,
                discovery.snapshot(),
                &mailbox_secret_name(account),
                b"mailbox password",
                point_now().unwrap(),
            )
            .unwrap();
            drop(discovery);
            store.close().unwrap();
            let mut fragment = Fragment::empty();
            let (config_fragment, config) = mail::account_config_fragment(
                account,
                AccountConfigInput {
                    address: "me@example.test".into(),
                    display_name: "Me".into(),
                    pop_endpoint: "pop.example.test:995".into(),
                    smtp_endpoint: "smtp.example.test:465".into(),
                    username: "me@example.test".into(),
                    credential: credential_id,
                    enabled: true,
                    predecessors: Vec::new(),
                },
            )
            .unwrap();
            fragment += config_fragment;
            publish_fragment(&pile, Some(&key), mail_schema::DEFAULT_SCOPE_ID, fragment).unwrap();

            let fixture = Self {
                _directory: directory,
                pile,
                key,
                account,
                config,
                credential: credential_id,
                secret_vault,
            };
            let storage = fixture.storage();
            storage.views().unwrap();
            storage.close().unwrap();
            fixture
        }

        fn storage(&self) -> Storage<'_> {
            Storage::open(&self.pile, Some(&self.key), scopes()).unwrap()
        }
    }

    fn raw(message_id: &str) -> Vec<u8> {
        format!(
            "From: Sender <sender@example.test>\r\nTo: me@example.test\r\nMessage-ID: <{message_id}>\r\nDate: Sat, 8 Aug 2026 00:00:01 +0000\r\nSubject: Hello\r\nContent-Type: multipart/mixed; boundary=test\r\n\r\n--test\r\nContent-Type: text/plain\r\n\r\nbody\r\n--test\r\nContent-Type: application/octet-stream; name=note.bin\r\nContent-Disposition: attachment; filename=note.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAQID\r\n--test--\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn views_share_the_secrets_discovery_snapshot() {
        let fixture = Fixture::new();
        let storage = fixture.storage();

        // Leave one vault commit without its maintained representations. This
        // makes Secrets discovery advance the pile after the ordinary Mail
        // collections have been maintained and catches cross-watermark views.
        storage
            .add_secret(fixture.secret_vault, "snapshot-regression", b"new secret")
            .unwrap();

        let views = storage.views().unwrap();
        let secrets_snapshot = views.secrets.snapshot().store_snapshot();
        for reader in [
            &views.mail.reader,
            &views.files.reader,
            &views.decide.reader,
            &views.relations.reader,
        ] {
            assert!(reader.changes_since(secrets_snapshot).is_empty());
            assert!(secrets_snapshot.changes_since(reader).is_empty());
        }
    }

    #[test]
    fn account_config_update_reuses_exact_secret_without_opening_it() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let before = storage.views().unwrap();
        let secrets_before = vaults::secret_rows(
            before
                .secrets
                .snapshot()
                .vault(fixture.secret_vault)
                .unwrap()
                .facts(),
        );

        account_set(
            &storage,
            Some(format!("{:x}", fixture.account)),
            "me@example.test".into(),
            "Renamed".into(),
            "pop.example.test:995".into(),
            "smtp.example.test:465".into(),
            None,
            None,
            None,
            None,
            false,
        )
        .unwrap();

        let after = storage.views().unwrap();
        assert_eq!(
            vaults::secret_rows(
                after
                    .secrets
                    .snapshot()
                    .vault(fixture.secret_vault)
                    .unwrap()
                    .facts(),
            ),
            secrets_before
        );
        let head = match mail::account_head(&after.mail.facts, fixture.account).unwrap() {
            Head::Unique(id) => id,
            other => panic!("expected unique account head, got {other:?}"),
        };
        assert_ne!(head, fixture.config);
        assert_eq!(
            mail::account_config(&after.mail.facts, head)
                .unwrap()
                .credential,
            fixture.credential
        );
    }

    #[test]
    fn supplied_password_always_seals_a_fresh_version_before_mail() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let before = storage.views().unwrap();
        let versions_before = vaults::secret_rows(
            before
                .secrets
                .snapshot()
                .vault(fixture.secret_vault)
                .unwrap()
                .facts(),
        )
        .len();

        account_set(
            &storage,
            Some(format!("{:x}", fixture.account)),
            "me@example.test".into(),
            "Me".into(),
            "pop.example.test:995".into(),
            "smtp.example.test:465".into(),
            None,
            Some("mailbox password".into()),
            None,
            Some(fixture.secret_vault),
            false,
        )
        .unwrap();

        let after = storage.views().unwrap();
        assert_eq!(
            vaults::secret_rows(
                after
                    .secrets
                    .snapshot()
                    .vault(fixture.secret_vault)
                    .unwrap()
                    .facts(),
            )
            .len(),
            versions_before + 1
        );
        let head = match mail::account_head(&after.mail.facts, fixture.account).unwrap() {
            Head::Unique(id) => id,
            other => panic!("expected unique account head, got {other:?}"),
        };
        let credential = mail::account_config(&after.mail.facts, head)
            .unwrap()
            .credential;
        assert_ne!(credential, fixture.credential);
        assert_eq!(
            after.secrets.snapshot().lookup(credential).unwrap().0,
            fixture.secret_vault
        );
    }

    #[test]
    fn interrupted_secrets_first_update_has_an_exact_repair_path() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let credential = storage
            .add_secret(
                fixture.secret_vault,
                &mailbox_secret_name(fixture.account),
                b"replacement password",
            )
            .unwrap();
        let views = storage.views().unwrap();
        let versions = vaults::secret_rows(
            views
                .secrets
                .snapshot()
                .vault(fixture.secret_vault)
                .unwrap()
                .facts(),
        )
        .len();
        drop(views);

        account_set(
            &storage,
            Some(format!("{:x}", fixture.account)),
            "  me@example.test  ".into(),
            "  Me  ".into(),
            "  pop.example.test:995  ".into(),
            "  smtp.example.test:465  ".into(),
            None,
            None,
            Some(credential),
            None,
            false,
        )
        .unwrap();

        let after = storage.views().unwrap();
        assert_eq!(
            vaults::secret_rows(
                after
                    .secrets
                    .snapshot()
                    .vault(fixture.secret_vault)
                    .unwrap()
                    .facts(),
            )
            .len(),
            versions
        );
        let head = match mail::account_head(&after.mail.facts, fixture.account).unwrap() {
            Head::Unique(id) => id,
            other => panic!("expected unique account head, got {other:?}"),
        };
        assert_eq!(
            mail::account_config(&after.mail.facts, head)
                .unwrap()
                .credential,
            credential
        );
        let mail_after_first_repair = after.mail.facts.iter().collect::<Vec<_>>();
        drop(after);
        account_set(
            &storage,
            Some(format!("{:x}", fixture.account)),
            "  me@example.test  ".into(),
            "  Me  ".into(),
            "  pop.example.test:995  ".into(),
            "  smtp.example.test:465  ".into(),
            None,
            None,
            Some(credential),
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            storage
                .views()
                .unwrap()
                .mail
                .facts
                .iter()
                .collect::<Vec<_>>(),
            mail_after_first_repair
        );
    }

    #[test]
    fn invalid_account_input_does_not_publish_the_staged_secret() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let views = storage.views().unwrap();
        let secrets_before = vaults::secret_rows(
            views
                .secrets
                .snapshot()
                .vault(fixture.secret_vault)
                .unwrap()
                .facts(),
        );
        drop(views);

        let error = account_set(
            &storage,
            Some(format!("{:x}", fixture.account)),
            "   ".into(),
            "Me".into(),
            "pop.example.test:995".into(),
            "smtp.example.test:465".into(),
            None,
            Some("replacement password".into()),
            None,
            Some(fixture.secret_vault),
            false,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("account address"));
        let after = storage.views().unwrap();
        assert_eq!(
            vaults::secret_rows(
                after
                    .secrets
                    .snapshot()
                    .vault(fixture.secret_vault)
                    .unwrap()
                    .facts(),
            ),
            secrets_before
        );
    }

    #[test]
    fn new_account_requires_an_explicit_vault_epoch() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let error = account_set(
            &storage,
            None,
            "other@example.test".into(),
            "Other".into(),
            "pop.example.test:995".into(),
            "smtp.example.test:465".into(),
            None,
            Some("new password".into()),
            None,
            None,
            false,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("--vault is required"));

        account_set(
            &storage,
            None,
            "other@example.test".into(),
            "Other".into(),
            "pop.example.test:995".into(),
            "smtp.example.test:465".into(),
            None,
            Some("new password".into()),
            None,
            Some(fixture.secret_vault),
            false,
        )
        .unwrap();
        assert_eq!(
            mail::account_anchors(&storage.views().unwrap().mail.facts).len(),
            2
        );
        let views = storage.views().unwrap();
        assert_eq!(
            resolve_account(&views, "me@example.test").unwrap(),
            fixture.account
        );
        assert_ne!(
            resolve_account(&views, "other@example.test").unwrap(),
            fixture.account
        );
    }

    #[test]
    fn fetch_skips_disabled_accounts_before_credential_open() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        account_set(
            &storage,
            Some(format!("{:x}", fixture.account)),
            "me@example.test".into(),
            "Me".into(),
            "pop.example.test:995".into(),
            "smtp.example.test:465".into(),
            None,
            None,
            None,
            None,
            true,
        )
        .unwrap();

        // Disabled accounts do not participate in the all-enabled credential
        // opening preflight.
        cmd_fetch(&storage).unwrap();
    }

    #[test]
    fn cli_rejects_legacy_secret_identity_and_scope_surface() {
        assert!(Cli::try_parse_from([
            "mail",
            "--pile",
            "/tmp/not-opened-mail-test.pile",
            "--secrets-identity",
            "operator",
            "account",
            "list",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "mail",
            "--pile",
            "/tmp/not-opened-mail-test.pile",
            "account",
            "set",
            "--address",
            "me@example.test",
            "--display-name",
            "Me",
            "--pop-endpoint",
            "pop.example.test:995",
            "--smtp-endpoint",
            "smtp.example.test:465",
            "--password",
            "secret",
            "--secret-scope",
            "mail-test",
        ])
        .is_err());
    }

    #[test]
    fn cli_password_requires_one_exact_vault_epoch() {
        let without_vault = [
            "mail",
            "--pile",
            "/tmp/not-opened-mail-test.pile",
            "account",
            "set",
            "--address",
            "me@example.test",
            "--display-name",
            "Me",
            "--pop-endpoint",
            "pop.example.test:995",
            "--smtp-endpoint",
            "smtp.example.test:465",
            "--password",
            "secret",
        ];
        assert!(Cli::try_parse_from(without_vault).is_err());

        let mut with_vault = without_vault.to_vec();
        with_vault.extend(["--vault", "78787878787878787878787878787878"]);
        assert!(Cli::try_parse_from(with_vault).is_ok());

        let mut malformed = without_vault.to_vec();
        malformed.extend(["--vault", "mail-test"]);
        assert!(Cli::try_parse_from(malformed).is_err());
    }

    #[test]
    fn disabled_send_refuses_before_credential_access() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        cmd_draft(
            &storage,
            DraftArgs {
                account: format!("{:x}", fixture.account),
                to: vec!["recipient@example.test".into()],
                cc: Vec::new(),
                bcc: Vec::new(),
                subject: "Disabled account".into(),
                body: "must not send".into(),
                attach: Vec::new(),
            },
        )
        .unwrap();
        let views = storage.views().unwrap();
        let drafts: Vec<Id> = find!(
            draft: Id,
            pattern!(&views.mail.facts, [{ ?draft @ metadata::tag: &mail_schema::KIND_DRAFT_INTENT }])
        )
        .collect();
        assert_eq!(drafts.len(), 1);
        drop(views);

        account_set(
            &storage,
            Some(format!("{:x}", fixture.account)),
            "me@example.test".into(),
            "Me".into(),
            "pop.example.test:995".into(),
            "smtp.example.test:465".into(),
            None,
            None,
            None,
            None,
            true,
        )
        .unwrap();
        let error = cmd_send(&storage, &format!("{:x}", drafts[0])).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("disabled"), "{message}");
        assert!(!message.contains("open secret"), "{message}");
    }

    #[derive(Default)]
    struct PopState {
        events: Vec<String>,
        marked: Vec<u32>,
        committed: Vec<u32>,
    }

    struct FakePop {
        state: Rc<RefCell<PopState>>,
        items: Vec<mail::PopItem>,
        messages: HashMap<u32, Vec<u8>>,
        fail_dele: Option<u32>,
        fail_quit: bool,
        quit: bool,
    }

    impl Drop for FakePop {
        fn drop(&mut self) {
            if !self.quit {
                self.state.borrow_mut().events.push("disconnect".into());
            }
        }
    }

    impl mail::PopTxn for FakePop {
        fn enumerate_uidls(&mut self) -> Result<Vec<mail::PopItem>> {
            self.state.borrow_mut().events.push("uidl".into());
            Ok(self.items.clone())
        }

        fn retrieve_exact(&mut self, session_seq: u32) -> Result<Vec<u8>> {
            self.state
                .borrow_mut()
                .events
                .push(format!("retr:{session_seq}"));
            self.messages
                .get(&session_seq)
                .cloned()
                .ok_or_else(|| anyhow!("missing scripted message {session_seq}"))
        }

        fn mark_delete(&mut self, session_seq: u32) -> Result<()> {
            self.state
                .borrow_mut()
                .events
                .push(format!("dele:{session_seq}"));
            if self.fail_dele == Some(session_seq) {
                bail!("scripted DELE rejection");
            }
            self.state.borrow_mut().marked.push(session_seq);
            Ok(())
        }

        fn quit(mut self) -> Result<()> {
            self.state.borrow_mut().events.push("quit".into());
            if self.fail_quit {
                bail!("scripted lost QUIT reply");
            }
            let marked = self.state.borrow().marked.clone();
            self.state.borrow_mut().committed = marked;
            self.quit = true;
            Ok(())
        }
    }

    fn fake_pop(state: Rc<RefCell<PopState>>, messages: Vec<(u32, &str, Vec<u8>)>) -> FakePop {
        FakePop {
            state,
            items: messages
                .iter()
                .map(|(sequence, uidl, _)| mail::PopItem {
                    session_seq: *sequence,
                    uidl: (*uidl).to_owned(),
                })
                .collect(),
            messages: messages
                .into_iter()
                .map(|(sequence, _, raw)| (sequence, raw))
                .collect(),
            fail_dele: None,
            fail_quit: false,
            quit: false,
        }
    }

    fn publish_recording(
        storage: &Storage<'_>,
        state: &Rc<RefCell<PopState>>,
        publication: &mail::SourcePublication,
        fail_scope: Option<Id>,
    ) -> Result<()> {
        publish_pop_publication_with(
            publication,
            storage.scopes,
            |scope, fragment, description| {
                let label = if scope == storage.scopes.files {
                    "files"
                } else if scope == storage.scopes.mail {
                    "mail"
                } else {
                    "unexpected-scope"
                };
                state.borrow_mut().events.push(label.into());
                if fail_scope == Some(scope) {
                    bail!("scripted {label} publication failure");
                }
                storage.publish(scope, fragment, description)
            },
        )
    }

    #[test]
    fn reply_to_digest_only_wire_omits_remote_thread_headers() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let publication = mail::pop_publication(
            fixture.account,
            fixture.config,
            "no-message-id",
            b"From: Sender <sender@example.test>\r\nTo: me@example.test\r\nSubject: No remote identity\r\n\r\nbody",
        )
        .unwrap();
        let wire = publication.wire;
        publish_pop_publication_with(
            &publication,
            storage.scopes,
            |scope, fragment, description| storage.publish(scope, fragment, description),
        )
        .unwrap();

        cmd_reply(
            &storage,
            ReplyArgs {
                message: format!("{wire:x}"),
                account: format!("{:x}", fixture.account),
                body: "reply without invented Message-ID".into(),
            },
        )
        .unwrap();

        let views = storage.views().unwrap();
        let drafts: Vec<Id> = find!(
            draft: Id,
            pattern!(&views.mail.facts, [{ ?draft @ metadata::tag: &mail_schema::KIND_DRAFT_INTENT }])
        )
        .collect();
        assert_eq!(drafts.len(), 1);
        let draft = mail::draft_value(&views.mail.facts, drafts[0]).unwrap();
        assert!(draft.in_reply_to.is_empty());
        assert!(draft.references.is_empty());
    }

    #[test]
    fn pop_composition_is_files_then_mail_then_dele_then_quit() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let bytes = raw("ordered@example.test");
        let expected =
            mail::pop_publication(fixture.account, fixture.config, "uid-1", &bytes).unwrap();
        let state = Rc::new(RefCell::new(PopState::default()));
        let transaction = fake_pop(state.clone(), vec![(1, "uid-1", bytes)]);

        mail::drain_pop(
            transaction,
            fixture.account,
            fixture.config,
            |publication| publish_recording(&storage, &state, publication, None),
        )
        .unwrap();

        assert_eq!(
            state.borrow().events,
            ["uidl", "retr:1", "files", "mail", "dele:1", "quit"]
        );
        assert_eq!(state.borrow().committed, [1]);
        let views = storage.views().unwrap();
        assert!(fragment_is_materialized(
            &views.files.facts,
            &expected.files
        ));
        assert!(fragment_is_materialized(&views.mail.facts, &expected.mail));
    }

    #[test]
    fn pop_publication_failures_prevent_dele_and_retry_reuses_durable_files() {
        let fixture = Fixture::new();
        let storage = fixture.storage();

        let state = Rc::new(RefCell::new(PopState::default()));
        let bytes = raw("files-fail@example.test");
        let transaction = fake_pop(state.clone(), vec![(1, "uid-files", bytes)]);
        assert!(mail::drain_pop(
            transaction,
            fixture.account,
            fixture.config,
            |publication| {
                publish_recording(&storage, &state, publication, Some(storage.scopes.files))
            }
        )
        .is_err());
        assert_eq!(
            state.borrow().events,
            ["uidl", "retr:1", "files", "disconnect"]
        );

        let bytes = raw("mail-fail@example.test");
        let expected =
            mail::pop_publication(fixture.account, fixture.config, "uid-mail", &bytes).unwrap();
        let state = Rc::new(RefCell::new(PopState::default()));
        let transaction = fake_pop(state.clone(), vec![(2, "uid-mail", bytes.clone())]);
        assert!(mail::drain_pop(
            transaction,
            fixture.account,
            fixture.config,
            |publication| {
                publish_recording(&storage, &state, publication, Some(storage.scopes.mail))
            }
        )
        .is_err());
        assert_eq!(
            state.borrow().events,
            ["uidl", "retr:2", "files", "mail", "disconnect"]
        );
        let views = storage.views().unwrap();
        assert!(fragment_is_materialized(
            &views.files.facts,
            &expected.files
        ));
        assert!(!fragment_is_materialized(&views.mail.facts, &expected.mail));

        let state = Rc::new(RefCell::new(PopState::default()));
        let transaction = fake_pop(state.clone(), vec![(2, "uid-mail", bytes)]);
        mail::drain_pop(
            transaction,
            fixture.account,
            fixture.config,
            |publication| publish_recording(&storage, &state, publication, None),
        )
        .unwrap();
        assert_eq!(
            state.borrow().events,
            ["uidl", "retr:2", "files", "mail", "dele:2", "quit"]
        );
        assert_eq!(state.borrow().committed, [2]);
    }

    #[test]
    fn dele_and_quit_failures_leave_durable_mail_without_claiming_rollback() {
        for fail_quit in [false, true] {
            let fixture = Fixture::new();
            let storage = fixture.storage();
            let bytes = raw(if fail_quit {
                "quit-fail@example.test"
            } else {
                "dele-fail@example.test"
            });
            let uidl = if fail_quit { "uid-quit" } else { "uid-dele" };
            let expected =
                mail::pop_publication(fixture.account, fixture.config, uidl, &bytes).unwrap();
            let state = Rc::new(RefCell::new(PopState::default()));
            let mut transaction = fake_pop(state.clone(), vec![(1, uidl, bytes)]);
            transaction.fail_dele = (!fail_quit).then_some(1);
            transaction.fail_quit = fail_quit;
            let error = mail::drain_pop(
                transaction,
                fixture.account,
                fixture.config,
                |publication| publish_recording(&storage, &state, publication, None),
            )
            .unwrap_err();
            let views = storage.views().unwrap();
            assert!(fragment_is_materialized(&views.mail.facts, &expected.mail));
            assert!(state.borrow().committed.is_empty());
            if fail_quit {
                assert!(format!("{error:#}").contains("uncertain"));
                assert_eq!(
                    state.borrow().events,
                    [
                        "uidl",
                        "retr:1",
                        "files",
                        "mail",
                        "dele:1",
                        "quit",
                        "disconnect"
                    ]
                );
            } else {
                assert_eq!(
                    state.borrow().events,
                    ["uidl", "retr:1", "files", "mail", "dele:1", "disconnect"]
                );
            }
        }
    }

    #[test]
    fn empty_maildrop_quits_and_late_failure_commits_no_earlier_delete() {
        let state = Rc::new(RefCell::new(PopState::default()));
        mail::drain_pop(
            fake_pop(state.clone(), Vec::new()),
            id(72),
            id(73),
            |_| unreachable!(),
        )
        .unwrap();
        assert_eq!(state.borrow().events, ["uidl", "quit"]);

        let fixture = Fixture::new();
        let storage = fixture.storage();
        let state = Rc::new(RefCell::new(PopState::default()));
        let transaction = fake_pop(
            state.clone(),
            vec![
                (1, "uid-first", raw("first@example.test")),
                (2, "uid-second", raw("second@example.test")),
            ],
        );
        let mut seen = 0usize;
        let error = mail::drain_pop(
            transaction,
            fixture.account,
            fixture.config,
            |publication| {
                seen += 1;
                if seen == 2 {
                    state.borrow_mut().events.push("publish-2-failed".into());
                    bail!("scripted second-message failure");
                }
                publish_recording(&storage, &state, publication, None)
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("second-message"));
        assert_eq!(state.borrow().marked, [1]);
        assert!(state.borrow().committed.is_empty());
        assert_eq!(
            state.borrow().events,
            [
                "uidl",
                "retr:1",
                "files",
                "mail",
                "dele:1",
                "retr:2",
                "publish-2-failed",
                "disconnect"
            ]
        );
    }
}
