//! `mail` — collection-native RFC 5322 evidence, intent, and receipt faculty.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use faculties::collection_access::{self, CollectionSnapshot, CollectionView};
use faculties::decide;
use faculties::files;
use faculties::mail::{self, AccountConfigInput, DraftInput, Head, SendAttemptInput};
use faculties::mail_pop;
use faculties::relations;
use faculties::schemas::{
    decide as decide_schema, files as files_schema, mail as mail_schema,
    relations as relations_schema,
};
use hifitime::Epoch;
use lettre::address::{Address as SmtpAddress, Envelope as LettreEnvelope};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use triblespace::core::metadata;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(version = faculties::GIT_VERSION, name = "mail", about = "Immutable email evidence, drafts, and delivery receipts")]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable collection signer. Ordinary commands never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[arg(long, value_parser = parse_id)]
    mail_scope: Option<Id>,
    #[arg(long, value_parser = parse_id)]
    files_scope: Option<Id>,
    #[arg(long, value_parser = parse_id)]
    decide_scope: Option<Id>,
    #[arg(long, value_parser = parse_id)]
    relations_scope: Option<Id>,
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
    /// Submit one authorized draft exactly once.
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
        #[arg(long, env = "MAIL_PASS", hide_env_values = true)]
        password: Option<String>,
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

struct Views {
    mail: CollectionView,
    files: CollectionView,
    decide: CollectionView,
    relations: CollectionView,
}

struct Storage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    scopes: Scopes,
}

impl Storage<'_> {
    fn views(&self) -> Result<Views> {
        let signer = collection_access::load_signer(self.pile, self.key)?;
        let allowed = HashSet::from([signer.verifying_key()]);
        let snapshot = CollectionSnapshot::open(self.pile)?;
        let views = Views {
            mail: snapshot.materialize_scope(self.scopes.mail, &allowed)?,
            files: snapshot.materialize_scope(self.scopes.files, &allowed)?,
            decide: snapshot.materialize_scope(self.scopes.decide, &allowed)?,
            relations: snapshot.materialize_scope(self.scopes.relations, &allowed)?,
        };
        files::validate_catalog(&views.files.reader, &views.files.facts)
            .context("validate Files collection")?;
        decide::validate_catalog(&views.decide.reader, &views.decide.facts)
            .context("validate Decide collection")?;
        relations::validate_catalog(&views.relations.reader, &views.relations.facts)
            .context("validate Relations collection")?;
        mail::validate_catalog(
            &views.mail.reader,
            &views.mail.facts,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
        )
        .context("validate Mail collection")?;
        Ok(views)
    }

    fn publish(&self, scope: Id, fragment: Fragment, description: &str) -> Result<()> {
        let mut metadata_fragment = Fragment::empty();
        let description = metadata_fragment.put(description.to_owned());
        metadata_fragment += entity! { metadata::description: description };
        collection_access::publish_fragment(
            self.pile,
            self.key,
            scope,
            fragment,
            metadata_fragment,
        )?;
        Ok(())
    }
}

fn parse_id(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id {raw:?}"))
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn point_now() -> Result<mail::IntervalValue> {
    let now = Epoch::now().map_err(|error| anyhow!("read current clock: {error:?}"))?;
    (now, now)
        .try_to_inline()
        .map_err(|error| anyhow!("encode current clock: {error:?}"))
}

fn passphrase() -> Result<Vec<u8>> {
    let value = std::env::var("FACULTIES_SECRETS_PW")
        .context("FACULTIES_SECRETS_PW is required to unlock mail credentials")?;
    if value.is_empty() {
        bail!("FACULTIES_SECRETS_PW is empty");
    }
    Ok(value.into_bytes())
}

fn persona(views: &Views) -> Result<Id> {
    let raw =
        std::env::var("PERSONA").context("PERSONA must select one active Relations person")?;
    relations::resolve_person(&views.relations.reader, &views.relations.facts, &raw, false)?
        .require_unique("active Relations person", &raw)
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

fn resolve_draft(facts: &TribleSet, input: &str) -> Result<Id> {
    let candidates: BTreeSet<Id> = find!(
        id: Id,
        pattern!(facts, [{ ?id @ metadata::tag: &mail_schema::KIND_DRAFT_INTENT }])
    )
    .collect();
    faculties::resolve_id_prefix(input, candidates)
}

fn wire_candidates(facts: &TribleSet) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: &mail_schema::KIND_WIRE_MESSAGE }]))
        .collect()
}

fn resolve_wire(facts: &TribleSet, input: &str) -> Result<Id> {
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
    disabled: bool,
) -> Result<()> {
    let views = storage.views()?;
    let master = passphrase()?;
    let (anchor, predecessors, old_credential, old_secret, replacing_fork) =
        if let Some(selector) = account_selector {
            let anchor = resolve_account(&views, &selector)?;
            match mail::account_head(&views.mail.facts, anchor)? {
                Head::Unique(head) => {
                    let config = mail::account_config(&views.mail.facts, head)?;
                    let opened =
                        mail::open_account(&views.mail.reader, &views.mail.facts, anchor, &master)?;
                    (
                        anchor,
                        vec![head],
                        Some(config.credential),
                        Some(opened.password),
                        false,
                    )
                }
                Head::Missing => bail!("account {anchor:x} has no configuration"),
                // A complete new snapshot can reconcile every observed branch,
                // but no branch may be selected as the credential donor.
                Head::Forked(heads) => (anchor, heads, None, None, true),
            }
        } else {
            (genid().id, Vec::new(), None, None, false)
        };

    let mut fragment = Fragment::empty();
    let credential_id = match (password, old_credential, old_secret) {
        (None, Some(id), _) => id,
        (None, None, _) if replacing_fork => {
            bail!("MAIL_PASS/--password is required to reconcile a forked account")
        }
        (None, None, _) => bail!("MAIL_PASS/--password is required for a new account"),
        (Some(value), Some(id), Some(old)) if value == old => id,
        (Some(value), _, _) => {
            let id = genid().id;
            fragment += mail::credential_fragment(id, &master, &value)?;
            id
        }
    };
    let (config_fragment, config_id) = mail::account_config_fragment(
        anchor,
        AccountConfigInput {
            address: address.clone(),
            display_name,
            pop_endpoint,
            smtp_endpoint,
            username: username.unwrap_or(address),
            credential: credential_id,
            enabled: !disabled,
            predecessors,
        },
    )?;
    fragment += config_fragment;
    mail::validate_catalog_union(
        &views.mail.reader,
        &views.mail.facts,
        &fragment,
        &views.files.facts,
        &views.decide.facts,
        &views.relations.facts,
    )?;
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
        let file = files::fragment(bytes, name, files::infer_media_type(path))?;
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
    let mut files_union = views.files.facts.clone();
    files_union += files_fragment.facts().clone();
    let decide_union =
        decide::validate_catalog_union(&views.decide.reader, &views.decide.facts, &draft.decide)?;
    mail::validate_catalog_union(
        &views.mail.reader,
        &views.mail.facts,
        &draft.mail,
        &files_union,
        &decide_union,
        &views.relations.facts,
    )?;
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
    references.push(wire_id);
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
        vec![wire_id],
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
    let master = passphrase()?;
    let account = mail::open_account(
        &views.mail.reader,
        &views.mail.facts,
        record.account,
        &master,
    )?;
    if !account.enabled {
        bail!("draft account {} is disabled", fmt_id(account.anchor));
    }
    let draft = mail::materialize_draft(
        &views.mail.reader,
        &views.mail.facts,
        &views.files.facts,
        draft_id,
    )?;
    let rendered = mail::render_draft(&draft, &account)?;
    let (decision, heads) =
        mail::authorized_send(&views.decide.reader, &views.decide.facts, draft_id)?;
    let (attempt_fragment, attempt_id) = mail::send_attempt_fragment(SendAttemptInput {
        draft: draft_id,
        config: account.config,
        decision,
        decision_heads: heads,
        raw: rendered.raw.clone(),
        envelope_from: draft.envelope_from.clone(),
        to: draft.to.clone(),
        cc: draft.cc.clone(),
        bcc: draft.bcc.clone(),
    })?;
    let outgoing = mail::outgoing_publication(attempt_id, &rendered.raw)?;
    let mut files_union = views.files.facts.clone();
    files_union += outgoing.files.facts().clone();
    mail::validate_catalog_union(
        &views.mail.reader,
        &views.mail.facts,
        &attempt_fragment,
        &files_union,
        &views.decide.facts,
        &views.relations.facts,
    )?;
    // Any Files evidence needed by the post-effect outgoing projection is
    // durable before SMTP. Most drafts reuse already-published file values.
    if !outgoing.files.facts().is_empty() {
        storage.publish(
            storage.scopes.files,
            outgoing.files.clone(),
            "mail: outgoing attachment evidence",
        )?;
    }
    let mut after_attempt = views.mail.facts.clone();
    after_attempt += attempt_fragment.facts().clone();
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
        &attempt_fragment,
        attempt_id,
        &outgoing,
        &rendered.envelope,
        &rendered.raw,
        |fragment| {
            storage.publish(
                storage.scopes.mail,
                fragment.clone(),
                "mail: send attempt before SMTP",
            )
        },
        |fragment| {
            mail::validate_catalog_union(
                &views.mail.reader,
                &after_attempt,
                fragment,
                &files_union,
                &views.decide.facts,
                &views.relations.facts,
            )?;
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
    let persona = persona(&views)?;
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
    let reader = persona(&views)?;
    let (fragment, id) = mail::read_observation_fragment(wire, reader);
    mail::validate_catalog_union(
        &views.mail.reader,
        &views.mail.facts,
        &fragment,
        &views.files.facts,
        &views.decide.facts,
        &views.relations.facts,
    )?;
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
        println!("Message-ID: {}", view.message_id);
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

fn fragment_is_materialized(facts: &TribleSet, fragment: &Fragment) -> bool {
    fragment.facts().iter().all(|fact| facts.contains(fact))
}

fn publish_pop_publication_with<V, P>(
    publication: &mail::SourcePublication,
    scopes: Scopes,
    mut materialize: V,
    mut publish: P,
) -> Result<()>
where
    V: FnMut() -> Result<Views>,
    P: FnMut(Id, Fragment, &str) -> Result<()>,
{
    // First prove the prospective cross-scope state while both fragments and
    // all of their attachment blobs are still available in memory.
    let before = materialize()?;
    let mut prospective_files = before.files.facts.clone();
    prospective_files += publication.files.facts().clone();
    mail::validate_catalog_union(
        &before.mail.reader,
        &before.mail.facts,
        &publication.mail,
        &prospective_files,
        &before.decide.facts,
        &before.relations.facts,
    )?;

    if !publication.files.facts().is_empty()
        && !fragment_is_materialized(&before.files.facts, &publication.files)
    {
        publish(
            scopes.files,
            publication.files.clone(),
            "mail: POP attachment evidence",
        )?;
    }

    // A PileReader is an immutable snapshot. Reopen after Files so exact
    // validation sees both its facts and newly appended attachment blobs.
    let after_files = materialize()?;
    if !fragment_is_materialized(&after_files.files.facts, &publication.files) {
        bail!("published POP attachment evidence did not materialize");
    }
    mail::validate_catalog_union(
        &after_files.mail.reader,
        &after_files.mail.facts,
        &publication.mail,
        &after_files.files.facts,
        &after_files.decide.facts,
        &after_files.relations.facts,
    )?;
    if fragment_is_materialized(&after_files.mail.facts, &publication.mail) {
        return Ok(());
    }
    publish(
        scopes.mail,
        publication.mail.clone(),
        "mail: POP source evidence and parser projection",
    )?;

    // Only a fully rematerialized, exactly validated Mail observation lets
    // drain_pop proceed to DELE.
    let after_mail = materialize()?;
    if !fragment_is_materialized(&after_mail.mail.facts, &publication.mail) {
        bail!("published POP mail evidence did not materialize");
    }
    Ok(())
}

fn cmd_fetch(storage: &Storage<'_>) -> Result<()> {
    let master = passphrase()?;
    let views = storage.views()?;
    let mut accounts = Vec::new();
    for anchor in mail::account_anchors(&views.mail.facts) {
        let account = mail::open_account(&views.mail.reader, &views.mail.facts, anchor, &master)
            .with_context(|| format!("open POP account {anchor:x}"))?;
        if account.enabled {
            accounts.push(account);
        }
    }
    drop(views);

    for account in accounts {
        let (host, port) = endpoint(&account.pop_endpoint, "POP")?;
        let session =
            mail_pop::connect_implicit_tls(host, port, &account.username, &account.password)
                .with_context(|| format!("connect POP account {}", account.address))?;
        let mut fetched = 0usize;
        mail::drain_pop(session, account.anchor, |publication| {
            publish_pop_publication_with(
                publication,
                storage.scopes,
                || storage.views(),
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
    let storage = Storage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
        scopes: Scopes {
            mail: cli.mail_scope.unwrap_or(mail_schema::DEFAULT_SCOPE_ID),
            files: cli.files_scope.unwrap_or(files_schema::DEFAULT_SCOPE_ID),
            decide: cli.decide_scope.unwrap_or(decide_schema::DEFAULT_SCOPE_ID),
            relations: cli
                .relations_scope
                .unwrap_or(relations_schema::DEFAULT_SCOPE_ID),
        },
    };
    match cli.command {
        Command::Account { command } => match command {
            AccountCommand::Set {
                account,
                address,
                display_name,
                pop_endpoint,
                smtp_endpoint,
                username,
                password,
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

    use faculties::schemas::mail::credential;

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
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("mail-cli.pile");
            let key = directory.path().join("mail-cli.key");
            File::create(&pile).unwrap();
            collection_access::initialize_signer(&pile, Some(&key)).unwrap();

            let account = id(70);
            let credential_id = id(71);
            let mut fragment = Fragment::empty();
            let box_handle: mail::BytesHandle = fragment.put(vec![0u8; 64]);
            fragment += entity! {
                ExclusiveId::force_ref(&credential_id) @
                metadata::tag: &mail_schema::KIND_CREDENTIAL
            };
            fragment += entity! {
                metadata::tag: &mail_schema::KIND_CREDENTIAL_ENVELOPE,
                credential::of: &credential_id,
                credential::r#box: box_handle,
            };
            fragment += mail::account_config_fragment(
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
            .unwrap()
            .0;
            collection_access::publish_fragment(
                &pile,
                Some(&key),
                mail_schema::DEFAULT_SCOPE_ID,
                fragment,
                Fragment::empty(),
            )
            .unwrap();

            let fixture = Self {
                _directory: directory,
                pile,
                key,
                account,
            };
            fixture.storage().views().unwrap();
            fixture
        }

        fn storage(&self) -> Storage<'_> {
            Storage {
                pile: &self.pile,
                key: Some(&self.key),
                scopes: scopes(),
            }
        }
    }

    fn raw(message_id: &str) -> Vec<u8> {
        format!(
            "From: Sender <sender@example.test>\r\nTo: me@example.test\r\nMessage-ID: <{message_id}>\r\nDate: Sat, 8 Aug 2026 00:00:01 +0000\r\nSubject: Hello\r\nContent-Type: multipart/mixed; boundary=test\r\n\r\n--test\r\nContent-Type: text/plain\r\n\r\nbody\r\n--test\r\nContent-Type: application/octet-stream; name=note.bin\r\nContent-Disposition: attachment; filename=note.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAQID\r\n--test--\r\n"
        )
        .into_bytes()
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
            || storage.views(),
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
    fn pop_composition_is_files_then_mail_then_dele_then_quit() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let bytes = raw("ordered@example.test");
        let expected = mail::pop_publication(fixture.account, "uid-1", &bytes).unwrap();
        let state = Rc::new(RefCell::new(PopState::default()));
        let transaction = fake_pop(state.clone(), vec![(1, "uid-1", bytes)]);

        mail::drain_pop(transaction, fixture.account, |publication| {
            publish_recording(&storage, &state, publication, None)
        })
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
        assert!(
            mail::drain_pop(transaction, fixture.account, |publication| {
                publish_recording(&storage, &state, publication, Some(storage.scopes.files))
            })
            .is_err()
        );
        assert_eq!(
            state.borrow().events,
            ["uidl", "retr:1", "files", "disconnect"]
        );

        let bytes = raw("mail-fail@example.test");
        let expected = mail::pop_publication(fixture.account, "uid-mail", &bytes).unwrap();
        let state = Rc::new(RefCell::new(PopState::default()));
        let transaction = fake_pop(state.clone(), vec![(2, "uid-mail", bytes.clone())]);
        assert!(
            mail::drain_pop(transaction, fixture.account, |publication| {
                publish_recording(&storage, &state, publication, Some(storage.scopes.mail))
            })
            .is_err()
        );
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
        mail::drain_pop(transaction, fixture.account, |publication| {
            publish_recording(&storage, &state, publication, None)
        })
        .unwrap();
        assert_eq!(
            state.borrow().events,
            ["uidl", "retr:2", "mail", "dele:2", "quit"]
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
            let expected = mail::pop_publication(fixture.account, uidl, &bytes).unwrap();
            let state = Rc::new(RefCell::new(PopState::default()));
            let mut transaction = fake_pop(state.clone(), vec![(1, uidl, bytes)]);
            transaction.fail_dele = (!fail_quit).then_some(1);
            transaction.fail_quit = fail_quit;
            let error = mail::drain_pop(transaction, fixture.account, |publication| {
                publish_recording(&storage, &state, publication, None)
            })
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
        let error = mail::drain_pop(transaction, fixture.account, |publication| {
            seen += 1;
            if seen == 2 {
                state.borrow_mut().events.push("publish-2-failed".into());
                bail!("scripted second-message failure");
            }
            publish_recording(&storage, &state, publication, None)
        })
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
