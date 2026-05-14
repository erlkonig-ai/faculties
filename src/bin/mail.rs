//! `mail` — RFC 5322 email faculty.
//!
//! POP3 fetch with delete-after-pile-commit semantics, SMTP submission
//! for send/reply, thread walks via `in_reply_to` + `references` graph
//! edges. Attachments land in the `files` faculty (content-addressed
//! dedup is automatic); senders auto-register in `relations` so the
//! social graph grows from incoming traffic.
//!
//! Identity: outgoing mail signs as `"Toby Trible" <toby@trible.space>`.
//!
//! Env vars:
//!   MAIL_USER       — full address (e.g. toby@trible.space)
//!   MAIL_PASS       — Migadu app-password or main password
//!   MAIL_FROM_NAME  — display name on outgoing From (default: Toby Trible)
//!   MAIL_POP3_HOST  — default pop.migadu.com
//!   MAIL_POP3_PORT  — default 995 (TLS)
//!   MAIL_SMTP_HOST  — default smtp.migadu.com
//!   MAIL_SMTP_PORT  — default 465 (TLS)

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Local, Utc};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use faculties::schemas::files::{file, KIND_FILE};
use faculties::schemas::local_messages::{local as read_attrs, KIND_READ_ID};
use faculties::schemas::mail::{mail, KIND_MESSAGE, KIND_SPAM};
use faculties::schemas::relations::{relations as rel_attrs, KIND_PERSON_ID};
use hifitime::Epoch;
use lettre::message::{Mailbox, header};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use rand_core::OsRng;
use rust_pop3_client::{Pop3Connection, Pop3ConnectionFactory};
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::*;

type IntervalValue = Value<valueschemas::NsTAIInterval>;
type TextHandle = Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>;
type FileHandle = Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::FileBytes>>;

const DEFAULT_FROM_NAME: &str = "Toby Trible";

// ── CLI ───────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "mail", about = "RFC 5322 email faculty")]
struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name for the mail state
    #[arg(long, default_value = "mail")]
    branch: String,
    /// Branch name for the files state (attachments land here)
    #[arg(long, default_value = "files")]
    files_branch: String,
    /// Branch name for relations (auto-registered senders)
    #[arg(long, default_value = "relations")]
    relations_branch: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch new messages from the POP3 server. Each retrieved message
    /// is decomposed into tribles, attachments land in the files
    /// branch, then the server-side message is deleted (atomically
    /// on QUIT — if anything fails before then, nothing is deleted).
    Fetch,
    /// Send a new email. Body may be `@path` or `@-` for stdin.
    Send {
        /// Comma-separated TO recipients.
        to: String,
        /// Subject line.
        subject: String,
        /// Body text. `@path` for file, `@-` for stdin.
        body: String,
        #[arg(long)]
        cc: Vec<String>,
        #[arg(long)]
        bcc: Vec<String>,
    },
    /// Reply to a message. Auto-fills In-Reply-To and References from
    /// the parent's headers.
    Reply {
        /// Full 32-char hex entity id of the message to reply to
        /// (use `mail show` to find one).
        message: String,
        /// Reply body. `@path` for file, `@-` for stdin.
        body: String,
    },
    /// List messages overlapping the given window.
    List {
        /// Window start (ISO 8601 date or datetime).
        #[arg(long)]
        from: Option<String>,
        /// Window end (ISO 8601 date or datetime).
        #[arg(long)]
        to: Option<String>,
        /// Show only spam-tagged messages.
        #[arg(long)]
        spam: bool,
        /// Show everything (spam + ham).
        #[arg(long)]
        all: bool,
        /// Show only unread messages (no read-receipt by us).
        #[arg(long)]
        unread: bool,
    },
    /// Mark a message as read (a no-op if already marked).
    Read {
        /// Full 32-char hex entity id.
        message: String,
    },
    /// Messages received or sent today (local TZ).
    Today,
    /// Messages from the last 7 days (local TZ).
    Week,
    /// Walk the thread containing the given message — both up
    /// (ancestors via in_reply_to / references) and down (descendants
    /// that point at any of those).
    Thread {
        /// Full 32-char hex entity id of any message in the thread.
        message: String,
    },
    /// Show one message with all properties + attachments.
    Show {
        /// Full 32-char hex entity id.
        message: String,
    },
    /// Substring search over subject + body (case-insensitive).
    Search {
        /// Query string.
        query: String,
    },
    /// Resolve a hex prefix to a full 32-char message entity id.
    Resolve { prefix: String },
}

// ── config ────────────────────────────────────────────────────────────────

struct MailConfig {
    user: String,
    pass: String,
    from_name: String,
    pop3_host: String,
    pop3_port: u16,
    smtp_host: String,
    smtp_port: u16,
}

fn load_config() -> Result<MailConfig> {
    let user = std::env::var("MAIL_USER")
        .context("MAIL_USER not set (e.g. toby@trible.space)")?;
    let pass = std::env::var("MAIL_PASS").context("MAIL_PASS not set")?;
    let from_name = std::env::var("MAIL_FROM_NAME").unwrap_or_else(|_| DEFAULT_FROM_NAME.into());
    let pop3_host = std::env::var("MAIL_POP3_HOST").unwrap_or_else(|_| "pop.migadu.com".into());
    let pop3_port = std::env::var("MAIL_POP3_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(995);
    let smtp_host = std::env::var("MAIL_SMTP_HOST").unwrap_or_else(|_| "smtp.migadu.com".into());
    let smtp_port = std::env::var("MAIL_SMTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(465);
    Ok(MailConfig {
        user,
        pass,
        from_name,
        pop3_host,
        pop3_port,
        smtp_host,
        smtp_port,
    })
}

// ── helpers ───────────────────────────────────────────────────────────────

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_to_chrono_utc(e: Epoch) -> DateTime<Utc> {
    let secs = e.to_unix_seconds();
    DateTime::from_timestamp(secs as i64, ((secs.fract() * 1e9) as u32).min(999_999_999))
        .unwrap_or_else(Utc::now)
}

fn chrono_to_epoch(dt: DateTime<Utc>) -> Epoch {
    Epoch::from_unix_seconds(dt.timestamp() as f64 + dt.timestamp_subsec_nanos() as f64 * 1e-9)
}

fn instant_interval(at: Epoch) -> IntervalValue {
    (at, at).try_to_value().unwrap()
}

fn make_interval(start: Epoch, end: Epoch) -> IntervalValue {
    (start, end).try_to_value().unwrap()
}

fn unpack_interval(iv: IntervalValue) -> (Epoch, Epoch) {
    iv.try_from_value().unwrap()
}

/// Deterministic entity id derived from a Message-Id string.
/// Same Message-Id always produces the same Id; cross-references
/// (in_reply_to, references) point at predicted ids even when
/// the referenced message isn't in our pile yet.
fn entity_id_for_message(message_id: &str) -> Id {
    let hash = blake3::hash(message_id.trim().as_bytes());
    let bytes: [u8; 16] = hash.as_bytes()[..16].try_into().unwrap();
    Id::new(bytes).expect("blake3 output is non-zero")
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn parse_full_id(input: &str) -> Result<Id> {
    Id::from_hex(input.trim())
        .ok_or_else(|| anyhow::anyhow!("invalid id '{}': expected 32-char hex", input.trim()))
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

fn parse_iso8601(input: &str) -> Result<DateTime<Utc>> {
    let trimmed = input.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S") {
        return Ok(Utc.from_utc_datetime(&naive));
    }
    if let Ok(date) = chrono::NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let naive = date.and_hms_opt(0, 0, 0).unwrap();
        return Ok(Utc.from_utc_datetime(&naive));
    }
    bail!("could not parse '{}' as ISO 8601", trimmed)
}

// chrono TimeZone re-export for the parse helper above.
use chrono::TimeZone;

fn open_repo(path: &Path) -> Result<Repository<Pile<valueschemas::Blake3>>> {
    let mut pile = Pile::<valueschemas::Blake3>::open(path)
        .map_err(|e| anyhow::anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        let _ = pile.close();
        return Err(anyhow::anyhow!("restore pile {}: {err:?}", path.display()));
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))
}

fn with_repo<T>(
    pile: &Path,
    f: impl FnOnce(&mut Repository<Pile<valueschemas::Blake3>>) -> Result<T>,
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

fn read_text(ws: &mut Workspace<Pile<valueschemas::Blake3>>, h: TextHandle) -> Option<String> {
    ws.get::<View<str>, blobschemas::LongString>(h)
        .ok()
        .map(|view| view.to_string())
}

fn read_bytes(ws: &mut Workspace<Pile<valueschemas::Blake3>>, h: FileHandle) -> Option<Vec<u8>> {
    let blob: Blob<blobschemas::FileBytes> = ws.get(h).ok()?;
    Some(blob.bytes.to_vec())
}

// ── read tracking ─────────────────────────────────────────────────────────
//
// Re-uses the KIND_READ_ID + about_message/reader/read_at schema from
// `local_messages` — those attributes are generic message-read-receipt
// shapes (the module name is historical from the faculty that
// introduced them; the IDs themselves are cross-faculty).

/// Find a relations entry whose `email` attribute matches the
/// provided address (case-folded). Used to resolve "the local
/// agent's identity" — i.e. who we are when marking messages read.
fn find_self_persona(relations_space: &TribleSet, email: &str) -> Option<Id> {
    let needle = email.trim().to_ascii_lowercase();
    find!(
        (id: Id, e: String),
        pattern!(relations_space, [{
            ?id @
                metadata::tag: (KIND_PERSON_ID),
                rel_attrs::email: ?e,
        }])
    )
    .find_map(|(id, e)| {
        if e.to_ascii_lowercase() == needle {
            Some(id)
        } else {
            None
        }
    })
}

/// Returns true if `reader_id` has marked `message_id` as read.
fn is_read(mail_space: &TribleSet, message_id: Id, reader_id: Id) -> bool {
    find!(
        r: Id,
        pattern!(mail_space, [{
            ?r @
                metadata::tag: (KIND_READ_ID),
                read_attrs::about_message: (message_id),
                read_attrs::reader: (reader_id),
        }])
    )
    .next()
    .is_some()
}

/// Mint a read-receipt entity if one doesn't already exist for
/// `(message_id, reader_id)`. Idempotent.
fn mark_read_if_unread(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    mail_branch_id: Id,
    message_id: Id,
    reader_id: Id,
) -> Result<bool> {
    let mut ws = repo
        .pull(mail_branch_id)
        .map_err(|e| anyhow::anyhow!("pull mail: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    if is_read(&space, message_id, reader_id) {
        return Ok(false);
    }
    let read_id = ufoid();
    let now = instant_interval(now_epoch());
    let mut change = TribleSet::new();
    change += entity! { &read_id @
        metadata::tag: &KIND_READ_ID,
        metadata::created_at: now,
        read_attrs::about_message: &message_id,
        read_attrs::reader: &reader_id,
        read_attrs::read_at: now,
    };
    ws.commit(change, "mail: mark read");
    repo.push(&mut ws)
        .map_err(|e| anyhow::anyhow!("push read receipt: {e:?}"))?;
    Ok(true)
}

// ── address handling ──────────────────────────────────────────────────────

/// (display_name, email) pair parsed from RFC 5322 address forms like
/// `"Alice" <alice@example.com>` or just `alice@example.com`.
#[derive(Debug, Clone)]
struct Address {
    name: Option<String>,
    email: String,
}

fn parse_address(input: &str) -> Result<Address> {
    let trimmed = input.trim();
    // Use mailparse's address parser (handles RFC 5322 quoting/encoding).
    let addrs = mailparse::addrparse(trimmed)
        .with_context(|| format!("parse address '{}'", trimmed))?;
    let first = addrs
        .iter()
        .find_map(|a| match a {
            mailparse::MailAddr::Single(s) => Some(s),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("no address in '{}'", trimmed))?;
    Ok(Address {
        name: first.display_name.clone(),
        email: first.addr.clone(),
    })
}

fn parse_address_list(input: &str) -> Result<Vec<Address>> {
    let mut out = Vec::new();
    let addrs = mailparse::addrparse(input.trim())
        .with_context(|| format!("parse address list '{}'", input.trim()))?;
    for a in addrs.iter() {
        if let mailparse::MailAddr::Single(s) = a {
            out.push(Address {
                name: s.display_name.clone(),
                email: s.addr.clone(),
            });
        }
    }
    Ok(out)
}

/// Look up an existing relations entry by email (case-folded). Returns
/// the entity id if found.
fn find_relation_by_email(space: &TribleSet, email: &str) -> Option<Id> {
    let needle = email.trim().to_ascii_lowercase();
    find!(
        (id: Id, e: String),
        pattern!(space, [{
            ?id @
                metadata::tag: (KIND_PERSON_ID),
                rel_attrs::email: ?e,
        }])
    )
    .find_map(|(id, e)| {
        if e.to_ascii_lowercase() == needle {
            Some(id)
        } else {
            None
        }
    })
}

/// Resolve an Address to a relations entity id. Mints a new entry
/// with the email (and display_name if known) tagged `KIND_PERSON_ID`
/// if no existing entry matches. New entries are deliberately
/// minimal — promotion to "verified" happens by manually editing the
/// relations entry (adding display_name, affinity, etc.).
fn resolve_or_register(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    space: &TribleSet,
    addr: &Address,
    change: &mut TribleSet,
) -> Option<Id> {
    let email = addr.email.trim();
    if email.is_empty() {
        return None;
    }
    if email.as_bytes().len() > 32 {
        eprintln!("[mail] skipping auto-register for over-long email '{email}'");
        return None;
    }
    if let Some(id) = find_relation_by_email(space, email) {
        return Some(id);
    }
    let new_id = ufoid();
    let new_ref = new_id.id;
    let now = instant_interval(now_epoch());
    let mut entity_change = TribleSet::new();
    entity_change += entity! { &new_id @
        metadata::tag: &KIND_PERSON_ID,
        metadata::created_at: now,
        rel_attrs::email: email,
    };
    if let Some(name) = addr.name.as_deref() {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            let handle = ws.put(trimmed.to_string());
            entity_change += entity! { &new_id @
                rel_attrs::display_name: handle,
            };
        }
    }
    *change += entity_change;
    Some(new_ref)
}

// ── kind entities ─────────────────────────────────────────────────────────

fn ensure_kind_entities(ws: &mut Workspace<Pile<valueschemas::Blake3>>) -> Result<TribleSet> {
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let existing: HashSet<Id> = find!(
        (kind: Id),
        pattern!(&space, [{ ?kind @ metadata::name: _?handle }])
    )
    .map(|(kind,)| kind)
    .collect();
    let mut change = TribleSet::new();
    let label = |id: Id| -> &'static str {
        if id == KIND_MESSAGE {
            "mail-message"
        } else {
            "mail-spam"
        }
    };
    for kind in [KIND_MESSAGE, KIND_SPAM] {
        if !existing.contains(&kind) {
            let name = ws.put(label(kind));
            change += entity! { ExclusiveId::force_ref(&kind) @
                metadata::name: name,
            };
        }
    }
    Ok(change)
}

// ── ingest: RFC 5322 → tribles ────────────────────────────────────────────

/// Decomposed view of an RFC 5322 message ready for trible-land.
struct ParsedMail {
    message_id: String,
    from: Option<Address>,
    to: Vec<Address>,
    cc: Vec<Address>,
    bcc: Vec<Address>,
    subject: String,
    body: String,
    sent_at: Epoch,
    in_reply_to: Vec<String>,
    references: Vec<String>,
    is_spam: bool,
    raw: Vec<u8>,
    attachments: Vec<Attachment>,
}

struct Attachment {
    filename: String,
    mime: String,
    bytes: Vec<u8>,
}

fn parse_message_id_list(field: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = field.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '<' {
            let mut id = String::new();
            for cc in chars.by_ref() {
                if cc == '>' {
                    break;
                }
                id.push(cc);
            }
            let trimmed = id.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
        }
    }
    out
}

fn parse_rfc5322(bytes: &[u8]) -> Result<ParsedMail> {
    let parsed = mailparse::parse_mail(bytes).context("parse RFC 5322")?;
    let headers = &parsed.headers;
    let get = |name: &str| -> Option<String> {
        headers
            .iter()
            .find(|h| h.get_key().eq_ignore_ascii_case(name))
            .map(|h| h.get_value())
    };

    let message_id_raw = get("Message-Id")
        .or_else(|| get("Message-ID"))
        .unwrap_or_default();
    let message_id = parse_message_id_list(&message_id_raw)
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            // Synthesize a stable id if the message arrived without one.
            // Hash the raw bytes so re-fetching the same message produces
            // the same synth-id (dedupable).
            let h = blake3::hash(bytes);
            format!("synth-{}@trible.space", hex::encode(&h.as_bytes()[..8]))
        });

    let from = get("From").and_then(|s| parse_address(&s).ok());
    let to = get("To").map(|s| parse_address_list(&s).unwrap_or_default()).unwrap_or_default();
    let cc = get("Cc").map(|s| parse_address_list(&s).unwrap_or_default()).unwrap_or_default();
    let bcc = get("Bcc").map(|s| parse_address_list(&s).unwrap_or_default()).unwrap_or_default();
    let subject = get("Subject").unwrap_or_default();

    let sent_at = get("Date")
        .and_then(|s| mailparse::dateparse(&s).ok())
        .map(|ts| Epoch::from_unix_seconds(ts as f64))
        .unwrap_or_else(now_epoch);

    let in_reply_to = get("In-Reply-To")
        .map(|s| parse_message_id_list(&s))
        .unwrap_or_default();
    let references = get("References")
        .map(|s| parse_message_id_list(&s))
        .unwrap_or_default();

    let is_spam = get("X-Spam-Status")
        .map(|s| s.trim_start().to_ascii_lowercase().starts_with("yes"))
        .unwrap_or(false);

    let (body, attachments) = extract_body_and_attachments(&parsed);

    Ok(ParsedMail {
        message_id,
        from,
        to,
        cc,
        bcc,
        subject,
        body,
        sent_at,
        in_reply_to,
        references,
        is_spam,
        raw: bytes.to_vec(),
        attachments,
    })
}

fn extract_body_and_attachments(part: &mailparse::ParsedMail) -> (String, Vec<Attachment>) {
    let mut body = String::new();
    let mut attachments = Vec::new();
    collect_parts(part, &mut body, &mut attachments);
    (body, attachments)
}

fn collect_parts(
    part: &mailparse::ParsedMail,
    body: &mut String,
    attachments: &mut Vec<Attachment>,
) {
    let ctype = part.ctype.mimetype.to_ascii_lowercase();
    let disposition = part.get_content_disposition();
    let is_attachment = matches!(
        disposition.disposition,
        mailparse::DispositionType::Attachment
    ) || disposition
        .params
        .get("filename")
        .map(|n| !n.is_empty())
        .unwrap_or(false);

    if ctype.starts_with("multipart/") {
        for sub in &part.subparts {
            collect_parts(sub, body, attachments);
        }
        return;
    }

    if is_attachment || (!ctype.starts_with("text/") && !part.subparts.is_empty() == false) {
        if !ctype.starts_with("text/") || is_attachment {
            let filename = disposition
                .params
                .get("filename")
                .cloned()
                .unwrap_or_else(|| {
                    part.ctype
                        .params
                        .get("name")
                        .cloned()
                        .unwrap_or_else(|| "attachment.bin".into())
                });
            if let Ok(bytes) = part.get_body_raw() {
                attachments.push(Attachment {
                    filename,
                    mime: ctype.clone(),
                    bytes,
                });
            }
            return;
        }
    }

    // Plain text part — prefer text/plain over text/html for body.
    if ctype == "text/plain" {
        if let Ok(text) = part.get_body() {
            if body.is_empty() {
                *body = text;
            }
        }
    } else if ctype == "text/html" && body.is_empty() {
        if let Ok(text) = part.get_body() {
            *body = text;
        }
    }
}

// ── fetch (POP3) ──────────────────────────────────────────────────────────

fn cmd_fetch(
    pile: &Path,
    mail_branch_id: Id,
    files_branch_id: Id,
    relations_branch_id: Id,
) -> Result<()> {
    let config = load_config()?;
    eprintln!(
        "Connecting to {}:{} as {}...",
        config.pop3_host, config.pop3_port, config.user
    );
    let mut connection: Box<dyn Pop3Connection> = Box::new(
        Pop3ConnectionFactory::new(&config.pop3_host, config.pop3_port)
            .map_err(|e| anyhow::anyhow!("connect pop3: {e}"))?,
    );
    connection
        .login(&config.user, &config.pass)
        .map_err(|e| anyhow::anyhow!("pop3 login: {e}"))?;
    let stat = connection
        .stat()
        .map_err(|e| anyhow::anyhow!("pop3 stat: {e}"))?;
    eprintln!(
        "{} messages on server ({} bytes total)",
        stat.message_count, stat.maildrop_size
    );
    if stat.message_count == 0 {
        return Ok(());
    }

    let infos = connection
        .list()
        .map_err(|e| anyhow::anyhow!("pop3 list: {e}"))?;

    // Two-phase: retrieve all messages, commit + push everything to
    // the pile, then issue DELE for each retrieved one, then QUIT.
    // QUIT is what atomically commits the deletions server-side; if
    // anything blows up before then, nothing is deleted and we re-
    // fetch next session (idempotent via entity-id-from-Message-Id).
    let mut retrieved: Vec<(u32, Vec<u8>)> = Vec::new();
    for info in &infos {
        let mut buf = Vec::new();
        connection
            .retrieve(info.message_id, &mut buf)
            .map_err(|e| anyhow::anyhow!("pop3 retrieve {}: {e}", info.message_id))?;
        retrieved.push((info.message_id, buf));
    }

    let mut ingested = 0usize;
    with_repo(pile, |repo| {
        for (_, bytes) in &retrieved {
            let parsed = match parse_rfc5322(bytes) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[mail] skipping unparseable message: {e:#}");
                    continue;
                }
            };
            ingest_message(repo, mail_branch_id, files_branch_id, relations_branch_id, parsed)?;
            ingested += 1;
        }
        Ok(())
    })?;

    eprintln!("Ingested {ingested} messages into the pile.");

    // Pile is durable; issue deletes.
    for (sid, _) in &retrieved {
        if let Err(e) = connection.delete(*sid) {
            eprintln!("[mail] delete server msg {sid}: {e}");
        }
    }
    // QUIT commits the deletions. The `Pop3Connection` doesn't expose
    // a QUIT method explicitly; dropping the connection sends QUIT in
    // this crate's implementation.
    drop(connection);
    eprintln!("Server deletes committed.");
    Ok(())
}

/// Decompose one parsed message + its attachments into tribles and
/// commit them across the three branches (relations, files, mail).
fn ingest_message(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    mail_branch_id: Id,
    files_branch_id: Id,
    relations_branch_id: Id,
    parsed: ParsedMail,
) -> Result<()> {
    // 1. relations branch: auto-register any new addresses.
    let mut from_id: Option<Id> = None;
    let mut to_ids: Vec<Id> = Vec::new();
    let mut cc_ids: Vec<Id> = Vec::new();
    let mut bcc_ids: Vec<Id> = Vec::new();
    {
        let mut ws = repo
            .pull(relations_branch_id)
            .map_err(|e| anyhow::anyhow!("pull relations: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;

        let mut change = TribleSet::new();
        if let Some(addr) = &parsed.from {
            from_id = resolve_or_register(&mut ws, &space, addr, &mut change);
        }
        for addr in &parsed.to {
            if let Some(id) = resolve_or_register(&mut ws, &space, addr, &mut change) {
                to_ids.push(id);
            }
        }
        for addr in &parsed.cc {
            if let Some(id) = resolve_or_register(&mut ws, &space, addr, &mut change) {
                cc_ids.push(id);
            }
        }
        for addr in &parsed.bcc {
            if let Some(id) = resolve_or_register(&mut ws, &space, addr, &mut change) {
                bcc_ids.push(id);
            }
        }
        if !change.is_empty() {
            ws.commit(change, "mail: register senders/recipients");
            repo.push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push relations: {e:?}"))?;
        }
    }

    // 2. files branch: store attachments.
    let mut attachment_ids: Vec<Id> = Vec::new();
    if !parsed.attachments.is_empty() {
        let mut ws = repo
            .pull(files_branch_id)
            .map_err(|e| anyhow::anyhow!("pull files: {e:?}"))?;

        let mut change = TribleSet::new();
        let now = instant_interval(now_epoch());
        let provenance = format!("mail:{}", parsed.message_id);
        for att in &parsed.attachments {
            let file_id = ufoid();
            let file_ref = file_id.id;
            let blob: Blob<blobschemas::FileBytes> = att.bytes.clone().to_blob();
            let content_handle: FileHandle = ws.put(blob);
            let name_handle: TextHandle = ws.put(att.filename.clone());
            let source_handle: TextHandle = ws.put(provenance.clone());
            let mime_short = if att.mime.as_bytes().len() <= 32 {
                att.mime.clone()
            } else {
                att.mime.chars().take(32).collect()
            };
            change += entity! { &file_id @
                metadata::tag: &KIND_FILE,
                metadata::created_at: now,
                file::content: content_handle,
                file::name: name_handle,
                file::mime: mime_short.as_str(),
                file::source_path: source_handle,
                file::tag: "mail-attachment",
            };
            attachment_ids.push(file_ref);
        }
        ws.commit(change, "mail: store attachments");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push files: {e:?}"))?;
    }

    // 3. mail branch: the message entity.
    {
        let mut ws = repo
            .pull(mail_branch_id)
            .map_err(|e| anyhow::anyhow!("pull mail: {e:?}"))?;
        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;

        let entity_id = entity_id_for_message(&parsed.message_id);
        let now = instant_interval(now_epoch());
        let sent_at_iv = instant_interval(parsed.sent_at);
        let subject_handle: TextHandle = ws.put(parsed.subject.clone());
        let body_handle: TextHandle = ws.put(parsed.body.clone());
        let message_id_handle: TextHandle = ws.put(parsed.message_id.clone());
        let raw_blob: Blob<blobschemas::FileBytes> = parsed.raw.clone().to_blob();
        let raw_handle: FileHandle = ws.put(raw_blob);

        let in_reply_ids: Vec<Id> = parsed
            .in_reply_to
            .iter()
            .map(|m| entity_id_for_message(m))
            .collect();
        let reference_ids: Vec<Id> = parsed
            .references
            .iter()
            .map(|m| entity_id_for_message(m))
            .collect();

        change += entity! { ExclusiveId::force_ref(&entity_id) @
            metadata::tag: &KIND_MESSAGE,
            metadata::created_at: now,
            mail::subject: subject_handle,
            mail::body: body_handle,
            mail::message_id: message_id_handle,
            mail::sent_at: sent_at_iv,
            mail::raw: raw_handle,
            mail::from?: from_id.as_ref(),
            mail::to*: to_ids.iter(),
            mail::cc*: cc_ids.iter(),
            mail::bcc*: bcc_ids.iter(),
            mail::in_reply_to*: in_reply_ids.iter(),
            mail::references*: reference_ids.iter(),
            mail::attachment*: attachment_ids.iter(),
        };
        if parsed.is_spam {
            change += entity! { ExclusiveId::force_ref(&entity_id) @
                metadata::tag: &KIND_SPAM,
            };
        }

        ws.commit(change, "mail: ingest message");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push mail: {e:?}"))?;
    }

    Ok(())
}

// ── send / reply ──────────────────────────────────────────────────────────

fn synthesize_message_id(local_part_seed: &str) -> String {
    let hash = blake3::hash(local_part_seed.as_bytes());
    format!("<{}-toby@trible.space>", hex::encode(&hash.as_bytes()[..12]))
}

fn cmd_send(
    pile: &Path,
    mail_branch_id: Id,
    files_branch_id: Id,
    relations_branch_id: Id,
    to: String,
    subject: String,
    body: String,
    cc: Vec<String>,
    bcc: Vec<String>,
) -> Result<()> {
    let body_text = load_value_or_file(&body, "body")?;
    let config = load_config()?;

    let to_addrs: Vec<Address> = to
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(parse_address)
        .collect::<Result<_>>()?;
    let cc_addrs: Vec<Address> = cc
        .into_iter()
        .map(|s| parse_address(&s))
        .collect::<Result<_>>()?;
    let bcc_addrs: Vec<Address> = bcc
        .into_iter()
        .map(|s| parse_address(&s))
        .collect::<Result<_>>()?;
    if to_addrs.is_empty() {
        bail!("no TO recipients");
    }

    let now = now_epoch();
    let seed = format!("{}:{}:{}", config.user, subject, now.to_tai_seconds());
    let message_id = synthesize_message_id(&seed);

    let from_mb: Mailbox = format!("{} <{}>", config.from_name, config.user)
        .parse()
        .context("parse from address")?;
    let mut builder = Message::builder()
        .from(from_mb.clone())
        .message_id(Some(message_id.clone()))
        .subject(subject.clone())
        .date(std::time::SystemTime::now());

    for addr in &to_addrs {
        let mb: Mailbox = format_address_for_lettre(addr)?.parse().context("to mailbox")?;
        builder = builder.to(mb);
    }
    for addr in &cc_addrs {
        let mb: Mailbox = format_address_for_lettre(addr)?.parse().context("cc mailbox")?;
        builder = builder.cc(mb);
    }
    for addr in &bcc_addrs {
        let mb: Mailbox = format_address_for_lettre(addr)?.parse().context("bcc mailbox")?;
        builder = builder.bcc(mb);
    }

    let message = builder
        .header(header::ContentType::TEXT_PLAIN)
        .body(body_text.clone())
        .context("build message")?;

    send_via_smtp(&config, &message)?;
    let raw_bytes = message.formatted();

    // Persist the sent message to the pile.
    let parsed = ParsedMail {
        message_id: message_id.trim_matches(|c| c == '<' || c == '>').to_string(),
        from: Some(Address {
            name: Some(config.from_name.clone()),
            email: config.user.clone(),
        }),
        to: to_addrs,
        cc: cc_addrs,
        bcc: bcc_addrs,
        subject,
        body: body_text,
        sent_at: now,
        in_reply_to: Vec::new(),
        references: Vec::new(),
        is_spam: false,
        raw: raw_bytes,
        attachments: Vec::new(),
    };
    with_repo(pile, |repo| {
        ingest_message(repo, mail_branch_id, files_branch_id, relations_branch_id, parsed)
    })?;

    println!("Sent {}", message_id);
    Ok(())
}

fn format_address_for_lettre(addr: &Address) -> Result<String> {
    Ok(match &addr.name {
        Some(name) if !name.is_empty() => format!("{} <{}>", name, addr.email),
        _ => addr.email.clone(),
    })
}

fn send_via_smtp(config: &MailConfig, message: &Message) -> Result<()> {
    let creds = Credentials::new(config.user.clone(), config.pass.clone());
    let mailer = SmtpTransport::relay(&config.smtp_host)
        .map_err(|e| anyhow::anyhow!("smtp relay {}: {e}", config.smtp_host))?
        .port(config.smtp_port)
        .credentials(creds)
        .build();
    mailer
        .send(message)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("smtp send: {e}"))
}

fn cmd_reply(
    pile: &Path,
    mail_branch_id: Id,
    files_branch_id: Id,
    relations_branch_id: Id,
    parent_hex: String,
    body: String,
) -> Result<()> {
    let body_text = load_value_or_file(&body, "reply body")?;
    let parent_id = parse_full_id(&parent_hex)?;

    // Pull parent's properties for thread headers.
    let (parent_msg_id, parent_subject, parent_from, parent_references) =
        with_repo(pile, |repo| {
            let mut ws = repo
                .pull(mail_branch_id)
                .map_err(|e| anyhow::anyhow!("pull mail: {e:?}"))?;
            let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
            let msg_id_h: Option<TextHandle> = find!(
                h: TextHandle,
                pattern!(&space, [{ parent_id @ mail::message_id: ?h }])
            )
            .next();
            let msg_id = msg_id_h
                .and_then(|h| read_text(&mut ws, h))
                .ok_or_else(|| anyhow::anyhow!("parent has no message_id"))?;
            let subject_h: Option<TextHandle> = find!(
                h: TextHandle,
                pattern!(&space, [{ parent_id @ mail::subject: ?h }])
            )
            .next();
            let subject = subject_h.and_then(|h| read_text(&mut ws, h)).unwrap_or_default();
            let from_relation: Option<Id> = find!(
                r: Id,
                pattern!(&space, [{ parent_id @ mail::from: ?r }])
            )
            .next();
            let from_email: Option<String> = match from_relation {
                Some(rid) => {
                    let rel_space = ws
                        .checkout(..)
                        .map_err(|e| anyhow::anyhow!("checkout for relations: {e:?}"))?;
                    find!(
                        e: String,
                        pattern!(&rel_space, [{ rid @ rel_attrs::email: ?e }])
                    )
                    .next()
                }
                None => None,
            };
            let mut refs: Vec<Id> = find!(
                r: Id,
                pattern!(&space, [{ parent_id @ mail::references: ?r }])
            )
            .collect();
            let mut all_refs_ids: Vec<Id> = find!(
                r: Id,
                pattern!(&space, [{ parent_id @ mail::in_reply_to: ?r }])
            )
            .collect();
            refs.append(&mut all_refs_ids);
            // Look up the message_id strings for each referenced id so we
            // can emit them in the References header.
            let mut ref_strings: Vec<String> = Vec::new();
            for r in &refs {
                let h: Option<TextHandle> = find!(
                    h: TextHandle,
                    pattern!(&space, [{ r @ mail::message_id: ?h }])
                )
                .next();
                if let Some(handle) = h {
                    if let Some(s) = read_text(&mut ws, handle) {
                        ref_strings.push(s);
                    }
                }
            }
            Ok((msg_id, subject, from_email, ref_strings))
        })?;

    let reply_to = parent_from.ok_or_else(|| {
        anyhow::anyhow!("parent has no resolvable From address — can't determine reply target")
    })?;
    let reply_subject = if parent_subject.to_lowercase().starts_with("re:") {
        parent_subject
    } else {
        format!("Re: {}", parent_subject)
    };

    let config = load_config()?;
    let seed = format!(
        "{}:{}:{}",
        config.user,
        parent_msg_id,
        now_epoch().to_tai_seconds()
    );
    let new_message_id = synthesize_message_id(&seed);
    let new_references = {
        let mut v = parent_references.clone();
        v.push(parent_msg_id.clone());
        v.iter().map(|s| format!("<{}>", s)).collect::<Vec<_>>().join(" ")
    };
    let in_reply_to = format!("<{}>", parent_msg_id);

    let from_mb: Mailbox = format!("{} <{}>", config.from_name, config.user)
        .parse()
        .context("parse from address")?;
    let to_mb: Mailbox = reply_to.parse().context("parse reply-to mailbox")?;

    let message = Message::builder()
        .from(from_mb)
        .to(to_mb)
        .message_id(Some(new_message_id.clone()))
        .subject(reply_subject.clone())
        .in_reply_to(in_reply_to.clone())
        .references(new_references.clone())
        .date(std::time::SystemTime::now())
        .header(header::ContentType::TEXT_PLAIN)
        .body(body_text.clone())
        .context("build reply")?;

    send_via_smtp(&config, &message)?;
    let raw_bytes = message.formatted();

    let now = now_epoch();
    let parsed = ParsedMail {
        message_id: new_message_id.trim_matches(|c| c == '<' || c == '>').to_string(),
        from: Some(Address {
            name: Some(config.from_name.clone()),
            email: config.user.clone(),
        }),
        to: vec![Address {
            name: None,
            email: reply_to.clone(),
        }],
        cc: Vec::new(),
        bcc: Vec::new(),
        subject: reply_subject,
        body: body_text,
        sent_at: now,
        in_reply_to: vec![parent_msg_id.clone()],
        references: parent_references,
        is_spam: false,
        raw: raw_bytes,
        attachments: Vec::new(),
    };
    with_repo(pile, |repo| {
        ingest_message(repo, mail_branch_id, files_branch_id, relations_branch_id, parsed)
    })?;

    println!("Replied to {} (new id {})", parent_msg_id, new_message_id);
    Ok(())
}

// ── queries ───────────────────────────────────────────────────────────────

struct Row {
    id: Id,
    sent_at: Epoch,
    subject: String,
    from_email: Option<String>,
    is_spam: bool,
}

fn collect_messages(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    space: &TribleSet,
    relations_space: &TribleSet,
    window: Option<(Epoch, Epoch)>,
    spam_only: bool,
    include_spam: bool,
    unread_only: Option<Id>,
) -> Vec<Row> {
    let mut out = Vec::new();
    let ids: Vec<Id> = find!(
        e: Id,
        pattern!(space, [{ ?e @ metadata::tag: (KIND_MESSAGE) }])
    )
    .collect();
    for id in ids {
        let sent_at_iv: Option<IntervalValue> = find!(
            t: IntervalValue,
            pattern!(space, [{ id @ mail::sent_at: ?t }])
        )
        .next();
        let Some(iv) = sent_at_iv else { continue };
        let (sent_at, _) = unpack_interval(iv);
        if let Some((s, e)) = window {
            if sent_at < s || sent_at > e {
                continue;
            }
        }
        let is_spam: bool = find!(
            t: Id,
            pattern!(space, [{ id @ metadata::tag: ?t }])
        )
        .any(|t| t == KIND_SPAM);
        if spam_only && !is_spam {
            continue;
        }
        if !spam_only && !include_spam && is_spam {
            continue;
        }
        if let Some(reader_id) = unread_only {
            if is_read(space, id, reader_id) {
                continue;
            }
        }
        let subject_h: Option<TextHandle> = find!(
            h: TextHandle,
            pattern!(space, [{ id @ mail::subject: ?h }])
        )
        .next();
        let subject = subject_h.and_then(|h| read_text(ws, h)).unwrap_or_default();
        let from_relation: Option<Id> = find!(
            r: Id,
            pattern!(space, [{ id @ mail::from: ?r }])
        )
        .next();
        let from_email = from_relation.and_then(|rid| {
            find!(
                e: String,
                pattern!(relations_space, [{ rid @ rel_attrs::email: ?e }])
            )
            .next()
        });
        out.push(Row {
            id,
            sent_at,
            subject,
            from_email,
            is_spam,
        });
    }
    out.sort_by_key(|r| r.sent_at.to_tai_seconds() as i128);
    out
}

fn print_rows(rows: &[Row]) {
    if rows.is_empty() {
        println!("(no messages)");
        return;
    }
    for r in rows {
        let when = epoch_to_chrono_utc(r.sent_at).format("%Y-%m-%d %H:%M");
        let from = r.from_email.as_deref().unwrap_or("?");
        let flag = if r.is_spam { " [SPAM]" } else { "" };
        println!(
            "  {} {} {:30} {}{}",
            &fmt_id(r.id)[..8],
            when,
            truncate_for_display(from, 30),
            r.subject,
            flag,
        );
    }
}

fn truncate_for_display(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let trimmed: String = s.chars().take(max - 1).collect();
        format!("{trimmed}…")
    }
}

fn cmd_list(
    pile: &Path,
    mail_branch_id: Id,
    relations_branch_id: Id,
    from: Option<String>,
    to: Option<String>,
    spam_only: bool,
    all: bool,
    unread_only: bool,
) -> Result<()> {
    let window = match (from.as_deref(), to.as_deref()) {
        (None, None) => None,
        (f, t) => {
            let start = f
                .map(parse_iso8601)
                .transpose()?
                .map(chrono_to_epoch)
                .unwrap_or_else(|| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
            let end = t
                .map(parse_iso8601)
                .transpose()?
                .map(chrono_to_epoch)
                .unwrap_or_else(|| Epoch::from_gregorian_utc(2100, 1, 1, 0, 0, 0, 0));
            Some((start, end))
        }
    };
    with_repo(pile, |repo| {
        let mut mws = repo
            .pull(mail_branch_id)
            .map_err(|e| anyhow::anyhow!("pull mail: {e:?}"))?;
        let mail_space = mws.checkout(..).map_err(|e| anyhow::anyhow!("checkout mail: {e:?}"))?;
        let mut rws = repo
            .pull(relations_branch_id)
            .map_err(|e| anyhow::anyhow!("pull relations: {e:?}"))?;
        let rel_space = rws.checkout(..).map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;
        let reader_filter = if unread_only {
            let config = load_config()?;
            find_self_persona(&rel_space, &config.user)
        } else {
            None
        };
        let rows = collect_messages(
            &mut mws,
            &mail_space,
            &rel_space,
            window,
            spam_only,
            all,
            reader_filter,
        );
        print_rows(&rows);
        Ok(())
    })
}

fn local_day_window() -> (Epoch, Epoch) {
    let now = Local::now();
    let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
    let end = start + chrono::Duration::days(1);
    let s_utc: DateTime<Utc> = Local
        .from_local_datetime(&start)
        .unwrap()
        .with_timezone(&Utc);
    let e_utc: DateTime<Utc> = Local
        .from_local_datetime(&end)
        .unwrap()
        .with_timezone(&Utc);
    (chrono_to_epoch(s_utc), chrono_to_epoch(e_utc))
}

fn local_week_window() -> (Epoch, Epoch) {
    let now = Local::now();
    let start = now.date_naive().and_hms_opt(0, 0, 0).unwrap() - chrono::Duration::days(7);
    let end = now.date_naive().and_hms_opt(0, 0, 0).unwrap() + chrono::Duration::days(1);
    let s_utc: DateTime<Utc> = Local
        .from_local_datetime(&start)
        .unwrap()
        .with_timezone(&Utc);
    let e_utc: DateTime<Utc> = Local
        .from_local_datetime(&end)
        .unwrap()
        .with_timezone(&Utc);
    (chrono_to_epoch(s_utc), chrono_to_epoch(e_utc))
}

fn cmd_today(pile: &Path, mail_branch_id: Id, relations_branch_id: Id) -> Result<()> {
    let (s, e) = local_day_window();
    with_repo(pile, |repo| {
        let mut mws = repo
            .pull(mail_branch_id)
            .map_err(|err| anyhow::anyhow!("pull mail: {err:?}"))?;
        let mail_space = mws.checkout(..).map_err(|err| anyhow::anyhow!("checkout: {err:?}"))?;
        let mut rws = repo
            .pull(relations_branch_id)
            .map_err(|err| anyhow::anyhow!("pull relations: {err:?}"))?;
        let rel_space = rws.checkout(..).map_err(|err| anyhow::anyhow!("checkout: {err:?}"))?;
        let rows = collect_messages(&mut mws, &mail_space, &rel_space, Some((s, e)), false, false, None);
        print_rows(&rows);
        Ok(())
    })
}

fn cmd_week(pile: &Path, mail_branch_id: Id, relations_branch_id: Id) -> Result<()> {
    let (s, e) = local_week_window();
    with_repo(pile, |repo| {
        let mut mws = repo
            .pull(mail_branch_id)
            .map_err(|err| anyhow::anyhow!("pull mail: {err:?}"))?;
        let mail_space = mws.checkout(..).map_err(|err| anyhow::anyhow!("checkout: {err:?}"))?;
        let mut rws = repo
            .pull(relations_branch_id)
            .map_err(|err| anyhow::anyhow!("pull relations: {err:?}"))?;
        let rel_space = rws.checkout(..).map_err(|err| anyhow::anyhow!("checkout: {err:?}"))?;
        let rows = collect_messages(&mut mws, &mail_space, &rel_space, Some((s, e)), false, false, None);
        print_rows(&rows);
        Ok(())
    })
}

fn cmd_show(
    pile: &Path,
    mail_branch_id: Id,
    relations_branch_id: Id,
    message: String,
) -> Result<()> {
    let id = parse_full_id(&message)?;
    with_repo(pile, |repo| {
        let mut mws = repo
            .pull(mail_branch_id)
            .map_err(|e| anyhow::anyhow!("pull mail: {e:?}"))?;
        let space = mws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let mut rws = repo
            .pull(relations_branch_id)
            .map_err(|e| anyhow::anyhow!("pull relations: {e:?}"))?;
        let rel_space = rws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

        let subject = find!(h: TextHandle, pattern!(&space, [{ id @ mail::subject: ?h }]))
            .next()
            .and_then(|h| read_text(&mut mws, h))
            .unwrap_or_default();
        let message_id = find!(h: TextHandle, pattern!(&space, [{ id @ mail::message_id: ?h }]))
            .next()
            .and_then(|h| read_text(&mut mws, h))
            .unwrap_or_default();
        let sent_at = find!(t: IntervalValue, pattern!(&space, [{ id @ mail::sent_at: ?t }]))
            .next()
            .map(unpack_interval)
            .map(|(s, _)| s);
        let from_relation: Option<Id> =
            find!(r: Id, pattern!(&space, [{ id @ mail::from: ?r }])).next();
        let from_email = from_relation.and_then(|rid| {
            find!(e: String, pattern!(&rel_space, [{ rid @ rel_attrs::email: ?e }])).next()
        });
        let to_relations: Vec<Id> =
            find!(r: Id, pattern!(&space, [{ id @ mail::to: ?r }])).collect();
        let to_emails: Vec<String> = to_relations
            .iter()
            .filter_map(|rid| {
                find!(e: String, pattern!(&rel_space, [{ rid @ rel_attrs::email: ?e }])).next()
            })
            .collect();
        let body = find!(h: TextHandle, pattern!(&space, [{ id @ mail::body: ?h }]))
            .next()
            .and_then(|h| read_text(&mut mws, h))
            .unwrap_or_default();
        let attachments: Vec<Id> =
            find!(a: Id, pattern!(&space, [{ id @ mail::attachment: ?a }])).collect();
        let is_spam = find!(t: Id, pattern!(&space, [{ id @ metadata::tag: ?t }]))
            .any(|t| t == KIND_SPAM);

        println!("message {}", fmt_id(id));
        if !subject.is_empty() {
            println!("  subject:    {subject}");
        }
        if let Some(em) = from_email {
            println!("  from:       {em}");
        }
        if !to_emails.is_empty() {
            println!("  to:         {}", to_emails.join(", "));
        }
        if let Some(s) = sent_at {
            println!("  sent_at:    {}", epoch_to_chrono_utc(s).format("%Y-%m-%d %H:%M UTC"));
        }
        println!("  message_id: {message_id}");
        if is_spam {
            println!("  status:     SPAM");
        }
        if !attachments.is_empty() {
            println!("  attachments: {}", attachments.len());
            for aid in &attachments {
                println!("    {}", fmt_id(*aid));
            }
        }
        println!("  ----");
        for line in body.lines() {
            println!("  {line}");
        }
        Ok(())
    })?;
    // Auto-mark on show (opening = reading, mirrors what mail clients do).
    // Idempotent: if a read receipt already exists for this message + the
    // local agent, mark_read_if_unread is a no-op. Quietly skip if we
    // can't resolve the local agent's relations entry (no MAIL_USER set
    // yet, or no auto-registered Toby entry — the user can still mark
    // explicitly with `mail read <id>` later).
    if let Ok(config) = load_config() {
        let _ = with_repo(pile, |repo| {
            let mut rws = repo
                .pull(relations_branch_id)
                .map_err(|e| anyhow::anyhow!("pull relations: {e:?}"))?;
            let rel_space = rws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
            if let Some(self_id) = find_self_persona(&rel_space, &config.user) {
                mark_read_if_unread(repo, mail_branch_id, id, self_id)?;
            }
            Ok(())
        });
    }
    Ok(())
}

fn cmd_read(
    pile: &Path,
    mail_branch_id: Id,
    relations_branch_id: Id,
    message: String,
) -> Result<()> {
    let id = parse_full_id(&message)?;
    let config = load_config()?;
    with_repo(pile, |repo| {
        let mut rws = repo
            .pull(relations_branch_id)
            .map_err(|e| anyhow::anyhow!("pull relations: {e:?}"))?;
        let rel_space = rws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let self_id = find_self_persona(&rel_space, &config.user).ok_or_else(|| {
            anyhow::anyhow!(
                "no relations entry for {} — send or receive at least one message first \
                 so the auto-registration mints your entry",
                config.user
            )
        })?;
        let now_new = mark_read_if_unread(repo, mail_branch_id, id, self_id)?;
        if now_new {
            println!("Marked {} as read.", fmt_id(id));
        } else {
            println!("{} was already read.", fmt_id(id));
        }
        Ok(())
    })
}

fn cmd_thread(
    pile: &Path,
    mail_branch_id: Id,
    relations_branch_id: Id,
    message: String,
) -> Result<()> {
    let start = parse_full_id(&message)?;
    with_repo(pile, |repo| {
        let mut mws = repo
            .pull(mail_branch_id)
            .map_err(|e| anyhow::anyhow!("pull mail: {e:?}"))?;
        let space = mws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let mut rws = repo
            .pull(relations_branch_id)
            .map_err(|e| anyhow::anyhow!("pull relations: {e:?}"))?;
        let rel_space = rws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

        // BFS over both in_reply_to and references edges, both directions
        // (ancestors and descendants).
        let mut visited: HashSet<Id> = HashSet::new();
        let mut queue: Vec<Id> = vec![start];
        while let Some(cur) = queue.pop() {
            if !visited.insert(cur) {
                continue;
            }
            // Ancestors: cur's in_reply_to + references targets.
            for parent in find!(p: Id, pattern!(&space, [{ cur @ mail::in_reply_to: ?p }])) {
                queue.push(parent);
            }
            for parent in find!(p: Id, pattern!(&space, [{ cur @ mail::references: ?p }])) {
                queue.push(parent);
            }
            // Descendants: anyone whose in_reply_to or references points at cur.
            for child in find!(c: Id, pattern!(&space, [{ ?c @ mail::in_reply_to: (cur) }])) {
                queue.push(child);
            }
            for child in find!(c: Id, pattern!(&space, [{ ?c @ mail::references: (cur) }])) {
                queue.push(child);
            }
        }
        let mut ids: Vec<Id> = visited.into_iter().collect();
        // Filter to ones that actually exist as messages in our pile —
        // predicted-but-unfetched parents are valid GenIds but have no
        // mail entity yet.
        ids.retain(|id| {
            find!(t: Id, pattern!(&space, [{ id @ metadata::tag: ?t }]))
                .any(|t| t == KIND_MESSAGE)
        });

        let rows: Vec<Row> = ids
            .into_iter()
            .filter_map(|id| {
                let sent_at_iv: Option<IntervalValue> = find!(
                    t: IntervalValue,
                    pattern!(&space, [{ id @ mail::sent_at: ?t }])
                )
                .next();
                let (sent_at, _) = unpack_interval(sent_at_iv?);
                let subject_h: Option<TextHandle> =
                    find!(h: TextHandle, pattern!(&space, [{ id @ mail::subject: ?h }])).next();
                let subject = subject_h.and_then(|h| read_text(&mut mws, h)).unwrap_or_default();
                let from_relation: Option<Id> =
                    find!(r: Id, pattern!(&space, [{ id @ mail::from: ?r }])).next();
                let from_email = from_relation.and_then(|rid| {
                    find!(
                        e: String,
                        pattern!(&rel_space, [{ rid @ rel_attrs::email: ?e }])
                    )
                    .next()
                });
                let is_spam = find!(t: Id, pattern!(&space, [{ id @ metadata::tag: ?t }]))
                    .any(|t| t == KIND_SPAM);
                Some(Row {
                    id,
                    sent_at,
                    subject,
                    from_email,
                    is_spam,
                })
            })
            .collect();
        let mut rows = rows;
        rows.sort_by_key(|r| r.sent_at.to_tai_seconds() as i128);
        print_rows(&rows);
        Ok(())
    })
}

fn cmd_search(
    pile: &Path,
    mail_branch_id: Id,
    relations_branch_id: Id,
    query: String,
) -> Result<()> {
    let needle = query.to_ascii_lowercase();
    with_repo(pile, |repo| {
        let mut mws = repo
            .pull(mail_branch_id)
            .map_err(|e| anyhow::anyhow!("pull mail: {e:?}"))?;
        let space = mws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let mut rws = repo
            .pull(relations_branch_id)
            .map_err(|e| anyhow::anyhow!("pull relations: {e:?}"))?;
        let rel_space = rws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let ids: Vec<Id> =
            find!(e: Id, pattern!(&space, [{ ?e @ metadata::tag: (KIND_MESSAGE) }])).collect();
        let mut matches: Vec<Row> = Vec::new();
        for id in ids {
            let subject = find!(h: TextHandle, pattern!(&space, [{ id @ mail::subject: ?h }]))
                .next()
                .and_then(|h| read_text(&mut mws, h))
                .unwrap_or_default();
            let body = find!(h: TextHandle, pattern!(&space, [{ id @ mail::body: ?h }]))
                .next()
                .and_then(|h| read_text(&mut mws, h))
                .unwrap_or_default();
            if !subject.to_ascii_lowercase().contains(&needle)
                && !body.to_ascii_lowercase().contains(&needle)
            {
                continue;
            }
            let sent_at_iv: Option<IntervalValue> = find!(
                t: IntervalValue,
                pattern!(&space, [{ id @ mail::sent_at: ?t }])
            )
            .next();
            let (sent_at, _) = unpack_interval(sent_at_iv.unwrap_or_else(|| instant_interval(now_epoch())));
            let from_relation: Option<Id> =
                find!(r: Id, pattern!(&space, [{ id @ mail::from: ?r }])).next();
            let from_email = from_relation.and_then(|rid| {
                find!(e: String, pattern!(&rel_space, [{ rid @ rel_attrs::email: ?e }])).next()
            });
            let is_spam = find!(t: Id, pattern!(&space, [{ id @ metadata::tag: ?t }]))
                .any(|t| t == KIND_SPAM);
            matches.push(Row {
                id,
                sent_at,
                subject,
                from_email,
                is_spam,
            });
        }
        matches.sort_by_key(|r| r.sent_at.to_tai_seconds() as i128);
        print_rows(&matches);
        Ok(())
    })
}

fn cmd_resolve(pile: &Path, mail_branch_id: Id, prefix: String) -> Result<()> {
    let needle = prefix.trim().to_ascii_lowercase();
    if needle.is_empty() {
        bail!("empty prefix");
    }
    with_repo(pile, |repo| {
        let mut mws = repo
            .pull(mail_branch_id)
            .map_err(|e| anyhow::anyhow!("pull mail: {e:?}"))?;
        let space = mws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let mut matches = Vec::new();
        for id in find!(e: Id, pattern!(&space, [{ ?e @ metadata::tag: (KIND_MESSAGE) }])) {
            let hex = fmt_id(id);
            if hex.starts_with(&needle) {
                matches.push(id);
            }
        }
        match matches.len() {
            0 => bail!("no message id starts with '{}'", needle),
            1 => {
                println!("{}", fmt_id(matches[0]));
                Ok(())
            }
            n => bail!("{n} matches; provide a longer prefix"),
        }
    })
}

// ── main ──────────────────────────────────────────────────────────────────

fn resolve_branch(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    branch_name: &str,
) -> Result<Id> {
    repo.ensure_branch(branch_name, None)
        .map_err(|e| anyhow::anyhow!("ensure branch '{branch_name}': {e:?}"))
}

fn main() -> Result<()> {
    // rust-pop3-client depends on rustls 0.23 but doesn't select a
    // crypto provider; install one explicitly here so the lazy
    // default-provider lookup doesn't panic on first TLS use.
    // Idempotent — re-installing is a no-op error we ignore.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let cmd = cli.command.unwrap_or(Command::Today);

    let (mail_branch, files_branch, relations_branch) = with_repo(&cli.pile, |repo| {
        let m = resolve_branch(repo, &cli.branch)?;
        let f = resolve_branch(repo, &cli.files_branch)?;
        let r = resolve_branch(repo, &cli.relations_branch)?;
        Ok((m, f, r))
    })?;

    match cmd {
        Command::Fetch => cmd_fetch(&cli.pile, mail_branch, files_branch, relations_branch),
        Command::Send {
            to,
            subject,
            body,
            cc,
            bcc,
        } => cmd_send(
            &cli.pile,
            mail_branch,
            files_branch,
            relations_branch,
            to,
            subject,
            body,
            cc,
            bcc,
        ),
        Command::Reply { message, body } => cmd_reply(
            &cli.pile,
            mail_branch,
            files_branch,
            relations_branch,
            message,
            body,
        ),
        Command::List { from, to, spam, all, unread } => cmd_list(
            &cli.pile,
            mail_branch,
            relations_branch,
            from,
            to,
            spam,
            all,
            unread,
        ),
        Command::Read { message } => cmd_read(&cli.pile, mail_branch, relations_branch, message),
        Command::Today => cmd_today(&cli.pile, mail_branch, relations_branch),
        Command::Week => cmd_week(&cli.pile, mail_branch, relations_branch),
        Command::Thread { message } => {
            cmd_thread(&cli.pile, mail_branch, relations_branch, message)
        }
        Command::Show { message } => cmd_show(&cli.pile, mail_branch, relations_branch, message),
        Command::Search { query } => cmd_search(&cli.pile, mail_branch, relations_branch, query),
        Command::Resolve { prefix } => cmd_resolve(&cli.pile, mail_branch, prefix),
    }
}
