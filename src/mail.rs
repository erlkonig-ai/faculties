//! Collection-native Mail values, projections, validation, and protocol seams.
//!
//! This module deliberately separates facts from effects.  Constructors
//! produce self-contained immutable fragments; callers validate the exact
//! collection union and durably publish those fragments before asking a POP
//! or SMTP transport to perform an irreversible action.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use dryoc::classic::crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm};
use dryoc::constants::{
    CRYPTO_PWHASH_MEMLIMIT_MODERATE, CRYPTO_PWHASH_OPSLIMIT_MODERATE, CRYPTO_PWHASH_SALTBYTES,
};
use dryoc::dryocsecretbox::{DryocSecretBox, Key, Nonce};
use dryoc::types::*;
use hifitime::Epoch;
use lettre::message::{header, Mailbox, MultiPart, SinglePart};
use lettre::Message;
use rand_core::{OsRng, RngCore};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::prelude::*;

use crate::decide::{self, Resolution};
use crate::files;
use crate::files::FileEntityKind;
use crate::relations::IdentityComponents;
use crate::schemas::decide::KIND_DECISION;
use crate::schemas::mail::{
    acceptance, account, attachment_occurrence, attempt, credential, draft, observation,
    projection, read, wire, KIND_ACCOUNT_CONFIG, KIND_ATTACHMENT_OCCURRENCE, KIND_CREDENTIAL,
    KIND_CREDENTIAL_ENVELOPE, KIND_DRAFT_INTENT, KIND_MAIL_ACCOUNT, KIND_OUTGOING_OBSERVATION,
    KIND_PARSED_PROJECTION, KIND_POP_OBSERVATION, KIND_READ_OBSERVATION, KIND_SEND_ATTEMPT,
    KIND_SMTP_ACCEPTANCE, KIND_WIRE_MESSAGE, RECIPE_RFC5322_V1,
};

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
pub type BytesHandle = Inline<inlineencodings::Handle<blobencodings::RawBytes>>;
pub type DigestValue = Inline<inlineencodings::Hash<inlineencodings::Blake3>>;
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;
pub type CountValue = Inline<inlineencodings::U256BE>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountConfigInput {
    pub address: String,
    pub display_name: String,
    pub pop_endpoint: String,
    pub smtp_endpoint: String,
    pub username: String,
    pub credential: Id,
    pub enabled: bool,
    pub predecessors: Vec<Id>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountConfigRecord {
    pub id: Id,
    pub account: Id,
    pub address: TextHandle,
    pub display_name: TextHandle,
    pub pop_endpoint: TextHandle,
    pub smtp_endpoint: TextHandle,
    pub username: TextHandle,
    pub credential: Id,
    pub enabled: bool,
    pub predecessors: Vec<Id>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAccount {
    pub anchor: Id,
    pub config: Id,
    pub address: String,
    pub display_name: String,
    pub pop_endpoint: String,
    pub smtp_endpoint: String,
    pub username: String,
    pub password: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Head {
    Missing,
    Unique(Id),
    Forked(Vec<Id>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentData {
    pub filename: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireIdentity {
    /// An opaque identity explicitly claimed in exactly one Message-ID field.
    Claimed(String),
    /// A digest of the exact raw bytes, used only when Message-ID is absent.
    RawDigest(DigestValue),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedMessage {
    pub identity: WireIdentity,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: String,
    pub claimed_date: Option<IntervalValue>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub spam: bool,
    pub attachments: Vec<AttachmentData>,
}

#[derive(Debug)]
pub struct SourcePublication {
    pub mail: Fragment,
    pub files: Fragment,
    pub wire: Id,
    pub observation: Id,
    pub projection: Id,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DraftInput {
    pub nonce: Id,
    pub account: Id,
    pub envelope_from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<Id>,
    pub in_reply_to: Vec<Id>,
    pub references: Vec<Id>,
    pub created_at: IntervalValue,
}

#[derive(Debug)]
pub struct DraftPublication {
    pub mail: Fragment,
    pub decide: Fragment,
    pub draft: Id,
    pub decision: Id,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DraftRecord {
    pub id: Id,
    pub nonce: Id,
    pub account: Id,
    pub envelope_from: TextHandle,
    pub to: Vec<TextHandle>,
    pub cc: Vec<TextHandle>,
    pub bcc: Vec<TextHandle>,
    pub subject: TextHandle,
    pub body: TextHandle,
    pub attachments: Vec<Id>,
    pub in_reply_to: Vec<Id>,
    pub references: Vec<Id>,
    pub created_at: IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendAttemptInput {
    pub draft: Id,
    pub config: Id,
    pub decision: Id,
    pub decision_heads: Vec<Id>,
    pub raw: Vec<u8>,
    pub envelope_from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendAttemptRecord {
    pub id: Id,
    pub draft: Id,
    pub config: Id,
    pub decision: Id,
    pub decision_heads: Vec<Id>,
    pub raw: BytesHandle,
    pub envelope_from: TextHandle,
    pub to: Vec<TextHandle>,
    pub cc: Vec<TextHandle>,
    pub bcc: Vec<TextHandle>,
}

/// A locally validated, immutable SMTP effect plan.
///
/// Its fields are private so the exact attempt, envelope, wire bytes, and
/// outgoing evidence cannot be mixed with pieces from another plan between
/// validation and the irreversible transport call.
#[derive(Debug)]
pub struct PreparedSend {
    attempt: Fragment,
    attempt_id: Id,
    outgoing: SourcePublication,
    envelope: SmtpEnvelope,
    raw: Vec<u8>,
}

impl PreparedSend {
    pub fn attempt_fragment(&self) -> &Fragment {
        &self.attempt
    }

    pub fn attempt_id(&self) -> Id {
        self.attempt_id
    }

    pub fn outgoing_files(&self) -> &Fragment {
        &self.outgoing.files
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboxProjection {
    pub wire: Id,
    pub projection: Id,
    pub source: Id,
    pub unread: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializedDraft {
    pub id: Id,
    pub account: Id,
    pub envelope_from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<AttachmentData>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub created_at: IntervalValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedMail {
    pub raw: Vec<u8>,
    pub envelope: SmtpEnvelope,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionView {
    pub id: Id,
    pub source: Id,
    pub wire: Id,
    pub message_id: Option<String>,
    pub from: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: String,
    pub claimed_date: Option<IntervalValue>,
    pub in_reply_to: Vec<Id>,
    pub references: Vec<Id>,
    pub spam: bool,
    pub attachments: Vec<Id>,
}

fn sorted_ids(values: impl IntoIterator<Item = Id>) -> Vec<Id> {
    let mut values: Vec<_> = values.into_iter().collect();
    values.sort_unstable();
    values.dedup();
    values
}

fn canonical_nonempty(value: impl Into<String>, field: &str) -> Result<String> {
    let value = value.into();
    let value = value.trim();
    if value.is_empty() || value.bytes().any(|byte| byte == 0) {
        bail!("{field} is empty or contains a NUL byte");
    }
    Ok(value.to_owned())
}

fn exact_text(value: impl Into<String>, field: &str) -> Result<String> {
    let value = value.into();
    if value.bytes().any(|byte| byte == 0) {
        bail!("{field} contains a NUL byte");
    }
    Ok(value)
}

fn point_interval(value: IntervalValue, field: &str) -> Result<()> {
    let (low, high): (i128, i128) = value
        .try_from_inline()
        .map_err(|error| anyhow!("decode {field}: {error:?}"))?;
    if low != high {
        bail!("{field} must be a point interval");
    }
    Ok(())
}

fn one<T: Ord>(mut values: BTreeSet<T>, field: &str) -> Result<Option<T>> {
    match values.len() {
        0 => Ok(None),
        1 => Ok(values.pop_first()),
        count => bail!("{field} is ambiguous ({count} distinct values)"),
    }
}

fn required<T: Ord>(values: BTreeSet<T>, field: &str) -> Result<T> {
    one(values, field)?.ok_or_else(|| anyhow!("missing {field}"))
}

fn ids_of_kind(facts: &TribleSet, kind: Id) -> BTreeSet<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: &kind }])).collect()
}

fn ensure_intrinsic(id: Id, fragment: Fragment, label: &str) -> Result<Fragment> {
    let expected = fragment
        .root()
        .ok_or_else(|| anyhow!("{label} does not export exactly one root"))?;
    if id != expected {
        bail!("{label} {id:x} does not match intrinsic core {expected:x}");
    }
    Ok(fragment)
}

// ── credential lockboxes ──────────────────────────────────────────────────

fn derive_key(password: &[u8], salt: &[u8]) -> Key {
    let mut out = [0u8; 32];
    crypto_pwhash(
        &mut out,
        password,
        salt,
        CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        CRYPTO_PWHASH_MEMLIMIT_MODERATE,
        PasswordHashAlgorithm::Argon2id13,
    )
    .expect("argon2id");
    Key::try_from(&out[..]).expect("32-byte key")
}

fn lock(password: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; CRYPTO_PWHASH_SALTBYTES];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt);
    let nonce = Nonce::gen();
    let ciphertext = DryocSecretBox::encrypt_to_vecbox(plaintext, &nonce, &key).to_vec();
    let mut out = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

fn unlock(password: &[u8], lockbox: &[u8]) -> Result<Vec<u8>> {
    if lockbox.len() < CRYPTO_PWHASH_SALTBYTES + 24 {
        bail!("malformed mail credential envelope");
    }
    let salt = &lockbox[..CRYPTO_PWHASH_SALTBYTES];
    let nonce = Nonce::try_from(&lockbox[CRYPTO_PWHASH_SALTBYTES..CRYPTO_PWHASH_SALTBYTES + 24])
        .context("credential nonce")?;
    let ciphertext = &lockbox[CRYPTO_PWHASH_SALTBYTES + 24..];
    let key = derive_key(password, salt);
    DryocSecretBox::from_bytes(ciphertext)
        .map_err(|error| anyhow!("parse credential envelope: {error:?}"))?
        .decrypt_to_vec(&nonce, &key)
        .map_err(|_| anyhow!("credential envelope cannot be unlocked with this passphrase"))
}

/// Build a stable authored credential anchor and one randomized envelope.
///
/// Random salt and nonce prevent ciphertext equality from correlating secrets
/// or perturbing the authored anchor. They do not remove the inherent offline
/// passphrase verifier: AEAD authentication lets an attacker test guesses
/// against a copied envelope. Argon2id and a high-entropy passphrase are the
/// mitigation. Whether two envelopes carry the same plaintext is known only
/// after opening them or by trusting the executor which authored them.
pub fn credential_fragment(anchor: Id, passphrase: &[u8], secret: &str) -> Result<Fragment> {
    let secret = canonical_nonempty(secret, "mail credential")?;
    let mut fragment = Fragment::empty();
    let box_handle: BytesHandle = fragment.put(lock(passphrase, secret.as_bytes()));
    fragment += entity! { ExclusiveId::force_ref(&anchor) @ metadata::tag: &KIND_CREDENTIAL };
    fragment += entity! {
        metadata::tag: &KIND_CREDENTIAL_ENVELOPE,
        credential::of: &anchor,
        credential::r#box: box_handle,
    };
    Ok(fragment)
}

// ── accounts ──────────────────────────────────────────────────────────────

fn account_anchor_record(anchor: Id) -> Fragment {
    entity! { ExclusiveId::force_ref(&anchor) @ metadata::tag: &KIND_MAIL_ACCOUNT }
}

fn account_config_record(record: &AccountConfigRecord) -> Fragment {
    entity! {
        metadata::tag: &KIND_ACCOUNT_CONFIG,
        account::of: &record.account,
        account::address: record.address,
        account::display_name: record.display_name,
        account::pop_endpoint: record.pop_endpoint,
        account::smtp_endpoint: record.smtp_endpoint,
        account::username: record.username,
        account::credential: &record.credential,
        account::enabled: record.enabled,
        metadata::supersedes*: record.predecessors.iter(),
    }
}

/// Build one account anchor plus one intrinsic full-state configuration.
pub fn account_config_fragment(anchor: Id, input: AccountConfigInput) -> Result<(Fragment, Id)> {
    let mut fragment = Fragment::empty();
    let record = AccountConfigRecord {
        id: anchor,
        account: anchor,
        address: fragment.put(canonical_nonempty(input.address, "account address")?),
        display_name: fragment.put(canonical_nonempty(input.display_name, "display name")?),
        pop_endpoint: fragment.put(canonical_nonempty(input.pop_endpoint, "POP endpoint")?),
        smtp_endpoint: fragment.put(canonical_nonempty(input.smtp_endpoint, "SMTP endpoint")?),
        username: fragment.put(canonical_nonempty(input.username, "account username")?),
        credential: input.credential,
        enabled: input.enabled,
        predecessors: sorted_ids(input.predecessors),
    };
    let config = account_config_record(&record);
    let id = config
        .root()
        .expect("account config has one intrinsic root");
    fragment += account_anchor_record(anchor);
    fragment += config;
    Ok((fragment, id))
}

pub fn account_anchors(facts: &TribleSet) -> BTreeSet<Id> {
    ids_of_kind(facts, KIND_MAIL_ACCOUNT)
}

pub fn account_config(facts: &TribleSet, id: Id) -> Result<AccountConfigRecord> {
    Ok(AccountConfigRecord {
        id,
        account: required(
            find!(v: Id, pattern!(facts, [{ id @ account::of: ?v }])).collect(),
            "account config owner",
        )?,
        address: required(
            find!(v: TextHandle, pattern!(facts, [{ id @ account::address: ?v }])).collect(),
            "account address",
        )?,
        display_name: required(
            find!(v: TextHandle, pattern!(facts, [{ id @ account::display_name: ?v }])).collect(),
            "account display name",
        )?,
        pop_endpoint: required(
            find!(v: TextHandle, pattern!(facts, [{ id @ account::pop_endpoint: ?v }])).collect(),
            "POP endpoint",
        )?,
        smtp_endpoint: required(
            find!(v: TextHandle, pattern!(facts, [{ id @ account::smtp_endpoint: ?v }])).collect(),
            "SMTP endpoint",
        )?,
        username: required(
            find!(v: TextHandle, pattern!(facts, [{ id @ account::username: ?v }])).collect(),
            "account username",
        )?,
        credential: required(
            find!(v: Id, pattern!(facts, [{ id @ account::credential: ?v }])).collect(),
            "account credential",
        )?,
        enabled: required(
            find!(v: bool, pattern!(facts, [{ id @ account::enabled: ?v }])).collect(),
            "account enabled flag",
        )?,
        predecessors: sorted_ids(
            find!(v: Id, pattern!(facts, [{ id @ metadata::supersedes: ?v }])),
        ),
    })
}

fn dag_heads(graph: &BTreeMap<Id, Vec<Id>>, label: &str) -> Result<Vec<Id>> {
    for (&id, predecessors) in graph {
        for predecessor in predecessors {
            if !graph.contains_key(predecessor) {
                bail!("{label} node {id:x} names missing predecessor {predecessor:x}");
            }
        }
    }
    fn visit(
        id: Id,
        graph: &BTreeMap<Id, Vec<Id>>,
        visiting: &mut BTreeSet<Id>,
        done: &mut BTreeSet<Id>,
        label: &str,
    ) -> Result<()> {
        if done.contains(&id) {
            return Ok(());
        }
        if !visiting.insert(id) {
            bail!("{label} contains a cycle through {id:x}");
        }
        for predecessor in &graph[&id] {
            visit(*predecessor, graph, visiting, done, label)?;
        }
        visiting.remove(&id);
        done.insert(id);
        Ok(())
    }
    let mut visiting = BTreeSet::new();
    let mut done = BTreeSet::new();
    for &id in graph.keys() {
        visit(id, graph, &mut visiting, &mut done, label)?;
    }
    let superseded: BTreeSet<_> = graph.values().flatten().copied().collect();
    Ok(graph
        .keys()
        .filter(|id| !superseded.contains(*id))
        .copied()
        .collect())
}

pub fn account_head(facts: &TribleSet, anchor: Id) -> Result<Head> {
    let mut graph = BTreeMap::new();
    for id in ids_of_kind(facts, KIND_ACCOUNT_CONFIG) {
        let record = account_config(facts, id)?;
        if record.account == anchor {
            graph.insert(id, record.predecessors);
        }
    }
    let heads = dag_heads(&graph, &format!("account {anchor:x} configuration DAG"))?;
    Ok(match heads.as_slice() {
        [] => Head::Missing,
        [id] => Head::Unique(*id),
        _ => Head::Forked(heads),
    })
}

// ── RFC 5322 identity and projection ──────────────────────────────────────

fn header_values(parsed: &mailparse::ParsedMail<'_>, name: &str) -> Vec<String> {
    parsed
        .headers
        .iter()
        .filter(|header| header.get_key().eq_ignore_ascii_case(name))
        .map(|header| header.get_value())
        .collect()
}

fn canonical_message_id_value(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("empty Message-ID field");
    }
    let value = if raw.starts_with('<') || raw.ends_with('>') {
        if !(raw.starts_with('<') && raw.ends_with('>')) || raw.len() < 3 {
            bail!("malformed Message-ID field {raw:?}");
        }
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    if value.trim() != value
        || value.is_empty()
        || value.chars().any(char::is_whitespace)
        || value.contains(['<', '>'])
    {
        bail!("Message-ID must contain one opaque id, got {raw:?}");
    }
    Ok(value.to_owned())
}

/// Canonical opaque Message-ID claim, or a structurally distinct full
/// raw-byte digest when that header is absent.
pub fn canonical_wire_identity(
    parsed: &mailparse::ParsedMail<'_>,
    raw: &[u8],
) -> Result<WireIdentity> {
    let values = header_values(parsed, "Message-ID");
    match values.as_slice() {
        [] => Ok(WireIdentity::RawDigest(Inline::new(
            *blake3::hash(raw).as_bytes(),
        ))),
        [value] => canonical_message_id_value(value).map(WireIdentity::Claimed),
        _ => bail!("message has multiple Message-ID fields"),
    }
}

fn message_id_list(value: &str) -> Result<Vec<String>> {
    let mut values = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find('<') {
        let after = &rest[start + 1..];
        let end = after
            .find('>')
            .ok_or_else(|| anyhow!("unterminated message id in {value:?}"))?;
        values.push(canonical_message_id_value(&format!("<{}>", &after[..end]))?);
        rest = &after[end + 1..];
    }
    if values.is_empty() && !value.trim().is_empty() {
        values.push(canonical_message_id_value(value)?);
    }
    Ok(values)
}

fn message_ids_from_headers(parsed: &mailparse::ParsedMail<'_>, name: &str) -> Result<Vec<String>> {
    let mut values = Vec::new();
    for header in header_values(parsed, name) {
        values.extend(message_id_list(&header)?);
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn collect_parts(
    part: &mailparse::ParsedMail<'_>,
    plain: &mut Option<String>,
    html: &mut Option<String>,
    attachments: &mut Vec<AttachmentData>,
) {
    let media_type = part.ctype.mimetype.to_ascii_lowercase();
    let disposition = part.get_content_disposition();
    let is_attachment = matches!(
        disposition.disposition,
        mailparse::DispositionType::Attachment
    ) || disposition
        .params
        .get("filename")
        .is_some_and(|name| !name.is_empty());

    if media_type.starts_with("multipart/") {
        for child in &part.subparts {
            collect_parts(child, plain, html, attachments);
        }
    } else if is_attachment || !media_type.starts_with("text/") {
        if let Ok(bytes) = part.get_body_raw() {
            let filename = disposition
                .params
                .get("filename")
                .or_else(|| part.ctype.params.get("name"))
                .cloned()
                .unwrap_or_else(|| "attachment.bin".to_owned());
            attachments.push(AttachmentData {
                filename,
                media_type: files::normalize_media_type_or_default(&media_type),
                bytes,
            });
        }
    } else if media_type == "text/plain" && plain.is_none() {
        *plain = part.get_body().ok();
    } else if media_type == "text/html" && html.is_none() {
        *html = part.get_body().ok();
    }
}

/// Parse immutable source bytes without inventing clock or identity evidence.
pub fn parse_rfc5322(raw: &[u8]) -> Result<ParsedMessage> {
    let parsed = mailparse::parse_mail(raw).context("parse RFC 5322")?;
    let identity = canonical_wire_identity(&parsed, raw)?;
    let singular = |name: &str| -> Result<Option<String>> {
        let values = header_values(&parsed, name);
        match values.as_slice() {
            [] => Ok(None),
            [value] => Ok(Some(value.trim().to_owned())),
            _ => bail!("message has multiple {name} fields"),
        }
    };
    let claimed_date = singular("Date")?
        .map(|value| {
            let seconds = mailparse::dateparse(&value).context("parse claimed Date header")?;
            let epoch = Epoch::from_unix_seconds(seconds as f64);
            (epoch, epoch)
                .try_to_inline()
                .map_err(|error| anyhow!("encode claimed Date: {error:?}"))
        })
        .transpose()?;
    let mut plain = None;
    let mut html = None;
    let mut attachments = Vec::new();
    collect_parts(&parsed, &mut plain, &mut html, &mut attachments);
    let spam = header_values(&parsed, "X-Spam-Status")
        .iter()
        .any(|value| value.trim_start().to_ascii_lowercase().starts_with("yes"));
    Ok(ParsedMessage {
        identity,
        from: singular("From")?,
        to: header_values(&parsed, "To"),
        cc: header_values(&parsed, "Cc"),
        bcc: header_values(&parsed, "Bcc"),
        subject: singular("Subject")?.unwrap_or_default(),
        body: plain.or(html).unwrap_or_default(),
        claimed_date,
        in_reply_to: message_ids_from_headers(&parsed, "In-Reply-To")?,
        references: message_ids_from_headers(&parsed, "References")?,
        spam,
        attachments,
    })
}

fn claimed_wire_record(message_id: TextHandle) -> Fragment {
    entity! { metadata::tag: &KIND_WIRE_MESSAGE, wire::claimed_message_id: message_id }
}

fn digest_wire_record(digest: DigestValue) -> Fragment {
    entity! { metadata::tag: &KIND_WIRE_MESSAGE, wire::raw_digest: digest }
}

fn add_claimed_wire(fragment: &mut Fragment, message_id: &str) -> Result<Id> {
    let message_id = fragment.put(canonical_message_id_value(message_id)?);
    let wire = claimed_wire_record(message_id);
    let id = wire.root().expect("claimed wire message has one root");
    *fragment += wire;
    Ok(id)
}

pub fn wire_id_for(message_id: &str) -> Result<Id> {
    let mut fragment = Fragment::empty();
    add_claimed_wire(&mut fragment, message_id)
}

fn attachment_occurrence_record(source: Id, ordinal: u64, file: Id) -> Fragment {
    entity! {
        metadata::tag: &KIND_ATTACHMENT_OCCURRENCE,
        attachment_occurrence::source: &source,
        attachment_occurrence::recipe: &RECIPE_RFC5322_V1,
        attachment_occurrence::ordinal: ordinal,
        attachment_occurrence::file: &file,
    }
}

#[allow(clippy::too_many_arguments)]
fn projection_record(
    source: Id,
    from: Option<TextHandle>,
    to: &[TextHandle],
    cc: &[TextHandle],
    bcc: &[TextHandle],
    subject: TextHandle,
    body: TextHandle,
    claimed_date: Option<IntervalValue>,
    in_reply_to: &[Id],
    references: &[Id],
    spam: bool,
    attachments: &[Id],
) -> Fragment {
    entity! {
        metadata::tag: &KIND_PARSED_PROJECTION,
        projection::source: &source,
        projection::recipe: &RECIPE_RFC5322_V1,
        projection::from?: from.as_ref(),
        projection::to*: to.iter(),
        projection::cc*: cc.iter(),
        projection::bcc*: bcc.iter(),
        projection::subject: subject,
        projection::body: body,
        projection::claimed_date?: claimed_date.as_ref(),
        projection::in_reply_to*: in_reply_to.iter(),
        projection::reference*: references.iter(),
        projection::spam: spam,
        projection::attachment*: attachments.iter(),
    }
}

fn source_publication(
    account_id: Option<Id>,
    config_id: Option<Id>,
    uidl: Option<&str>,
    attempt_id: Option<Id>,
    raw: &[u8],
) -> Result<SourcePublication> {
    let parsed = parse_rfc5322(raw)?;
    let mut mail_fragment = Fragment::empty();
    let wire = match &parsed.identity {
        WireIdentity::Claimed(message_id) => add_claimed_wire(&mut mail_fragment, message_id)?,
        WireIdentity::RawDigest(digest) => {
            let wire_fragment = digest_wire_record(*digest);
            let wire = wire_fragment.root().expect("digest wire root");
            mail_fragment += wire_fragment;
            wire
        }
    };
    let raw_handle: BytesHandle = mail_fragment.put(raw.to_vec());
    let observation_fragment = match (account_id, config_id, uidl, attempt_id) {
        (Some(account_id), Some(config_id), Some(uidl), None) => {
            let uidl = mail_fragment.put(canonical_nonempty(uidl, "POP UIDL")?);
            entity! {
                metadata::tag: &KIND_POP_OBSERVATION,
                observation::wire: &wire,
                observation::account: &account_id,
                observation::config: &config_id,
                observation::uidl: uidl,
                observation::raw: raw_handle,
            }
        }
        (None, None, None, Some(attempt_id)) => entity! {
            metadata::tag: &KIND_OUTGOING_OBSERVATION,
            observation::wire: &wire,
            observation::attempt: &attempt_id,
            observation::raw: raw_handle,
        },
        _ => bail!("source publication requires exactly POP coordinates or a send attempt"),
    };
    let observation = observation_fragment.root().expect("observation root");
    mail_fragment += observation_fragment;

    let mut files_fragment = Fragment::empty();
    let mut occurrence_ids = Vec::new();
    for (index, attachment) in parsed.attachments.iter().enumerate() {
        let file_fragment = files::fragment(
            attachment.bytes.clone(),
            attachment.filename.clone(),
            &attachment.media_type,
        )?;
        let file = file_fragment.root().expect("canonical file root");
        files_fragment += file_fragment;
        let occurrence = attachment_occurrence_record(observation, index as u64, file);
        occurrence_ids.push(occurrence.root().expect("attachment occurrence root"));
        mail_fragment += occurrence;
    }

    let from = parsed.from.map(|value| mail_fragment.put(value));
    let to: Vec<TextHandle> = parsed
        .to
        .into_iter()
        .map(|value| mail_fragment.put(value))
        .collect();
    let cc: Vec<TextHandle> = parsed
        .cc
        .into_iter()
        .map(|value| mail_fragment.put(value))
        .collect();
    let bcc: Vec<TextHandle> = parsed
        .bcc
        .into_iter()
        .map(|value| mail_fragment.put(value))
        .collect();
    let subject = mail_fragment.put(parsed.subject);
    let body = mail_fragment.put(parsed.body);
    let mut in_reply_to = Vec::new();
    for value in &parsed.in_reply_to {
        in_reply_to.push(add_claimed_wire(&mut mail_fragment, value)?);
    }
    let mut references = Vec::new();
    for value in &parsed.references {
        references.push(add_claimed_wire(&mut mail_fragment, value)?);
    }
    let projection_fragment = projection_record(
        observation,
        from,
        &to,
        &cc,
        &bcc,
        subject,
        body,
        parsed.claimed_date,
        &in_reply_to,
        &references,
        parsed.spam,
        &occurrence_ids,
    );
    let projection = projection_fragment.root().expect("projection root");
    mail_fragment += projection_fragment;
    Ok(SourcePublication {
        mail: mail_fragment,
        files: files_fragment,
        wire,
        observation,
        projection,
    })
}

pub fn pop_publication(
    account: Id,
    config: Id,
    uidl: &str,
    raw: &[u8],
) -> Result<SourcePublication> {
    source_publication(Some(account), Some(config), Some(uidl), None, raw)
}

pub fn outgoing_publication(attempt: Id, raw: &[u8]) -> Result<SourcePublication> {
    source_publication(None, None, None, Some(attempt), raw)
}

// ── immutable draft / attempt / acceptance values ─────────────────────────

fn draft_record(record: &DraftRecord) -> Fragment {
    entity! {
        metadata::tag: &KIND_DRAFT_INTENT,
        draft::nonce: &record.nonce,
        draft::account: &record.account,
        draft::envelope_from: record.envelope_from,
        draft::to*: record.to.iter(),
        draft::cc*: record.cc.iter(),
        draft::bcc*: record.bcc.iter(),
        draft::subject: record.subject,
        draft::body: record.body,
        draft::attachment*: record.attachments.iter(),
        draft::in_reply_to*: record.in_reply_to.iter(),
        draft::reference*: record.references.iter(),
        metadata::created_at: record.created_at,
    }
}

pub fn draft_decision_id(draft_id: Id) -> Id {
    entity! { draft::decision_for: &draft_id }
        .root()
        .expect("draft decision derivation has one root")
}

pub fn draft_publication(input: DraftInput) -> Result<DraftPublication> {
    point_interval(input.created_at, "draft creation time")?;
    if input.to.is_empty() && input.cc.is_empty() && input.bcc.is_empty() {
        bail!("draft has no recipients");
    }
    let mut mail_fragment = Fragment::empty();
    let to = input
        .to
        .into_iter()
        .map(|value| Ok(mail_fragment.put(canonical_nonempty(value, "To recipient")?)))
        .collect::<Result<Vec<_>>>()?;
    let cc = input
        .cc
        .into_iter()
        .map(|value| Ok(mail_fragment.put(canonical_nonempty(value, "Cc recipient")?)))
        .collect::<Result<Vec<_>>>()?;
    let bcc = input
        .bcc
        .into_iter()
        .map(|value| Ok(mail_fragment.put(canonical_nonempty(value, "Bcc recipient")?)))
        .collect::<Result<Vec<_>>>()?;
    let record = DraftRecord {
        id: input.account,
        nonce: input.nonce,
        account: input.account,
        envelope_from: mail_fragment.put(canonical_nonempty(
            input.envelope_from,
            "draft envelope sender",
        )?),
        to,
        cc,
        bcc,
        subject: mail_fragment.put(exact_text(input.subject, "draft subject")?),
        body: mail_fragment.put(exact_text(input.body, "draft body")?),
        attachments: sorted_ids(input.attachments),
        in_reply_to: sorted_ids(input.in_reply_to),
        references: sorted_ids(input.references),
        created_at: input.created_at,
    };
    let draft_fragment = draft_record(&record);
    let draft_id = draft_fragment.root().expect("draft has one intrinsic root");
    mail_fragment += draft_fragment;
    let decision = draft_decision_id(draft_id);
    let title = format!(
        "Send mail: {}",
        read_local_text(&mail_fragment, record.subject)?
    );
    let (decide_fragment, _) = decide::decision_fragment(
        decision,
        title,
        Some("Authorize exactly this immutable DraftIntent".to_owned()),
        Some(draft_id),
        record.created_at,
    )?;
    Ok(DraftPublication {
        mail: mail_fragment,
        decide: decide_fragment,
        draft: draft_id,
        decision,
    })
}

fn attempt_record(record: &SendAttemptRecord) -> Fragment {
    entity! {
        metadata::tag: &KIND_SEND_ATTEMPT,
        attempt::draft: &record.draft,
        attempt::config: &record.config,
        attempt::decision: &record.decision,
        attempt::decision_head*: record.decision_heads.iter(),
        attempt::raw: record.raw,
        attempt::envelope_from: record.envelope_from,
        attempt::to*: record.to.iter(),
        attempt::cc*: record.cc.iter(),
        attempt::bcc*: record.bcc.iter(),
    }
}

pub fn send_attempt_fragment(input: SendAttemptInput) -> Result<(Fragment, Id)> {
    if input.to.is_empty() && input.cc.is_empty() && input.bcc.is_empty() {
        bail!("send attempt has no recipients");
    }
    let mut fragment = Fragment::empty();
    let record = SendAttemptRecord {
        id: input.draft,
        draft: input.draft,
        config: input.config,
        decision: input.decision,
        decision_heads: sorted_ids(input.decision_heads),
        raw: fragment.put(input.raw),
        envelope_from: fragment.put(canonical_nonempty(
            input.envelope_from,
            "attempt envelope sender",
        )?),
        to: input
            .to
            .into_iter()
            .map(|value| Ok(fragment.put(canonical_nonempty(value, "attempt To recipient")?)))
            .collect::<Result<_>>()?,
        cc: input
            .cc
            .into_iter()
            .map(|value| Ok(fragment.put(canonical_nonempty(value, "attempt Cc recipient")?)))
            .collect::<Result<_>>()?,
        bcc: input
            .bcc
            .into_iter()
            .map(|value| Ok(fragment.put(canonical_nonempty(value, "attempt Bcc recipient")?)))
            .collect::<Result<_>>()?,
    };
    let attempt = attempt_record(&record);
    let id = attempt.root().expect("send attempt has one intrinsic root");
    fragment += attempt;
    Ok((fragment, id))
}

pub fn smtp_acceptance_fragment(
    attempt_id: Id,
    response_code: u64,
    response: impl Into<String>,
) -> Result<(Fragment, Id)> {
    if !(200..=299).contains(&response_code) {
        bail!("SMTP acceptance code must be a final positive 2xx reply");
    }
    let mut fragment = Fragment::empty();
    let response = fragment.put(canonical_nonempty(response, "SMTP acceptance response")?);
    let acceptance = entity! {
        metadata::tag: &KIND_SMTP_ACCEPTANCE,
        acceptance::attempt: &attempt_id,
        acceptance::response_code: response_code,
        acceptance::response: response,
    };
    let id = acceptance.root().expect("SMTP acceptance has one root");
    fragment += acceptance;
    Ok((fragment, id))
}

pub fn read_observation_fragment(wire_id: Id, reader: Id) -> (Fragment, Id) {
    let fragment = entity! {
        metadata::tag: &KIND_READ_OBSERVATION,
        read::wire: &wire_id,
        read::reader: &reader,
    };
    let id = fragment.root().expect("read observation has one root");
    (fragment, id)
}

fn read_local_text(fragment: &Fragment, handle: TextHandle) -> Result<String> {
    let mut local = fragment.clone();
    let reader = local
        .blobs_mut()
        .reader()
        .expect("memory blob reader creation is infallible");
    let value: View<str> = reader.get(handle).context("read staged Mail text")?;
    Ok(value.to_string())
}

pub fn read_text(reader: &PileReader, handle: TextHandle) -> Result<String> {
    let value: View<str> = reader
        .get(handle)
        .with_context(|| format!("read Mail text blob {}", hex::encode(handle.raw)))?;
    Ok(value.to_string())
}

pub fn read_bytes(reader: &PileReader, handle: BytesHandle) -> Result<Vec<u8>> {
    let value: anybytes::Bytes = reader
        .get(handle)
        .with_context(|| format!("read Mail byte blob {}", hex::encode(handle.raw)))?;
    Ok(value.as_ref().to_vec())
}

fn text_union<Overlay: BlobStoreGet>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    handle: TextHandle,
) -> Result<String> {
    if let Ok(value) = reader.get::<View<str>, _>(handle) {
        return Ok(value.to_string());
    }
    if let Some(overlay) = overlay {
        let value: View<str> = overlay
            .get(handle)
            .with_context(|| format!("read staged Mail text {}", hex::encode(handle.raw)))?;
        return Ok(value.to_string());
    }
    bail!("missing Mail text blob {}", hex::encode(handle.raw))
}

fn bytes_union<Overlay: BlobStoreGet>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    handle: BytesHandle,
) -> Result<Vec<u8>> {
    if let Ok(value) = reader.get::<anybytes::Bytes, _>(handle) {
        return Ok(value.as_ref().to_vec());
    }
    if let Some(overlay) = overlay {
        let value: anybytes::Bytes = overlay
            .get(handle)
            .with_context(|| format!("read staged Mail bytes {}", hex::encode(handle.raw)))?;
        return Ok(value.as_ref().to_vec());
    }
    bail!("missing Mail byte blob {}", hex::encode(handle.raw))
}

fn validate_source_text_payloads<Overlay: BlobStoreGet>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    source_facts: &TribleSet,
) -> Result<()> {
    let attributes = BTreeSet::from([
        wire::claimed_message_id.id(),
        projection::from.id(),
        projection::to.id(),
        projection::cc.id(),
        projection::bcc.id(),
        projection::subject.id(),
        projection::body.id(),
    ]);
    let handles: BTreeSet<TextHandle> = source_facts
        .iter()
        .filter(|fact| attributes.contains(fact.a()))
        .map(|fact| *fact.v::<inlineencodings::Handle<blobencodings::LongString>>())
        .collect();
    for handle in handles {
        text_union(reader, overlay, handle)?;
    }
    Ok(())
}

fn credential_envelope_record(secret: Id, box_handle: BytesHandle) -> Fragment {
    entity! {
        metadata::tag: &KIND_CREDENTIAL_ENVELOPE,
        credential::of: &secret,
        credential::r#box: box_handle,
    }
}

fn draft_from_facts(facts: &TribleSet, id: Id) -> Result<DraftRecord> {
    Ok(DraftRecord {
        id,
        nonce: required(
            find!(v: Id, pattern!(facts, [{ id @ draft::nonce: ?v }])).collect(),
            "draft nonce",
        )?,
        account: required(
            find!(v: Id, pattern!(facts, [{ id @ draft::account: ?v }])).collect(),
            "draft account",
        )?,
        envelope_from: required(
            find!(v: TextHandle, pattern!(facts, [{ id @ draft::envelope_from: ?v }])).collect(),
            "draft envelope sender",
        )?,
        to: find!(v: TextHandle, pattern!(facts, [{ id @ draft::to: ?v }]))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        cc: find!(v: TextHandle, pattern!(facts, [{ id @ draft::cc: ?v }]))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        bcc: find!(v: TextHandle, pattern!(facts, [{ id @ draft::bcc: ?v }]))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        subject: required(
            find!(v: TextHandle, pattern!(facts, [{ id @ draft::subject: ?v }])).collect(),
            "draft subject",
        )?,
        body: required(
            find!(v: TextHandle, pattern!(facts, [{ id @ draft::body: ?v }])).collect(),
            "draft body",
        )?,
        attachments: sorted_ids(find!(v: Id, pattern!(facts, [{ id @ draft::attachment: ?v }]))),
        in_reply_to: sorted_ids(find!(v: Id, pattern!(facts, [{ id @ draft::in_reply_to: ?v }]))),
        references: sorted_ids(find!(v: Id, pattern!(facts, [{ id @ draft::reference: ?v }]))),
        created_at: required(
            find!(v: IntervalValue, pattern!(facts, [{ id @ metadata::created_at: ?v }])).collect(),
            "draft creation time",
        )?,
    })
}

pub fn draft_value(facts: &TribleSet, id: Id) -> Result<DraftRecord> {
    if !ids_of_kind(facts, KIND_DRAFT_INTENT).contains(&id) {
        bail!("unknown draft {id:x}");
    }
    draft_from_facts(facts, id)
}

fn attempt_from_facts(facts: &TribleSet, id: Id) -> Result<SendAttemptRecord> {
    Ok(SendAttemptRecord {
        id,
        draft: required(
            find!(v: Id, pattern!(facts, [{ id @ attempt::draft: ?v }])).collect(),
            "attempt draft",
        )?,
        config: required(
            find!(v: Id, pattern!(facts, [{ id @ attempt::config: ?v }])).collect(),
            "attempt config",
        )?,
        decision: required(
            find!(v: Id, pattern!(facts, [{ id @ attempt::decision: ?v }])).collect(),
            "attempt decision",
        )?,
        decision_heads: sorted_ids(
            find!(v: Id, pattern!(facts, [{ id @ attempt::decision_head: ?v }])),
        ),
        raw: required(
            find!(v: BytesHandle, pattern!(facts, [{ id @ attempt::raw: ?v }])).collect(),
            "attempt raw message",
        )?,
        envelope_from: required(
            find!(v: TextHandle, pattern!(facts, [{ id @ attempt::envelope_from: ?v }])).collect(),
            "attempt envelope sender",
        )?,
        to: find!(v: TextHandle, pattern!(facts, [{ id @ attempt::to: ?v }]))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        cc: find!(v: TextHandle, pattern!(facts, [{ id @ attempt::cc: ?v }]))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        bcc: find!(v: TextHandle, pattern!(facts, [{ id @ attempt::bcc: ?v }]))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    })
}

pub fn send_attempt(facts: &TribleSet, id: Id) -> Result<SendAttemptRecord> {
    if !ids_of_kind(facts, KIND_SEND_ATTEMPT).contains(&id) {
        bail!("unknown send attempt {id:x}");
    }
    attempt_from_facts(facts, id)
}

pub fn attempts_for_draft(facts: &TribleSet, draft_id: Id) -> Vec<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: &KIND_SEND_ATTEMPT, attempt::draft: &draft_id }]))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn acceptances_for_attempt(facts: &TribleSet, attempt_id: Id) -> Vec<Id> {
    find!(id: Id, pattern!(facts, [{ ?id @ metadata::tag: &KIND_SMTP_ACCEPTANCE, acceptance::attempt: &attempt_id }]))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Resolve the exact Decide frontier which authorizes a send.
pub fn authorized_send(
    reader: &PileReader,
    decide_facts: &TribleSet,
    draft_id: Id,
) -> Result<(Id, Vec<Id>)> {
    let decision = draft_decision_id(draft_id);
    let snapshots = match decide::resolution(decide_facts, decision) {
        Resolution::Unique(snapshot) => vec![snapshot],
        Resolution::Agreed(snapshots) => snapshots,
        Resolution::Missing => bail!("send decision {decision:x} has no resolution"),
        Resolution::Forked(heads) => {
            bail!(
                "send decision {decision:x} has divergent heads: {:?}",
                sorted_ids(heads.into_iter().map(|head| head.id))
            )
        }
        Resolution::Invalid(error) => bail!("send decision {decision:x} is invalid: {error}"),
    };
    if snapshots.is_empty() {
        bail!("send decision {decision:x} resolved to an empty frontier");
    }
    for snapshot in &snapshots {
        let outcome = decide::read_text(reader, snapshot.outcome)?;
        if outcome != "send" {
            bail!("send decision {decision:x} resolves to {outcome:?}, not exact outcome \"send\"");
        }
    }
    Ok((
        decision,
        sorted_ids(snapshots.into_iter().map(|snapshot| snapshot.id)),
    ))
}

fn open_credential(
    reader: &PileReader,
    facts: &TribleSet,
    credential_id: Id,
    passphrase: &[u8],
) -> Result<String> {
    let boxes: BTreeSet<BytesHandle> = find!(
        box_handle: BytesHandle,
        pattern!(facts, [{ _?envelope @
            metadata::tag: &KIND_CREDENTIAL_ENVELOPE,
            credential::of: &credential_id,
            credential::r#box: ?box_handle,
        }])
    )
    .collect();
    if boxes.is_empty() {
        bail!("credential {credential_id:x} has no envelope");
    }
    let mut opened = BTreeSet::new();
    for handle in boxes {
        let bytes = read_bytes(reader, handle)?;
        if let Ok(plaintext) = unlock(passphrase, &bytes) {
            let value =
                String::from_utf8(plaintext).context("credential plaintext is not UTF-8")?;
            opened.insert(value);
        }
    }
    match opened.len() {
        0 => bail!("no envelope for credential {credential_id:x} opens with this passphrase"),
        1 => Ok(opened.pop_first().unwrap()),
        _ => bail!("credential {credential_id:x} has disagreeing decryptable envelopes"),
    }
}

pub fn open_account(
    reader: &PileReader,
    facts: &TribleSet,
    anchor: Id,
    passphrase: &[u8],
) -> Result<OpenAccount> {
    let config_id = match account_head(facts, anchor)? {
        Head::Unique(id) => id,
        Head::Missing => bail!("mail account {anchor:x} has no configuration"),
        Head::Forked(ids) => {
            bail!("mail account {anchor:x} has forked configuration heads: {ids:?}")
        }
    };
    let config = account_config(facts, config_id)?;
    Ok(OpenAccount {
        anchor,
        config: config_id,
        address: read_text(reader, config.address)?,
        display_name: read_text(reader, config.display_name)?,
        pop_endpoint: read_text(reader, config.pop_endpoint)?,
        smtp_endpoint: read_text(reader, config.smtp_endpoint)?,
        username: read_text(reader, config.username)?,
        password: open_credential(reader, facts, config.credential, passphrase)?,
        enabled: config.enabled,
    })
}

fn config_owner_map(facts: &TribleSet) -> Result<HashMap<Id, AccountConfigRecord>> {
    ids_of_kind(facts, KIND_ACCOUNT_CONFIG)
        .into_iter()
        .map(|id| account_config(facts, id).map(|record| (id, record)))
        .collect()
}

fn validate_send_heads(
    reader: &PileReader,
    decide_facts: &TribleSet,
    decision: Id,
    heads: &[Id],
) -> Result<()> {
    if heads.is_empty() {
        bail!("send attempt records no decision frontier");
    }
    let selected: BTreeSet<Id> = heads.iter().copied().collect();
    let mut forced = BTreeSet::new();
    for &head in heads {
        let snapshot = decide::resolution_snapshot(decide_facts, head)?;
        if snapshot.decision != decision {
            bail!("resolution {head:x} belongs to another decision");
        }
        if decide::read_text(reader, snapshot.outcome)? != "send" {
            bail!("resolution {head:x} does not carry exact outcome \"send\"");
        }
        forced.insert(snapshot.forced);
    }
    if forced.len() != 1 {
        bail!("stored send frontier does not have Agreed semantics");
    }

    // A genuine frontier is an antichain. Completeness at the historical
    // executor snapshot is an attestation, but an ancestor and descendant can
    // never both have been heads of the same resolution DAG.
    for &head in heads {
        let mut stack = decide::resolution_snapshot(decide_facts, head)?.predecessors;
        let mut visited = BTreeSet::new();
        while let Some(ancestor) = stack.pop() {
            if !visited.insert(ancestor) {
                continue;
            }
            if selected.contains(&ancestor) {
                bail!(
                    "stored send frontier contains both resolution {ancestor:x} and a descendant"
                );
            }
            let snapshot = decide::resolution_snapshot(decide_facts, ancestor)?;
            if snapshot.decision != decision {
                bail!("resolution {ancestor:x} belongs to another decision");
            }
            stack.extend(snapshot.predecessors);
        }
    }
    Ok(())
}

fn normalized_mailboxes(
    values: impl IntoIterator<Item = String>,
) -> Result<Vec<(Option<String>, String)>> {
    let mut out = Vec::new();
    for value in values {
        let parsed = mailparse::addrparse(&value)
            .with_context(|| format!("parse mailbox claim {value:?}"))?;
        for address in parsed.iter() {
            match address {
                mailparse::MailAddr::Single(single) => {
                    out.push((single.display_name.clone(), single.addr.clone()));
                }
                mailparse::MailAddr::Group(group) => {
                    out.extend(
                        group
                            .addrs
                            .iter()
                            .map(|single| (single.display_name.clone(), single.addr.clone())),
                    );
                }
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn validate_attempt_rendering(
    reader: &PileReader,
    overlay: Option<&impl BlobStoreGet>,
    mail_facts: &TribleSet,
    files_facts: &TribleSet,
    attempt: &SendAttemptRecord,
    draft: &DraftRecord,
    config: &AccountConfigRecord,
) -> Result<()> {
    let raw = bytes_union(reader, overlay, attempt.raw)?;
    let parsed = parse_rfc5322(&raw).context("parse frozen send-attempt bytes")?;
    let materialized = materialize_draft(reader, mail_facts, files_facts, draft.id)?;

    let expected_message_id = format!("mail-{}@triblespace", draft.id);
    if parsed.identity != WireIdentity::Claimed(expected_message_id.clone()) {
        bail!(
            "attempt Message-ID {:?} does not match deterministic draft id {:?}",
            parsed.identity,
            expected_message_id
        );
    }
    if parsed.subject != materialized.subject || parsed.body != materialized.body {
        bail!("attempt wire subject/body does not equal the authorized DraftIntent");
    }
    if parsed.attachments != materialized.attachments {
        bail!("attempt wire attachments do not equal the authorized DraftIntent");
    }
    if parsed.spam {
        bail!("locally rendered attempt unexpectedly claims spam status");
    }
    if !parsed.bcc.is_empty() {
        bail!("attempt wire leaks Bcc headers; Bcc is envelope-only");
    }

    let expected_from = normalized_mailboxes([format!(
        "{} <{}>",
        text_union(reader, overlay, config.display_name)?,
        materialized.envelope_from
    )])?;
    let actual_from = normalized_mailboxes(parsed.from.into_iter())?;
    if actual_from != expected_from {
        bail!("attempt wire From does not equal the frozen account/draft sender");
    }
    if normalized_mailboxes(parsed.to)? != normalized_mailboxes(materialized.to.clone())?
        || normalized_mailboxes(parsed.cc)? != normalized_mailboxes(materialized.cc.clone())?
    {
        bail!("attempt wire recipients do not equal the authorized DraftIntent");
    }
    let expected_reply = sorted_ids(
        materialized
            .in_reply_to
            .iter()
            .map(|value| wire_id_for(value))
            .collect::<Result<Vec<_>>>()?,
    );
    let expected_references = sorted_ids(
        materialized
            .references
            .iter()
            .map(|value| wire_id_for(value))
            .collect::<Result<Vec<_>>>()?,
    );
    let actual_reply = sorted_ids(
        parsed
            .in_reply_to
            .iter()
            .map(|value| wire_id_for(value))
            .collect::<Result<Vec<_>>>()?,
    );
    let actual_references = sorted_ids(
        parsed
            .references
            .iter()
            .map(|value| wire_id_for(value))
            .collect::<Result<Vec<_>>>()?,
    );
    if actual_reply != expected_reply || actual_references != expected_references {
        bail!("attempt wire thread headers do not equal the authorized DraftIntent");
    }
    let expected_date: (Epoch, Epoch) = draft
        .created_at
        .try_from_inline()
        .map_err(|error| anyhow!("decode draft creation time: {error:?}"))?;
    let actual_date = parsed
        .claimed_date
        .ok_or_else(|| anyhow!("attempt wire has no Date header"))?;
    let actual_date: (Epoch, Epoch) = actual_date
        .try_from_inline()
        .map_err(|error| anyhow!("decode attempt Date: {error:?}"))?;
    if actual_date.0.to_unix_seconds().trunc() as i64
        != expected_date.0.to_unix_seconds().trunc() as i64
    {
        bail!("attempt wire Date does not equal the draft creation second");
    }
    Ok(())
}

/// Exact structural and cross-collection validation for one Mail materialization.
pub fn validate_catalog(
    reader: &PileReader,
    facts: &TribleSet,
    files_facts: &TribleSet,
    decide_facts: &TribleSet,
    relations_facts: &TribleSet,
) -> Result<()> {
    validate_catalog_inner(
        reader,
        None::<&PileReader>,
        facts,
        files_facts,
        decide_facts,
        relations_facts,
    )
}

/// Preflight the exact set union a Mail publication would create, including
/// the new fragment's in-memory blobs, without writing pile bytes.
pub fn validate_catalog_union(
    reader: &PileReader,
    current: &TribleSet,
    fragment: &Fragment,
    files_facts: &TribleSet,
    decide_facts: &TribleSet,
    relations_facts: &TribleSet,
) -> Result<TribleSet> {
    let mut expected = current.clone();
    expected += fragment.facts().clone();
    let mut staged = fragment.clone();
    let overlay = staged
        .blobs_mut()
        .reader()
        .expect("memory blob reader creation is infallible");
    validate_catalog_inner(
        reader,
        Some(&overlay),
        &expected,
        files_facts,
        decide_facts,
        relations_facts,
    )?;
    Ok(expected)
}

fn validate_catalog_inner<Overlay: BlobStoreGet>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    facts: &TribleSet,
    files_facts: &TribleSet,
    decide_facts: &TribleSet,
    relations_facts: &TribleSet,
) -> Result<()> {
    let accounts = account_anchors(facts);
    let credentials = ids_of_kind(facts, KIND_CREDENTIAL);
    let configs = config_owner_map(facts)?;
    let wires: BTreeSet<_> = ids_of_kind(facts, KIND_WIRE_MESSAGE);
    let drafts: BTreeSet<_> = ids_of_kind(facts, KIND_DRAFT_INTENT);
    let attempts: BTreeSet<_> = ids_of_kind(facts, KIND_SEND_ATTEMPT);
    let acceptances: BTreeSet<_> = ids_of_kind(facts, KIND_SMTP_ACCEPTANCE);
    let reads: BTreeSet<_> = ids_of_kind(facts, KIND_READ_OBSERVATION);
    let pop_observations: BTreeSet<_> = ids_of_kind(facts, KIND_POP_OBSERVATION);
    let outgoing_observations: BTreeSet<_> = ids_of_kind(facts, KIND_OUTGOING_OBSERVATION);
    let mut expected = TribleSet::new();

    for &anchor in &accounts {
        expected += account_anchor_record(anchor);
    }
    for (&id, record) in &configs {
        if !accounts.contains(&record.account) {
            bail!(
                "account config {id:x} names unknown account {:x}",
                record.account
            );
        }
        if !credentials.contains(&record.credential) {
            bail!(
                "account config {id:x} names unknown credential {:x}",
                record.credential
            );
        }
        for handle in [
            record.address,
            record.display_name,
            record.pop_endpoint,
            record.smtp_endpoint,
            record.username,
        ] {
            canonical_nonempty(text_union(reader, overlay, handle)?, "account config text")?;
        }
        expected += ensure_intrinsic(id, account_config_record(record), "account config")?;
    }
    for &anchor in &accounts {
        if matches!(account_head(facts, anchor)?, Head::Missing) {
            bail!("mail account {anchor:x} has no configuration");
        }
    }

    for &credential_id in &credentials {
        expected +=
            entity! { ExclusiveId::force_ref(&credential_id) @ metadata::tag: &KIND_CREDENTIAL };
        let envelope_ids: BTreeSet<Id> = find!(
            id: Id,
            pattern!(facts, [{ ?id @ metadata::tag: &KIND_CREDENTIAL_ENVELOPE, credential::of: &credential_id }])
        )
        .collect();
        if envelope_ids.is_empty() {
            bail!("credential {credential_id:x} has no envelope");
        }
        for id in envelope_ids {
            let box_handle = required(
                find!(v: BytesHandle, pattern!(facts, [{ id @ credential::r#box: ?v }])).collect(),
                "credential box",
            )?;
            bytes_union(reader, overlay, box_handle)?;
            expected += ensure_intrinsic(
                id,
                credential_envelope_record(credential_id, box_handle),
                "credential envelope",
            )?;
        }
    }
    for id in ids_of_kind(facts, KIND_CREDENTIAL_ENVELOPE) {
        let owner = required(
            find!(v: Id, pattern!(facts, [{ id @ credential::of: ?v }])).collect(),
            "credential envelope owner",
        )?;
        if !credentials.contains(&owner) {
            bail!("credential envelope {id:x} names unknown credential {owner:x}");
        }
    }

    for &wire_id in &wires {
        wire_claimed_message_id_union(reader, overlay, facts, wire_id)?;
    }

    for &id in &drafts {
        let record = draft_from_facts(facts, id)?;
        point_interval(record.created_at, "draft creation time")?;
        if !accounts.contains(&record.account) {
            bail!("draft {id:x} names unknown account {:x}", record.account);
        }
        if record.to.is_empty() && record.cc.is_empty() && record.bcc.is_empty() {
            bail!("draft {id:x} has no recipients");
        }
        for attachment in &record.attachments {
            if files::entity_kind(files_facts, *attachment)? != Some(FileEntityKind::File) {
                bail!("draft {id:x} names non-file attachment {attachment:x}");
            }
        }
        for wire_id in record.in_reply_to.iter().chain(&record.references) {
            if !wires.contains(wire_id) {
                bail!("draft {id:x} names non-resident thread wire {wire_id:x}");
            }
            if wire_claimed_message_id_union(reader, overlay, facts, *wire_id)?.is_none() {
                bail!("draft {id:x} names digest-only thread wire {wire_id:x}");
            }
        }
        for handle in record
            .to
            .iter()
            .chain(&record.cc)
            .chain(&record.bcc)
            .chain([&record.envelope_from])
        {
            canonical_nonempty(
                text_union(reader, overlay, *handle)?,
                "draft envelope address",
            )?;
        }
        exact_text(
            text_union(reader, overlay, record.subject)?,
            "draft subject",
        )?;
        exact_text(text_union(reader, overlay, record.body)?, "draft body")?;
        expected += ensure_intrinsic(id, draft_record(&record), "draft intent")?;

        let decision = draft_decision_id(id);
        if !exists!(pattern!(decide_facts, [{ decision @ metadata::tag: &KIND_DECISION }])) {
            bail!("draft {id:x} has no deterministic Decide anchor {decision:x}");
        }
        let genesis = decide::genesis_for_decision(decide_facts, decision)?
            .ok_or_else(|| anyhow!("draft decision {decision:x} has no genesis"))?;
        if genesis.about != Some(id) {
            bail!("draft decision {decision:x} does not concern draft {id:x}");
        }
    }

    for &id in &attempts {
        let record = attempt_from_facts(facts, id)?;
        let draft = draft_from_facts(facts, record.draft)
            .with_context(|| format!("attempt {id:x} names invalid draft"))?;
        let config = configs
            .get(&record.config)
            .ok_or_else(|| anyhow!("attempt {id:x} names unknown config {:x}", record.config))?;
        if config.account != draft.account {
            bail!("attempt {id:x} config and draft belong to different accounts");
        }
        if !config.enabled {
            bail!("attempt {id:x} cites a disabled account configuration");
        }
        if config.address != draft.envelope_from {
            bail!("attempt {id:x} draft sender differs from its account configuration");
        }
        if record.decision != draft_decision_id(record.draft) {
            bail!("attempt {id:x} names the wrong deterministic decision");
        }
        validate_send_heads(
            reader,
            decide_facts,
            record.decision,
            &record.decision_heads,
        )?;
        if record.envelope_from != draft.envelope_from
            || record.to != draft.to
            || record.cc != draft.cc
            || record.bcc != draft.bcc
        {
            bail!("attempt {id:x} does not preserve the draft's exact envelope");
        }
        validate_attempt_rendering(reader, overlay, facts, files_facts, &record, &draft, config)?;
        expected += ensure_intrinsic(id, attempt_record(&record), "send attempt")?;
    }
    for &draft_id in &drafts {
        let draft_attempts = attempts_for_draft(facts, draft_id);
        if draft_attempts.len() > 1 {
            bail!("draft {draft_id:x} has multiple send attempts; uncertain attempts are never retried");
        }
    }

    for &id in &acceptances {
        let attempt_id = required(
            find!(v: Id, pattern!(facts, [{ id @ acceptance::attempt: ?v }])).collect(),
            "SMTP acceptance attempt",
        )?;
        if !attempts.contains(&attempt_id) {
            bail!("SMTP acceptance {id:x} names unknown attempt {attempt_id:x}");
        }
        let response = required(
            find!(v: TextHandle, pattern!(facts, [{ id @ acceptance::response: ?v }])).collect(),
            "SMTP acceptance response",
        )?;
        canonical_nonempty(text_union(reader, overlay, response)?, "SMTP response")?;
        let code = required(
            find!(v: CountValue, pattern!(facts, [{ id @ acceptance::response_code: ?v }]))
                .collect(),
            "SMTP acceptance response code",
        )?;
        let numeric_code = u64::try_from_inline(&code)
            .map_err(|_| anyhow!("SMTP acceptance {id:x} response code exceeds u64"))?;
        if !(200..=299).contains(&numeric_code) {
            bail!("SMTP acceptance {id:x} has non-positive reply code {numeric_code}");
        }
        let outgoing: BTreeSet<Id> = find!(
            source: Id,
            pattern!(facts, [{ ?source @
                metadata::tag: &KIND_OUTGOING_OBSERVATION,
                observation::attempt: &attempt_id,
            }])
        )
        .collect();
        if outgoing.len() != 1 {
            bail!(
                "SMTP acceptance {id:x} must have exactly one outgoing observation, found {}",
                outgoing.len()
            );
        }
        expected += ensure_intrinsic(
            id,
            entity! {
                metadata::tag: &KIND_SMTP_ACCEPTANCE,
                acceptance::attempt: &attempt_id,
                acceptance::response_code: code,
                acceptance::response: response,
            },
            "SMTP acceptance",
        )?;
    }
    for &attempt_id in &attempts {
        let receipts = acceptances_for_attempt(facts, attempt_id);
        if receipts.len() > 1 {
            bail!("send attempt {attempt_id:x} has multiple SMTP acceptance receipts");
        }
        let outgoing: BTreeSet<Id> = find!(
            source: Id,
            pattern!(facts, [{ ?source @
                metadata::tag: &KIND_OUTGOING_OBSERVATION,
                observation::attempt: &attempt_id,
            }])
        )
        .collect();
        if outgoing.len() > 1 {
            bail!("send attempt {attempt_id:x} has multiple outgoing observations");
        }
    }

    for &id in &pop_observations {
        let account_id = required(
            find!(v: Id, pattern!(facts, [{ id @ observation::account: ?v }])).collect(),
            "POP observation account",
        )?;
        if !accounts.contains(&account_id) {
            bail!("POP observation {id:x} names unknown account {account_id:x}");
        }
        let config_id = required(
            find!(v: Id, pattern!(facts, [{ id @ observation::config: ?v }])).collect(),
            "POP observation config",
        )?;
        let config = configs
            .get(&config_id)
            .ok_or_else(|| anyhow!("POP observation {id:x} names unknown config {config_id:x}"))?;
        if config.account != account_id {
            bail!("POP observation {id:x} config belongs to another account");
        }
        if !config.enabled {
            bail!("POP observation {id:x} cites a disabled account configuration");
        }
        let uidl = required(
            find!(v: TextHandle, pattern!(facts, [{ id @ observation::uidl: ?v }])).collect(),
            "POP UIDL",
        )?;
        let raw = required(
            find!(v: BytesHandle, pattern!(facts, [{ id @ observation::raw: ?v }])).collect(),
            "POP raw message",
        )?;
        let uidl = text_union(reader, overlay, uidl)?;
        let raw = bytes_union(reader, overlay, raw)?;
        let publication = pop_publication(account_id, config_id, &uidl, &raw)?;
        if publication.observation != id {
            bail!("POP observation {id:x} does not match exact source evidence");
        }
        validate_source_text_payloads(reader, overlay, publication.mail.facts())?;
        for fact in publication.files.facts() {
            if !files_facts.contains(fact) {
                bail!("POP observation {id:x} has unpublished Files attachment evidence");
            }
        }
        expected += publication.mail.into_facts();
    }

    for &id in &outgoing_observations {
        let attempt_id = required(
            find!(v: Id, pattern!(facts, [{ id @ observation::attempt: ?v }])).collect(),
            "outgoing observation attempt",
        )?;
        if acceptances_for_attempt(facts, attempt_id).is_empty() {
            bail!("outgoing observation {id:x} has no SMTP acceptance");
        }
        let raw = required(
            find!(v: BytesHandle, pattern!(facts, [{ id @ observation::raw: ?v }])).collect(),
            "outgoing raw message",
        )?;
        let attempt_raw = attempt_from_facts(facts, attempt_id)?.raw;
        if raw != attempt_raw {
            bail!("outgoing observation {id:x} bytes differ from its frozen send attempt");
        }
        let raw = bytes_union(reader, overlay, raw)?;
        let publication = outgoing_publication(attempt_id, &raw)?;
        if publication.observation != id {
            bail!("outgoing observation {id:x} does not match accepted bytes");
        }
        validate_source_text_payloads(reader, overlay, publication.mail.facts())?;
        for fact in publication.files.facts() {
            if !files_facts.contains(fact) {
                bail!("outgoing observation {id:x} has unpublished Files attachment evidence");
            }
        }
        expected += publication.mail.into_facts();
    }

    let inbound_wires: BTreeSet<Id> = find!(
        wire_id: Id,
        pattern!(facts, [{ _?source @ metadata::tag: &KIND_POP_OBSERVATION, observation::wire: ?wire_id }])
    )
    .collect();
    let identities = IdentityComponents::from_facts(relations_facts)?;
    for &id in &reads {
        let wire_id = required(
            find!(v: Id, pattern!(facts, [{ id @ read::wire: ?v }])).collect(),
            "read wire",
        )?;
        let reader_id = required(
            find!(v: Id, pattern!(facts, [{ id @ read::reader: ?v }])).collect(),
            "read persona",
        )?;
        if !inbound_wires.contains(&wire_id) {
            bail!("read observation {id:x} does not name an inbound wire message");
        }
        identities.component(reader_id)?;
        expected += ensure_intrinsic(
            id,
            read_observation_fragment(wire_id, reader_id).0,
            "read observation",
        )?;
    }

    if expected != *facts {
        let unexpected = facts.iter().filter(|fact| !expected.contains(fact)).count();
        let missing = expected.iter().filter(|fact| !facts.contains(fact)).count();
        bail!("Mail catalog is not its exact canonical reconstruction ({unexpected} unexpected facts, {missing} missing facts)");
    }
    Ok(())
}

/// Project every inbound parser result and its read state for one exact
/// persona component.  A later observation of the same WireMessage does not
/// reopen it because read evidence is keyed by `(wire, reader)`.
pub fn inbox_projection(
    mail_facts: &TribleSet,
    relations_facts: &TribleSet,
    persona: Id,
) -> Result<Vec<InboxProjection>> {
    let identities = IdentityComponents::from_facts(relations_facts)?;
    let component = identities.component(persona)?;
    let read_wires: BTreeSet<Id> = find!(
        (wire_id: Id, reader_id: Id),
        pattern!(mail_facts, [{ _?read @
            metadata::tag: &KIND_READ_OBSERVATION,
            read::wire: ?wire_id,
            read::reader: ?reader_id,
        }])
    )
    .filter_map(|(wire_id, reader_id)| component.contains(&reader_id).then_some(wire_id))
    .collect();
    let sources: BTreeMap<Id, Id> = find!(
        (source: Id, wire_id: Id),
        pattern!(mail_facts, [{ ?source @
            metadata::tag: &KIND_POP_OBSERVATION,
            observation::wire: ?wire_id,
        }])
    )
    .collect();
    let mut rows = Vec::new();
    for (source, wire) in sources {
        for projection_id in find!(
            id: Id,
            pattern!(mail_facts, [{ ?id @
                metadata::tag: &KIND_PARSED_PROJECTION,
                projection::source: &source,
                projection::recipe: &RECIPE_RFC5322_V1,
            }])
        ) {
            rows.push(InboxProjection {
                wire,
                projection: projection_id,
                source,
                unread: !read_wires.contains(&wire),
            });
        }
    }
    rows.sort_by_key(|row| (row.wire, row.source, row.projection));
    Ok(rows)
}

fn text_values(
    reader: &PileReader,
    facts: &TribleSet,
    id: Id,
    attribute: Id,
) -> Result<Vec<String>> {
    let handles: BTreeSet<TextHandle> = facts
        .iter()
        .filter(|fact| fact.e() == &id && fact.a() == &attribute)
        .map(|fact| *fact.v::<inlineencodings::Handle<blobencodings::LongString>>())
        .collect();
    handles
        .into_iter()
        .map(|handle| read_text(reader, handle))
        .collect()
}

pub fn projection_view(
    reader: &PileReader,
    facts: &TribleSet,
    projection_id: Id,
) -> Result<ProjectionView> {
    if !ids_of_kind(facts, KIND_PARSED_PROJECTION).contains(&projection_id) {
        bail!("unknown Mail projection {projection_id:x}");
    }
    let source = required(
        find!(v: Id, pattern!(facts, [{ projection_id @ projection::source: ?v }])).collect(),
        "projection source",
    )?;
    let wire_id = required(
        find!(v: Id, pattern!(facts, [{ source @ observation::wire: ?v }])).collect(),
        "source wire message",
    )?;
    let from_handle = one(
        find!(v: TextHandle, pattern!(facts, [{ projection_id @ projection::from: ?v }])).collect(),
        "projection From",
    )?;
    let subject = required(
        find!(v: TextHandle, pattern!(facts, [{ projection_id @ projection::subject: ?v }]))
            .collect(),
        "projection subject",
    )?;
    let body = required(
        find!(v: TextHandle, pattern!(facts, [{ projection_id @ projection::body: ?v }])).collect(),
        "projection body",
    )?;
    Ok(ProjectionView {
        id: projection_id,
        source,
        wire: wire_id,
        message_id: wire_claimed_message_id(reader, facts, wire_id)?,
        from: from_handle.map(|handle| read_text(reader, handle)).transpose()?,
        to: text_values(reader, facts, projection_id, projection::to.id())?,
        cc: text_values(reader, facts, projection_id, projection::cc.id())?,
        bcc: text_values(reader, facts, projection_id, projection::bcc.id())?,
        subject: read_text(reader, subject)?,
        body: read_text(reader, body)?,
        claimed_date: one(
            find!(v: IntervalValue, pattern!(facts, [{ projection_id @ projection::claimed_date: ?v }])).collect(),
            "projection claimed date",
        )?,
        in_reply_to: sorted_ids(find!(v: Id, pattern!(facts, [{ projection_id @ projection::in_reply_to: ?v }]))),
        references: sorted_ids(find!(v: Id, pattern!(facts, [{ projection_id @ projection::reference: ?v }]))),
        spam: required(
            find!(v: bool, pattern!(facts, [{ projection_id @ projection::spam: ?v }])).collect(),
            "projection spam flag",
        )?,
        attachments: sorted_ids(find!(v: Id, pattern!(facts, [{ projection_id @ projection::attachment: ?v }]))),
    })
}

fn wire_claimed_message_id_union<Overlay: BlobStoreGet>(
    reader: &PileReader,
    overlay: Option<&Overlay>,
    facts: &TribleSet,
    wire_id: Id,
) -> Result<Option<String>> {
    let claimed = one(
        find!(v: TextHandle, pattern!(facts, [{ wire_id @ wire::claimed_message_id: ?v }]))
            .collect(),
        "wire claimed Message-ID",
    )?;
    let digest = one(
        find!(v: DigestValue, pattern!(facts, [{ wire_id @ wire::raw_digest: ?v }])).collect(),
        "wire raw digest",
    )?;
    match (claimed, digest) {
        (Some(handle), None) => Ok(Some(canonical_message_id_value(&text_union(
            reader, overlay, handle,
        )?)?)),
        (None, Some(_)) => Ok(None),
        (Some(_), Some(_)) => bail!("wire {wire_id:x} mixes claimed and raw-digest identity"),
        (None, None) => bail!("wire {wire_id:x} has no identity"),
    }
}

pub fn wire_claimed_message_id(
    reader: &PileReader,
    facts: &TribleSet,
    wire_id: Id,
) -> Result<Option<String>> {
    if !ids_of_kind(facts, KIND_WIRE_MESSAGE).contains(&wire_id) {
        bail!("unknown wire message {wire_id:x}");
    }
    wire_claimed_message_id_union(reader, None::<&PileReader>, facts, wire_id)
}

pub fn materialize_draft(
    reader: &PileReader,
    mail_facts: &TribleSet,
    files_facts: &TribleSet,
    id: Id,
) -> Result<MaterializedDraft> {
    let record = draft_value(mail_facts, id)?;
    let read_all = |handles: &[TextHandle]| -> Result<Vec<String>> {
        handles
            .iter()
            .map(|&handle| read_text(reader, handle))
            .collect()
    };
    let mut attachments = Vec::new();
    for file_id in &record.attachments {
        let content = files::content_handle(files_facts, *file_id)?
            .ok_or_else(|| anyhow!("attachment {file_id:x} has no content"))?;
        let bytes: anybytes::Bytes = reader
            .get(content)
            .with_context(|| format!("read attachment content {file_id:x}"))?;
        attachments.push(AttachmentData {
            filename: files::read_name(files_facts, reader, *file_id)?
                .ok_or_else(|| anyhow!("attachment {file_id:x} has no name"))?,
            media_type: files::read_media_type(files_facts, reader, *file_id)?
                .ok_or_else(|| anyhow!("attachment {file_id:x} has no media type"))?,
            bytes: bytes.as_ref().to_vec(),
        });
    }
    Ok(MaterializedDraft {
        id,
        account: record.account,
        envelope_from: read_text(reader, record.envelope_from)?,
        to: read_all(&record.to)?,
        cc: read_all(&record.cc)?,
        bcc: read_all(&record.bcc)?,
        subject: read_text(reader, record.subject)?,
        body: read_text(reader, record.body)?,
        attachments,
        in_reply_to: record
            .in_reply_to
            .iter()
            .map(|&wire| {
                wire_claimed_message_id(reader, mail_facts, wire)?
                    .ok_or_else(|| anyhow!("draft names digest-only In-Reply-To wire {wire:x}"))
            })
            .collect::<Result<_>>()?,
        references: record
            .references
            .iter()
            .map(|&wire| {
                wire_claimed_message_id(reader, mail_facts, wire)?
                    .ok_or_else(|| anyhow!("draft names digest-only References wire {wire:x}"))
            })
            .collect::<Result<_>>()?,
        created_at: record.created_at,
    })
}

/// Format a draft once. The returned bytes and envelope are what a caller must
/// freeze into SendAttempt before invoking SMTP.
pub fn render_draft(draft: &MaterializedDraft, account: &OpenAccount) -> Result<RenderedMail> {
    if draft.account != account.anchor {
        bail!("draft and account do not share an anchor");
    }
    if draft.envelope_from != account.address {
        bail!("draft sender does not match the frozen account address");
    }
    let from: Mailbox = format!("{} <{}>", account.display_name, draft.envelope_from)
        .parse()
        .context("parse draft From mailbox")?;
    let mut builder = Message::builder()
        .from(from)
        .message_id(Some(format!("<mail-{}@triblespace>", draft.id)))
        .subject(draft.subject.clone());
    let (start, _): (Epoch, Epoch) = draft
        .created_at
        .try_from_inline()
        .map_err(|error| anyhow!("decode draft creation time: {error:?}"))?;
    let unix = start.to_unix_seconds();
    if unix >= 0.0 {
        builder = builder.date(std::time::UNIX_EPOCH + std::time::Duration::from_secs_f64(unix));
    }
    let mut recipients = Vec::new();
    for value in &draft.to {
        let mailbox: Mailbox = value
            .parse()
            .with_context(|| format!("parse To {value:?}"))?;
        recipients.push(mailbox.email.to_string());
        builder = builder.to(mailbox);
    }
    for value in &draft.cc {
        let mailbox: Mailbox = value
            .parse()
            .with_context(|| format!("parse Cc {value:?}"))?;
        recipients.push(mailbox.email.to_string());
        builder = builder.cc(mailbox);
    }
    for value in &draft.bcc {
        let mailbox: Mailbox = value
            .parse()
            .with_context(|| format!("parse Bcc {value:?}"))?;
        recipients.push(mailbox.email.to_string());
        builder = builder.bcc(mailbox);
    }
    if !draft.in_reply_to.is_empty() {
        builder = builder.in_reply_to(
            draft
                .in_reply_to
                .iter()
                .map(|value| format!("<{value}>"))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    if !draft.references.is_empty() {
        builder = builder.references(
            draft
                .references
                .iter()
                .map(|value| format!("<{value}>"))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    let message = if draft.attachments.is_empty() {
        builder
            .header(header::ContentType::TEXT_PLAIN)
            .body(draft.body.clone())
            .context("format draft")?
    } else {
        // Lettre otherwise invents a random boundary here.  The immutable
        // draft id commits to the body and attachment identities, making it a
        // canonical boundary seed and therefore making raw rendering—and the
        // intrinsic SendAttempt that contains it—repeatable.
        let boundary = format!("=_triblespace_{:x}", draft.id);
        let mut multipart = MultiPart::mixed().boundary(boundary).singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_PLAIN)
                .body(draft.body.clone()),
        );
        for attachment in &draft.attachments {
            let content_type = header::ContentType::parse(&attachment.media_type)
                .unwrap_or(header::ContentType::parse(files::DEFAULT_MEDIA_TYPE).unwrap());
            multipart = multipart.singlepart(
                lettre::message::Attachment::new(attachment.filename.clone())
                    .body(attachment.bytes.clone(), content_type),
            );
        }
        builder
            .multipart(multipart)
            .context("format multipart draft")?
    };
    Ok(RenderedMail {
        raw: message.formatted(),
        envelope: SmtpEnvelope {
            from: draft.envelope_from.clone(),
            recipients,
        },
    })
}

// ── irreversible-effect protocol seams ────────────────────────────────────

pub use crate::mail_pop::PopItem;

/// One POP transaction. Implementations must make ordinary Drop disconnect
/// without issuing QUIT; only explicit `quit` may commit marked deletions.
pub trait PopTxn {
    fn enumerate_uidls(&mut self) -> Result<Vec<PopItem>>;
    fn retrieve_exact(&mut self, session_seq: u32) -> Result<Vec<u8>>;
    fn mark_delete(&mut self, session_seq: u32) -> Result<()>;
    fn quit(self) -> Result<()>;
}

/// Fetch every UIDL exactly under one frozen account configuration, publish
/// its evidence, then mark it for deletion.
/// Duplicate or zero session identities are protocol errors and no deletion is
/// attempted. A failed explicit QUIT is an uncertain remote transaction, not
/// evidence that already-marked deletions were rolled back.
pub fn drain_pop<T, F>(
    mut transaction: T,
    account_id: Id,
    config_id: Id,
    mut publish: F,
) -> Result<()>
where
    T: PopTxn,
    F: FnMut(&SourcePublication) -> Result<()>,
{
    let items = transaction.enumerate_uidls()?;
    let mut uidls = BTreeSet::new();
    let mut sequences = BTreeSet::new();
    for item in &items {
        if item.session_seq == 0 {
            bail!("POP server returned zero session sequence");
        }
        if !sequences.insert(item.session_seq) {
            bail!(
                "POP server returned duplicate session sequence {}",
                item.session_seq
            );
        }
        if !uidls.insert(item.uidl.clone()) {
            bail!("POP server returned duplicate UIDL {:?}", item.uidl);
        }
    }
    for item in items {
        let raw = transaction.retrieve_exact(item.session_seq)?;
        let publication = pop_publication(account_id, config_id, &item.uidl, &raw)?;
        publish(&publication)?;
        transaction.mark_delete(item.session_seq)?;
    }
    transaction
        .quit()
        .context("POP QUIT failed after delete marks; remote deletion commit is uncertain")
}

impl<S> PopTxn for crate::mail_pop::PopSession<S>
where
    S: std::io::Read + std::io::Write,
{
    fn enumerate_uidls(&mut self) -> Result<Vec<PopItem>> {
        Ok(self.uidl()?)
    }

    fn retrieve_exact(&mut self, session_seq: u32) -> Result<Vec<u8>> {
        Ok(self.retr(session_seq)?)
    }

    fn mark_delete(&mut self, session_seq: u32) -> Result<()> {
        self.dele(session_seq)?;
        Ok(())
    }

    fn quit(self) -> Result<()> {
        crate::mail_pop::PopSession::quit(self)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpEnvelope {
    pub from: String,
    pub recipients: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedReply {
    pub code: u16,
    pub message: String,
}

pub trait SmtpSubmit {
    /// Return only a final positive SMTP completion reply. Rejection or an
    /// indeterminate transport outcome is an error, after which the durable
    /// attempt must not be retried automatically.
    fn submit(&mut self, envelope: &SmtpEnvelope, raw: &[u8]) -> Result<AcceptedReply>;
}

fn smtp_envelope_for_attempt(input: &SendAttemptInput) -> Result<SmtpEnvelope> {
    let senders = normalized_mailboxes([input.envelope_from.clone()])?;
    let [(_, from)] = senders.as_slice() else {
        bail!("attempt envelope sender must contain exactly one mailbox");
    };
    let recipients =
        normalized_mailboxes(input.to.iter().chain(&input.cc).chain(&input.bcc).cloned())?
            .into_iter()
            .map(|(_, address)| address)
            .collect::<Vec<_>>();
    if recipients.is_empty() {
        bail!("send attempt has no envelope recipients");
    }
    Ok(SmtpEnvelope {
        from: from.clone(),
        recipients,
    })
}

/// Freeze and validate one exact SMTP effect plan against one local snapshot.
///
/// The stored Decide heads are the complete frontier observed by this
/// executor at preparation time. A later resolution does not retroactively
/// invalidate that historical authorization. Conversely, the eventual union
/// cannot prove that this local snapshot was globally fresh or complete: SMTP
/// execution is therefore an affine authority which deployments must
/// serialize per account rather than running concurrently on replicas.
#[allow(clippy::too_many_arguments)]
pub fn prepare_send(
    mail_reader: &PileReader,
    decide_reader: &PileReader,
    mail_facts: &TribleSet,
    files_facts: &TribleSet,
    decide_facts: &TribleSet,
    relations_facts: &TribleSet,
    input: SendAttemptInput,
) -> Result<PreparedSend> {
    let draft = draft_from_facts(mail_facts, input.draft)
        .with_context(|| format!("prepare send for unknown draft {:x}", input.draft))?;
    match account_head(mail_facts, draft.account)? {
        Head::Unique(current) if current == input.config => {}
        Head::Unique(current) => bail!(
            "send config {:x} is stale; current account config is {current:x}",
            input.config
        ),
        Head::Missing => bail!("draft account {:x} has no configuration", draft.account),
        Head::Forked(heads) => bail!(
            "draft account {:x} has forked configurations {heads:?}",
            draft.account
        ),
    }
    let (current_decision, current_heads) =
        authorized_send(decide_reader, decide_facts, input.draft)?;
    if input.decision != current_decision
        || sorted_ids(input.decision_heads.iter().copied()) != current_heads
    {
        bail!("send attempt does not cite the exact locally observed Decide frontier");
    }

    let envelope = smtp_envelope_for_attempt(&input)?;
    let raw = input.raw.clone();
    let (attempt, attempt_id) = send_attempt_fragment(input)?;
    let outgoing = outgoing_publication(attempt_id, &raw)?;
    let mut files_union = files_facts.clone();
    files_union += outgoing.files.facts().clone();
    validate_catalog_union(
        mail_reader,
        mail_facts,
        &attempt,
        &files_union,
        decide_facts,
        relations_facts,
    )?;
    Ok(PreparedSend {
        attempt,
        attempt_id,
        outgoing,
        envelope,
        raw,
    })
}

/// Persist attempt-before-effect and acceptance-after-effect.  Any error after
/// attempt publication leaves an intentionally uncertain attempt which callers
/// must never retry automatically. The prepared value binds every byte and
/// address crossing the effect boundary to the exact validated attempt.
pub fn submit_once<T, PA, PC>(
    transport: &mut T,
    prepared: &PreparedSend,
    mut publish_attempt: PA,
    mut publish_acceptance: PC,
) -> Result<AcceptedReply>
where
    T: SmtpSubmit,
    PA: FnMut(&Fragment) -> Result<()>,
    PC: FnMut(&Fragment) -> Result<()>,
{
    publish_attempt(&prepared.attempt)?;
    let accepted = transport.submit(&prepared.envelope, &prepared.raw)?;
    if !(200..=299).contains(&accepted.code) {
        bail!(
            "SMTP submitter returned non-acceptance code {}; attempt outcome remains uncertain",
            accepted.code
        );
    }
    let (mut fragment, _) = smtp_acceptance_fragment(
        prepared.attempt_id,
        u64::from(accepted.code),
        accepted.message.clone(),
    )?;
    fragment += prepared.outgoing.mail.clone();
    publish_acceptance(&fragment)?;
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::{self, Cursor, Read, Write};
    use std::path::PathBuf;
    use std::rc::Rc;

    use crate::collection_access::{self, CollectionSnapshot, CollectionView};
    use crate::relations::{self, ProfileInput};
    use crate::schemas::{
        decide as decide_schema, files as files_schema, mail as mail_schema,
        relations as relations_schema,
    };
    use ed25519_dalek::VerifyingKey;

    fn id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at(second: u8) -> IntervalValue {
        let epoch = Epoch::from_gregorian_utc(2026, 8, 8, 0, 0, second, 0);
        (epoch, epoch).try_to_inline().unwrap()
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        pile: PathBuf,
        key: PathBuf,
        signer: VerifyingKey,
    }

    struct Views {
        mail: CollectionView,
        files: CollectionView,
        decide: CollectionView,
        relations: CollectionView,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let pile = directory.path().join("mail.pile");
            let key = directory.path().join("mail.key");
            File::create(&pile).unwrap();
            let signer = collection_access::initialize_signer(&pile, Some(&key))
                .unwrap()
                .verifying_key();
            Self {
                _directory: directory,
                pile,
                key,
                signer,
            }
        }

        fn publish(&self, scope: Id, fragment: Fragment) {
            collection_access::publish_fragment(
                &self.pile,
                Some(&self.key),
                scope,
                fragment,
                Fragment::empty(),
            )
            .unwrap();
        }

        fn views(&self) -> Views {
            let snapshot = CollectionSnapshot::open(&self.pile).unwrap();
            let allowed = HashSet::from([self.signer]);
            Views {
                mail: snapshot
                    .materialize_scope(mail_schema::DEFAULT_SCOPE_ID, &allowed)
                    .unwrap(),
                files: snapshot
                    .materialize_scope(files_schema::DEFAULT_SCOPE_ID, &allowed)
                    .unwrap(),
                decide: snapshot
                    .materialize_scope(decide_schema::DEFAULT_SCOPE_ID, &allowed)
                    .unwrap(),
                relations: snapshot
                    .materialize_scope(relations_schema::DEFAULT_SCOPE_ID, &allowed)
                    .unwrap(),
            }
        }
    }

    fn add_person(fixture: &Fixture, person: Id) {
        let (fragment, _, _) = relations::person_fragment(
            person,
            ProfileInput {
                label: "JP".into(),
                display_name: Some("JP".into()),
                emails: vec!["jp@example.test".into()],
                ..ProfileInput::default()
            },
        )
        .unwrap();
        fixture.publish(relations_schema::DEFAULT_SCOPE_ID, fragment);
    }

    fn add_account(fixture: &Fixture, account_id: Id, credential_id: Id, passphrase: &[u8]) -> Id {
        let views = fixture.views();
        let mut fragment = credential_fragment(credential_id, passphrase, "smtp-secret").unwrap();
        let (config, config_id) = account_config_fragment(
            account_id,
            AccountConfigInput {
                address: "sender@example.test".into(),
                display_name: "Sender".into(),
                pop_endpoint: "pop.example.test:995".into(),
                smtp_endpoint: "smtp.example.test:465".into(),
                username: "sender@example.test".into(),
                credential: credential_id,
                enabled: true,
                predecessors: Vec::new(),
            },
        )
        .unwrap();
        fragment += config;
        validate_catalog_union(
            &views.mail.reader,
            &views.mail.facts,
            &fragment,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
        )
        .unwrap();
        fixture.publish(mail_schema::DEFAULT_SCOPE_ID, fragment);
        config_id
    }

    const RAW_INBOUND: &[u8] = b"From: Alice <alice@example.test>\r\nTo: sender@example.test\r\nSubject: Hello\r\nDate: Sat, 8 Aug 2026 00:00:01 +0000\r\nMessage-ID: <CaseSensitive@Example.TEST>\r\nContent-Type: multipart/mixed; boundary=demo\r\n\r\n--demo\r\nContent-Type: text/plain\r\n\r\nhello body\r\n--demo\r\nContent-Type: application/octet-stream; name=note.bin\r\nContent-Disposition: attachment; filename=note.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAQID\r\n--demo--\r\n";

    #[test]
    fn message_identity_is_opaque_and_missing_id_hashes_full_raw_bytes() {
        let parsed = parse_rfc5322(RAW_INBOUND).unwrap();
        assert_eq!(
            parsed.identity,
            WireIdentity::Claimed("CaseSensitive@Example.TEST".into())
        );
        assert_eq!(parsed.claimed_date.unwrap(), at(1));
        assert_eq!(parsed.attachments[0].bytes, vec![1, 2, 3]);

        let first = parse_rfc5322(b"From: a@b\r\n\r\none").unwrap();
        let same = parse_rfc5322(b"From: a@b\r\n\r\none").unwrap();
        let other = parse_rfc5322(b"From: a@b\r\n\r\ntwo").unwrap();
        assert_eq!(first.identity, same.identity);
        assert_ne!(first.identity, other.identity);

        let WireIdentity::RawDigest(digest) = first.identity else {
            panic!("missing Message-ID must use raw digest identity")
        };
        let claimed = format!(
            "From: a@b\r\nMessage-ID: <raw-blake3:{}>\r\n\r\nclaim",
            hex::encode(digest.raw)
        );
        let fallback =
            pop_publication(id(86), id(87), "fallback", b"From: a@b\r\n\r\none").unwrap();
        let deliberate = pop_publication(id(86), id(87), "claimed", claimed.as_bytes()).unwrap();
        assert_ne!(fallback.wire, deliberate.wire);
        let rotated = pop_publication(id(86), id(88), "fallback", b"From: a@b\r\n\r\none").unwrap();
        assert_eq!(fallback.wire, rotated.wire);
        assert_ne!(fallback.observation, rotated.observation);
        assert!(parse_rfc5322(b"Message-ID: <a@b>\r\nMessage-ID: <c@d>\r\n\r\n").is_err());
    }

    #[test]
    fn source_validation_requires_every_recomputed_projection_blob_to_be_resident() {
        let fixture = Fixture::new();
        let account = id(97);
        let credential = id(98);
        let config = add_account(&fixture, account, credential, b"payload residency");
        let publication = pop_publication(
            account,
            config,
            "missing-subject",
            b"From: sender@example.test\r\nTo: receiver@example.test\r\nMessage-ID: <missing-payload@example.test>\r\nSubject: uniquely absent projection text\r\n\r\nbody",
        )
        .unwrap();
        let subject = required(
            find!(v: TextHandle, pattern!(publication.mail.facts(), [{ _?projection @ projection::subject: ?v }])).collect(),
            "test projection subject",
        )
        .unwrap();
        let SourcePublication { mail, files, .. } = publication;
        let (facts, mut blobs) = mail.into_facts_and_blobs();
        let survivors: Vec<_> = blobs
            .reader()
            .unwrap()
            .into_iter()
            .map(|(handle, _)| handle)
            .filter(|handle| handle.raw != subject.raw)
            .collect();
        blobs.keep(survivors);
        let broken = Fragment::from_facts_and_blobs(facts, blobs);
        let views = fixture.views();
        let mut files_union = views.files.facts.clone();
        files_union += files.facts().clone();
        let error = validate_catalog_union(
            &views.mail.reader,
            &views.mail.facts,
            &broken,
            &files_union,
            &views.decide.facts,
            &views.relations.facts,
        )
        .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("read staged Mail text"), "{error}");
    }

    #[test]
    fn multipart_draft_rendering_is_byte_deterministic() {
        let draft = MaterializedDraft {
            id: id(80),
            account: id(81),
            envelope_from: "sender@example.test".into(),
            to: vec!["Receiver <receiver@example.test>".into()],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: "Deterministic multipart".into(),
            body: "same body every time".into(),
            attachments: vec![AttachmentData {
                filename: "bytes.bin".into(),
                media_type: "application/octet-stream".into(),
                bytes: vec![0, 1, 2, 3, 254, 255],
            }],
            in_reply_to: Vec::new(),
            references: Vec::new(),
            created_at: at(4),
        };
        let account = OpenAccount {
            anchor: draft.account,
            config: id(82),
            address: draft.envelope_from.clone(),
            display_name: "Sender".into(),
            pop_endpoint: "pop.example.test:995".into(),
            smtp_endpoint: "smtp.example.test:465".into(),
            username: "sender@example.test".into(),
            password: "unused".into(),
            enabled: true,
        };

        let first = render_draft(&draft, &account).unwrap();
        let second = render_draft(&draft, &account).unwrap();
        assert_eq!(first, second);
        let boundary = format!("boundary=\"=_triblespace_{:x}\"", draft.id);
        assert!(first
            .raw
            .windows(boundary.len())
            .any(|window| window == boundary.as_bytes()));
    }

    #[test]
    fn account_snapshot_superseding_every_fork_head_rejoins_the_dag() {
        let anchor = id(83);
        let credential = id(84);
        let input = |display_name: &str, predecessors: Vec<Id>| AccountConfigInput {
            address: "me@example.test".into(),
            display_name: display_name.into(),
            pop_endpoint: "pop.example.test:995".into(),
            smtp_endpoint: "smtp.example.test:465".into(),
            username: "me@example.test".into(),
            credential,
            enabled: true,
            predecessors,
        };
        let (first, first_id) =
            account_config_fragment(anchor, input("First branch", Vec::new())).unwrap();
        let (second, second_id) =
            account_config_fragment(anchor, input("Second branch", Vec::new())).unwrap();
        let mut facts = first.into_facts();
        facts += second.into_facts();
        assert_eq!(
            account_head(&facts, anchor).unwrap(),
            Head::Forked(vec![first_id, second_id])
        );

        let (joined, joined_id) =
            account_config_fragment(anchor, input("Reconciled", vec![second_id, first_id]))
                .unwrap();
        facts += joined.into_facts();
        assert_eq!(
            account_head(&facts, anchor).unwrap(),
            Head::Unique(joined_id)
        );
    }

    #[test]
    fn smtp_acceptance_requires_a_final_positive_reply() {
        assert!(smtp_acceptance_fragment(id(85), 199, "not accepted").is_err());
        assert!(smtp_acceptance_fragment(id(85), 300, "not accepted").is_err());
        assert!(smtp_acceptance_fragment(id(85), 550, "rejected").is_err());
        assert!(smtp_acceptance_fragment(id(85), 250, "queued").is_ok());
    }

    #[test]
    fn collection_roundtrip_enforces_unread_and_exact_outbound_bytes() {
        let fixture = Fixture::new();
        let persona = id(1);
        let account_id = id(2);
        let credential_id = id(3);
        let passphrase = b"master password";
        add_person(&fixture, persona);
        let account_config = add_account(&fixture, account_id, credential_id, passphrase);

        let missing_thread = draft_publication(DraftInput {
            nonce: id(93),
            account: account_id,
            envelope_from: "sender@example.test".into(),
            to: vec!["receiver@example.test".into()],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: "Missing thread anchor".into(),
            body: "must not materialize later and fail".into(),
            attachments: Vec::new(),
            in_reply_to: vec![id(94)],
            references: Vec::new(),
            created_at: at(5),
        })
        .unwrap();
        let views = fixture.views();
        let decide_union = decide::validate_catalog_union(
            &views.decide.reader,
            &views.decide.facts,
            &missing_thread.decide,
        )
        .unwrap();
        let error = validate_catalog_union(
            &views.mail.reader,
            &views.mail.facts,
            &missing_thread.mail,
            &views.files.facts,
            &decide_union,
            &views.relations.facts,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("non-resident thread wire"));

        let digest_source = pop_publication(
            account_id,
            account_config,
            "digest-parent",
            b"From: parent@example.test\r\nTo: sender@example.test\r\nSubject: no id\r\n\r\nbody",
        )
        .unwrap();
        let digest_thread = draft_publication(DraftInput {
            nonce: id(96),
            account: account_id,
            envelope_from: "sender@example.test".into(),
            to: vec!["parent@example.test".into()],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: "Re: no id".into(),
            body: "a digest is local identity, not an RFC thread id".into(),
            attachments: Vec::new(),
            in_reply_to: vec![digest_source.wire],
            references: Vec::new(),
            created_at: at(6),
        })
        .unwrap();
        let views = fixture.views();
        let decide_union = decide::validate_catalog_union(
            &views.decide.reader,
            &views.decide.facts,
            &digest_thread.decide,
        )
        .unwrap();
        let mut digest_mail = digest_source.mail;
        digest_mail += digest_thread.mail;
        let mut digest_files = views.files.facts.clone();
        digest_files += digest_source.files.facts().clone();
        let error = validate_catalog_union(
            &views.mail.reader,
            &views.mail.facts,
            &digest_mail,
            &digest_files,
            &decide_union,
            &views.relations.facts,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("digest-only thread wire"));

        let views = fixture.views();
        let wrong_config =
            pop_publication(account_id, id(95), "wrong-config", RAW_INBOUND).unwrap();
        let mut wrong_files = views.files.facts.clone();
        wrong_files += wrong_config.files.facts().clone();
        let error = validate_catalog_union(
            &views.mail.reader,
            &views.mail.facts,
            &wrong_config.mail,
            &wrong_files,
            &views.decide.facts,
            &views.relations.facts,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("unknown config"));

        // POP evidence is precomputed, Files is published before Mail, and one
        // immutable multi-scope snapshot is sufficient for preflight.
        let views = fixture.views();
        let incoming =
            pop_publication(account_id, account_config, "UidL-CaSe", RAW_INBOUND).unwrap();
        let mut files_union = views.files.facts.clone();
        files_union += incoming.files.facts().clone();
        validate_catalog_union(
            &views.mail.reader,
            &views.mail.facts,
            &incoming.mail,
            &files_union,
            &views.decide.facts,
            &views.relations.facts,
        )
        .unwrap();
        fixture.publish(files_schema::DEFAULT_SCOPE_ID, incoming.files.clone());
        fixture.publish(mail_schema::DEFAULT_SCOPE_ID, incoming.mail.clone());

        let views = fixture.views();
        files::validate_catalog(&views.files.reader, &views.files.facts).unwrap();
        validate_catalog(
            &views.mail.reader,
            &views.mail.facts,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
        )
        .unwrap();
        let inbox = inbox_projection(&views.mail.facts, &views.relations.facts, persona).unwrap();
        assert_eq!(inbox.len(), 1);
        assert!(inbox[0].unread);

        let (read_fragment, _) = read_observation_fragment(incoming.wire, persona);
        validate_catalog_union(
            &views.mail.reader,
            &views.mail.facts,
            &read_fragment,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
        )
        .unwrap();
        fixture.publish(mail_schema::DEFAULT_SCOPE_ID, read_fragment);

        // A new source observation of the same wire message does not reopen it.
        let views = fixture.views();
        let replay =
            pop_publication(account_id, account_config, "second-uidl", RAW_INBOUND).unwrap();
        validate_catalog_union(
            &views.mail.reader,
            &views.mail.facts,
            &replay.mail,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
        )
        .unwrap();
        fixture.publish(mail_schema::DEFAULT_SCOPE_ID, replay.mail);
        let views = fixture.views();
        assert!(
            inbox_projection(&views.mail.facts, &views.relations.facts, persona)
                .unwrap()
                .iter()
                .all(|row| !row.unread)
        );

        // Draft and its deterministic Decide genesis are independent signed
        // roots; Decide lands first, then Mail validates against that union.
        let draft = draft_publication(DraftInput {
            nonce: id(4),
            account: account_id,
            envelope_from: "sender@example.test".into(),
            to: vec!["Bob <bob@example.test>".into()],
            cc: Vec::new(),
            bcc: vec!["quiet@example.test".into()],
            subject: "Authorized subject".into(),
            body: "Authorized body".into(),
            attachments: Vec::new(),
            in_reply_to: Vec::new(),
            references: Vec::new(),
            created_at: at(2),
        })
        .unwrap();
        let views = fixture.views();
        let decide_union = decide::validate_catalog_union(
            &views.decide.reader,
            &views.decide.facts,
            &draft.decide,
        )
        .unwrap();
        validate_catalog_union(
            &views.mail.reader,
            &views.mail.facts,
            &draft.mail,
            &views.files.facts,
            &decide_union,
            &views.relations.facts,
        )
        .unwrap();
        fixture.publish(decide_schema::DEFAULT_SCOPE_ID, draft.decide);
        fixture.publish(mail_schema::DEFAULT_SCOPE_ID, draft.mail);

        let views = fixture.views();
        let (resolution, resolution_id) =
            decide::resolution_fragment(draft.decision, "send", true, &[], &[], at(3)).unwrap();
        decide::validate_catalog_union(&views.decide.reader, &views.decide.facts, &resolution)
            .unwrap();
        fixture.publish(decide_schema::DEFAULT_SCOPE_ID, resolution);

        let views = fixture.views();
        let account = open_account(
            &views.mail.reader,
            &views.mail.facts,
            account_id,
            passphrase,
        )
        .unwrap();
        let materialized = materialize_draft(
            &views.mail.reader,
            &views.mail.facts,
            &views.files.facts,
            draft.draft,
        )
        .unwrap();
        let rendered = render_draft(&materialized, &account).unwrap();
        let (decision, heads) =
            authorized_send(&views.decide.reader, &views.decide.facts, draft.draft).unwrap();
        assert_eq!(heads, vec![resolution_id]);
        let base_attempt = SendAttemptInput {
            draft: draft.draft,
            config: account.config,
            decision,
            decision_heads: heads,
            raw: rendered.raw.clone(),
            envelope_from: materialized.envelope_from.clone(),
            to: materialized.to.clone(),
            cc: materialized.cc.clone(),
            bcc: materialized.bcc.clone(),
        };

        // A frozen attempt must cite an enabled config whose sender is the
        // draft sender, even if the config itself is otherwise canonical.
        for (address, enabled, needle) in [
            ("sender@example.test", false, "disabled"),
            ("other@example.test", true, "sender differs"),
        ] {
            let (mut config_fragment, config_id) = account_config_fragment(
                account_id,
                AccountConfigInput {
                    address: address.into(),
                    display_name: "Sender".into(),
                    pop_endpoint: "pop.example.test:995".into(),
                    smtp_endpoint: "smtp.example.test:465".into(),
                    username: "sender@example.test".into(),
                    credential: credential_id,
                    enabled,
                    predecessors: vec![account.config],
                },
            )
            .unwrap();
            let (attempt, _) = send_attempt_fragment(SendAttemptInput {
                config: config_id,
                ..base_attempt.clone()
            })
            .unwrap();
            config_fragment += attempt;
            let error = validate_catalog_union(
                &views.mail.reader,
                &views.mail.facts,
                &config_fragment,
                &views.files.facts,
                &views.decide.facts,
                &views.relations.facts,
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains(needle));
        }

        // Substituting the body while preserving the envelope and authorization
        // is rejected before a byte is published or SMTP is touched.
        let mut corrupt = rendered.raw.clone();
        let offset = corrupt
            .windows("Authorized body".len())
            .position(|window| window == b"Authorized body")
            .unwrap();
        corrupt.splice(
            offset..offset + "Authorized body".len(),
            b"Substituted body".iter().copied(),
        );
        let error = prepare_send(
            &views.mail.reader,
            &views.decide.reader,
            &views.mail.facts,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
            SendAttemptInput {
                raw: corrupt,
                ..base_attempt.clone()
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("subject/body"));

        let prepared = prepare_send(
            &views.mail.reader,
            &views.decide.reader,
            &views.mail.facts,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
            base_attempt,
        )
        .unwrap();
        let attempt_id = prepared.attempt_id();
        assert!(prepared.outgoing_files().facts().is_empty());

        let events = Rc::new(RefCell::new(Vec::new()));
        let mut smtp = FakeSmtp {
            events: events.clone(),
            fail: false,
        };
        let mut after_attempt = views.mail.facts.clone();
        after_attempt += prepared.attempt_fragment().facts().clone();

        // Acceptance is inseparable from exact outgoing evidence.
        let (receipt_only, _) =
            smtp_acceptance_fragment(attempt_id, 250, "queued without evidence").unwrap();
        let mut malformed_post_effect = prepared.attempt_fragment().clone();
        malformed_post_effect += receipt_only;
        let error = validate_catalog_union(
            &views.mail.reader,
            &views.mail.facts,
            &malformed_post_effect,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
        )
        .unwrap_err();
        let error = format!("{error:#}");
        assert!(
            error.contains("exactly one outgoing observation"),
            "{error}"
        );

        let mut outgoing_only = prepared.attempt_fragment().clone();
        outgoing_only += prepared.outgoing.mail.clone();
        let error = validate_catalog_union(
            &views.mail.reader,
            &views.mail.facts,
            &outgoing_only,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
        )
        .unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("has no SMTP acceptance"), "{error}");

        submit_once(
            &mut smtp,
            &prepared,
            |fragment| {
                events.borrow_mut().push("publish-attempt");
                fixture.publish(mail_schema::DEFAULT_SCOPE_ID, fragment.clone());
                Ok(())
            },
            |fragment| {
                events.borrow_mut().push("publish-post-effect");
                validate_catalog_union(
                    &views.mail.reader,
                    &after_attempt,
                    fragment,
                    &views.files.facts,
                    &views.decide.facts,
                    &views.relations.facts,
                )?;
                fixture.publish(mail_schema::DEFAULT_SCOPE_ID, fragment.clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            events.borrow().as_slice(),
            ["publish-attempt", "smtp", "publish-post-effect"]
        );
        let views = fixture.views();
        validate_catalog(
            &views.mail.reader,
            &views.mail.facts,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
        )
        .unwrap();
        assert_eq!(
            acceptances_for_attempt(&views.mail.facts, attempt_id).len(),
            1
        );
    }

    #[test]
    fn send_authorization_is_current_at_effect_time_but_historical_after_publication() {
        let fixture = Fixture::new();
        let account_id = id(90);
        let credential_id = id(91);
        let passphrase = b"frontier trust";
        add_account(&fixture, account_id, credential_id, passphrase);

        let draft = draft_publication(DraftInput {
            nonce: id(92),
            account: account_id,
            envelope_from: "sender@example.test".into(),
            to: vec!["receiver@example.test".into()],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: "Snapshot authorization".into(),
            body: "The authorization is historical after the effect starts.".into(),
            attachments: Vec::new(),
            in_reply_to: Vec::new(),
            references: Vec::new(),
            created_at: at(1),
        })
        .unwrap();
        let views = fixture.views();
        let decide_union = decide::validate_catalog_union(
            &views.decide.reader,
            &views.decide.facts,
            &draft.decide,
        )
        .unwrap();
        validate_catalog_union(
            &views.mail.reader,
            &views.mail.facts,
            &draft.mail,
            &views.files.facts,
            &decide_union,
            &views.relations.facts,
        )
        .unwrap();
        fixture.publish(decide_schema::DEFAULT_SCOPE_ID, draft.decide);
        fixture.publish(mail_schema::DEFAULT_SCOPE_ID, draft.mail);

        let (send, send_id) =
            decide::resolution_fragment(draft.decision, "send", true, &[], &[], at(2)).unwrap();
        fixture.publish(decide_schema::DEFAULT_SCOPE_ID, send);
        let views = fixture.views();
        let account = open_account(
            &views.mail.reader,
            &views.mail.facts,
            account_id,
            passphrase,
        )
        .unwrap();
        let materialized = materialize_draft(
            &views.mail.reader,
            &views.mail.facts,
            &views.files.facts,
            draft.draft,
        )
        .unwrap();
        let rendered = render_draft(&materialized, &account).unwrap();
        let (decision, heads) =
            authorized_send(&views.decide.reader, &views.decide.facts, draft.draft).unwrap();
        assert_eq!(heads, vec![send_id]);
        let prepared = prepare_send(
            &views.mail.reader,
            &views.decide.reader,
            &views.mail.facts,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
            SendAttemptInput {
                draft: draft.draft,
                config: account.config,
                decision,
                decision_heads: heads,
                raw: rendered.raw,
                envelope_from: materialized.envelope_from,
                to: materialized.to,
                cc: materialized.cc,
                bcc: materialized.bcc,
            },
        )
        .unwrap();
        fixture.publish(
            mail_schema::DEFAULT_SCOPE_ID,
            prepared.attempt_fragment().clone(),
        );

        // A concurrent disagreeing resolution makes the current frontier a
        // fork. It prevents a new effect, but it cannot rewrite the evidence
        // of which genuine send head the executor previously observed.
        let (reject, reject_id) =
            decide::resolution_fragment(draft.decision, "reject", true, &[], &[], at(3)).unwrap();
        fixture.publish(decide_schema::DEFAULT_SCOPE_ID, reject);
        let views = fixture.views();
        assert!(format!(
            "{:#}",
            authorized_send(&views.decide.reader, &views.decide.facts, draft.draft).unwrap_err()
        )
        .contains("divergent heads"));
        validate_catalog(
            &views.mail.reader,
            &views.mail.facts,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
        )
        .unwrap();

        // Joining that fork as a rejection likewise governs only future
        // effects. The final union cannot reconstruct whether the executor's
        // earlier local frontier was globally complete; that is its affine
        // authority attestation, not a fact derivable after the event.
        let (reject_join, _) = decide::resolution_fragment(
            draft.decision,
            "reject",
            true,
            &[],
            &[send_id, reject_id],
            at(4),
        )
        .unwrap();
        fixture.publish(decide_schema::DEFAULT_SCOPE_ID, reject_join);
        let views = fixture.views();
        assert!(format!(
            "{:#}",
            authorized_send(&views.decide.reader, &views.decide.facts, draft.draft).unwrap_err()
        )
        .contains("not exact outcome \"send\""));
        validate_catalog(
            &views.mail.reader,
            &views.mail.facts,
            &views.files.facts,
            &views.decide.facts,
            &views.relations.facts,
        )
        .unwrap();
    }

    struct FakeSmtp {
        events: Rc<RefCell<Vec<&'static str>>>,
        fail: bool,
    }

    impl SmtpSubmit for FakeSmtp {
        fn submit(&mut self, _envelope: &SmtpEnvelope, _raw: &[u8]) -> Result<AcceptedReply> {
            self.events.borrow_mut().push("smtp");
            if self.fail {
                bail!("scripted SMTP uncertainty");
            }
            Ok(AcceptedReply {
                code: 250,
                message: "queued".into(),
            })
        }
    }

    struct FakePop {
        events: Rc<RefCell<Vec<&'static str>>>,
        items: Vec<PopItem>,
        messages: HashMap<u32, Vec<u8>>,
        deleted: Vec<u32>,
        quit: bool,
    }

    impl Drop for FakePop {
        fn drop(&mut self) {
            if !self.quit {
                self.events.borrow_mut().push("disconnect");
            }
        }
    }

    impl PopTxn for FakePop {
        fn enumerate_uidls(&mut self) -> Result<Vec<PopItem>> {
            self.events.borrow_mut().push("uidl");
            Ok(self.items.clone())
        }

        fn retrieve_exact(&mut self, session_seq: u32) -> Result<Vec<u8>> {
            self.events.borrow_mut().push("retr");
            Ok(self.messages[&session_seq].clone())
        }

        fn mark_delete(&mut self, session_seq: u32) -> Result<()> {
            self.events.borrow_mut().push("dele");
            self.deleted.push(session_seq);
            Ok(())
        }

        fn quit(mut self) -> Result<()> {
            self.events.borrow_mut().push("quit");
            self.quit = true;
            Ok(())
        }
    }

    fn fake_pop(events: Rc<RefCell<Vec<&'static str>>>) -> FakePop {
        FakePop {
            events,
            items: vec![PopItem {
                session_seq: 7,
                uidl: "Case-Sensitive".into(),
            }],
            messages: HashMap::from([(7, RAW_INBOUND.to_vec())]),
            deleted: Vec::new(),
            quit: false,
        }
    }

    struct ScriptedPopStream {
        reads: Cursor<Vec<u8>>,
        writes: Rc<RefCell<Vec<u8>>>,
    }

    impl Read for ScriptedPopStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads.read(buffer)
        }
    }

    impl Write for ScriptedPopStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.writes.borrow_mut().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn real_pop_session_runs_through_transactional_drain() {
        let mut script =
            b"+OK ready\r\n+OK listing\r\n1 Uidl-Bridge\r\n.\r\n+OK message follows\r\n".to_vec();
        script.extend_from_slice(RAW_INBOUND);
        script.extend_from_slice(b".\r\n+OK deleted\r\n+OK bye\r\n");
        let writes = Rc::new(RefCell::new(Vec::new()));
        let session = crate::mail_pop::PopSession::new(ScriptedPopStream {
            reads: Cursor::new(script),
            writes: writes.clone(),
        })
        .unwrap();
        let mut published = Vec::new();

        drain_pop(session, id(9), id(10), |publication| {
            published.push((publication.wire, publication.observation));
            Ok(())
        })
        .unwrap();

        assert_eq!(published.len(), 1);
        assert_eq!(
            writes.borrow().as_slice(),
            b"UIDL\r\nRETR 1\r\nDELE 1\r\nQUIT\r\n"
        );
    }

    #[test]
    fn pop_publish_precedes_delete_and_failure_disconnects_without_quit() {
        let events = Rc::new(RefCell::new(Vec::new()));
        drain_pop(fake_pop(events.clone()), id(9), id(10), |_| {
            events.borrow_mut().push("publish");
            Ok(())
        })
        .unwrap();
        assert_eq!(
            events.borrow().as_slice(),
            ["uidl", "retr", "publish", "dele", "quit"]
        );

        let events = Rc::new(RefCell::new(Vec::new()));
        let error = drain_pop(fake_pop(events.clone()), id(9), id(10), |_| {
            events.borrow_mut().push("publish-failed");
            bail!("disk full")
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("disk full"));
        assert_eq!(
            events.borrow().as_slice(),
            ["uidl", "retr", "publish-failed", "disconnect"]
        );
    }

    #[test]
    fn pop_rejects_zero_and_duplicate_session_identities_before_retrieval() {
        let invalid = [
            vec![PopItem {
                session_seq: 0,
                uidl: "zero".into(),
            }],
            vec![
                PopItem {
                    session_seq: 1,
                    uidl: "first".into(),
                },
                PopItem {
                    session_seq: 1,
                    uidl: "second".into(),
                },
            ],
            vec![
                PopItem {
                    session_seq: 1,
                    uidl: "same".into(),
                },
                PopItem {
                    session_seq: 2,
                    uidl: "same".into(),
                },
            ],
        ];
        for items in invalid {
            let events = Rc::new(RefCell::new(Vec::new()));
            let transaction = FakePop {
                events: events.clone(),
                items,
                messages: HashMap::new(),
                deleted: Vec::new(),
                quit: false,
            };
            assert!(drain_pop(transaction, id(9), id(10), |_| Ok(())).is_err());
            assert_eq!(events.borrow().as_slice(), ["uidl", "disconnect"]);
        }
    }
}
