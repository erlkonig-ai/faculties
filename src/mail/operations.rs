//! `mail` — collection-native RFC 5322 evidence, intent, and receipt faculty.

use std::cell::RefCell;
use std::collections::BTreeSet;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use crate::clock;
use crate::collection_names::open_configured;
use crate::files;
use crate::mail::{self, AccountConfigInput, DraftInput, Head, SendAttemptInput};
use crate::mail_pop;
use crate::relations;
use crate::schemas::{
    decide as decide_schema, files as files_schema, mail as mail_schema,
    relations as relations_schema,
};
use crate::secrets::{storage as secret_storage, SecretsSnapshot};
#[cfg(test)]
use crate::storage::{load_signer, open_pile_strict};
use crate::storage::{open_secrets_collection, open_secrets_collection_read, FactArchive};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use lettre::address::{Address as SmtpAddress, Envelope as LettreEnvelope};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::query::TriblePattern;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::*;

#[derive(Clone, Debug)]
pub struct AccountOptions {
    pub account: Option<String>,
    pub address: String,
    pub display_name: String,
    pub pop_endpoint: String,
    pub smtp_endpoint: String,
    pub username: Option<String>,
    pub credential_version: Option<Id>,
    pub disabled: bool,
}
#[derive(Clone, Debug)]
pub struct AccountSetReceipt {
    pub account: Id,
    pub config: Id,
    pub credential: Id,
    pub changed: bool,
    pub notices: Vec<String>,
}
#[derive(Clone, Debug)]
pub enum AccountState {
    Missing,
    Forked(Vec<Id>),
    Configured {
        config: Id,
        address: String,
        enabled: bool,
    },
}
#[derive(Clone, Debug)]
pub struct AccountSummary {
    pub account: Id,
    pub state: AccountState,
}
#[derive(Clone, Debug)]
pub enum DraftAttachment {
    File(Id),
    Resident(mail::AttachmentData),
}
#[derive(Clone, Debug)]
pub struct DraftRequest {
    pub account: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<DraftAttachment>,
}
#[derive(Clone, Debug)]
pub struct ReplyRequest {
    pub message: String,
    pub account: String,
    pub body: String,
}
#[derive(Clone, Debug)]
pub struct DraftReceipt {
    pub draft: Id,
    pub decision: Id,
}
#[derive(Clone, Debug)]
pub enum SendStatus {
    AlreadyAccepted,
    Accepted(mail::AcceptedReply),
}
#[derive(Clone, Debug)]
pub struct SendReceipt {
    pub draft: Id,
    pub attempt: Id,
    pub status: SendStatus,
}
#[derive(Clone, Debug)]
pub enum DraftDelivery {
    Pending,
    Uncertain(Id),
    Accepted(Id),
    MultipleAttempts,
}
#[derive(Clone, Debug)]
pub struct DraftStatus {
    pub draft: Id,
    pub subject: String,
    pub delivery: DraftDelivery,
}
#[derive(Clone, Debug)]
pub struct InboxMessage {
    pub projection: mail::ProjectionView,
    pub unread: bool,
}
#[derive(Clone, Debug)]
pub struct ReadReceipt {
    pub wire: Id,
    pub observation: Id,
    pub reader: Id,
}
#[derive(Clone, Debug)]
pub struct AccountFetched {
    pub account: Id,
    pub config: Id,
    pub address: String,
    pub fetched: usize,
}

/// Configured direct Mail operations. Each call observes maintained Mail, Files,
/// Decide, Relations and Secrets through one shared store snapshot.
/// Text and attachments are resident values; no argv, host-path expansion, or ambient persona.
#[derive(Clone, Debug)]
pub struct Mail {
    storage: crate::storage::Storage,
}
impl Mail {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self { storage }
    }
    fn with_operation<T>(&self, execute: impl FnOnce(&Storage) -> Result<T>) -> Result<T> {
        self.storage.scope(|storage| {
            let context = Storage::from_storage(storage.clone(), Scopes::FIXED)?;
            let result = execute(&context);
            let notices = context.notices.take();
            match result {
                Err(error) if !notices.is_empty() => Err(error.context(notices.join("\n"))),
                other => other,
            }
        })
    }
    pub fn account_set(&self, input: AccountOptions) -> Result<AccountSetReceipt> {
        self.update_account(input, None)
    }
    /// Host credential-provisioning interface. MCP accepts exact Secrets versions instead.
    pub fn account_set_with_password(
        &self,
        input: AccountOptions,
        password: String,
    ) -> Result<AccountSetReceipt> {
        self.update_account(input, Some(password))
    }
    fn update_account(
        &self,
        input: AccountOptions,
        password: Option<String>,
    ) -> Result<AccountSetReceipt> {
        self.with_operation(|storage| {
            account_set(
                storage,
                input.account,
                input.address,
                input.display_name,
                input.pop_endpoint,
                input.smtp_endpoint,
                input.username,
                password,
                input.credential_version,
                input.disabled,
            )
        })
    }
    pub fn account_list(&self) -> Result<Vec<AccountSummary>> {
        self.with_operation(account_list)
    }
    /// Drain every enabled POP account: publish exact evidence before DELE and QUIT.
    /// A failed QUIT after DELE leaves remote deletion uncertain and is never hidden.
    pub fn fetch(&self) -> Result<Vec<AccountFetched>> {
        self.with_operation(cmd_fetch)
    }
    pub fn draft(&self, input: DraftRequest) -> Result<DraftReceipt> {
        self.with_operation(|storage| cmd_draft(storage, input))
    }
    pub fn reply(&self, input: ReplyRequest) -> Result<DraftReceipt> {
        self.with_operation(|storage| cmd_reply(storage, input))
    }
    /// Submit one authorized immutable draft. Deployments MUST externally serialize
    /// SMTP execution per account, including other processes/replicas. An uncertain
    /// durable attempt is never retried automatically.
    pub fn send(&self, draft: &str) -> Result<SendReceipt> {
        self.with_operation(|storage| cmd_send(storage, draft))
    }
    pub fn outbox(&self) -> Result<Vec<DraftStatus>> {
        self.with_operation(cmd_outbox)
    }
    pub fn list(&self, persona: &str, unread: bool, spam: bool) -> Result<Vec<InboxMessage>> {
        self.with_operation(|storage| cmd_list(storage, persona, unread, spam))
    }
    /// Add intrinsic seen evidence; this does not display the message.
    pub fn read(&self, persona: &str, message: &str) -> Result<ReadReceipt> {
        self.with_operation(|storage| cmd_read(storage, message, persona))
    }
    pub fn show(&self, message: &str) -> Result<Vec<mail::ProjectionView>> {
        self.with_operation(|storage| cmd_show(storage, message))
    }
    pub fn search(&self, query: &str) -> Result<Vec<mail::ProjectionView>> {
        self.with_operation(|storage| cmd_search(storage, query))
    }
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
    secrets: SecretsSnapshot<PileSnapshot>,
}

struct Storage {
    storage: crate::storage::Storage,
    signer: SigningKey,
    scopes: Scopes,
    notices: RefCell<Vec<String>>,
}

impl Storage {
    fn from_storage(storage: crate::storage::Storage, scopes: Scopes) -> Result<Self> {
        let signer = storage.with_pile(|_, signer| Ok(signer.clone()))?;
        Ok(Self {
            storage,
            signer,
            scopes,
            notices: RefCell::new(Vec::new()),
        })
    }

    #[cfg(test)]
    fn open(pile: &Path, key: Option<&Path>, scopes: Scopes) -> Result<Self> {
        Self::from_storage(
            crate::storage::Storage::shared(pile.to_owned(), key.map(Path::to_owned)),
            scopes,
        )
    }

    fn views(&self) -> Result<Views> {
        self.storage.with_pile(|pile, _| {
            let (mail_facts, files_facts, decide_facts, relations_facts, store_snapshot, secrets) = {
                let mail_collection =
                    open_configured(pile, self.scopes.mail, self.signer.verifying_key())?;
                let files_collection =
                    open_configured(pile, self.scopes.files, self.signer.verifying_key())?;
                let decide_collection =
                    open_configured(pile, self.scopes.decide, self.signer.verifying_key())?;
                let relations_collection =
                    open_configured(pile, self.scopes.relations, self.signer.verifying_key())?;
                let secrets_collection =
                    open_secrets_collection_read(pile, self.signer.verifying_key())?;
                let descriptor_snapshot = pile.snapshot()?;
                let policy = mail_collection.policy(&descriptor_snapshot)?;
                drop(descriptor_snapshot);
                let mail_succinct =
                    pile.derive::<SuccinctArchiveBlob>(mail_collection, (), policy.clone())?;
                let mail_rank9 =
                    pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(mail_succinct, (), policy)?;
                let descriptor_snapshot = pile.snapshot()?;
                let policy = files_collection.policy(&descriptor_snapshot)?;
                drop(descriptor_snapshot);
                let files_succinct =
                    pile.derive::<SuccinctArchiveBlob>(files_collection, (), policy.clone())?;
                let files_rank9 =
                    pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(files_succinct, (), policy)?;
                let descriptor_snapshot = pile.snapshot()?;
                let policy = decide_collection.policy(&descriptor_snapshot)?;
                drop(descriptor_snapshot);
                let decide_succinct =
                    pile.derive::<SuccinctArchiveBlob>(decide_collection, (), policy.clone())?;
                let decide_rank9 =
                    pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(decide_succinct, (), policy)?;
                let descriptor_snapshot = pile.snapshot()?;
                let policy = relations_collection.policy(&descriptor_snapshot)?;
                drop(descriptor_snapshot);
                let relations_succinct =
                    pile.derive::<SuccinctArchiveBlob>(relations_collection, (), policy.clone())?;
                let relations_rank9 =
                    pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(relations_succinct, (), policy)?;
                // Ensure every root, then advance each ordinary fact chain before
                // observing the views through one final snapshot.
                let secrets = pollster::block_on(async {
                    for (label, source) in [
                        ("Mail", mail_collection),
                        ("Files", files_collection),
                        ("Decide", decide_collection),
                        ("Relations", relations_collection),
                        ("Secrets", secrets_collection.source()),
                    ] {
                        drop(
                            pile.ensure(source)
                                .await
                                .with_context(|| format!("ensure {label} source collection"))?,
                        );
                    }
                    let before = pile
                        .snapshot()
                        .context("freeze shared Mail support snapshot")?;
                    let secrets_support = secrets_collection
                        .source()
                        .admitted(&before)
                        .context("admit Secrets collection support")?;
                    drop(before);

                    drop(
                        pile.maintain(mail_succinct)
                            .await
                            .context("maintain Mail fact collection")?,
                    );
                    drop(
                        pile.maintain(mail_rank9)
                            .await
                            .context("maintain Mail fact collection")?,
                    );
                    drop(
                        pile.maintain(files_succinct)
                            .await
                            .context("maintain Files fact collection")?,
                    );
                    drop(
                        pile.maintain(files_rank9)
                            .await
                            .context("maintain Files fact collection")?,
                    );
                    drop(
                        pile.maintain(decide_succinct)
                            .await
                            .context("maintain Decide fact collection")?,
                    );
                    drop(
                        pile.maintain(decide_rank9)
                            .await
                            .context("maintain Decide fact collection")?,
                    );
                    drop(
                        pile.maintain(relations_succinct)
                            .await
                            .context("maintain Relations fact collection")?,
                    );
                    drop(
                        pile.maintain(relations_rank9)
                            .await
                            .context("maintain Relations fact collection")?,
                    );

                    let store_snapshot = secrets_collection
                        .ensure_exact(pile, &secrets_support)
                        .await
                        .context("ensure configured Secrets collection")?;
                    let secrets = secret_storage::snapshot_exact(
                        store_snapshot,
                        secrets_collection,
                        secrets_support,
                    )
                    .context("attach exact Secrets collection")?;
                    Ok::<_, anyhow::Error>(secrets)
                })?;
                // Secrets attachment owns the final immutable pile snapshot. Attach
                // every maintained view through that same world so Mail
                // facts, file payloads, decisions, relations, and credentials can
                // never be assembled from different store prefixes.
                let store_snapshot = secrets.store_snapshot().clone();
                let mail_facts = store_snapshot
                    .collection(mail_rank9)
                    .context("attach maintained Mail fact collection")?
                    .view::<FactArchive>()
                    .context("read maintained Mail fact collection")?;
                let files_facts = store_snapshot
                    .collection(files_rank9)
                    .context("attach maintained Files fact collection")?
                    .view::<FactArchive>()
                    .context("read maintained Files fact collection")?;
                let decide_facts = store_snapshot
                    .collection(decide_rank9)
                    .context("attach maintained Decide fact collection")?
                    .view::<FactArchive>()
                    .context("read maintained Decide fact collection")?;
                let relations_facts = store_snapshot
                    .collection(relations_rank9)
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
        })
    }

    fn add_secret(&self, name: &str, plaintext: &[u8]) -> Result<Id> {
        self.storage.with_pile(|pile, _| {
            let collection = open_secrets_collection(&mut *pile, self.signer.verifying_key())?;
            secret_storage::add_secret(
                &mut *pile,
                &self.signer,
                collection,
                name,
                plaintext,
                point_now()?,
            )
            .context("publish mailbox credential to configured Secrets collection")
        })
    }

    fn publish(&self, scope: Id, fragment: Fragment, description: &str) -> Result<()> {
        self.storage.with_pile(|pile, _| {
            let mut fragment = fragment;
            fragment.describe_with(entity! { metadata::description: description.to_owned() });
            let collection = open_configured(pile, scope, self.signer.verifying_key())?;
            pile.commit(collection, &self.signer, fragment)
                .with_context(|| format!("commit collection {scope:x}"))?;
            Ok(())
        })
    }

    #[cfg(test)]
    fn close(self) -> Result<()> {
        self.storage.close()
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn point_now() -> Result<mail::IntervalValue> {
    clock::point_now()
}

fn relation_persona(views: &Views, raw: &str) -> Result<Id> {
    relations::resolve_person(&views.relations.reader, &views.relations.facts, raw, false)?
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
    crate::resolve_id_prefix(input, candidates)
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
    crate::resolve_id_prefix(input, wire_candidates(facts))
}

fn account_set(
    storage: &Storage,
    account_selector: Option<String>,
    address: String,
    display_name: String,
    pop_endpoint: String,
    smtp_endpoint: String,
    username: Option<String>,
    password: Option<String>,
    credential_version: Option<Id>,
    disabled: bool,
) -> Result<AccountSetReceipt> {
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
        if !views.secrets.contains(id) {
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

    let credential_id = match (password, credential_version, old_credential) {
        (None, None, Some(id)) => id,
        (None, None, None) if replacing_fork => {
            bail!("--credential-version or MAIL_PASS/--password is required to reconcile a forked account")
        }
        (None, None, None) => {
            bail!("--credential-version or MAIL_PASS/--password is required for a new account")
        }
        (None, Some(id), _) => id,
        (Some(value), None, _) => {
            let id = storage.add_secret(&mailbox_secret_name(anchor), value.as_bytes())?;
            storage.notices.borrow_mut().push(format!(
                "Published mailbox credential {id:x}; if Mail publication is interrupted, retry with --credential-version {id:x}"
            ));
            views = storage.views()?;
            if !views.secrets.contains(id) {
                bail!("published mailbox secret {id:x} did not materialize");
            }
            id
        }
        (Some(_), Some(_), _) => {
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
            return Ok(AccountSetReceipt {
                account: anchor,
                config: *predecessor,
                changed: false,
                credential: credential_id,
                notices: storage.notices.borrow().clone(),
            });
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
    Ok(AccountSetReceipt {
        account: anchor,
        config: config_id,
        changed: true,
        credential: credential_id,
        notices: storage.notices.borrow().clone(),
    })
}

fn account_list(storage: &Storage) -> Result<Vec<AccountSummary>> {
    let views = storage.views()?;
    let mut result = Vec::new();
    for account in mail::account_anchors(&views.mail.facts) {
        let state = match mail::account_head(&views.mail.facts, account)? {
            Head::Missing => AccountState::Missing,
            Head::Forked(ids) => AccountState::Forked(ids),
            Head::Unique(id) => {
                let config = mail::account_config(&views.mail.facts, id)?;
                AccountState::Configured {
                    config: id,
                    address: mail::read_text(&views.mail.reader, config.address)?,
                    enabled: config.enabled,
                }
            }
        };
        result.push(AccountSummary { account, state });
    }
    Ok(result)
}

fn stage_attachments(
    views: &Views,
    attachments: Vec<DraftAttachment>,
) -> Result<(Fragment, Vec<Id>)> {
    let mut fragment = Fragment::empty();
    let mut ids = Vec::new();
    for attachment in attachments {
        match attachment {
            DraftAttachment::File(id) => {
                if !exists!(
                    pattern!(&views.files.facts, [{ id @ metadata::tag: &files_schema::KIND_FILE }])
                ) {
                    bail!("unknown Files attachment {id:x}");
                }
                if files::content_handle(&views.files.facts, id)?.is_none()
                    || files::name_handle(&views.files.facts, id)?.is_none()
                    || files::media_type_name_handle_strict(&views.files.facts, id)?.is_none()
                {
                    bail!("incomplete Files attachment {id:x}");
                }
                ids.push(id);
            }
            DraftAttachment::Resident(value) => {
                let file = files::stage(value.bytes, value.filename, &value.media_type)?;
                ids.push(file.root().expect("canonical file root"));
                fragment += file;
            }
        }
    }
    Ok((fragment, ids))
}

#[allow(clippy::too_many_arguments)]
fn create_draft(
    storage: &Storage,
    views: &Views,
    account_selector: &str,
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    subject: String,
    body: String,
    attachments: Vec<DraftAttachment>,
    in_reply_to: Vec<Id>,
    references: Vec<Id>,
) -> Result<DraftReceipt> {
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
    let (files_fragment, attachment_ids) = stage_attachments(views, attachments)?;
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
    Ok(DraftReceipt {
        draft: draft.draft,
        decision: draft.decision,
    })
}

fn cmd_draft(storage: &Storage, args: DraftRequest) -> Result<DraftReceipt> {
    let views = storage.views()?;
    create_draft(
        storage,
        &views,
        &args.account,
        args.to,
        args.cc,
        args.bcc,
        args.subject,
        args.body,
        args.attachments,
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

fn cmd_reply(storage: &Storage, args: ReplyRequest) -> Result<DraftReceipt> {
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
        args.body,
        Vec::new(),
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

fn cmd_send(storage: &Storage, selector: &str) -> Result<SendReceipt> {
    let views = storage.views()?;
    let draft_id = resolve_draft(&views.mail.facts, selector)?;
    let existing = mail::attempts_for_draft(&views.mail.facts, draft_id);
    if let Some(&attempt) = existing.first() {
        if mail::acceptances_for_attempt(&views.mail.facts, attempt).is_empty() {
            bail!("draft {draft_id:x} already has uncertain attempt {attempt:x}; never retry automatically");
        }
        return Ok(SendReceipt {
            draft: draft_id,
            attempt,
            status: SendStatus::AlreadyAccepted,
        });
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
        &views.secrets,
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
    Ok(SendReceipt {
        draft: draft_id,
        attempt: attempt_id,
        status: SendStatus::Accepted(response),
    })
}

fn cmd_outbox(storage: &Storage) -> Result<Vec<DraftStatus>> {
    let views = storage.views()?;
    let drafts: BTreeSet<Id> = find!(
        id: Id,
        pattern!(&views.mail.facts, [{ ?id @ metadata::tag: &mail_schema::KIND_DRAFT_INTENT }])
    )
    .collect();
    let mut result = Vec::new();
    for id in drafts {
        let draft = mail::materialize_draft(
            &views.mail.reader,
            &views.mail.facts,
            &views.files.facts,
            id,
        )?;
        let attempts = mail::attempts_for_draft(&views.mail.facts, id);
        let state = match attempts.as_slice() {
            [] => DraftDelivery::Pending,
            [attempt] if mail::acceptances_for_attempt(&views.mail.facts, *attempt).is_empty() => {
                DraftDelivery::Uncertain(*attempt)
            }
            [attempt] => DraftDelivery::Accepted(*attempt),
            _ => DraftDelivery::MultipleAttempts,
        };
        result.push(DraftStatus {
            draft: id,
            subject: draft.subject,
            delivery: state,
        });
    }
    Ok(result)
}

fn cmd_list(
    storage: &Storage,
    persona: &str,
    unread_only: bool,
    spam_only: bool,
) -> Result<Vec<InboxMessage>> {
    let views = storage.views()?;
    let persona = relation_persona(&views, persona)?;
    let mut result = Vec::new();
    for row in mail::inbox_projection(&views.mail.facts, &views.relations.facts, persona)? {
        if unread_only && !row.unread {
            continue;
        }
        let view = mail::projection_view(&views.mail.reader, &views.mail.facts, row.projection)?;
        if spam_only && !view.spam {
            continue;
        }
        result.push(InboxMessage {
            projection: view,
            unread: row.unread,
        });
    }
    Ok(result)
}

fn cmd_read(storage: &Storage, selector: &str, persona: &str) -> Result<ReadReceipt> {
    let views = storage.views()?;
    let wire = resolve_wire(&views.mail.facts, selector)?;
    let reader = relation_persona(&views, persona)?;
    let (fragment, id) = mail::read_observation_fragment(wire, reader);
    storage.publish(storage.scopes.mail, fragment, "mail: read observation")?;
    Ok(ReadReceipt {
        wire,
        observation: id,
        reader,
    })
}

fn cmd_show(storage: &Storage, selector: &str) -> Result<Vec<mail::ProjectionView>> {
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
    projections
        .into_iter()
        .map(|id| mail::projection_view(&views.mail.reader, &views.mail.facts, id))
        .collect()
}

fn cmd_search(storage: &Storage, query: &str) -> Result<Vec<mail::ProjectionView>> {
    let views = storage.views()?;
    let needle = query.to_lowercase();
    let projections: BTreeSet<Id> = find!(
        id: Id,
        pattern!(&views.mail.facts, [{ ?id @ metadata::tag: &mail_schema::KIND_PARSED_PROJECTION }])
    )
    .collect();
    let mut result = Vec::new();
    for id in projections {
        let view = mail::projection_view(&views.mail.reader, &views.mail.facts, id)?;
        if view.subject.to_lowercase().contains(&needle)
            || view.body.to_lowercase().contains(&needle)
        {
            result.push(view);
        }
    }
    Ok(result)
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

fn cmd_fetch(storage: &Storage) -> Result<Vec<AccountFetched>> {
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
        return Ok(Vec::new());
    }

    let mut accounts = Vec::new();
    for anchor in enabled_anchors {
        let account = mail::open_account(
            &views.mail.reader,
            &views.mail.facts,
            &views.secrets,
            anchor,
            &storage.signer,
        )
        .with_context(|| format!("open POP account {anchor:x}"))?;
        accounts.push(account);
    }
    drop(views);

    let mut result = Vec::new();
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
        storage
            .notices
            .borrow_mut()
            .push(format!("{}: fetched {fetched} message(s)", account.address));
        result.push(AccountFetched {
            account: account.anchor,
            config: account.config,
            address: account.address,
            fetched,
        });
    }
    Ok(result)
}

use crate::schemas::mail::{observation, projection};

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs::File;
    use std::rc::Rc;

    use crate::secrets::secret_rows;
    use crate::storage::{initialize_signer, publish_fragment};
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
            let collection = open_secrets_collection(&mut store, signer.verifying_key()).unwrap();
            let credential_id = secret_storage::add_secret(
                &mut store,
                &signer,
                collection,
                &mailbox_secret_name(account),
                b"mailbox password",
                point_now().unwrap(),
            )
            .unwrap();
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
            };
            let storage = fixture.storage();
            storage.views().unwrap();
            storage.close().unwrap();
            fixture
        }

        fn storage(&self) -> Storage {
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
    fn views_share_the_final_secrets_snapshot() {
        let fixture = Fixture::new();
        let storage = fixture.storage();

        // Leave one secret commit without its maintained representations. This
        // makes Secrets attachment advance the pile after the ordinary Mail
        // collections have been maintained and catches cross-watermark views.
        storage
            .add_secret("snapshot-regression", b"new secret")
            .unwrap();

        let views = storage.views().unwrap();
        let secrets_snapshot = views.secrets.store_snapshot();
        for reader in [
            &views.mail.reader,
            &views.files.reader,
            &views.decide.reader,
            &views.relations.reader,
        ] {
            assert!(reader.changes_since(secrets_snapshot).is_empty());
            assert!(secrets_snapshot.changes_since(reader).is_empty());
            assert_eq!(reader.instant(), secrets_snapshot.instant());
        }
    }

    #[test]
    fn account_config_update_reuses_exact_secret_without_opening_it() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let before = storage.views().unwrap();
        let secrets_before = secret_rows(before.secrets.facts().unwrap());

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
            false,
        )
        .unwrap();

        let after = storage.views().unwrap();
        assert_eq!(secret_rows(after.secrets.facts().unwrap()), secrets_before);
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
        let versions_before = secret_rows(before.secrets.facts().unwrap()).len();

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
            false,
        )
        .unwrap();

        let after = storage.views().unwrap();
        assert_eq!(
            secret_rows(after.secrets.facts().unwrap()).len(),
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
        assert!(after.secrets.contains(credential));
    }

    #[test]
    fn interrupted_secrets_first_update_has_an_exact_repair_path() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        let credential = storage
            .add_secret(
                &mailbox_secret_name(fixture.account),
                b"replacement password",
            )
            .unwrap();
        let views = storage.views().unwrap();
        let versions = secret_rows(views.secrets.facts().unwrap()).len();
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
            false,
        )
        .unwrap();

        let after = storage.views().unwrap();
        assert_eq!(secret_rows(after.secrets.facts().unwrap()).len(), versions);
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
        let secrets_before = secret_rows(views.secrets.facts().unwrap());
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
            false,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("account address"));
        let after = storage.views().unwrap();
        assert_eq!(secret_rows(after.secrets.facts().unwrap()), secrets_before);
    }

    #[test]
    fn new_account_uses_the_configured_secrets_collection() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
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
            true,
        )
        .unwrap();

        // Disabled accounts do not participate in the all-enabled credential
        // opening preflight.
        cmd_fetch(&storage).unwrap();
    }

    #[test]
    fn disabled_send_refuses_before_credential_access() {
        let fixture = Fixture::new();
        let storage = fixture.storage();
        cmd_draft(
            &storage,
            DraftRequest {
                account: format!("{:x}", fixture.account),
                to: vec!["recipient@example.test".into()],
                cc: Vec::new(),
                bcc: Vec::new(),
                subject: "Disabled account".into(),
                body: "must not send".into(),
                attachments: Vec::new(),
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
        storage: &Storage,
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
            ReplyRequest {
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
