//! Direct Headspace configuration operations over current fork-visible tracks.
//! Storage acquisition and each publication retain the existing shared snapshot
//! boundaries. Plaintext is exposed only by an explicit show_secrets request.
use crate::out::Out;

#[derive(Clone, Debug)]
pub struct Headspace {
    pile: PathBuf,
    key: Option<PathBuf>,
}
#[derive(Clone, Debug, Default)]
pub struct AddProfileOptions {
    pub name: String,
    pub model: Option<String>,
    pub base_url: Option<String>,
    /// Exact existing Secrets version for the new profile's model credential.
    pub model_secret_version: Option<String>,
    pub reasoning_effort: Option<String>,
    pub stream: Option<bool>,
    pub context_window_tokens: Option<u64>,
    pub max_output_tokens: Option<u64>,
    pub context_safety_margin_tokens: Option<u64>,
    pub chars_per_token: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProfileEdit {
    Model(String),
    BaseUrl(String),
    ReasoningEffort(String),
    Stream(bool),
    ContextWindowTokens(u64),
    MaxOutputTokens(u64),
    PromptSafetyMarginTokens(u64),
    PromptCharsPerToken(u64),
}
#[derive(Clone, Copy, Debug)]
pub enum OptionalProfileField {
    ReasoningEffort,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretRole {
    Model,
    Tavily,
    Exa,
}
/// An exact version or resident plaintext, never a host file reference.
pub enum Credential {
    Plaintext(Zeroizing<String>),
    Version(String),
}

/// Typed evidence for a Secrets-first update that failed after credential
/// publication. Never retry plaintext publication automatically: reuse version.
#[derive(Debug)]
pub struct CredentialUpdateError {
    pub version: Id,
    pub role: SecretRole,
    pub reference_published: bool,
    source: anyhow::Error,
}
impl std::fmt::Display for CredentialUpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exact credential {:x} was published; Headspace reference_published={}; retry the reference with: headspace secret {} set --version {:x}: {}", self.version, self.reference_published, role_name(self.role), self.version, self.source)
    }
}
impl std::error::Error for CredentialUpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl Headspace {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self { pile, key }
    }
    fn with_storage<T>(&self, operation: impl FnOnce(&Storage<'_>) -> Result<T>) -> Result<T> {
        let storage = Storage::open(&self.pile, self.key.as_deref())?;
        let result = operation(&storage);
        match (result, storage.close()) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) | (Err(error), Ok(())) => Err(error),
            (Err(error), Err(close_error)) => Err(error.context(format!(
                "closing Headspace storage also failed: {close_error}"
            ))),
        }
    }
    pub fn show(&self, show_secrets: bool, out: &mut Out<'_>) -> Result<()> {
        self.with_storage(|storage| {
            let views = storage.views()?;
            let opened = if show_secrets {
                open_display_secrets(storage, &views)?
            } else {
                None
            };
            print_headspace(&views, opened.as_ref(), out)
        })
    }
    pub fn list(&self, out: &mut Out<'_>) -> Result<()> {
        self.with_storage(|storage| print_profile_list(&storage.views()?, out))
    }
    pub fn use_profile(&self, selector: &str, out: &mut Out<'_>) -> Result<()> {
        self.with_storage(|storage| use_profile(storage, selector, out))
    }
    pub fn add(&self, options: &AddProfileOptions, out: &mut Out<'_>) -> Result<Id> {
        self.with_storage(|storage| add_profile(storage, options, out))
    }
    pub fn set(&self, edit: &ProfileEdit, out: &mut Out<'_>) -> Result<()> {
        self.with_storage(|storage| set_profile_field(storage, edit, out))
    }
    pub fn unset(&self, field: OptionalProfileField, out: &mut Out<'_>) -> Result<()> {
        self.with_storage(|storage| unset_profile_field(storage, field, out))
    }
    pub fn secret_set(
        &self,
        role: SecretRole,
        credential: Credential,
        out: &mut Out<'_>,
    ) -> Result<Id> {
        self.with_storage(|storage| set_secret(storage, role, credential, out))
    }
    pub fn secret_unset(&self, role: SecretRole, out: &mut Out<'_>) -> Result<()> {
        self.with_storage(|storage| unset_secret(storage, role, out))
    }
    pub fn reconcile(&self, snapshot: &str, out: &mut Out<'_>) -> Result<()> {
        self.with_storage(|storage| reconcile(storage, snapshot, out))
    }
}

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::clock;
use crate::collection_names::open_configured;
use crate::headspace::{self, ConfigValue, OpenedSecrets, ProfileValue, Resolution};
use crate::schemas::headspace::DEFAULT_SCOPE_ID;
use crate::secrets::{self as secrets_model, storage as secret_storage, SecretsSnapshot};
use crate::storage::{
    load_signer, open_pile_strict, open_secrets_collection, open_secrets_collection_read,
    FactArchive,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{CollectionSnapshotExt, CollectionStoreExt};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, PileSnapshot};
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::*;
use zeroize::Zeroizing;

struct CollectionView {
    facts: FactArchive,
    reader: PileSnapshot,
}

struct Views {
    headspace: CollectionView,
    secrets: SecretsSnapshot<PileSnapshot>,
}

struct Storage<'a> {
    pile_path: &'a Path,
    pile: RefCell<Option<Pile>>,
    signer: SigningKey,
}

impl Storage<'_> {
    fn open<'a>(pile_path: &'a Path, key: Option<&Path>) -> Result<Storage<'a>> {
        // Authority is resolved before touching storage. A missing signer can
        // neither create a pile nor append a descriptor.
        let signer = load_signer(pile_path, key)?;
        let pile = open_pile_strict(pile_path)?;
        Ok(Storage {
            pile_path,
            pile: RefCell::new(Some(pile)),
            signer,
        })
    }

    fn views(&self) -> Result<Views> {
        let mut pile = self.pile.borrow_mut();
        let pile = pile
            .as_mut()
            .ok_or_else(|| anyhow!("Headspace storage is already closed"))?;
        let source = open_configured(pile, DEFAULT_SCOPE_ID, self.signer.verifying_key())?;
        let descriptor_snapshot = pile.snapshot()?;
        let policy = source.policy(&descriptor_snapshot)?;
        drop(descriptor_snapshot);
        let collection_succinct = pile.derive::<SuccinctArchiveBlob>(source, (), policy.clone())?;
        let collection_rank9 =
            pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(collection_succinct, (), policy)?;
        let secrets_collection = open_secrets_collection_read(pile, self.signer.verifying_key())?;
        let secrets = pollster::block_on(async {
            for (label, source) in [
                ("Headspace", source),
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
                .context("freeze shared Headspace support snapshot")?;
            let secrets_support = secrets_collection
                .source()
                .admitted(&before)
                .context("admit Secrets collection support")?;
            drop(before);
            drop(
                pile.maintain(collection_succinct)
                    .await
                    .context("maintain Headspace fact collection")?,
            );
            drop(
                pile.maintain(collection_rank9)
                    .await
                    .context("maintain Headspace fact collection")?,
            );
            let store_snapshot = secrets_collection
                .ensure_exact(pile, &secrets_support)
                .await
                .context("ensure configured Secrets collection")?;
            let secrets =
                secret_storage::snapshot_exact(store_snapshot, secrets_collection, secrets_support)
                    .context("attach exact Secrets collection")?;
            Ok::<_, anyhow::Error>(secrets)
        })?;
        // Attach Headspace through the same final immutable physical snapshot
        // that backs every Secrets lookup in this view.
        let reader = secrets.store_snapshot().clone();
        let facts = reader
            .collection(collection_rank9)
            .context("attach maintained Headspace collection")?
            .view::<FactArchive>()
            .context("read maintained Headspace collection")?;
        let headspace = CollectionView { facts, reader };
        Ok(Views { headspace, secrets })
    }

    fn add_secret(&self, name: &str, plaintext: &[u8]) -> Result<Id> {
        let mut pile = self.pile.borrow_mut();
        let pile = pile
            .as_mut()
            .ok_or_else(|| anyhow!("Headspace storage is already closed"))?;
        let collection = open_secrets_collection(pile, self.signer.verifying_key())?;
        secret_storage::add_secret(
            pile,
            &self.signer,
            collection,
            name,
            plaintext,
            point_now()?,
        )
        .context("seal and publish Headspace credential version")
    }

    fn publish(&self, scope: Id, mut fragment: Fragment, description: &str) -> Result<()> {
        fragment.describe_with(entity! { metadata::description: description.to_owned() });
        let mut pile = self.pile.borrow_mut();
        let pile = pile
            .as_mut()
            .ok_or_else(|| anyhow!("Headspace storage is already closed"))?;
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
            .with_context(|| format!("close Headspace pile {}", self.pile_path.display()))
    }
}

impl Drop for Storage<'_> {
    fn drop(&mut self) {
        let _ = self.close_inner();
    }
}

fn settled_config(config: &Resolution<ConfigValue>) -> Result<Option<&ConfigValue>> {
    config.settled_value("Headspace config")
}

fn require_profile(profile: &Resolution<ProfileValue>, anchor: Id) -> Result<&ProfileValue> {
    profile
        .settled_value(&format!("profile {anchor:x}"))?
        .ok_or_else(|| anyhow!("profile {anchor:x} has no snapshot"))
}

fn resolve_profile_selector(views: &Views, raw: &str) -> Result<Id> {
    if let Some(id) = Id::from_hex(raw.trim()) {
        let profile =
            headspace::current_profile(&views.headspace.reader, &views.headspace.facts, id)?;
        require_profile(&profile, id)?;
        return Ok(id);
    }
    let needle = raw.trim().to_ascii_lowercase();
    let mut matches = Vec::new();
    for (anchor, resolution) in
        headspace::current_profiles(&views.headspace.reader, &views.headspace.facts)?
    {
        let profile = match resolution {
            Resolution::Unique(snapshot) => Some(snapshot.value),
            Resolution::Agreed(snapshots) => {
                snapshots.first().map(|snapshot| snapshot.value.clone())
            }
            Resolution::Missing | Resolution::Forked(_) | Resolution::Invalid(_) => None,
        };
        if profile.is_some_and(|profile| profile.name.to_ascii_lowercase() == needle) {
            matches.push(anchor);
        }
    }
    match matches.as_slice() {
        [] => bail!("unknown profile {raw:?}"),
        [id] => Ok(*id),
        _ => bail!("profile name {raw:?} is ambiguous; use the full anchor id"),
    }
}

fn parse_exact_secret(views: &Views, raw: &str, label: &str) -> Result<Id> {
    let id = Id::from_hex(raw.trim())
        .ok_or_else(|| anyhow!("{label} requires one exact 32-hex Secrets version id"))?;
    if !views.secrets.contains(id) {
        bail!("unknown exact Secrets version {id:x}");
    }
    Ok(id)
}

fn publish_headspace(storage: &Storage<'_>, fragment: Fragment, description: &str) -> Result<()> {
    storage.publish(DEFAULT_SCOPE_ID, fragment, description)
}

fn use_profile(storage: &Storage<'_>, selector: &str, out: &mut Out<'_>) -> Result<()> {
    let views = storage.views()?;
    let anchor = resolve_profile_selector(&views, selector)?;
    let profile =
        headspace::current_profile(&views.headspace.reader, &views.headspace.facts, anchor)?;
    require_profile(&profile, anchor)?;
    let config_resolution =
        headspace::current_config(&views.headspace.reader, &views.headspace.facts)?;
    let existing = settled_config(&config_resolution)?;
    if existing.is_some_and(|config| config.active_profile == anchor) {
        return print_headspace(&views, None, out);
    }
    let mut config = existing
        .cloned()
        .unwrap_or_else(|| headspace::default_config(anchor));
    config.active_profile = anchor;
    let fragment = headspace::config_snapshot_fragment(&config, &config_resolution.head_ids())?.0;
    publish_headspace(storage, fragment, "headspace: switch active profile")?;
    print_reloaded(storage, out)
}

fn add_profile(storage: &Storage<'_>, args: &AddProfileOptions, out: &mut Out<'_>) -> Result<Id> {
    let views = storage.views()?;
    let config = headspace::current_config(&views.headspace.reader, &views.headspace.facts)?;
    let anchor = genid().id;
    let mut profile = match settled_config(&config)? {
        Some(config) => {
            let active = headspace::current_profile(
                &views.headspace.reader,
                &views.headspace.facts,
                config.active_profile,
            )?;
            require_profile(&active, config.active_profile)?.clone()
        }
        None => headspace::default_profile(anchor, args.name.clone()),
    };
    profile.anchor = anchor;
    profile.name = args.name.clone();
    if let Some(value) = args.model.as_deref() {
        profile.model = value.to_owned();
    }
    if let Some(value) = args.base_url.as_deref() {
        profile.base_url = value.to_owned();
    }
    if let Some(value) = args.model_secret_version.as_deref() {
        profile.model_secret_version =
            Some(parse_exact_secret(&views, value, "--model-secret-version")?);
    }
    if let Some(value) = args.reasoning_effort.as_deref() {
        profile.reasoning_effort = Some(value.trim().to_owned());
    }
    if let Some(value) = args.stream {
        profile.stream = value;
    }
    if let Some(value) = args.context_window_tokens {
        profile.context_window_tokens = value;
    }
    if let Some(value) = args.max_output_tokens {
        profile.max_output_tokens = value;
    }
    if let Some(value) = args.context_safety_margin_tokens {
        profile.context_safety_margin_tokens = value;
    }
    if let Some(value) = args.chars_per_token {
        profile.chars_per_token = value;
    }

    let mut next_config = settled_config(&config)?
        .cloned()
        .unwrap_or_else(|| headspace::default_config(anchor));
    next_config.active_profile = anchor;
    let fragment = headspace::add_profile_fragment(&profile, &next_config, &config.head_ids())?.0;
    publish_headspace(storage, fragment, "headspace: add and activate profile")?;
    print_reloaded(storage, out)?;
    Ok(anchor)
}

fn set_profile_field(storage: &Storage<'_>, field: &ProfileEdit, out: &mut Out<'_>) -> Result<()> {
    let views = storage.views()?;
    let config_resolution =
        headspace::current_config(&views.headspace.reader, &views.headspace.facts)?;
    let config = settled_config(&config_resolution)?
        .ok_or_else(|| anyhow!("Headspace has no active configuration; add a profile first"))?;
    let profile = headspace::current_profile(
        &views.headspace.reader,
        &views.headspace.facts,
        config.active_profile,
    )?;
    let current = require_profile(&profile, config.active_profile)?;
    let mut changed = current.clone();
    match field {
        ProfileEdit::Model(value) => changed.model = value.clone(),
        ProfileEdit::BaseUrl(value) => changed.base_url = value.clone(),
        ProfileEdit::ReasoningEffort(value) => {
            changed.reasoning_effort = Some(value.trim().to_owned())
        }
        ProfileEdit::Stream(value) => changed.stream = *value,
        ProfileEdit::ContextWindowTokens(value) => changed.context_window_tokens = *value,
        ProfileEdit::MaxOutputTokens(value) => changed.max_output_tokens = *value,
        ProfileEdit::PromptSafetyMarginTokens(value) => {
            changed.context_safety_margin_tokens = *value
        }
        ProfileEdit::PromptCharsPerToken(value) => changed.chars_per_token = *value,
    }
    if changed == *current {
        return print_headspace(&views, None, out);
    }
    let fragment = headspace::profile_snapshot_fragment(&changed, &profile.head_ids())?.0;
    publish_headspace(storage, fragment, "headspace: update profile")?;
    print_reloaded(storage, out)
}

fn unset_profile_field(
    storage: &Storage<'_>,
    field: OptionalProfileField,
    out: &mut Out<'_>,
) -> Result<()> {
    let views = storage.views()?;
    let config_resolution =
        headspace::current_config(&views.headspace.reader, &views.headspace.facts)?;
    let config = settled_config(&config_resolution)?
        .ok_or_else(|| anyhow!("Headspace has no active configuration; add a profile first"))?;
    let profile = headspace::current_profile(
        &views.headspace.reader,
        &views.headspace.facts,
        config.active_profile,
    )?;
    let current = require_profile(&profile, config.active_profile)?;
    let mut changed = current.clone();
    match field {
        OptionalProfileField::ReasoningEffort => changed.reasoning_effort = None,
    }
    if changed == *current {
        return print_headspace(&views, None, out);
    }
    let fragment = headspace::profile_snapshot_fragment(&changed, &profile.head_ids())?.0;
    publish_headspace(storage, fragment, "headspace: unset profile field")?;
    print_reloaded(storage, out)
}

fn secret_label(role: SecretRole, profile: Id) -> String {
    match role {
        SecretRole::Model => format!("hs/model/{}", URL_SAFE_NO_PAD.encode(profile.raw())),
        SecretRole::Tavily => "hs/tavily".to_owned(),
        SecretRole::Exa => "hs/exa".to_owned(),
    }
}

fn point_now() -> Result<secrets_model::IntervalValue> {
    clock::point_now()
}

struct SecretSuccessor {
    fragment: Fragment,
    current: Option<Id>,
}

fn secret_successor(
    views: &Views,
    role: SecretRole,
    replacement: Option<Id>,
) -> Result<SecretSuccessor> {
    let config_resolution =
        headspace::current_config(&views.headspace.reader, &views.headspace.facts)?;
    let config = settled_config(&config_resolution)?
        .ok_or_else(|| anyhow!("Headspace has no active configuration; add a profile first"))?;
    let profile_resolution = headspace::current_profile(
        &views.headspace.reader,
        &views.headspace.facts,
        config.active_profile,
    )?;
    let profile = require_profile(&profile_resolution, config.active_profile)?;
    match role {
        SecretRole::Model => {
            let mut changed = profile.clone();
            let current = changed.model_secret_version;
            changed.model_secret_version = replacement;
            Ok(SecretSuccessor {
                fragment: headspace::profile_snapshot_fragment(
                    &changed,
                    &profile_resolution.head_ids(),
                )?
                .0,
                current,
            })
        }
        SecretRole::Tavily | SecretRole::Exa => {
            let mut changed = config.clone();
            let current = match role {
                SecretRole::Tavily => changed.tavily_secret_version,
                SecretRole::Exa => changed.exa_secret_version,
                SecretRole::Model => unreachable!(),
            };
            match role {
                SecretRole::Tavily => changed.tavily_secret_version = replacement,
                SecretRole::Exa => changed.exa_secret_version = replacement,
                SecretRole::Model => unreachable!(),
            }
            Ok(SecretSuccessor {
                fragment: headspace::config_snapshot_fragment(
                    &changed,
                    &config_resolution.head_ids(),
                )?
                .0,
                current,
            })
        }
    }
}

fn unset_secret(storage: &Storage<'_>, role: SecretRole, out: &mut Out<'_>) -> Result<()> {
    let views = storage.views()?;
    let successor = secret_successor(&views, role, None)?;
    if successor.current.is_none() {
        out.line(format!("{role:?} credential is already unset"))?;
        return Ok(());
    }
    publish_headspace(
        storage,
        successor.fragment,
        "headspace: unset exact credential reference",
    )?;
    out.line(format!("{role:?} credential unset"))?;
    Ok(())
}

fn role_name(role: SecretRole) -> &'static str {
    match role {
        SecretRole::Model => "model",
        SecretRole::Tavily => "tavily",
        SecretRole::Exa => "exa",
    }
}

fn reconcile(storage: &Storage<'_>, raw: &str, out: &mut Out<'_>) -> Result<()> {
    let views = storage.views()?;
    // Reconciliation alone explicitly projects arbitrary retained history;
    // every ordinary read above asks only for its current typed frontier.
    let history = headspace::project_result(&views.headspace.reader, &views.headspace.facts)
        .context("project complete Headspace history for reconcile")?;
    let chosen = crate::resolve_id_prefix(raw, history.snapshot_ids())?;
    let Some((fragment, _)) = history.reconcile_fragment(chosen)? else {
        return print_headspace(&views, None, out);
    };
    publish_headspace(storage, fragment, "headspace: reconcile snapshot track")?;
    print_reloaded(storage, out)
}

fn open_secret_text(
    storage: &Storage<'_>,
    views: &Views,
    secret: Option<Id>,
    role: &str,
) -> Result<Option<String>> {
    let Some(secret) = secret else {
        return Ok(None);
    };
    let plaintext = views
        .secrets
        .open(secret, &storage.signer)
        .with_context(|| format!("open exact {role} Secrets version {secret:x}"))?;
    String::from_utf8(plaintext)
        .with_context(|| format!("exact {role} Secrets version {secret:x} is not UTF-8"))
        .map(Some)
}

fn open_display_secrets(storage: &Storage<'_>, views: &Views) -> Result<Option<OpenedSecrets>> {
    let config_resolution =
        headspace::current_config(&views.headspace.reader, &views.headspace.facts)?;
    let Some(config) = settled_config(&config_resolution)? else {
        return Ok(None);
    };
    let profile_resolution = headspace::current_profile(
        &views.headspace.reader,
        &views.headspace.facts,
        config.active_profile,
    )?;
    let profile = require_profile(&profile_resolution, config.active_profile)?;
    if profile.model_secret_version.is_none()
        && config.tavily_secret_version.is_none()
        && config.exa_secret_version.is_none()
    {
        return Ok(None);
    }
    Ok(Some(OpenedSecrets {
        model_api_key: open_secret_text(storage, views, profile.model_secret_version, "model")?,
        tavily_api_key: open_secret_text(storage, views, config.tavily_secret_version, "Tavily")?,
        exa_api_key: open_secret_text(storage, views, config.exa_secret_version, "Exa")?,
    }))
}

fn print_reloaded(storage: &Storage<'_>, out: &mut Out<'_>) -> Result<()> {
    let views = storage.views()?;
    print_headspace(&views, None, out)
}

fn print_headspace(views: &Views, opened: Option<&OpenedSecrets>, out: &mut Out<'_>) -> Result<()> {
    let config_resolution =
        headspace::current_config(&views.headspace.reader, &views.headspace.facts)?;
    let profiles = headspace::current_profiles(&views.headspace.reader, &views.headspace.facts)?;
    out.line(format!("active:"))?;
    let Some(config) = settled_config(&config_resolution)? else {
        let profile = headspace::default_profile(Id::new([1; 16]).unwrap(), "default");
        print_profile(None, &profile, None, out)?;
        out.line(format!("  tavily_secret_version = null"))?;
        out.line(format!("  tavily_api_key = null"))?;
        out.line(format!("  exa_secret_version = null"))?;
        out.line(format!("  exa_api_key = null"))?;
        out.line("")?;
        out.line(format!("profiles:"))?;
        return print_profile_resolutions(&config_resolution, &profiles, out);
    };
    let profile = profiles
        .get(&config.active_profile)
        .ok_or_else(|| anyhow!("unknown profile {:x}", config.active_profile))?;
    let profile = require_profile(profile, config.active_profile)?;
    print_profile(
        Some(config.active_profile),
        profile,
        opened.and_then(|value| value.model_api_key.as_deref()),
        out,
    )?;
    print_secret_line(
        "tavily",
        config.tavily_secret_version,
        opened.and_then(|value| value.tavily_api_key.as_deref()),
        out,
    )?;
    print_secret_line(
        "exa",
        config.exa_secret_version,
        opened.and_then(|value| value.exa_api_key.as_deref()),
        out,
    )?;
    out.line("")?;
    out.line(format!("profiles:"))?;
    print_profile_resolutions(&config_resolution, &profiles, out)
}

fn print_profile(
    anchor: Option<Id>,
    profile: &ProfileValue,
    opened: Option<&str>,
    out: &mut Out<'_>,
) -> Result<()> {
    out.line(format!(
        "  profile_id = {}",
        anchor
            .map(|id| format!("\"{id:x}\""))
            .unwrap_or_else(|| "null".to_owned())
    ))?;
    out.line(format!("  profile_name = \"{}\"", profile.name))?;
    out.line(format!("  model = \"{}\"", profile.model))?;
    out.line(format!("  base_url = \"{}\"", profile.base_url))?;
    print_secret_line("model", profile.model_secret_version, opened, out)?;
    out.line(format!(
        "  reasoning_effort = {}",
        profile
            .reasoning_effort
            .as_deref()
            .map(|value| format!("\"{value}\""))
            .unwrap_or_else(|| "null".to_owned())
    ))?;
    out.line(format!("  stream = {}", profile.stream))?;
    out.line(format!(
        "  context_window_tokens = {}",
        profile.context_window_tokens
    ))?;
    out.line(format!(
        "  max_output_tokens = {}",
        profile.max_output_tokens
    ))?;
    out.line(format!(
        "  context_safety_margin_tokens = {}",
        profile.context_safety_margin_tokens
    ))?;
    out.line(format!("  chars_per_token = {}", profile.chars_per_token))?;
    Ok(())
}

fn print_secret_line(
    role: &str,
    version: Option<Id>,
    opened: Option<&str>,
    out: &mut Out<'_>,
) -> Result<()> {
    out.line(format!(
        "  {role}_secret_version = {}",
        version
            .map(|id| format!("\"{id:x}\""))
            .unwrap_or_else(|| "null".to_owned())
    ))?;
    out.line(format!(
        "  {role}_api_key = {}",
        match (version, opened) {
            (None, _) => "null".to_owned(),
            (Some(_), Some(value)) => format!("\"{value}\""),
            (Some(_), None) => "\"<redacted>\"".to_owned(),
        }
    ))?;
    Ok(())
}

fn print_profile_list(views: &Views, out: &mut Out<'_>) -> Result<()> {
    let config = headspace::current_config(&views.headspace.reader, &views.headspace.facts)?;
    let profiles = headspace::current_profiles(&views.headspace.reader, &views.headspace.facts)?;
    print_profile_resolutions(&config, &profiles, out)
}

fn print_profile_resolutions(
    config: &Resolution<ConfigValue>,
    profiles: &BTreeMap<Id, Resolution<ProfileValue>>,
    out: &mut Out<'_>,
) -> Result<()> {
    let active = match config {
        Resolution::Unique(snapshot) => Some(snapshot.value.active_profile),
        Resolution::Agreed(snapshots) => snapshots
            .first()
            .map(|snapshot| snapshot.value.active_profile),
        Resolution::Missing | Resolution::Forked(_) | Resolution::Invalid(_) => None,
    };
    match config {
        Resolution::Missing => out.line(format!("config\t<missing>"))?,
        Resolution::Unique(snapshot) => out.line(format!(
            "config\t{:x}\tactive={:x}",
            snapshot.id, snapshot.value.active_profile
        ))?,
        Resolution::Agreed(snapshots) => out.line(format!(
            "config\t<agreed:{}>\theads={}",
            snapshots.len(),
            format_snapshot_ids(snapshots.iter().map(|snapshot| snapshot.id))
        ))?,
        Resolution::Forked(snapshots) => {
            out.line(format!(
                "config\t<forked:{}>\theads={}",
                snapshots.len(),
                format_snapshot_ids(snapshots.iter().map(|snapshot| snapshot.id))
            ))?;
            for snapshot in snapshots {
                out.line(format!(
                    "  head\t{:x}\tactive={:x}",
                    snapshot.id, snapshot.value.active_profile
                ))?;
            }
        }
        Resolution::Invalid(error) => out.line(format!("config\t<invalid>\t{error}"))?,
    }

    let mut rows = Vec::new();
    for (&anchor, resolution) in profiles {
        let marker = if active == Some(anchor) { '*' } else { ' ' };
        match resolution {
            Resolution::Unique(snapshot) => rows.push((
                snapshot.value.name.to_ascii_lowercase(),
                format!(
                    "{marker} {}\t{anchor:x}\tsnapshot={:x}",
                    snapshot.value.name, snapshot.id
                ),
            )),
            Resolution::Agreed(snapshots) => {
                let profile = &snapshots[0].value;
                rows.push((
                    profile.name.to_ascii_lowercase(),
                    format!(
                        "{marker} {}\t{anchor:x}\t[agreed:{}]\theads={}",
                        profile.name,
                        snapshots.len(),
                        format_snapshot_ids(snapshots.iter().map(|snapshot| snapshot.id))
                    ),
                ));
            }
            Resolution::Forked(snapshots) => {
                let names: BTreeSet<_> = snapshots
                    .iter()
                    .map(|snapshot| snapshot.value.name.as_str())
                    .collect();
                rows.push((
                    String::new(),
                    format!(
                        "! <forked:{}>\t{anchor:x}\theads={}\t{}",
                        snapshots.len(),
                        format_snapshot_ids(snapshots.iter().map(|snapshot| snapshot.id)),
                        names.into_iter().collect::<Vec<_>>().join(" | ")
                    ),
                ));
            }
            Resolution::Missing => rows.push((String::new(), format!("! <missing>\t{anchor:x}"))),
            Resolution::Invalid(error) => {
                rows.push((String::new(), format!("! <invalid>\t{anchor:x}\t{error}")))
            }
        }
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    for (_, row) in rows {
        out.line(format!("{row}"))?;
    }
    Ok(())
}

fn format_snapshot_ids(ids: impl IntoIterator<Item = Id>) -> String {
    ids.into_iter()
        .map(|id| format!("{id:x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn set_secret(
    storage: &Storage<'_>,
    role: SecretRole,
    credential: Credential,
    out: &mut Out<'_>,
) -> Result<Id> {
    let views = storage.views()?;
    let current = secret_successor(&views, role, None)?.current;
    match credential {
        Credential::Version(raw) => {
            let secret = parse_exact_secret(&views, &raw, "version")?;
            if current == Some(secret) {
                out.line(format!(
                    "{role:?} already references exact Secrets version {secret:x}"
                ))?;
                return Ok(secret);
            }
            let successor = secret_successor(&views, role, Some(secret))?;
            publish_headspace(
                storage,
                successor.fragment,
                "headspace: exact credential reference",
            )?;
            out.line(format!("{role:?} credential version {secret:x}"))?;
            Ok(secret)
        }
        Credential::Plaintext(plaintext) => {
            let plaintext = plaintext.trim();
            if plaintext.is_empty() || plaintext.bytes().any(|byte| byte == 0) {
                bail!("credential is empty or contains NUL");
            }
            let config =
                headspace::current_config(&views.headspace.reader, &views.headspace.facts)?;
            let profile = settled_config(&config)?
                .ok_or_else(|| {
                    anyhow!("Headspace has no active configuration; add a profile first")
                })?
                .active_profile;
            let secret = storage.add_secret(&secret_label(role, profile), plaintext.as_bytes())?;
            let mut reference_published = false;
            let finish = (|| {
                out.line(format!("Published exact credential {secret:x}; if Headspace publication is interrupted, retry with: headspace secret {} set --version {secret:x}", role_name(role)))?;
                // Refresh through this same open pile. Failure leaves an orphan
                // exact version, never a dangling Headspace credential reference.
                drop(views);
                let refreshed = storage.views()?;
                if !refreshed.secrets.contains(secret) {
                    bail!("published exact Secrets version {secret:x} did not materialize");
                }
                let successor = secret_successor(&refreshed, role, Some(secret))?;
                publish_headspace(
                    storage,
                    successor.fragment,
                    "headspace: exact credential reference",
                )?;
                reference_published = true;
                out.line(format!("{role:?} credential version {secret:x}"))?;
                Ok(secret)
            })();
            finish.map_err(|source| {
                CredentialUpdateError {
                    version: secret,
                    role,
                    reference_published,
                    source,
                }
                .into()
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::cli::{
        AddArgs, Cli, Command, SecretCommand, SecretRole, SecretSetArgs, SetField,
    };
    use super::*;
    use clap::CommandFactory;

    fn run(cli: Cli) -> Result<()> {
        super::super::cli::execute(cli, &mut Out::new(&mut |_| Ok(())))
    }

    use std::fs::File;

    use crate::storage::{initialize_signer, open_pile_strict};
    use triblespace::core::repo::StoreSnapshot;
    fn cli(pile: &Path, key: &Path, command: Command) -> Cli {
        Cli {
            pile: pile.to_owned(),
            key: Some(key.to_owned()),
            command: Some(command),
        }
    }

    fn add(name: &str) -> Command {
        Command::Add(AddArgs {
            name: name.to_owned(),
            model: None,
            base_url: None,
            model_secret_version: None,
            reasoning_effort: None,
            stream: None,
            context_window_tokens: None,
            max_output_tokens: None,
            context_safety_margin_tokens: None,
            chars_per_token: None,
        })
    }

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("headspace.pile");
        let key = directory.path().join("headspace.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        (directory, pile, key)
    }

    fn views<'a>(pile: &'a Path, key: &'a Path) -> (Storage<'a>, Views) {
        let storage = Storage::open(pile, Some(key)).unwrap();
        let views = storage.views().unwrap();
        (storage, views)
    }

    #[test]
    fn missing_signer_does_not_grow_the_pile() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("headspace.pile");
        File::create(&pile).unwrap();
        let before = std::fs::metadata(&pile).unwrap().len();
        assert!(Storage::open(&pile, None).is_err());
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), before);
    }

    #[test]
    fn headspace_and_secrets_share_one_final_store_snapshot() {
        let (_directory, pile, key) = fixture();
        let (storage, views) = views(&pile, &key);
        let secrets_reader = views.secrets.store_snapshot();
        assert!(views
            .headspace
            .reader
            .changes_since(secrets_reader)
            .is_empty());
        assert!(secrets_reader
            .changes_since(&views.headspace.reader)
            .is_empty());
        assert_eq!(views.headspace.reader.instant(), secrets_reader.instant());
        storage.close().unwrap();
    }

    #[test]
    fn add_use_and_idempotent_profile_set_advance_only_intended_tracks() {
        let (_directory, pile, key) = fixture();
        run(cli(&pile, &key, add("first"))).unwrap();
        let (storage, first) = views(&pile, &key);
        let first_config =
            headspace::current_config(&first.headspace.reader, &first.headspace.facts).unwrap();
        let first_anchor = settled_config(&first_config)
            .unwrap()
            .unwrap()
            .active_profile;
        storage.close().unwrap();

        run(cli(&pile, &key, add("second"))).unwrap();
        run(cli(
            &pile,
            &key,
            Command::Use {
                profile: format!("{first_anchor:x}"),
            },
        ))
        .unwrap();
        run(cli(
            &pile,
            &key,
            Command::Set {
                field: SetField::Model,
                value: "changed".to_owned(),
            },
        ))
        .unwrap();
        let (storage, before) = views(&pile, &key);
        let snapshots =
            headspace::project_result(&before.headspace.reader, &before.headspace.facts)
                .unwrap()
                .snapshot_ids()
                .len();
        storage.close().unwrap();

        run(cli(
            &pile,
            &key,
            Command::Set {
                field: SetField::Model,
                value: "changed".to_owned(),
            },
        ))
        .unwrap();
        let (storage, after) = views(&pile, &key);
        assert_eq!(
            headspace::project_result(&after.headspace.reader, &after.headspace.facts)
                .unwrap()
                .snapshot_ids()
                .len(),
            snapshots
        );
        storage.close().unwrap();
    }

    #[test]
    fn interrupted_secrets_first_publication_repairs_by_exact_version_id() {
        let (_directory, pile, key) = fixture();
        run(cli(&pile, &key, add("default"))).unwrap();

        let signer = load_signer(&pile, Some(&key)).unwrap();
        let mut store = open_pile_strict(&pile).unwrap();
        let collection = open_secrets_collection(&mut store, signer.verifying_key()).unwrap();
        let version = secret_storage::add_secret(
            &mut store,
            &signer,
            collection,
            "hs/model/interrupted",
            b"exact",
            point_now().unwrap(),
        )
        .unwrap();
        store.close().unwrap();

        // Deterministic second half after a crash between collection commits.
        run(cli(
            &pile,
            &key,
            Command::Secret {
                role: SecretRole::Model,
                command: SecretCommand::Set(SecretSetArgs {
                    value: None,
                    version: Some(format!("{version:x}")),
                }),
            },
        ))
        .unwrap();
        let (storage, repaired) = views(&pile, &key);
        assert_eq!(repaired.secrets.collection(), collection.handle());
        assert!(repaired.secrets.contains(version));
        let config_resolution =
            headspace::current_config(&repaired.headspace.reader, &repaired.headspace.facts)
                .unwrap();
        let config = settled_config(&config_resolution).unwrap().unwrap();
        let profile_resolution = headspace::current_profile(
            &repaired.headspace.reader,
            &repaired.headspace.facts,
            config.active_profile,
        )
        .unwrap();
        let profile = require_profile(&profile_resolution, config.active_profile).unwrap();
        assert_eq!(profile.model_secret_version, Some(version));
        storage.close().unwrap();

        run(cli(
            &pile,
            &key,
            Command::Secret {
                role: SecretRole::Model,
                command: SecretCommand::Set(SecretSetArgs {
                    value: None,
                    version: Some(format!("{version:x}")),
                }),
            },
        ))
        .unwrap();
        let (storage, replay) = views(&pile, &key);
        assert_eq!(replay.secrets.collection(), collection.handle());
        let config_resolution =
            headspace::current_config(&replay.headspace.reader, &replay.headspace.facts).unwrap();
        let config = settled_config(&config_resolution).unwrap().unwrap();
        let profile_resolution = headspace::current_profile(
            &replay.headspace.reader,
            &replay.headspace.facts,
            config.active_profile,
        )
        .unwrap();
        assert_eq!(
            require_profile(&profile_resolution, config.active_profile)
                .unwrap()
                .model_secret_version,
            Some(version)
        );
        storage.close().unwrap();
    }

    #[test]
    fn permanent_cli_exposes_no_collection_scope_branch_head_or_cas_knobs() {
        let command = Cli::command();
        for forbidden in ["scope", "branch", "branch_id", "head", "cas", "repair"] {
            assert!(!command
                .get_arguments()
                .any(|argument| argument.get_id() == forbidden));
        }
        assert!(command
            .get_arguments()
            .any(|argument| argument.get_id() == "key"));
    }
}
