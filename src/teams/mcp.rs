//! Independent Teams MCP UX: finite network actions, resident archive reads, raw exports.
use super::{operations::*, render};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;
use triblespace::prelude::Id;

const TOOLS: &[Tool] = &[
    Tool { name: "teams_read", description: "Read resident, causally current Teams archive messages. Does not call Graph; use teams_pull explicitly for fresh data.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."},"chat_id":{"type":"string"},"since":{"type":"string","description":"RFC3339 or Graph timestamp."},"limit":{"type":"integer","minimum":0,"default":20,"description":"Newest N resident results; 0 means unlimited."},"descending":{"type":"boolean","default":false}},"required":[],"additionalProperties":false}"# },
    Tool { name: "teams_pull", description: "Complete one finite Graph delta round and append validated page receipts. Uses the configured app credential and trusted endpoint; may acquire attachment bytes.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."}},"required":[],"additionalProperties":false}"# },
    Tool { name: "teams_send", description: "Send literal text to a Teams chat. Requires the configured professional context and an explicit matching present_as. May rotate encrypted delegated credentials.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."},"present_as":{"type":"string"},"chat_id":{"type":"string"},"text":{"type":"string","description":"Literal message text. @file and @- never read host input."}},"required":["present_as","chat_id","text"],"additionalProperties":false}"# },
    Tool { name: "teams_users_list", description: "Query one Microsoft Graph directory page using configured delegated authentication.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."},"prefix":{"type":"string"},"limit":{"type":"integer","minimum":0,"default":20,"description":"Requested page size; 0 omits Graph's top parameter."}},"required":[],"additionalProperties":false}"# },
    Tool { name: "teams_presence_set", description: "Set the configured user's presence with an explicit matching professional identity.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."},"present_as":{"type":"string"},"availability":{"type":"string","enum":["Available","Busy","Away","DoNotDisturb"]},"activity":{"type":"string","enum":["Available","InACall","InAConferenceCall","Away","Presenting"]},"duration_mins":{"type":"integer","minimum":5,"maximum":240,"default":60},"session_id":{"type":"string"}},"required":["present_as","availability"],"additionalProperties":false}"# },
    Tool { name: "teams_presence_get", description: "Query Graph presence for the supplied exact external user IDs.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."},"user_ids":{"type":"array","items":{"type":"string"},"minItems":1}},"required":["user_ids"],"additionalProperties":false}"# },
    Tool { name: "teams_chat_invite", description: "Add a user to a Teams chat, optionally as owner. Requires explicit matching present_as.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."},"present_as":{"type":"string"},"chat_id":{"type":"string"},"user_id":{"type":"string"},"owner":{"type":"boolean","default":false}},"required":["present_as","chat_id","user_id"],"additionalProperties":false}"# },
    Tool { name: "teams_chat_create", description: "Create a Teams chat including the configured user and the supplied members. Requires explicit matching present_as; topic is literal text.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."},"present_as":{"type":"string"},"user_ids":{"type":"array","items":{"type":"string"},"minItems":1},"group":{"type":"boolean","default":false},"topic":{"type":"string"}},"required":["present_as","user_ids"],"additionalProperties":false}"# },
    Tool { name: "teams_attachments_list", description: "List attachments of resident, currently live Teams messages. Does not sync or fetch remote attachment bytes.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."},"chat_id":{"type":"string"},"message_id":{"type":"string"},"limit":{"type":"integer","minimum":0,"default":20,"description":"Newest N resident results; 0 means unlimited."},"descending":{"type":"boolean","default":false}},"required":[],"additionalProperties":false}"# },
    Tool { name: "teams_attachment_get", description: "Export exact resident attachment bytes as a file resource, never as sensory image/audio. Does not sync, write a host path, or fetch missing remote bytes. Disambiguate with chat_id/message_id.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."},"source_id":{"type":"string","description":"Exact attachment source reference, optionally attachment:ID or hosted-content:ID."},"chat_id":{"type":"string"},"message_id":{"type":"string"}},"required":["source_id"],"additionalProperties":false}"# },
    Tool { name: "teams_context_set", description: "Publish the professional identity and work/privacy boundary for one explicit concrete tenant. Both strings are literal, not host input selectors.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."},"present_as":{"type":"string"},"boundary":{"type":"string"}},"required":["tenant","present_as","boundary"],"additionalProperties":false}"# },
    Tool { name: "teams_context_show", description: "Show the configured professional Teams identity and work/privacy boundary without opening credential plaintext.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."}},"required":[],"additionalProperties":false}"# },
    Tool { name: "teams_auth_status", description: "Inspect safe auth-profile metadata, exact encrypted Secrets version references, and any profile forks. Never returns credential plaintext.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."}},"required":[],"additionalProperties":false}"# },
    Tool { name: "teams_auth_set", description: "Publish or reconcile a complete auth profile using exact existing encrypted Secrets versions. At least one version is required. No raw credentials, host paths, or interactive OAuth input.", input_schema: r#"{"type":"object","properties":{"tenant":{"type":"string","description":"Concrete tenant selector. Omit only when one source is configured/available; never an OAuth authority such as common."},"client_id":{"type":"string"},"user_id":{"type":"string"},"scopes":{"type":"string","description":"Literal whitespace-separated OAuth scopes; @file and @- are not expanded."},"client_secret_version":{"type":"string"},"delegated_token_version":{"type":"string"}},"required":["tenant","client_id","user_id","scopes"],"additionalProperties":false}"# },
];

fn default_limit() -> usize {
    20
}
fn default_duration() -> u32 {
    60
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tenant {
    tenant: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Read {
    tenant: Option<String>,
    chat_id: Option<String>,
    since: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    descending: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Send {
    tenant: Option<String>,
    present_as: String,
    chat_id: String,
    text: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Users {
    tenant: Option<String>,
    prefix: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
}
#[derive(Clone, Copy, Deserialize)]
enum Availability {
    Available,
    Busy,
    Away,
    DoNotDisturb,
}
impl Availability {
    fn native(self) -> PresenceAvailability {
        match self {
            Self::Available => PresenceAvailability::Available,
            Self::Busy => PresenceAvailability::Busy,
            Self::Away => PresenceAvailability::Away,
            Self::DoNotDisturb => PresenceAvailability::DoNotDisturb,
        }
    }
}
#[derive(Clone, Copy, Deserialize)]
enum PresenceActivityArg {
    Available,
    InACall,
    InAConferenceCall,
    Away,
    Presenting,
}
impl PresenceActivityArg {
    fn native(self) -> PresenceActivity {
        match self {
            Self::Available => PresenceActivity::Available,
            Self::InACall => PresenceActivity::InACall,
            Self::InAConferenceCall => PresenceActivity::InAConferenceCall,
            Self::Away => PresenceActivity::Away,
            Self::Presenting => PresenceActivity::Presenting,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetPresence {
    tenant: Option<String>,
    present_as: String,
    availability: Availability,
    activity: Option<PresenceActivityArg>,
    #[serde(default = "default_duration")]
    duration_mins: u32,
    session_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetPresence {
    tenant: Option<String>,
    user_ids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invite {
    tenant: Option<String>,
    present_as: String,
    chat_id: String,
    user_id: String,
    #[serde(default)]
    owner: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateChat {
    tenant: Option<String>,
    present_as: String,
    user_ids: Vec<String>,
    #[serde(default)]
    group: bool,
    topic: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attachments {
    tenant: Option<String>,
    chat_id: Option<String>,
    message_id: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    descending: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetAttachment {
    tenant: Option<String>,
    source_id: String,
    chat_id: Option<String>,
    message_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetContext {
    tenant: String,
    present_as: String,
    boundary: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetAuth {
    tenant: String,
    client_id: String,
    user_id: String,
    scopes: String,
    client_secret_version: Option<String>,
    delegated_token_version: Option<String>,
}

fn nonempty(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(invalid_arguments(format!("{field} must not be empty")));
    }
    Ok(())
}
fn tenant_selector(tenant: &str) -> Result<()> {
    nonempty(tenant, "tenant")?;
    if super::is_generic_tenant(tenant) {
        return Err(invalid_arguments(
            "tenant must identify one concrete tenant, not common/organizations/consumers",
        ));
    }
    Ok(())
}
fn exact_id(value: &str) -> Result<Id> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_arguments(
            "secret version must be one exact nonzero 32-digit hexadecimal id",
        ));
    }
    Id::from_hex(value).ok_or_else(|| {
        invalid_arguments("secret version must be one exact nonzero 32-digit hexadecimal id")
    })
}
fn users_nonempty(values: &[String]) -> Result<()> {
    if values.is_empty() {
        return Err(invalid_arguments("user_ids requires at least one user id"));
    }
    for value in values {
        nonempty(value, "user id")?;
    }
    Ok(())
}

/// Server-owned configuration. Tool arguments cannot select paths, secret bytes, or delta URLs.
#[derive(Clone, Debug)]
pub struct Teams {
    operations: super::operations::Teams,
}
impl Teams {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self {
            operations: super::operations::Teams::new(pile, key),
        }
    }
    pub fn with_tenant(mut self, tenant: Option<String>) -> Self {
        self.operations = self.operations.with_tenant(tenant);
        self
    }
    /// Only trusted launcher configuration may override the Graph delta endpoint.
    pub fn with_delta_url(mut self, delta_url: String) -> Self {
        self.operations = self.operations.with_delta_url(delta_url);
        self
    }
    fn selected(&self, tenant: Option<String>) -> Result<super::operations::Teams> {
        if let Some(tenant) = tenant {
            tenant_selector(&tenant)?;
            Ok(self.operations.clone().with_tenant(Some(tenant)))
        } else {
            Ok(self.operations.clone())
        }
    }
}

impl Faculty for Teams {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "teams_read" => {
                let args: Read = decode_arguments(arguments)?;
                parse_since_key(args.since.as_deref()).map_err(invalid_arguments)?;
                let value = self.selected(args.tenant)?.read(
                    ReadOptions {
                        chat_id: args.chat_id,
                        since: args.since,
                        limit: args.limit,
                        descending: args.descending,
                    },
                    ArchiveAccess::Resident,
                )?;
                render::activity(&value, out)?;
                render::messages(&value.value, out)
            }
            "teams_pull" => {
                let args: Tenant = decode_arguments(arguments)?;
                let value = self.selected(args.tenant)?.pull()?;
                render::activity(&value, out)?;
                out.line(format!(
                    "Pulled {} page(s), {} observation(s).",
                    value.value.pages.len(),
                    value.value.observations
                ))?;
                for page in value.value.pages {
                    out.line(format!("coverage: {page:x}"))?;
                }
                Ok(())
            }
            "teams_send" => {
                let args: Send = decode_arguments(arguments)?;
                nonempty(&args.present_as, "present_as")?;
                nonempty(&args.chat_id, "chat_id")?;
                let value = self.selected(args.tenant)?.send(
                    &args.present_as,
                    &args.chat_id,
                    &args.text,
                )?;
                render::activity(&value, out)?;
                if let Some(id) = value.value.message_id {
                    out.line(format!("message_id: {id}"))?;
                }
                out.line(format!("sent_to: {}", value.value.chat_id))
            }
            "teams_users_list" => {
                let args: Users = decode_arguments(arguments)?;
                let value = self
                    .selected(args.tenant)?
                    .users_list(args.prefix.as_deref(), args.limit)?;
                render::activity(&value, out)?;
                render::users(&value.value, out)
            }
            "teams_presence_set" => {
                let args: SetPresence = decode_arguments(arguments)?;
                nonempty(&args.present_as, "present_as")?;
                let availability = args.availability.native();
                let activity = args.activity.map(PresenceActivityArg::native);
                validate_presence(availability, activity, args.duration_mins)
                    .map_err(invalid_arguments)?;
                let value = self.selected(args.tenant)?.presence_set(
                    &args.present_as,
                    availability,
                    activity,
                    args.duration_mins,
                    args.session_id,
                )?;
                render::activity(&value, out)?;
                out.line(format!(
                    "{}  {}  {}  session={} duration={}m",
                    value.value.user_id,
                    value.value.availability,
                    value.value.activity,
                    value.value.session_id,
                    value.value.duration_mins
                ))
            }
            "teams_presence_get" => {
                let args: GetPresence = decode_arguments(arguments)?;
                users_nonempty(&args.user_ids)?;
                let value = self.selected(args.tenant)?.presence_get(args.user_ids)?;
                render::activity(&value, out)?;
                render::presence(&value.value, out)
            }
            "teams_chat_invite" => {
                let args: Invite = decode_arguments(arguments)?;
                nonempty(&args.present_as, "present_as")?;
                nonempty(&args.chat_id, "chat_id")?;
                nonempty(&args.user_id, "user_id")?;
                let value = self.selected(args.tenant)?.chat_invite(
                    &args.present_as,
                    &args.chat_id,
                    &args.user_id,
                    args.owner,
                )?;
                render::activity(&value, out)?;
                out.line(format!(
                    "invited: {} chat={} owner={}",
                    value.value.user_id, value.value.chat_id, value.value.owner
                ))
            }
            "teams_chat_create" => {
                let args: CreateChat = decode_arguments(arguments)?;
                nonempty(&args.present_as, "present_as")?;
                users_nonempty(&args.user_ids)?;
                let value = self.selected(args.tenant)?.chat_create(
                    &args.present_as,
                    args.user_ids,
                    args.group,
                    args.topic,
                )?;
                render::activity(&value, out)?;
                out.line(value.value)
            }
            "teams_attachments_list" => {
                let args: Attachments = decode_arguments(arguments)?;
                let value = self.selected(args.tenant)?.attachments_list(
                    AttachmentListOptions {
                        chat_id: args.chat_id,
                        message_id: args.message_id,
                        limit: args.limit,
                        descending: args.descending,
                    },
                    ArchiveAccess::Resident,
                )?;
                render::activity(&value, out)?;
                render::attachments(&value.value, out)
            }
            "teams_attachment_get" => {
                let args: GetAttachment = decode_arguments(arguments)?;
                let source = args.source_id.trim();
                nonempty(
                    source
                        .strip_prefix("attachment:")
                        .or_else(|| source.strip_prefix("hosted-content:"))
                        .unwrap_or(source),
                    "source_id",
                )?;
                let value = self.selected(args.tenant)?.attachment_get(
                    AttachmentGetOptions {
                        source_id: args.source_id,
                        chat_id: args.chat_id,
                        message_id: args.message_id,
                    },
                    ArchiveAccess::Resident,
                )?;
                render::activity(&value, out)?;
                match value.value {
                    AttachmentLookup::Missing { reference } => {
                        render::attachment_missing(&reference, out)
                    }
                    AttachmentLookup::Ambiguous(matches) => {
                        out.line(
                            "Multiple attachments matched; supply chat_id and/or message_id:",
                        )?;
                        render::attachment_matches(&matches, out)
                    }
                    AttachmentLookup::Found(data) => {
                        out.line(format!(
                            "attachment={} name={} mime={}",
                            data.reference,
                            data.name,
                            data.media_type
                                .as_deref()
                                .unwrap_or("application/octet-stream")
                        ))?;
                        out.blob(
                            data.bytes,
                            "application/octet-stream",
                            format!("teams:///attachments/{:x}", data.id),
                        )
                    }
                }
            }
            "teams_context_set" => {
                let args: SetContext = decode_arguments(arguments)?;
                tenant_selector(&args.tenant)?;
                nonempty(&args.present_as, "present_as")?;
                nonempty(&args.boundary, "boundary")?;
                let receipt =
                    self.operations
                        .context_set(&args.tenant, &args.present_as, &args.boundary)?;
                out.line(format!("context_id: {:x}", receipt.context))?;
                render::context(&receipt.value, out)
            }
            "teams_context_show" => {
                let args: Tenant = decode_arguments(arguments)?;
                render::context(&self.selected(args.tenant)?.context_show()?, out)
            }
            "teams_auth_status" => {
                let args: Tenant = decode_arguments(arguments)?;
                let value = self.selected(args.tenant)?.auth_status()?;
                render::activity(&value, out)?;
                out.text(value.value)
            }
            "teams_auth_set" => {
                let args: SetAuth = decode_arguments(arguments)?;
                tenant_selector(&args.tenant)?;
                nonempty(&args.client_id, "client_id")?;
                nonempty(&args.user_id, "user_id")?;
                super::canonical_auth_scopes(&args.scopes).map_err(invalid_arguments)?;
                let client_secret_version = args
                    .client_secret_version
                    .as_deref()
                    .map(exact_id)
                    .transpose()?;
                let delegated_token_version = args
                    .delegated_token_version
                    .as_deref()
                    .map(exact_id)
                    .transpose()?;
                if client_secret_version.is_none() && delegated_token_version.is_none() {
                    return Err(invalid_arguments(
                        "an auth profile requires at least one exact encrypted Secrets version",
                    ));
                }
                render::auth_set(
                    &self.operations.auth_set(AuthProfileInput {
                        tenant: args.tenant,
                        client_id: args.client_id,
                        user_id: args.user_id,
                        scopes: args.scopes,
                        client_secret_version,
                        delegated_token_version,
                    })?,
                    out,
                )
            }
            _ => bail!("unknown Teams MCP tool {name:?}"),
        }
    }
}
