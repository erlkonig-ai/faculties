//! Independent Mail MCP schemas, literal prose, exact encrypted credentials, and resident attachments.
use super::{operations::*, render};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use base64::Engine as _;
use serde::Deserialize;
use std::path::PathBuf;
use triblespace::prelude::Id;

const TOOLS: &[Tool] = &[
    Tool { name: "mail_account_set", description: "Publish a full-state mail-account configuration, or reconcile every current fork. Accept only exact existing encrypted Secrets versions; omit credential_version only to inherit one settled current credential. No password or host-path input.", input_schema: r#"{"type":"object","properties":{"account":{"type":"string"},"address":{"type":"string"},"display_name":{"type":"string"},"pop_endpoint":{"type":"string","description":"Implicit-TLS POP endpoint as host:port."},"smtp_endpoint":{"type":"string","description":"Implicit-TLS SMTP endpoint as host:port."},"username":{"type":"string"},"credential_version":{"type":"string"},"disabled":{"type":"boolean","default":false}},"required":["address","display_name","pop_endpoint","smtp_endpoint"],"additionalProperties":false}"# },
    Tool { name: "mail_account_list", description: "List resident account identities, configuration heads and disabled/forked state without opening credential plaintext.", input_schema: r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"# },
    Tool { name: "mail_fetch", description: "Drain every enabled account through UIDL-safe POP. This is an explicit network/remote-deletion action: persist Files and Mail evidence before DELE, then QUIT. A failed QUIT can leave remote deletion uncertain.", input_schema: r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"# },
    Tool { name: "mail_draft", description: "Create one immutable draft and its deterministic Decide authorization proposal. Text is literal. Attach existing exact Files IDs and/or resident raw attachments; no host paths. Does not send mail.", input_schema: r#"{"type":"object","properties":{"account":{"type":"string"},"to":{"type":"array","items":{"type":"string"},"default":[]},"cc":{"type":"array","items":{"type":"string"},"default":[]},"bcc":{"type":"array","items":{"type":"string"},"default":[]},"subject":{"type":"string"},"body":{"type":"string"},"file_ids":{"type":"array","items":{"type":"string"},"default":[],"description":"Exact existing Files value IDs."},"attachments":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"mime":{"type":"string"},"data":{"type":"string","description":"Raw attachment bytes encoded as base64."}},"required":["name","mime","data"],"additionalProperties":false},"default":[]}},"required":["account","subject","body"],"additionalProperties":false,"anyOf":[{"required":["to"],"properties":{"to":{"minItems":1}}},{"required":["cc"],"properties":{"cc":{"minItems":1}}},{"required":["bcc"],"properties":{"bcc":{"minItems":1}}}]}"# },
    Tool { name: "mail_reply", description: "Create a reply draft using one unambiguous existing wire message and explicit sending account. Body is literal, including @-; does not send mail.", input_schema: r#"{"type":"object","properties":{"account":{"type":"string"},"message":{"type":"string"},"body":{"type":"string"}},"required":["account","message","body"],"additionalProperties":false}"# },
    Tool { name: "mail_send", description: "Submit one Decide-authorized immutable draft under host-serialized per-account execution. Persist its send attempt before SMTP and acceptance afterward. Never automatically retry an uncertain attempt; host must serialize other processes/replicas too.", input_schema: r#"{"type":"object","properties":{"draft":{"type":"string"}},"required":["draft"],"additionalProperties":false}"# },
    Tool { name: "mail_outbox", description: "List resident draft intents and their pending, accepted, or uncertain delivery state.", input_schema: r#"{"type":"object","properties":{},"required":[],"additionalProperties":false}"# },
    Tool { name: "mail_list", description: "List resident inbound projections for an explicit active Relations persona. This is not a fetch and does not mark messages read.", input_schema: r#"{"type":"object","properties":{"persona":{"type":"string"},"unread":{"type":"boolean","default":false},"spam":{"type":"boolean","default":false}},"required":["persona"],"additionalProperties":false}"# },
    Tool { name: "mail_read", description: "Publish intrinsic read/seen evidence for an explicit active Relations persona and wire message. This marks read; use mail_show to display contents.", input_schema: r#"{"type":"object","properties":{"persona":{"type":"string"},"message":{"type":"string"}},"required":["persona","message"],"additionalProperties":false}"# },
    Tool { name: "mail_show", description: "Display every resident parser projection for one wire message, without marking it read or fetching mail.", input_schema: r#"{"type":"object","properties":{"message":{"type":"string"}},"required":["message"],"additionalProperties":false}"# },
    Tool { name: "mail_search", description: "Search resident projected subjects/bodies by case-insensitive literal substring; does not fetch or mark read.", input_schema: r#"{"type":"object","properties":{"query":{"type":"string"}},"required":["query"],"additionalProperties":false}"# },
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountSet {
    account: Option<String>,
    address: String,
    display_name: String,
    pop_endpoint: String,
    smtp_endpoint: String,
    username: Option<String>,
    credential_version: Option<String>,
    #[serde(default)]
    disabled: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResidentAttachment {
    name: String,
    mime: String,
    data: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Draft {
    account: String,
    #[serde(default)]
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    #[serde(default)]
    bcc: Vec<String>,
    subject: String,
    body: String,
    #[serde(default)]
    file_ids: Vec<String>,
    #[serde(default, deserialize_with = "crate::mcp::object::vec")]
    attachments: Vec<ResidentAttachment>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    account: String,
    message: String,
    body: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Send {
    draft: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    persona: String,
    #[serde(default)]
    unread: bool,
    #[serde(default)]
    spam: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Read {
    persona: String,
    message: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Show {
    message: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    query: String,
}

fn text(value: &str, field: &str) -> Result<()> {
    if value.contains('\0') {
        return Err(invalid_arguments(format!("{field} must not contain NUL")));
    }
    Ok(())
}
fn nonempty(value: &str, field: &str) -> Result<()> {
    text(value, field)?;
    if value.trim().is_empty() {
        return Err(invalid_arguments(format!("{field} must not be empty")));
    }
    Ok(())
}
fn exact_id(value: &str) -> Result<Id> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_arguments(
            "expected one exact nonzero 32-digit hexadecimal id",
        ));
    }
    Id::from_hex(value)
        .ok_or_else(|| invalid_arguments("expected one exact nonzero 32-digit hexadecimal id"))
}

#[derive(Clone, Debug)]
pub struct Mail {
    operations: super::operations::Mail,
}
impl Mail {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self {
            operations: super::operations::Mail::new(pile, key),
        }
    }
}
impl Faculty for Mail {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }
    fn call(&self, name: &str, arguments: Bytes, out: &mut Out<'_>) -> Result<()> {
        match name {
            "mail_account_set" => {
                let args: AccountSet = decode_arguments(arguments)?;
                for (field, value) in [
                    ("address", &args.address),
                    ("display_name", &args.display_name),
                    ("pop_endpoint", &args.pop_endpoint),
                    ("smtp_endpoint", &args.smtp_endpoint),
                ] {
                    nonempty(value, field)?;
                }
                if let Some(username) = &args.username {
                    nonempty(username, "username")?;
                }
                if let Some(account) = &args.account {
                    nonempty(account, "account")?;
                }
                let credential_version = args
                    .credential_version
                    .as_deref()
                    .map(exact_id)
                    .transpose()?;
                if args.account.is_none() && credential_version.is_none() {
                    return Err(invalid_arguments(
                        "a new account requires one exact credential_version",
                    ));
                }
                let value = self.operations.account_set(AccountOptions {
                    account: args.account,
                    address: args.address,
                    display_name: args.display_name,
                    pop_endpoint: args.pop_endpoint,
                    smtp_endpoint: args.smtp_endpoint,
                    username: args.username,
                    credential_version,
                    disabled: args.disabled,
                })?;
                for notice in &value.notices {
                    out.line(notice)?;
                }
                render::account_set(&value, out)
            }
            "mail_account_list" => {
                let _: Empty = decode_arguments(arguments)?;
                render::accounts(&self.operations.account_list()?, out)
            }
            "mail_fetch" => {
                let _: Empty = decode_arguments(arguments)?;
                render::fetched(&self.operations.fetch()?, out)
            }
            "mail_draft" => {
                let args: Draft = decode_arguments(arguments)?;
                nonempty(&args.account, "account")?;
                text(&args.subject, "subject")?;
                text(&args.body, "body")?;
                if args.to.is_empty() && args.cc.is_empty() && args.bcc.is_empty() {
                    return Err(invalid_arguments("draft requires at least one recipient"));
                }
                for value in args.to.iter().chain(&args.cc).chain(&args.bcc) {
                    nonempty(value, "recipient")?;
                }
                let mut attachments = args
                    .file_ids
                    .iter()
                    .map(|id| exact_id(id).map(DraftAttachment::File))
                    .collect::<Result<Vec<_>>>()?;
                for value in args.attachments {
                    text(&value.name, "attachment name")?;
                    let media_type = crate::files::normalize_media_type(&value.mime)
                        .map_err(invalid_arguments)?;
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(&value.data)
                        .map_err(invalid_arguments)?;
                    attachments.push(DraftAttachment::Resident(super::AttachmentData {
                        filename: value.name,
                        media_type,
                        bytes,
                    }));
                }
                render::draft(
                    &self.operations.draft(DraftRequest {
                        account: args.account,
                        to: args.to,
                        cc: args.cc,
                        bcc: args.bcc,
                        subject: args.subject,
                        body: args.body,
                        attachments,
                    })?,
                    out,
                )
            }
            "mail_reply" => {
                let args: Reply = decode_arguments(arguments)?;
                nonempty(&args.account, "account")?;
                nonempty(&args.message, "message")?;
                text(&args.body, "body")?;
                render::draft(
                    &self.operations.reply(ReplyRequest {
                        account: args.account,
                        message: args.message,
                        body: args.body,
                    })?,
                    out,
                )
            }
            "mail_send" => {
                let args: Send = decode_arguments(arguments)?;
                nonempty(&args.draft, "draft")?;
                render::sent(&self.operations.send(&args.draft)?, out)
            }
            "mail_outbox" => {
                let _: Empty = decode_arguments(arguments)?;
                render::outbox(&self.operations.outbox()?, out)
            }
            "mail_list" => {
                let args: List = decode_arguments(arguments)?;
                nonempty(&args.persona, "persona")?;
                render::inbox(
                    &self
                        .operations
                        .list(&args.persona, args.unread, args.spam)?,
                    out,
                )
            }
            "mail_read" => {
                let args: Read = decode_arguments(arguments)?;
                nonempty(&args.persona, "persona")?;
                nonempty(&args.message, "message")?;
                render::read(&self.operations.read(&args.persona, &args.message)?, out)
            }
            "mail_show" => {
                let args: Show = decode_arguments(arguments)?;
                nonempty(&args.message, "message")?;
                render::show(&self.operations.show(&args.message)?, out)
            }
            "mail_search" => {
                let args: Search = decode_arguments(arguments)?;
                text(&args.query, "query")?;
                render::search(&self.operations.search(&args.query)?, out)
            }
            _ => bail!("unknown Mail MCP tool {name:?}"),
        }
    }
}
