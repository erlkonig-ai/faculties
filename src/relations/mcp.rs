//! Independent Relations MCP schemas and literal, typed argument decoding.

use super::{render, PeopleFilter, ProfileInput, ProfilePatch, Relations as Operations};
use crate::mcp::{decode_arguments, invalid_arguments, Faculty, Tool};
use crate::out::Out;
use anybytes::Bytes;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;
use triblespace::prelude::Id;

const TOOLS: &[Tool] = &[
    Tool {
        name: "relations_add",
        description: "Add a stable person anchor with an initial full profile and active lifecycle. All text is literal; authority is the configured signer, not an ambient persona.",
        input_schema: r#"{"type":"object","properties":{"label":{"type":"string"},"id":{"type":"string","description":"Optional exact 32-character person id; otherwise mint a new anchor."},"sources":{"type":"array","items":{"type":"string"},"default":[]},"profile":{"type":"object","properties":{"aliases":{"type":"array","items":{"type":"string"}},"affinities":{"type":"array","items":{"type":"string"}},"first_name":{"type":"string"},"last_name":{"type":"string"},"display_name":{"type":"string"},"note":{"type":"string","description":"Literal prose; @file and @- never read host input."},"teams_user_ids":{"type":"array","items":{"type":"string"}},"emails":{"type":"array","items":{"type":"string"}},"phones":{"type":"array","items":{"type":"string"}},"company":{"type":"string"},"position":{"type":"string"},"profile_urls":{"type":"array","items":{"type":"string"}}},"additionalProperties":false}},"required":["label"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_set",
        description: "Replace only supplied fields on one settled current profile; add optional provenance without changing profile identity.",
        input_schema: r#"{"type":"object","properties":{"person":{"type":"string"},"sources":{"type":"array","items":{"type":"string"},"default":[]},"patch":{"type":"object","properties":{"label":{"type":"string"},"aliases":{"type":"array","items":{"type":"string"}},"affinities":{"type":"array","items":{"type":"string"}},"first_name":{"type":"string"},"last_name":{"type":"string"},"display_name":{"type":"string"},"note":{"type":"string","description":"Literal prose; @file and @- never read host input."},"teams_user_ids":{"type":"array","items":{"type":"string"}},"emails":{"type":"array","items":{"type":"string"}},"phones":{"type":"array","items":{"type":"string"}},"company":{"type":"string"},"position":{"type":"string"},"profile_urls":{"type":"array","items":{"type":"string"}},"clear":{"type":"array","items":{"type":"string","enum":["aliases","affinities","first_name","last_name","display_name","note","teams_user_ids","emails","phones","company","position","profile_urls"]},"default":[]}},"additionalProperties":false,"description":"Omitted fields remain untouched; present arrays replace the complete set, including []. Use clear for optional fields; clearing and replacing the same field conflicts. A profile fork must be explicitly reconciled."}},"required":["person"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_reconcile",
        description: "Collapse all concurrent profile heads. Choose a current base head explicitly if semantic profile values disagree.",
        input_schema: r#"{"type":"object","properties":{"person":{"type":"string"},"base":{"type":"string"},"patch":{"type":"object","properties":{"label":{"type":"string"},"aliases":{"type":"array","items":{"type":"string"}},"affinities":{"type":"array","items":{"type":"string"}},"first_name":{"type":"string"},"last_name":{"type":"string"},"display_name":{"type":"string"},"note":{"type":"string","description":"Literal prose; @file and @- never read host input."},"teams_user_ids":{"type":"array","items":{"type":"string"}},"emails":{"type":"array","items":{"type":"string"}},"phones":{"type":"array","items":{"type":"string"}},"company":{"type":"string"},"position":{"type":"string"},"profile_urls":{"type":"array","items":{"type":"string"}},"clear":{"type":"array","items":{"type":"string","enum":["aliases","affinities","first_name","last_name","display_name","note","teams_user_ids","emails","phones","company","position","profile_urls"]},"default":[]}},"additionalProperties":false,"description":"Omitted fields remain untouched; present arrays replace the complete set, including []. Use clear for optional fields; clearing and replacing the same field conflicts. A profile fork must be explicitly reconciled."}},"required":["person"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_list",
        description: "List people and visible profile/lifecycle forks. Filter retired people explicitly.",
        input_schema: r#"{"type":"object","properties":{"limit":{"type":"integer","minimum":0,"default":50},"filter":{"type":"string","enum":["active","all","retired"],"default":"active"}},"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_show",
        description: "Show a person, including every current head when profiles or lifecycles are forked.",
        input_schema: r#"{"type":"object","properties":{"person":{"type":"string"}},"required":["person"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_retire",
        description: "Publish a retired lifecycle successor; reconcile every current lifecycle head.",
        input_schema: r#"{"type":"object","properties":{"person":{"type":"string"}},"required":["person"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_unretire",
        description: "Publish an active lifecycle successor; reconcile every current lifecycle head.",
        input_schema: r#"{"type":"object","properties":{"person":{"type":"string"}},"required":["person"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_group_create",
        description: "Create an addressable, initially empty group.",
        input_schema: r#"{"type":"object","properties":{"name":{"type":"string"}},"required":["name"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_group_add",
        description: "Add a person to a settled group. Settled same-person verdicts count as existing membership without rewriting exact anchors.",
        input_schema: r#"{"type":"object","properties":{"group":{"type":"string"},"person":{"type":"string"}},"required":["group","person"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_group_remove",
        description: "Remove a person's settled identity-equivalent members from a group.",
        input_schema: r#"{"type":"object","properties":{"group":{"type":"string"},"person":{"type":"string"}},"required":["group","person"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_group_rename",
        description: "Rename one settled group.",
        input_schema: r#"{"type":"object","properties":{"group":{"type":"string"},"name":{"type":"string"}},"required":["group","name"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_group_reconcile",
        description: "Reconcile all group heads using the exact union of their members. An explicit name is required when names disagree.",
        input_schema: r#"{"type":"object","properties":{"group":{"type":"string"},"name":{"type":"string"}},"required":["group"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_group_list",
        description: "List groups and visible current-head forks.",
        input_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_group_show",
        description: "Show every current group head with exact members.",
        input_schema: r#"{"type":"object","properties":{"group":{"type":"string"}},"required":["group"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_identity_resolve",
        description: "Publish an explicit same-person (same=true) or distinct-person (same=false) verdict for two exact person anchors, reconciling existing verdict heads.",
        input_schema: r#"{"type":"object","properties":{"first":{"type":"string"},"second":{"type":"string"},"same":{"type":"boolean"}},"required":["first","second","same"],"additionalProperties":false}"#,
    },
    Tool {
        name: "relations_identity_list",
        description: "List all canonical identity pairs and every live verdict head.",
        input_schema: r#"{"type":"object","properties":{},"additionalProperties":false}"#,
    },
];

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct NewProfile {
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    affinities: Vec<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    display_name: Option<String>,
    note: Option<String>,
    #[serde(default)]
    teams_user_ids: Vec<String>,
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    phones: Vec<String>,
    company: Option<String>,
    position: Option<String>,
    #[serde(default)]
    profile_urls: Vec<String>,
}
impl NewProfile {
    fn into_profile(self, label: String) -> ProfileInput {
        ProfileInput {
            label,
            aliases: self.aliases,
            affinities: self.affinities,
            first_name: self.first_name,
            last_name: self.last_name,
            display_name: self.display_name,
            note: self.note,
            teams_user_ids: self.teams_user_ids,
            emails: self.emails,
            phones: self.phones,
            company: self.company,
            position: self.position,
            profile_urls: self.profile_urls,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClearField {
    Aliases,
    Affinities,
    FirstName,
    LastName,
    DisplayName,
    Note,
    TeamsUserIds,
    Emails,
    Phones,
    Company,
    Position,
    ProfileUrls,
}
impl From<ClearField> for super::ProfileField {
    fn from(field: ClearField) -> Self {
        match field {
            ClearField::Aliases => Self::Aliases,
            ClearField::Affinities => Self::Affinities,
            ClearField::FirstName => Self::FirstName,
            ClearField::LastName => Self::LastName,
            ClearField::DisplayName => Self::DisplayName,
            ClearField::Note => Self::Note,
            ClearField::TeamsUserIds => Self::TeamsUserIds,
            ClearField::Emails => Self::Emails,
            ClearField::Phones => Self::Phones,
            ClearField::Company => Self::Company,
            ClearField::Position => Self::Position,
            ClearField::ProfileUrls => Self::ProfileUrls,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Patch {
    label: Option<String>,
    aliases: Option<Vec<String>>,
    affinities: Option<Vec<String>>,
    first_name: Option<String>,
    last_name: Option<String>,
    display_name: Option<String>,
    note: Option<String>,
    teams_user_ids: Option<Vec<String>>,
    emails: Option<Vec<String>>,
    phones: Option<Vec<String>>,
    company: Option<String>,
    position: Option<String>,
    profile_urls: Option<Vec<String>>,
    #[serde(default)]
    clear: Vec<ClearField>,
}
impl Patch {
    fn into_patch(self) -> ProfilePatch {
        ProfilePatch {
            label: self.label,
            aliases: self.aliases,
            affinities: self.affinities,
            first_name: self.first_name,
            last_name: self.last_name,
            display_name: self.display_name,
            note: self.note,
            teams_user_ids: self.teams_user_ids,
            emails: self.emails,
            phones: self.phones,
            company: self.company,
            position: self.position,
            profile_urls: self.profile_urls,
            clear: self.clear.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddArguments {
    label: String,
    id: Option<String>,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default, deserialize_with = "crate::mcp::object::deserialize")]
    profile: NewProfile,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetArguments {
    person: String,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default, deserialize_with = "crate::mcp::object::deserialize")]
    patch: Patch,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconcileArguments {
    person: String,
    base: Option<String>,
    #[serde(default, deserialize_with = "crate::mcp::object::deserialize")]
    patch: Patch,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum Filter {
    #[default]
    Active,
    All,
    Retired,
}
impl From<Filter> for PeopleFilter {
    fn from(filter: Filter) -> Self {
        match filter {
            Filter::Active => Self::Active,
            Filter::All => Self::All,
            Filter::Retired => Self::Retired,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArguments {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    filter: Filter,
}
fn default_limit() -> usize {
    50
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonArguments {
    person: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NameArguments {
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupPersonArguments {
    group: String,
    person: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupNameArguments {
    group: String,
    name: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupReconcileArguments {
    group: String,
    name: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupArguments {
    group: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArguments {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityArguments {
    first: String,
    second: String,
    same: bool,
}

pub struct Relations {
    operations: Operations,
}
impl Relations {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self {
            operations: Operations::new(pile, key),
        }
    }
}
impl Faculty for Relations {
    fn tools(&self) -> &[Tool] {
        TOOLS
    }

    fn call(&self, name: &str, arguments: Bytes, output: &mut Out<'_>) -> Result<()> {
        match name {
            "relations_add" => {
                let args: AddArguments = decode_arguments(arguments)?;
                let id = args
                    .id
                    .as_deref()
                    .map(|id| {
                        Id::from_hex(id.trim()).ok_or_else(|| {
                            invalid_arguments("id must be an exact 32-character nonzero hex id")
                        })
                    })
                    .transpose()?;
                render::added(
                    &self.operations.add(
                        args.profile.into_profile(args.label),
                        id,
                        &args.sources,
                    )?,
                    output,
                )
            }
            "relations_set" => {
                let args: SetArguments = decode_arguments(arguments)?;
                render::profile_updated(
                    &self
                        .operations
                        .set(&args.person, args.patch.into_patch(), &args.sources)?,
                    output,
                )
            }
            "relations_reconcile" => {
                let args: ReconcileArguments = decode_arguments(arguments)?;
                render::profile_reconciled(
                    &self.operations.reconcile(
                        &args.person,
                        args.base.as_deref(),
                        args.patch.into_patch(),
                    )?,
                    output,
                )
            }
            "relations_list" => {
                let args: ListArguments = decode_arguments(arguments)?;
                output.text(self.operations.list(args.limit, args.filter.into())?)
            }
            "relations_show" => {
                let args: PersonArguments = decode_arguments(arguments)?;
                output.text(self.operations.show(&args.person)?)
            }
            "relations_retire" => {
                let args: PersonArguments = decode_arguments(arguments)?;
                render::lifecycle(&self.operations.retire(&args.person)?, true, output)
            }
            "relations_unretire" => {
                let args: PersonArguments = decode_arguments(arguments)?;
                render::lifecycle(&self.operations.unretire(&args.person)?, false, output)
            }
            "relations_group_create" => {
                let args: NameArguments = decode_arguments(arguments)?;
                render::group_created(&self.operations.group_create(&args.name)?, output)
            }
            "relations_group_add" => {
                let args: GroupPersonArguments = decode_arguments(arguments)?;
                render::group_added(
                    &self.operations.group_add(&args.group, &args.person)?,
                    output,
                )
            }
            "relations_group_remove" => {
                let args: GroupPersonArguments = decode_arguments(arguments)?;
                render::group_removed(
                    &self.operations.group_remove(&args.group, &args.person)?,
                    output,
                )
            }
            "relations_group_rename" => {
                let args: GroupNameArguments = decode_arguments(arguments)?;
                render::group_renamed(
                    &self.operations.group_rename(&args.group, &args.name)?,
                    output,
                )
            }
            "relations_group_reconcile" => {
                let args: GroupReconcileArguments = decode_arguments(arguments)?;
                render::group_reconciled(
                    &self
                        .operations
                        .group_reconcile(&args.group, args.name.as_deref())?,
                    output,
                )
            }
            "relations_group_list" => {
                let _: EmptyArguments = decode_arguments(arguments)?;
                output.text(self.operations.group_list()?)
            }
            "relations_group_show" => {
                let args: GroupArguments = decode_arguments(arguments)?;
                output.text(self.operations.group_show(&args.group)?)
            }
            "relations_identity_resolve" => {
                let args: IdentityArguments = decode_arguments(arguments)?;
                render::identity(
                    &self
                        .operations
                        .identity_resolve(&args.first, &args.second, args.same)?,
                    args.same,
                    output,
                )
            }
            "relations_identity_list" => {
                let _: EmptyArguments = decode_arguments(arguments)?;
                output.text(self.operations.identity_list()?)
            }
            other => bail!("Relations MCP has no tool {other:?}"),
        }
    }
}
