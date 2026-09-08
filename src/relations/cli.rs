//! Relations' tailored CLI grammar. Notes and labels retain their existing
//! literal-string behavior; output delivery is a separate frontend concern.

use super::{render, PeopleFilter, ProfileInput, ProfilePatch, Relations};
use crate::out::Out;
use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use triblespace::prelude::Id;

#[derive(Parser)]
#[command(
    version = crate::GIT_VERSION,
    name = "relations",
    about = "Authored people, groups, and identity verdicts"
)]
pub struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add a stable person anchor with an initial profile and active lifecycle.
    Add {
        /// Canonical human-facing label.
        label: String,
        /// Exact stable person id. Omit to mint a fresh anchor.
        #[arg(long, value_parser = parse_id_arg)]
        id: Option<Id>,
        /// Additive provenance label (repeatable).
        #[arg(long)]
        source: Vec<String>,
        #[command(flatten)]
        profile: NewProfileArgs,
    },
    /// Replace selected fields of one current profile snapshot.
    Set {
        /// Person label, alias, exact id, or id prefix.
        person: String,
        /// Additive provenance label (repeatable; does not alter profile identity).
        #[arg(long)]
        source: Vec<String>,
        #[command(flatten)]
        patch: ProfilePatchArgs,
    },
    /// Collapse concurrent profile heads into one explicit successor.
    Reconcile {
        /// Person label, alias, exact id, or id prefix.
        person: String,
        /// Fork head whose full profile is the base. Optional only when every
        /// current head has the same semantic profile value.
        #[arg(long)]
        base: Option<String>,
        #[command(flatten)]
        patch: ProfilePatchArgs,
    },
    /// List person anchors and their current state.
    List {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Include settled retired people.
        #[arg(long)]
        all: bool,
        /// Show only settled retired people.
        #[arg(long, conflicts_with = "all")]
        retired: bool,
    },
    /// Show one person, including all heads when a track is forked.
    Show {
        /// Person label, alias, exact id, or id prefix.
        person: String,
    },
    /// Publish a retired lifecycle successor (also reconciles a lifecycle fork).
    Retire { person: String },
    /// Publish an active lifecycle successor (also reconciles a lifecycle fork).
    #[command(alias = "restore")]
    Unretire { person: String },
    /// Manage addressable exact-member groups.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    /// Record and inspect explicit same-person/distinct-person verdicts.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
}

#[derive(Args, Clone, Default)]
struct NewProfileArgs {
    #[arg(long)]
    alias: Vec<String>,
    #[arg(long)]
    affinity: Vec<String>,
    #[arg(long)]
    first_name: Option<String>,
    #[arg(long)]
    last_name: Option<String>,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long)]
    note: Option<String>,
    #[arg(long)]
    teams_user_id: Vec<String>,
    #[arg(long)]
    email: Vec<String>,
    #[arg(long)]
    phone: Vec<String>,
    #[arg(long)]
    company: Option<String>,
    #[arg(long)]
    position: Option<String>,
    #[arg(long)]
    profile_url: Vec<String>,
}

impl NewProfileArgs {
    fn into_profile(self, label: String) -> ProfileInput {
        ProfileInput {
            label,
            aliases: self.alias,
            affinities: self.affinity,
            first_name: self.first_name,
            last_name: self.last_name,
            display_name: self.display_name,
            note: self.note,
            teams_user_ids: self.teams_user_id,
            emails: self.email,
            phones: self.phone,
            company: self.company,
            position: self.position,
            profile_urls: self.profile_url,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, ValueEnum)]
enum ProfileField {
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

#[derive(Args, Clone, Default)]
struct ProfilePatchArgs {
    #[arg(long)]
    label: Option<String>,
    /// Replace the complete alias set (repeat for multiple values).
    #[arg(long)]
    alias: Vec<String>,
    /// Replace the complete affinity set (repeat for multiple values).
    #[arg(long)]
    affinity: Vec<String>,
    #[arg(long)]
    first_name: Option<String>,
    #[arg(long)]
    last_name: Option<String>,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long)]
    note: Option<String>,
    /// Replace the complete Teams-id set (repeat for multiple values).
    #[arg(long)]
    teams_user_id: Vec<String>,
    /// Replace the complete email set (repeat for multiple values).
    #[arg(long)]
    email: Vec<String>,
    /// Replace the complete phone set (repeat for multiple values).
    #[arg(long)]
    phone: Vec<String>,
    #[arg(long)]
    company: Option<String>,
    #[arg(long)]
    position: Option<String>,
    /// Replace the complete profile-URL set (repeat for multiple values).
    #[arg(long)]
    profile_url: Vec<String>,
    /// Clear one field or complete repeated field. Repeat as needed.
    #[arg(long, value_enum)]
    clear: Vec<ProfileField>,
}

#[derive(Subcommand)]
enum GroupCommand {
    Create {
        name: String,
    },
    Add {
        group: String,
        person: String,
    },
    Remove {
        group: String,
        person: String,
    },
    Rename {
        group: String,
        name: String,
    },
    /// Collapse all heads, taking the union of their exact member anchors.
    Reconcile {
        group: String,
        /// Required only when concurrent heads disagree on the name.
        #[arg(long)]
        name: Option<String>,
    },
    List,
    Show {
        group: String,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Resolve the current verdict for an unordered person pair.
    Resolve {
        first: String,
        second: String,
        #[arg(
            long,
            conflicts_with = "distinct",
            required_unless_present = "distinct"
        )]
        same: bool,
        #[arg(long, conflicts_with = "same", required_unless_present = "same")]
        distinct: bool,
    },
    /// List canonical person pairs and every live verdict head.
    List,
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
}

impl From<ProfileField> for super::ProfileField {
    fn from(value: ProfileField) -> Self {
        match value {
            ProfileField::Aliases => Self::Aliases,
            ProfileField::Affinities => Self::Affinities,
            ProfileField::FirstName => Self::FirstName,
            ProfileField::LastName => Self::LastName,
            ProfileField::DisplayName => Self::DisplayName,
            ProfileField::Note => Self::Note,
            ProfileField::TeamsUserIds => Self::TeamsUserIds,
            ProfileField::Emails => Self::Emails,
            ProfileField::Phones => Self::Phones,
            ProfileField::Company => Self::Company,
            ProfileField::Position => Self::Position,
            ProfileField::ProfileUrls => Self::ProfileUrls,
        }
    }
}
impl ProfilePatchArgs {
    fn into_patch(self) -> ProfilePatch {
        fn provided(values: Vec<String>) -> Option<Vec<String>> {
            (!values.is_empty()).then_some(values)
        }
        ProfilePatch {
            label: self.label,
            aliases: provided(self.alias),
            affinities: provided(self.affinity),
            first_name: self.first_name,
            last_name: self.last_name,
            display_name: self.display_name,
            note: self.note,
            teams_user_ids: provided(self.teams_user_id),
            emails: provided(self.email),
            phones: provided(self.phone),
            company: self.company,
            position: self.position,
            profile_urls: provided(self.profile_url),
            clear: self.clear.into_iter().map(Into::into).collect(),
        }
    }
}

pub fn execute(cli: Cli, output: &mut Out<'_>) -> Result<()> {
    let Some(command) = cli.command else {
        return output.line(Cli::command().render_help().to_string());
    };
    let operations = Relations::new(cli.pile, cli.key);
    match command {
        Command::Add {
            label,
            id,
            source,
            profile,
        } => render::added(
            &operations.add(profile.into_profile(label), id, &source)?,
            output,
        ),
        Command::Set {
            person,
            source,
            patch,
        } => render::profile_updated(
            &operations.set(&person, patch.into_patch(), &source)?,
            output,
        ),
        Command::Reconcile {
            person,
            base,
            patch,
        } => render::profile_reconciled(
            &operations.reconcile(&person, base.as_deref(), patch.into_patch())?,
            output,
        ),
        Command::List {
            limit,
            all,
            retired,
        } => {
            let filter = if all {
                PeopleFilter::All
            } else if retired {
                PeopleFilter::Retired
            } else {
                PeopleFilter::Active
            };
            output.text(operations.list(limit, filter)?)
        }
        Command::Show { person } => output.text(operations.show(&person)?),
        Command::Retire { person } => render::lifecycle(&operations.retire(&person)?, true, output),
        Command::Unretire { person } => {
            render::lifecycle(&operations.unretire(&person)?, false, output)
        }
        Command::Group { command } => match command {
            GroupCommand::Create { name } => {
                render::group_created(&operations.group_create(&name)?, output)
            }
            GroupCommand::Add { group, person } => {
                render::group_added(&operations.group_add(&group, &person)?, output)
            }
            GroupCommand::Remove { group, person } => {
                render::group_removed(&operations.group_remove(&group, &person)?, output)
            }
            GroupCommand::Rename { group, name } => {
                render::group_renamed(&operations.group_rename(&group, &name)?, output)
            }
            GroupCommand::Reconcile { group, name } => render::group_reconciled(
                &operations.group_reconcile(&group, name.as_deref())?,
                output,
            ),
            GroupCommand::List => output.text(operations.group_list()?),
            GroupCommand::Show { group } => output.text(operations.group_show(&group)?),
        },
        Command::Identity { command } => match command {
            IdentityCommand::Resolve {
                first,
                second,
                same,
                distinct: _,
            } => render::identity(
                &operations.identity_resolve(&first, &second, same)?,
                same,
                output,
            ),
            IdentityCommand::List => output.text(operations.identity_list()?),
        },
    }
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    }
    crate::cli::with_output("relations", |output| execute(cli, output))
}
