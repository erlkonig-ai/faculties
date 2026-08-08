use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use faculties::collection_access;
use faculties::headspace::{self, Catalog, ConfigValue, ProfileValue, Resolution};
use faculties::schemas::headspace::DEFAULT_SCOPE_ID;
use triblespace::core::metadata;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "headspace",
    bin_name = "headspace",
    about = "Manage fork-visible Headspace configuration and model profiles."
)]
struct Cli {
    /// Existing pile file. Reads never create a pile or signing identity.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Clone)]
enum Command {
    /// Show the resolved active Headspace and available profiles.
    Show {
        #[arg(long, default_value_t = false)]
        show_secrets: bool,
    },
    /// List profile anchors and their current resolution.
    List,
    /// Switch the active profile by anchor id or settled profile name.
    Use {
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
    /// Author a fresh profile anchor and activate it in one signed COMMIT.
    /// After an ambiguous transport failure, inspect `list` before retrying:
    /// every invocation intentionally creates a new logical profile.
    Add(AddArgs),
    /// Set one field on the resolved active profile.
    Set {
        #[arg(value_enum, value_name = "FIELD")]
        field: SetField,
        #[arg(
            value_name = "VALUE",
            help = "Value to set. Use @path for file input or @- for stdin."
        )]
        value: String,
    },
    /// Clear one optional field on the resolved active profile.
    Unset {
        #[arg(value_enum, value_name = "FIELD")]
        field: UnsetField,
    },
    /// Choose any existing complete snapshot as the intended state of its
    /// track and supersede every live head on that track.
    Reconcile {
        #[arg(value_name = "SNAPSHOT")]
        snapshot: String,
    },
}

#[derive(Args, Clone)]
struct AddArgs {
    #[arg(value_name = "NAME")]
    name: String,
    #[arg(long)]
    model: Option<String>,
    #[arg(long = "base-url")]
    base_url: Option<String>,
    #[arg(long = "api-key")]
    api_key: Option<String>,
    #[arg(long = "reasoning-effort")]
    reasoning_effort: Option<String>,
    #[arg(long)]
    stream: Option<bool>,
    #[arg(long = "context-window-tokens")]
    context_window_tokens: Option<u64>,
    #[arg(long = "max-output-tokens")]
    max_output_tokens: Option<u64>,
    #[arg(long = "prompt-safety-margin-tokens")]
    context_safety_margin_tokens: Option<u64>,
    #[arg(long = "prompt-chars-per-token")]
    chars_per_token: Option<u64>,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
#[value(rename_all = "kebab-case")]
enum SetField {
    Model,
    BaseUrl,
    ApiKey,
    ReasoningEffort,
    Stream,
    ContextWindowTokens,
    MaxOutputTokens,
    PromptSafetyMarginTokens,
    PromptCharsPerToken,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
#[value(rename_all = "kebab-case")]
enum UnsetField {
    ApiKey,
    ReasoningEffort,
}

struct LoadedHeadspace {
    view: collection_access::CollectionView,
    catalog: Catalog,
}

fn main() -> Result<()> {
    run(Cli::parse())
}

fn run(cli: Cli) -> Result<()> {
    let Some(command) = cli.command.as_ref() else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };

    match command {
        Command::Show { show_secrets } => {
            let state = load_headspace(&cli.pile)?;
            print_headspace(&state.catalog, *show_secrets)
        }
        Command::List => {
            let state = load_headspace(&cli.pile)?;
            print_profile_list(&state.catalog)
        }
        Command::Use { profile } => {
            let state = load_headspace(&cli.pile)?;
            let anchor = resolve_profile_selector(&state.catalog, profile)?;
            require_profile(&state.catalog, anchor)?;
            let existing = settled_config(&state.catalog)?;
            if existing.is_some_and(|config| config.active_profile == anchor) {
                return print_headspace(&state.catalog, false);
            }
            let mut config = existing
                .cloned()
                .unwrap_or_else(|| headspace::default_config(anchor));
            config.active_profile = anchor;
            let (fragment, _) =
                headspace::config_snapshot_fragment(&config, &state.catalog.config.head_ids())?;
            publish(
                &cli.pile,
                &state,
                fragment,
                "switch active Headspace profile",
            )?;
            print_reloaded(&cli.pile)
        }
        Command::Add(args) => {
            let state = load_headspace(&cli.pile)?;
            let anchor = genid().id;
            let mut profile = match settled_config(&state.catalog)? {
                Some(config) => require_profile(&state.catalog, config.active_profile)?.clone(),
                None => headspace::default_profile(anchor, args.name.clone()),
            };
            profile.anchor = anchor;
            profile.name = args.name.clone();
            apply_add_overrides(&mut profile, args)?;
            let mut config = settled_config(&state.catalog)?
                .cloned()
                .unwrap_or_else(|| headspace::default_config(anchor));
            config.active_profile = anchor;
            let (fragment, _, _) = headspace::add_profile_fragment(
                &profile,
                &config,
                &state.catalog.config.head_ids(),
            )?;
            publish(
                &cli.pile,
                &state,
                fragment,
                "add and activate Headspace profile",
            )?;
            print_reloaded(&cli.pile)
        }
        Command::Set { field, value } => {
            let state = load_headspace(&cli.pile)?;
            let config = settled_config(&state.catalog)?.ok_or_else(|| {
                anyhow!("Headspace has no active configuration; add a profile first")
            })?;
            let current = require_profile(&state.catalog, config.active_profile)?;
            let mut changed = current.clone();
            apply_set(&mut changed, *field, value)?;
            if changed == *current {
                return print_headspace(&state.catalog, false);
            }
            let resolution = &state.catalog.profiles[&config.active_profile];
            let (fragment, _) =
                headspace::profile_snapshot_fragment(&changed, &resolution.head_ids())?;
            publish(&cli.pile, &state, fragment, "update Headspace profile")?;
            print_reloaded(&cli.pile)
        }
        Command::Unset { field } => {
            let state = load_headspace(&cli.pile)?;
            let config = settled_config(&state.catalog)?.ok_or_else(|| {
                anyhow!("Headspace has no active configuration; add a profile first")
            })?;
            let current = require_profile(&state.catalog, config.active_profile)?;
            let mut changed = current.clone();
            apply_unset(&mut changed, *field);
            if changed == *current {
                return print_headspace(&state.catalog, false);
            }
            let resolution = &state.catalog.profiles[&config.active_profile];
            let (fragment, _) =
                headspace::profile_snapshot_fragment(&changed, &resolution.head_ids())?;
            publish(&cli.pile, &state, fragment, "unset Headspace profile field")?;
            print_reloaded(&cli.pile)
        }
        Command::Reconcile { snapshot } => {
            let state = load_headspace(&cli.pile)?;
            let chosen = faculties::resolve_id_prefix(snapshot, state.catalog.snapshot_ids())?;
            let Some((fragment, _)) = state.catalog.reconcile_fragment(chosen)? else {
                return print_headspace(&state.catalog, false);
            };
            publish(
                &cli.pile,
                &state,
                fragment,
                "reconcile Headspace snapshot track",
            )?;
            print_reloaded(&cli.pile)
        }
    }
}

fn load_headspace(pile: &Path) -> Result<LoadedHeadspace> {
    // Resolve authority before opening storage so a missing key cannot create
    // or mutate the requested pile.
    let signer = collection_access::load_signer(pile, None)?;
    let allowed = HashSet::from([signer.verifying_key()]);
    let snapshot = collection_access::CollectionSnapshot::open(pile)?;
    let view = snapshot.materialize_scope(DEFAULT_SCOPE_ID, &allowed)?;
    let catalog = headspace::project_result(&view.reader, &view.facts)?;
    Ok(LoadedHeadspace { view, catalog })
}

fn publish(pile: &Path, state: &LoadedHeadspace, fragment: Fragment, message: &str) -> Result<()> {
    headspace::validate_catalog_union(&state.view.reader, &state.view.facts, &fragment)
        .context("validate Headspace successor")?;
    collection_access::publish_fragment(
        pile,
        None,
        DEFAULT_SCOPE_ID,
        fragment,
        entity! { metadata::description: message.to_owned() },
    )?;
    Ok(())
}

fn print_reloaded(pile: &Path) -> Result<()> {
    let state = load_headspace(pile)?;
    print_headspace(&state.catalog, false)
}

fn settled_config(catalog: &Catalog) -> Result<Option<&ConfigValue>> {
    catalog.config.settled_value("Headspace config")
}

fn require_profile(catalog: &Catalog, anchor: Id) -> Result<&ProfileValue> {
    let resolution = catalog
        .profiles
        .get(&anchor)
        .ok_or_else(|| anyhow!("unknown profile {anchor:x}"))?;
    resolution
        .settled_value(&format!("profile {anchor:x}"))?
        .ok_or_else(|| anyhow!("profile {anchor:x} has no snapshot"))
}

fn resolve_profile_selector(catalog: &Catalog, raw: &str) -> Result<Id> {
    if let Some(id) = Id::from_hex(raw.trim()) {
        if catalog.profiles.contains_key(&id) {
            return Ok(id);
        }
        bail!("unknown profile {id:x}");
    }
    let needle = raw.trim().to_lowercase();
    let mut matches = Vec::new();
    for (&anchor, resolution) in &catalog.profiles {
        let profile = match resolution {
            Resolution::Unique(snapshot) => Some(&snapshot.value),
            Resolution::Agreed(snapshots) => snapshots.first().map(|snapshot| &snapshot.value),
            Resolution::Missing | Resolution::Forked(_) | Resolution::Invalid(_) => None,
        };
        if profile.is_some_and(|profile| profile.name.to_lowercase() == needle) {
            matches.push(anchor);
        }
    }
    match matches.as_slice() {
        [] => bail!("unknown profile '{raw}'"),
        [id] => Ok(*id),
        _ => bail!("profile name '{raw}' is ambiguous; use the hex anchor id"),
    }
}

fn apply_add_overrides(profile: &mut ProfileValue, args: &AddArgs) -> Result<()> {
    if let Some(value) = args.model.as_deref() {
        profile.model = value.to_owned();
    }
    if let Some(value) = args.base_url.as_deref() {
        profile.base_url = value.to_owned();
    }
    if let Some(value) = args.api_key.as_deref() {
        profile.api_key = Some(value.trim().to_owned());
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
    Ok(())
}

fn apply_set(profile: &mut ProfileValue, field: SetField, raw: &str) -> Result<()> {
    match field {
        SetField::Model => profile.model = faculties::text_arg(raw, "model name")?,
        SetField::BaseUrl => profile.base_url = faculties::text_arg(raw, "model base URL")?,
        SetField::ApiKey => {
            profile.api_key = Some(faculties::text_arg(raw, "model API key")?.trim().to_owned())
        }
        SetField::ReasoningEffort => {
            profile.reasoning_effort = Some(
                faculties::text_arg(raw, "model reasoning effort")?
                    .trim()
                    .to_owned(),
            )
        }
        SetField::Stream => profile.stream = parse_bool(raw, "model_stream")?,
        SetField::ContextWindowTokens => {
            profile.context_window_tokens = parse_u64(raw, "model_context_window_tokens")?
        }
        SetField::MaxOutputTokens => {
            profile.max_output_tokens = parse_u64(raw, "model_max_output_tokens")?
        }
        SetField::PromptSafetyMarginTokens => {
            profile.context_safety_margin_tokens =
                parse_u64(raw, "model_context_safety_margin_tokens")?
        }
        SetField::PromptCharsPerToken => {
            profile.chars_per_token = parse_u64(raw, "model_chars_per_token")?
        }
    }
    Ok(())
}

fn apply_unset(profile: &mut ProfileValue, field: UnsetField) {
    match field {
        UnsetField::ApiKey => profile.api_key = None,
        UnsetField::ReasoningEffort => profile.reasoning_effort = None,
    }
}

fn print_headspace(catalog: &Catalog, show_secrets: bool) -> Result<()> {
    println!("active:");
    let Some(config) = settled_config(catalog)? else {
        print_profile(
            None,
            &headspace::default_profile(Id::new([1; 16]).unwrap(), "default"),
            show_secrets,
        );
        println!();
        println!("profiles:");
        return print_profile_list(catalog);
    };
    let profile = require_profile(catalog, config.active_profile)?;
    print_profile(Some(config.active_profile), profile, show_secrets);
    println!();
    println!("profiles:");
    print_profile_list(catalog)
}

fn print_profile(anchor: Option<Id>, profile: &ProfileValue, show_secrets: bool) {
    println!(
        "  profile_id = {}",
        anchor
            .map(|id| format!("\"{id:x}\""))
            .unwrap_or_else(|| "null".to_owned())
    );
    println!("  profile_name = \"{}\"", profile.name);
    println!("  model = \"{}\"", profile.model);
    println!("  base_url = \"{}\"", profile.base_url);
    println!(
        "  api_key = {}",
        match (show_secrets, profile.api_key.as_deref()) {
            (_, None) => "null".to_owned(),
            (true, Some(value)) => format!("\"{value}\""),
            (false, Some(_)) => "\"<redacted>\"".to_owned(),
        }
    );
    println!(
        "  reasoning_effort = {}",
        profile
            .reasoning_effort
            .as_deref()
            .map(|value| format!("\"{value}\""))
            .unwrap_or_else(|| "null".to_owned())
    );
    println!("  stream = {}", profile.stream);
    println!(
        "  context_window_tokens = {}",
        profile.context_window_tokens
    );
    println!("  max_output_tokens = {}", profile.max_output_tokens);
    println!(
        "  context_safety_margin_tokens = {}",
        profile.context_safety_margin_tokens
    );
    println!("  chars_per_token = {}", profile.chars_per_token);
}

fn print_profile_list(catalog: &Catalog) -> Result<()> {
    let active = match &catalog.config {
        Resolution::Unique(snapshot) => Some(snapshot.value.active_profile),
        Resolution::Agreed(snapshots) => snapshots
            .first()
            .map(|snapshot| snapshot.value.active_profile),
        Resolution::Missing | Resolution::Forked(_) | Resolution::Invalid(_) => None,
    };
    match &catalog.config {
        Resolution::Missing => println!("config\t<missing>"),
        Resolution::Unique(snapshot) => println!(
            "config\t{:x}\tactive={:x}",
            snapshot.id, snapshot.value.active_profile
        ),
        Resolution::Agreed(snapshots) => println!(
            "config\t<agreed:{}>\theads={}",
            snapshots.len(),
            format_snapshot_ids(snapshots.iter().map(|snapshot| snapshot.id))
        ),
        Resolution::Forked(snapshots) => {
            println!(
                "config\t<forked:{}>\theads={}",
                snapshots.len(),
                format_snapshot_ids(snapshots.iter().map(|snapshot| snapshot.id))
            );
            for snapshot in snapshots {
                println!(
                    "  head\t{:x}\tactive={:x}",
                    snapshot.id, snapshot.value.active_profile
                );
            }
        }
        Resolution::Invalid(error) => println!("config\t<invalid>\t{error}"),
    }
    let mut rows = Vec::new();
    for (&anchor, resolution) in &catalog.profiles {
        let marker = if active == Some(anchor) { '*' } else { ' ' };
        match resolution {
            Resolution::Unique(snapshot) => rows.push((
                snapshot.value.name.to_lowercase(),
                format!(
                    "{marker} {}\t{anchor:x}\tsnapshot={:x}",
                    snapshot.value.name, snapshot.id
                ),
            )),
            Resolution::Agreed(snapshots) => {
                let profile = &snapshots[0].value;
                rows.push((
                    profile.name.to_lowercase(),
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
        println!("{row}");
    }
    Ok(())
}

fn format_snapshot_ids(ids: impl IntoIterator<Item = Id>) -> String {
    ids.into_iter()
        .map(|id| format!("{id:x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn parse_u64(raw: &str, label: &str) -> Result<u64> {
    raw.parse::<u64>()
        .map_err(|_| anyhow!("invalid {label} {raw}"))
}

fn parse_bool(raw: &str, label: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => bail!("invalid {label} {raw} (expected true/false)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;

    fn cli(pile: &Path, command: Command) -> Cli {
        Cli {
            pile: pile.to_owned(),
            command: Some(command),
        }
    }

    fn add(name: &str) -> Command {
        Command::Add(AddArgs {
            name: name.to_owned(),
            model: None,
            base_url: None,
            api_key: None,
            reasoning_effort: None,
            stream: None,
            context_window_tokens: None,
            max_output_tokens: None,
            context_safety_margin_tokens: None,
            chars_per_token: None,
        })
    }

    fn snapshot_counts(catalog: &Catalog) -> (usize, usize) {
        catalog
            .snapshot_ids()
            .into_iter()
            .fold((0, 0), |(profiles, configs), id| {
                if catalog.profile_snapshot(id).is_some() {
                    (profiles + 1, configs)
                } else {
                    (
                        profiles,
                        configs + usize::from(catalog.config_snapshot(id).is_some()),
                    )
                }
            })
    }

    #[test]
    fn immutable_load_does_not_append_or_create_identity() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("headspace.pile");
        File::create(&pile).unwrap();
        collection_access::initialize_signer(&pile, None).unwrap();
        let length = std::fs::metadata(&pile).unwrap().len();
        let state = load_headspace(&pile).unwrap();
        assert!(matches!(state.catalog.config, Resolution::Missing));
        assert_eq!(std::fs::metadata(&pile).unwrap().len(), length);

        let absent_pile = directory.path().join("absent.pile");
        let absent_key = directory.path().join("self.key");
        std::fs::remove_file(absent_key).unwrap();
        assert!(load_headspace(&absent_pile).is_err());
        assert!(!absent_pile.exists());
    }

    #[test]
    fn use_authors_config_genesis_when_only_the_profile_track_exists() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("headspace.pile");
        File::create(&pile).unwrap();
        collection_access::initialize_signer(&pile, None).unwrap();
        let anchor = Id::new([0x51; 16]).unwrap();
        let profile = headspace::default_profile(anchor, "only-profile");
        let mut fragment = headspace::profile_anchor_fragment(anchor);
        fragment += headspace::profile_snapshot_fragment(&profile, &[])
            .unwrap()
            .0;
        collection_access::publish_fragment(
            &pile,
            None,
            DEFAULT_SCOPE_ID,
            fragment,
            Fragment::empty(),
        )
        .unwrap();
        assert!(matches!(
            load_headspace(&pile).unwrap().catalog.config,
            Resolution::Missing
        ));

        run(cli(
            &pile,
            Command::Use {
                profile: "only-profile".to_owned(),
            },
        ))
        .unwrap();
        assert!(matches!(
            load_headspace(&pile).unwrap().catalog.config,
            Resolution::Unique(headspace::Snapshot { ref value, .. })
                if value.active_profile == anchor
        ));
    }

    #[test]
    fn name_selection_ignores_an_unrelated_forked_profile_track() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("headspace.pile");
        File::create(&pile).unwrap();
        collection_access::initialize_signer(&pile, None).unwrap();
        run(cli(&pile, add("first"))).unwrap();
        let first = settled_config(&load_headspace(&pile).unwrap().catalog)
            .unwrap()
            .unwrap()
            .active_profile;
        run(cli(&pile, add("second"))).unwrap();

        let state = load_headspace(&pile).unwrap();
        let second = settled_config(&state.catalog)
            .unwrap()
            .unwrap()
            .active_profile;
        let current = require_profile(&state.catalog, second).unwrap().clone();
        let predecessor = state.catalog.profiles[&second].head_ids();
        let mut left = current.clone();
        left.model = "left".to_owned();
        let mut right = current;
        right.model = "right".to_owned();
        let left = headspace::profile_snapshot_fragment(&left, &predecessor)
            .unwrap()
            .0;
        let right = headspace::profile_snapshot_fragment(&right, &predecessor)
            .unwrap()
            .0;
        publish(&pile, &state, left, "left profile branch").unwrap();
        let after_left = load_headspace(&pile).unwrap();
        publish(&pile, &after_left, right, "right profile branch").unwrap();

        let forked = load_headspace(&pile).unwrap();
        assert!(matches!(
            forked.catalog.profiles[&second],
            Resolution::Forked(_)
        ));
        assert_eq!(
            resolve_profile_selector(&forked.catalog, "first").unwrap(),
            first
        );
    }

    #[test]
    fn add_use_set_and_idempotent_set_advance_only_their_tracks() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("headspace.pile");
        File::create(&pile).unwrap();
        collection_access::initialize_signer(&pile, None).unwrap();

        run(cli(&pile, add("first"))).unwrap();
        let first_state = load_headspace(&pile).unwrap();
        let first_anchor = settled_config(&first_state.catalog)
            .unwrap()
            .unwrap()
            .active_profile;
        run(cli(&pile, add("second"))).unwrap();
        let second_state = load_headspace(&pile).unwrap();
        let (profile_count, config_count) = snapshot_counts(&second_state.catalog);

        run(cli(
            &pile,
            Command::Use {
                profile: format!("{first_anchor:x}"),
            },
        ))
        .unwrap();
        let used = load_headspace(&pile).unwrap();
        assert_eq!(
            snapshot_counts(&used.catalog),
            (profile_count, config_count + 1)
        );

        run(cli(
            &pile,
            Command::Set {
                field: SetField::Model,
                value: "changed-model".to_owned(),
            },
        ))
        .unwrap();
        let set = load_headspace(&pile).unwrap();
        assert_eq!(
            snapshot_counts(&set.catalog),
            (profile_count + 1, config_count + 1)
        );
        let commits = set.view.commits.len();

        run(cli(
            &pile,
            Command::Set {
                field: SetField::Model,
                value: "changed-model".to_owned(),
            },
        ))
        .unwrap();
        assert_eq!(load_headspace(&pile).unwrap().view.commits.len(), commits);
    }
}
