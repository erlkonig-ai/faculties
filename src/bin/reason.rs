use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser};
use faculties::{clock, cognition};
#[cfg(test)]
use hifitime::Epoch;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "reason",
    about = "Record explicit reasoning notes linked to the current execution turn"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Existing durable signing-key file. Reads and writes never create it;
    /// initialize explicitly with `trible pile signing-key init <pile>`.
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,
    /// Turn id to annotate (hex). Defaults to $TURN_ID.
    #[arg(long)]
    turn_id: Option<String>,
    /// Worker id to annotate (hex). Defaults to $WORKER_ID.
    #[arg(long)]
    worker_id: Option<String>,
    /// Free-form reasoning text.
    #[arg(
        value_name = "TEXT",
        help = "Free-form reasoning text. Use @path for file input or @- for stdin."
    )]
    text: Option<String>,
    /// Optional command to run after logging the reason (pass after `--`).
    #[arg(value_name = "COMMAND", allow_hyphen_values = true, last = true)]
    command: Vec<String>,
}

#[cfg(test)]
fn epoch_interval(epoch: Epoch) -> Inline<inlineencodings::NsTAIInterval> {
    (epoch, epoch).try_to_inline().unwrap()
}

fn parse_optional_hex_id(raw: Option<&str>, label: &str) -> Result<Option<Id>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("{label} is empty");
    }
    let Some(id) = Id::from_hex(trimmed) else {
        bail!("invalid {label} '{trimmed}'");
    };
    Ok(Some(id))
}

#[derive(Clone, Copy)]
struct ReasonStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

fn publish_reason(
    storage: ReasonStorage<'_>,
    turn_id: Option<Id>,
    worker_id: Option<Id>,
    text: &str,
    command_text: Option<&str>,
    created_at: Inline<inlineencodings::NsTAIInterval>,
) -> Result<(Id, CollectionCommit)> {
    let (event_id, event) =
        described_reason_fragment(turn_id, worker_id, text, command_text, created_at);
    let commit = cognition::publish_event(storage.pile, storage.key, event)?;
    Ok((event_id, commit))
}

fn described_reason_fragment(
    turn_id: Option<Id>,
    worker_id: Option<Id>,
    text: &str,
    command_text: Option<&str>,
    created_at: Inline<inlineencodings::NsTAIInterval>,
) -> (Id, Fragment) {
    let mut event = cognition::reason_fragment(turn_id, worker_id, text, command_text, created_at);
    let event_id = event.root().expect("reason event has one intrinsic root");
    event.describe_with(entity! { metadata::description: "reason".to_owned() });
    (event_id, event)
}

fn append_reason(
    storage: ReasonStorage<'_>,
    turn_id: Option<Id>,
    worker_id: Option<Id>,
    text: &str,
    command_text: Option<&str>,
) -> Result<Id> {
    publish_reason(
        storage,
        turn_id,
        worker_id,
        text,
        command_text,
        clock::point_now()?,
    )
    .map(|(event, _)| event)
}

fn shell_quote(word: &str) -> String {
    if word.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || std::matches!(ch, '_' | '-' | '.' | '/' | ':' | '=')
    }) {
        return word.to_string();
    }
    format!("'{}'", word.replace('\'', "'\\''"))
}

fn render_command(command: &[String]) -> String {
    command
        .iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_command(command: &[String]) -> Result<i32> {
    let Some(bin) = command.first() else {
        bail!("missing command");
    };
    let status = ProcessCommand::new(bin)
        .args(command.iter().skip(1))
        .status()
        .with_context(|| format!("run command `{}`", render_command(command)))?;
    Ok(status.code().unwrap_or(1))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let Some(text_raw) = cli.text.as_ref() else {
        let mut cmd = Cli::command();
        cmd.print_help()?;
        println!();
        return Ok(());
    };
    let text = faculties::text_arg(text_raw, "reason text")?;

    let env_turn_id = std::env::var("TURN_ID").ok();
    let env_worker_id = std::env::var("WORKER_ID").ok();

    let turn_id =
        parse_optional_hex_id(cli.turn_id.as_deref().or(env_turn_id.as_deref()), "turn id")?;
    let worker_id = parse_optional_hex_id(
        cli.worker_id.as_deref().or(env_worker_id.as_deref()),
        "worker id",
    )?;

    if text.trim().is_empty() {
        bail!("reason text is empty");
    }

    let storage = ReasonStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };

    if cli.command.is_empty() {
        let reason_id = append_reason(storage, turn_id, worker_id, &text, None)?;
        println!("reason_id: {reason_id:x}");
        return Ok(());
    }

    let command_text = render_command(&cli.command);
    let created_at = clock::point_now()?;
    let (reason_id, reason_event) =
        described_reason_fragment(turn_id, worker_id, &text, None, created_at);
    let (action_event_id, action_event) = described_reason_fragment(
        turn_id,
        worker_id,
        command_text.as_str(),
        Some(command_text.as_str()),
        created_at,
    );
    cognition::publish_events(storage.pile, storage.key, [reason_event, action_event])?;
    eprintln!("reason_id: {reason_id:x}");
    eprintln!("reason_action_id: {action_event_id:x}");
    let exit_code = run_command(&cli.command)?;
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    use anybytes::View;
    use faculties::schemas::cognition::DEFAULT_SCOPE_ID;
    use faculties::schemas::reason::{reason_schema, KIND_REASON_ID};
    use faculties::storage::{initialize_signer, load_signer, open_pile_strict};
    use std::fs::File;
    use triblespace::core::collection::CollectionStoreExt;
    use triblespace::core::repo::BlobStore;

    type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at_unix(seconds: f64) -> Inline<inlineencodings::NsTAIInterval> {
        epoch_interval(Epoch::from_unix_seconds(seconds))
    }

    #[test]
    fn exact_reason_event_is_one_intrinsic_idempotent_commit() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("reason.pile");
        let key_path = directory.path().join("reason.key");
        File::create(&pile_path).unwrap();

        initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let storage = ReasonStorage {
            pile: &pile_path,
            key: Some(&key_path),
        };
        let turn = test_id(0x72);
        let worker = test_id(0x73);
        let created = at_unix(42.0);
        let expected = cognition::reason_fragment(
            Some(turn),
            Some(worker),
            "choose the narrowest next constraint",
            Some("cargo test --lib"),
            created,
        );
        let expected_id = expected.root().unwrap();

        let (event_id, first_commit) = publish_reason(
            storage,
            Some(turn),
            Some(worker),
            "choose the narrowest next constraint",
            Some("cargo test --lib"),
            created,
        )
        .unwrap();
        let length_after_first = std::fs::metadata(&pile_path).unwrap().len();
        let (replayed_id, replayed_commit) = publish_reason(
            storage,
            Some(turn),
            Some(worker),
            "choose the narrowest next constraint",
            Some("cargo test --lib"),
            created,
        )
        .unwrap();

        assert_eq!(event_id, expected_id);
        assert_eq!(replayed_id, event_id);
        assert_eq!(replayed_commit, first_commit);
        assert_eq!(
            std::fs::metadata(&pile_path).unwrap().len(),
            length_after_first
        );
        let signer = load_signer(&pile_path, Some(&key_path)).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let collection =
            faculties::collection_names::open(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key())
                .unwrap();
        let (facts, _, reader) = pile.snapshot(collection, &[]).unwrap().into_parts();
        assert_eq!(facts, expected.into_facts());
        cognition::validate_catalog(&reader, &facts).unwrap();

        let (text, command, found_turn, found_worker) = find!(
            (text: TextHandle, command: TextHandle, turn: Id, worker: Id),
            pattern!(&facts, [{ event_id @
                metadata::tag: KIND_REASON_ID,
                reason_schema::text: ?text,
                reason_schema::command_text: ?command,
                reason_schema::about_turn: ?turn,
                reason_schema::worker: ?worker,
            }])
        )
        .next()
        .unwrap();
        assert_eq!(found_turn, turn);
        assert_eq!(found_worker, worker);
        assert_eq!(
            &*reader.get::<View<str>, _>(text).unwrap(),
            "choose the narrowest next constraint"
        );
        assert_eq!(
            &*reader.get::<View<str>, _>(command).unwrap(),
            "cargo test --lib"
        );
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn missing_signer_fails_before_touching_pile() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("reason.pile");
        let key_path = directory.path().join("missing.key");
        File::create(&pile_path).unwrap();
        let before = std::fs::metadata(&pile_path).unwrap().len();

        let error = publish_reason(
            ReasonStorage {
                pile: &pile_path,
                key: Some(&key_path),
            },
            None,
            None,
            "must not land",
            None,
            at_unix(43.0),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("load durable signing key"));
        assert!(!key_path.exists());
        assert_eq!(std::fs::metadata(&pile_path).unwrap().len(), before);
    }

    #[test]
    fn permanent_cli_has_no_scope_or_branch_selector() {
        let command = Cli::command();
        for forbidden in ["scope", "branch", "branch_id"] {
            assert!(!command
                .get_arguments()
                .any(|argument| argument.get_id() == forbidden));
        }
    }
}
