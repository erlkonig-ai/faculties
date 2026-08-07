use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser};
use faculties::collection_access;
use faculties::schemas::cognition::DEFAULT_SCOPE_ID;
use faculties::schemas::reason::{reason_schema, KIND_REASON_ID};
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
    /// Extrinsic collection scope for cognition events. Defaults to the stable
    /// shared cognition scope used by reason, patience, and related faculties.
    #[arg(long, value_parser = parse_id_arg)]
    scope: Option<Id>,
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
    #[arg(
        value_name = "COMMAND",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        last = true
    )]
    command: Vec<String>,
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> Inline<inlineencodings::NsTAIInterval> {
    (epoch, epoch).try_to_inline().unwrap()
}

fn parse_id_arg(raw: &str) -> std::result::Result<Id, String> {
    Id::from_hex(raw.trim()).ok_or_else(|| format!("invalid id '{raw}'"))
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
    scope: Id,
}

fn reason_fragment(
    turn_id: Option<Id>,
    worker_id: Option<Id>,
    text: &str,
    command_text: Option<&str>,
    created_at: Inline<inlineencodings::NsTAIInterval>,
) -> Fragment {
    let mut event = Fragment::empty();
    let text_handle = event.put(text.to_owned());
    let command_handle = command_text.map(|command| event.put(command.to_owned()));
    event += entity! { _ @
        metadata::tag: &KIND_REASON_ID,
        reason_schema::text: text_handle,
        metadata::created_at: created_at,
        reason_schema::about_turn?: turn_id,
        reason_schema::worker?: worker_id,
        reason_schema::command_text?: command_handle,
    };
    event
}

fn publish_reason(
    storage: ReasonStorage<'_>,
    turn_id: Option<Id>,
    worker_id: Option<Id>,
    text: &str,
    command_text: Option<&str>,
    created_at: Inline<inlineencodings::NsTAIInterval>,
) -> Result<(Id, CollectionCommit)> {
    let event = reason_fragment(turn_id, worker_id, text, command_text, created_at);
    let event_id = event.root().expect("reason event has one intrinsic root");
    let commit_metadata = entity! { metadata::description: "reason".to_owned() };
    let commit = collection_access::publish_fragment(
        storage.pile,
        storage.key,
        storage.scope,
        event,
        commit_metadata,
    )?;
    Ok((event_id, commit))
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
        epoch_interval(now_epoch()),
    )
    .map(|(event, _)| event)
}

#[cfg(test)]
fn validate_reason_payloads(
    reader: &triblespace::core::repo::pile::PileReader,
    facts: &TribleSet,
) -> Result<()> {
    use anybytes::View;

    for fact in facts.iter() {
        let field = if fact.a() == &reason_schema::text.id() {
            Some("reason::text")
        } else if fact.a() == &reason_schema::command_text.id() {
            Some("reason::command_text")
        } else {
            None
        };
        let Some(field) = field else {
            continue;
        };
        let handle = *fact.v::<inlineencodings::Handle<blobencodings::LongString>>();
        let _: View<str> = reader.get(handle).with_context(|| {
            format!(
                "strictly read {field} payload {}",
                hex::encode_upper(handle.raw)
            )
        })?;
    }
    Ok(())
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
        scope: cli.scope.unwrap_or(DEFAULT_SCOPE_ID),
    };

    if cli.command.is_empty() {
        let reason_id = append_reason(storage, turn_id, worker_id, &text, None)?;
        println!("reason_id: {reason_id:x}");
        return Ok(());
    }

    let command_text = render_command(&cli.command);
    let reason_id = append_reason(storage, turn_id, worker_id, &text, None)?;
    let action_event_id = append_reason(
        storage,
        turn_id,
        worker_id,
        command_text.as_str(),
        Some(command_text.as_str()),
    )?;
    eprintln!("reason_id: {reason_id:x}");
    eprintln!("reason_action_id: {action_event_id:x}");
    let exit_code = run_command(&cli.command)?;
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    use anybytes::View;
    use ed25519_dalek::SigningKey;
    use std::collections::HashSet;
    use std::fs::File;
    use triblespace::core::repo::{PinStore, Repository};

    type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;

    fn test_id(byte: u8) -> Id {
        Id::new([byte; 16]).unwrap()
    }

    fn at_unix(seconds: f64) -> Inline<inlineencodings::NsTAIInterval> {
        epoch_interval(Epoch::from_unix_seconds(seconds))
    }

    fn pin_head(
        pile_path: &Path,
        branch: Id,
    ) -> Inline<inlineencodings::Handle<blobencodings::SimpleArchive>> {
        let mut pile = collection_access::open_pile_strict(pile_path).unwrap();
        let head = pile.head(branch).unwrap().unwrap();
        pile.close().unwrap();
        head
    }

    #[test]
    fn exact_reason_event_is_one_intrinsic_idempotent_commit_and_keeps_pin() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("reason.pile");
        let key_path = directory.path().join("reason.key");
        File::create(&pile_path).unwrap();

        let pile = collection_access::open_pile_strict(&pile_path).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x61; 32]), Fragment::empty()).unwrap();
        let legacy_branch = *repository.create_branch("cognition", None).unwrap();
        repository.close().unwrap();
        let legacy_pin = pin_head(&pile_path, legacy_branch);

        collection_access::initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let scope = test_id(0x71);
        let storage = ReasonStorage {
            pile: &pile_path,
            key: Some(&key_path),
            scope,
        };
        let turn = test_id(0x72);
        let worker = test_id(0x73);
        let created = at_unix(42.0);
        let expected = reason_fragment(
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
        assert_eq!(pin_head(&pile_path, legacy_branch), legacy_pin);

        let signer = collection_access::load_signer(&pile_path, Some(&key_path)).unwrap();
        let view = collection_access::materialize_scope(
            &pile_path,
            scope,
            &HashSet::from([signer.verifying_key()]),
        )
        .unwrap();
        assert_eq!(view.commits, vec![first_commit]);
        assert_eq!(view.facts, expected.into_facts());
        validate_reason_payloads(&view.reader, &view.facts).unwrap();

        let (text, command, found_turn, found_worker) = find!(
            (text: TextHandle, command: TextHandle, turn: Id, worker: Id),
            pattern!(&view.facts, [{ event_id @
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
            &*view.reader.get::<View<str>, _>(text).unwrap(),
            "choose the narrowest next constraint"
        );
        assert_eq!(
            &*view.reader.get::<View<str>, _>(command).unwrap(),
            "cargo test --lib"
        );
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
                scope: test_id(0x74),
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
    fn reason_payload_validator_rejects_missing_known_handles() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("validator.pile");
        File::create(&pile_path).unwrap();
        let mut pile = collection_access::open_pile_strict(&pile_path).unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();
        let missing: TextHandle = Inline::new([0x91; 32]);

        for (facts, field) in [
            (
                entity! { reason_schema::text: missing }.into_facts(),
                "reason::text",
            ),
            (
                entity! { reason_schema::command_text: missing }.into_facts(),
                "reason::command_text",
            ),
        ] {
            let error = validate_reason_payloads(&reader, &facts).unwrap_err();
            assert!(format!("{error:#}").contains(field));
        }
    }

    #[test]
    fn permanent_cli_has_scope_but_no_branch_selector() {
        let command = Cli::command();
        assert!(command
            .get_arguments()
            .any(|argument| argument.get_id() == "scope"));
        assert!(!command
            .get_arguments()
            .any(|argument| argument.get_id() == "branch"));
        assert!(!command
            .get_arguments()
            .any(|argument| argument.get_id() == "branch_id"));
    }
}
