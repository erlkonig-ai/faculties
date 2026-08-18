use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser};
use faculties::cognition;
use hifitime::Epoch;
use humantime::parse_duration;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::metadata;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(
    version = faculties::GIT_VERSION,
    name = "patience",
    about = "Extend the active turn timeout and optionally run a command"
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
    /// Timeout extension duration (e.g. 5m, 90s, 1h).
    #[arg(value_name = "DURATION")]
    duration: Option<String>,
    /// Optional command to run after extending timeout (pass after `--`).
    #[arg(value_name = "COMMAND", allow_hyphen_values = true, last = true)]
    command: Vec<String>,
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> Inline<inlineencodings::NsTAIInterval> {
    (epoch, epoch).try_to_inline().unwrap()
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
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

fn parse_timeout_ms(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("duration is empty");
    }
    if let Ok(ms) = trimmed.parse::<u64>() {
        return Ok(ms);
    }
    let duration =
        parse_duration(trimmed).with_context(|| format!("invalid duration '{trimmed}'"))?;
    let millis = duration.as_millis();
    if millis == 0 {
        bail!("duration must be greater than zero");
    }
    if millis > u128::from(u64::MAX) {
        bail!("duration exceeds maximum supported timeout");
    }
    Ok(millis as u64)
}

#[derive(Clone, Copy)]
struct PatienceStorage<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
}

fn publish_timeout_extension(
    storage: PatienceStorage<'_>,
    request_id: Id,
    worker_id: Id,
    timeout_ms: u64,
    requested_at: Inline<inlineencodings::NsTAIInterval>,
) -> Result<(Id, CollectionCommit)> {
    let mut event =
        cognition::timeout_extension_fragment(request_id, worker_id, timeout_ms, requested_at);
    let event_id = event
        .root()
        .expect("timeout extension has one intrinsic root");
    event.describe_with(
        entity! { metadata::description: "playground_exec timeout_extension".to_owned() },
    );
    let commit = cognition::publish_event(storage.pile, storage.key, event)?;
    Ok((event_id, commit))
}

fn append_timeout_extension(
    storage: PatienceStorage<'_>,
    request_id: Id,
    worker_id: Id,
    timeout_ms: u64,
) -> Result<Id> {
    publish_timeout_extension(
        storage,
        request_id,
        worker_id,
        timeout_ms,
        epoch_interval(now_epoch()),
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
    let Some(duration_raw) = cli.duration.as_ref() else {
        let mut cmd = Cli::command();
        cmd.print_help()?;
        println!();
        return Ok(());
    };

    let timeout_ms = parse_timeout_ms(duration_raw)?;
    let env_turn_id = std::env::var("TURN_ID").ok();
    let env_worker_id = std::env::var("WORKER_ID").ok();

    let request_id =
        parse_optional_hex_id(cli.turn_id.as_deref().or(env_turn_id.as_deref()), "turn id")?
            .ok_or_else(|| anyhow!("missing turn id (pass --turn-id or set TURN_ID)"))?;
    let worker_id = parse_optional_hex_id(
        cli.worker_id.as_deref().or(env_worker_id.as_deref()),
        "worker id",
    )?
    .ok_or_else(|| anyhow!("missing worker id (pass --worker-id or set WORKER_ID)"))?;

    let storage = PatienceStorage {
        pile: &cli.pile,
        key: cli.key.as_deref(),
    };
    let event_id = append_timeout_extension(storage, request_id, worker_id, timeout_ms)?;

    eprintln!(
        "[{}] timeout extended by {} ms",
        fmt_id(event_id),
        timeout_ms
    );

    if cli.command.is_empty() {
        return Ok(());
    }

    let exit_code = run_command(&cli.command)?;
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::SigningKey;
    use faculties::storage::{initialize_signer, load_signer, open_pile_strict};
    use faculties::schemas::cognition::DEFAULT_SCOPE_ID;
    use faculties::schemas::patience::{exec_schema, KIND_TIMEOUT_EXTENSION_ID};
    use std::fs::File;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }
    use triblespace::core::collection::Collection;
    use triblespace::core::repo::BlobStore;
    use triblespace::core::repo::{PinStore, Repository};

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
        let mut pile = open_pile_strict(pile_path).unwrap();
        let head = pile.head(branch).unwrap().unwrap();
        pile.close().unwrap();
        head
    }

    fn u256be_to_u64(value: Inline<inlineencodings::U256BE>) -> Option<u64> {
        if value.raw[..24].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(u64::from_be_bytes(value.raw[24..].try_into().ok()?))
    }

    #[test]
    fn exact_timeout_event_is_one_intrinsic_idempotent_commit_and_keeps_pin() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("patience.pile");
        let key_path = directory.path().join("patience.key");
        File::create(&pile_path).unwrap();

        let pile = open_pile_strict(&pile_path).unwrap();
        let mut repository =
            Repository::new(pile, SigningKey::from_bytes(&[0x51; 32]), Fragment::empty()).unwrap();
        let legacy_branch = *repository.create_branch("cognition", None).unwrap();
        repository.close().unwrap();
        let legacy_pin = pin_head(&pile_path, legacy_branch);

        initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let storage = PatienceStorage {
            pile: &pile_path,
            key: Some(&key_path),
        };
        let request = test_id(0x62);
        let worker = test_id(0x63);
        let requested_at = at_unix(42.0);
        let expected = cognition::timeout_extension_fragment(request, worker, 90_000, requested_at);
        let expected_id = expected.root().unwrap();

        let (event_id, first_commit) =
            publish_timeout_extension(storage, request, worker, 90_000, requested_at).unwrap();
        let length_after_first = std::fs::metadata(&pile_path).unwrap().len();
        let (replayed_id, replayed_commit) =
            publish_timeout_extension(storage, request, worker, 90_000, requested_at).unwrap();

        assert_eq!(event_id, expected_id);
        assert_eq!(replayed_id, event_id);
        assert_eq!(replayed_commit, first_commit);
        assert_eq!(
            std::fs::metadata(&pile_path).unwrap().len(),
            length_after_first
        );
        assert_eq!(pin_head(&pile_path, legacy_branch), legacy_pin);

        let signer = load_signer(&pile_path, Some(&key_path)).unwrap();
        let pile = open_pile_strict(&pile_path).unwrap();
        let mut collection = Collection::new(pile, DEFAULT_SCOPE_ID, signer);
        let facts = collection.materialize().unwrap();
        assert_eq!(facts, expected.into_facts());
        let reader = collection.storage_mut().reader().unwrap();
        cognition::validate_catalog(&reader, &facts).unwrap();

        let (found_request, found_worker, timeout, found_at) = find!(
            (request: Id, worker: Id, timeout: Inline<inlineencodings::U256BE>, at: Inline<inlineencodings::NsTAIInterval>),
            pattern!(&facts, [{ event_id @
                metadata::tag: KIND_TIMEOUT_EXTENSION_ID,
                exec_schema::about_request: ?request,
                exec_schema::worker: ?worker,
                exec_schema::timeout_ms: ?timeout,
                exec_schema::requested_at: ?at,
            }])
        )
        .next()
        .unwrap();
        assert_eq!(found_request, request);
        assert_eq!(found_worker, worker);
        assert_eq!(u256be_to_u64(timeout), Some(90_000));
        assert_eq!(found_at, requested_at);
        collection.into_storage().close().unwrap();
    }

    #[test]
    fn missing_signer_fails_before_touching_pile() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("patience.pile");
        let key_path = directory.path().join("missing.key");
        File::create(&pile_path).unwrap();
        let before = std::fs::metadata(&pile_path).unwrap().len();

        let error = publish_timeout_extension(
            PatienceStorage {
                pile: &pile_path,
                key: Some(&key_path),
            },
            test_id(0x65),
            test_id(0x66),
            1_000,
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
