//! Shared argument projection for viewer and capture binaries.

use std::path::PathBuf;

/// Resolve the pile path without mistaking another option's value for the
/// positional path.
///
/// Explicit command-line input wins over ambient configuration:
/// `--pile PATH` / `--pile=PATH`, then the first true positional, then `PILE`,
/// then `./self.pile`. The value-taking options are owned by GORBIE's notebook
/// harness and must be skipped here even though this small projection does not
/// otherwise parse them.
pub fn resolve_pile_path(
    args: impl IntoIterator<Item = String>,
    pile_env: Option<String>,
) -> PathBuf {
    const VALUE_FLAGS: &[&str] = &[
        "--pile",
        "--out-dir",
        "--export-dir",
        "--scale",
        "--headless-wait-ms",
    ];

    let args: Vec<_> = args.into_iter().collect();
    let mut flagged = None;
    let mut positional = None;
    let mut options_ended = false;
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        if options_ended {
            positional.get_or_insert_with(|| args[index].clone());
            index += 1;
            continue;
        }
        if argument == "--" {
            options_ended = true;
            index += 1;
            continue;
        }
        if let Some(path) = argument.strip_prefix("--pile=") {
            if !path.is_empty() {
                flagged = Some(path.to_owned());
            }
            index += 1;
            continue;
        }
        if argument == "--pile" {
            flagged = args.get(index + 1).cloned();
            index += 2;
            continue;
        }
        if VALUE_FLAGS.contains(&argument) {
            index += 2;
            continue;
        }
        if !argument.starts_with('-') {
            positional.get_or_insert_with(|| args[index].clone());
        }
        index += 1;
    }

    flagged
        .or(positional)
        .or(pile_env)
        .unwrap_or_else(|| "./self.pile".to_owned())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn explicit_pile_beats_position_and_environment() {
        assert_eq!(
            resolve_pile_path(
                strings(&["positional.pile", "--pile", "flagged.pile"]),
                Some("ambient.pile".to_owned()),
            ),
            PathBuf::from("flagged.pile"),
        );
        assert_eq!(
            resolve_pile_path(
                strings(&["--pile=joined.pile"]),
                Some("ambient.pile".to_owned()),
            ),
            PathBuf::from("joined.pile"),
        );
    }

    #[test]
    fn notebook_option_values_are_not_positionals() {
        assert_eq!(
            resolve_pile_path(
                strings(&[
                    "--headless",
                    "--out-dir",
                    "/tmp/cards",
                    "--scale",
                    "2",
                    "actual.pile",
                ]),
                Some("ambient.pile".to_owned()),
            ),
            PathBuf::from("actual.pile"),
        );
    }

    #[test]
    fn environment_and_default_are_fallbacks() {
        assert_eq!(
            resolve_pile_path(strings(&["--headless"]), Some("ambient.pile".to_owned())),
            PathBuf::from("ambient.pile"),
        );
        assert_eq!(
            resolve_pile_path(strings(&["--headless"]), None),
            PathBuf::from("./self.pile"),
        );
    }

    #[test]
    fn option_terminator_allows_dash_prefixed_positionals() {
        assert_eq!(
            resolve_pile_path(strings(&["--", "--odd-name.pile"]), None),
            PathBuf::from("--odd-name.pile"),
        );
    }
}
