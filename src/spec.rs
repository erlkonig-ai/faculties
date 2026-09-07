//! Optional declarations for a faculty's CLI grammar and argument lowering.
//!
//! CLI adapters can use these helpers instead of defining clap parsers directly.
//! Their [`Invocation`] is a CLI detail, not the shared library's operation API.
//! MCP adapters define their own schemas and call those operations independently.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use clap::{Arg, ArgAction, Command};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Supply {
    Caller,
    Ambient,
}

/// CLI argument shapes. Filesystem paths retain their native OS representation.
/// Numeric values remain text and are interpreted by their faculty handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParamKind {
    Text,
    Path,
    Flag,
    Repeated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Param {
    name: &'static str,
    help: &'static str,
    supply: Supply,
    required: bool,
    positional: bool,
    env: Option<&'static str>,
    kind: ParamKind,
    default: Option<&'static str>,
    short: Option<char>,
}

impl Param {
    pub const fn caller(name: &'static str, help: &'static str) -> Self {
        Self {
            name,
            help,
            supply: Supply::Caller,
            required: true,
            positional: false,
            env: None,
            kind: ParamKind::Text,
            default: None,
            short: None,
        }
    }

    pub const fn ambient(mut self) -> Self {
        assert!(
            !self.positional,
            "an ambient parameter cannot be positional"
        );
        self.supply = Supply::Ambient;
        self
    }

    pub const fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    pub const fn positional(mut self) -> Self {
        assert!(
            matches!(self.supply, Supply::Caller),
            "an ambient parameter cannot be positional"
        );
        assert!(
            matches!(self.kind, ParamKind::Text | ParamKind::Path) && self.short.is_none(),
            "only a scalar argument without a short option can be positional"
        );
        self.positional = true;
        self
    }

    /// A filesystem path. Parsing preserves native OS bytes.
    pub const fn path(mut self) -> Self {
        assert!(
            matches!(self.kind, ParamKind::Text),
            "a path must be a scalar parameter"
        );
        self.kind = ParamKind::Path;
        self
    }

    /// A bare flag. Missing flags lower to false.
    pub const fn flag(mut self) -> Self {
        assert!(
            !self.positional && self.default.is_none() && matches!(self.kind, ParamKind::Text),
            "a flag must be a non-positional scalar without a text default"
        );
        self.kind = ParamKind::Flag;
        self.required = false;
        self
    }

    /// A repeatable option. Missing values lower to an empty array; order and
    /// duplicates are preserved.
    pub const fn repeated(mut self) -> Self {
        assert!(
            !self.positional && self.default.is_none() && matches!(self.kind, ParamKind::Text),
            "a repeated option must be a non-positional scalar without a text default"
        );
        self.kind = ParamKind::Repeated;
        self.required = false;
        self
    }

    /// A text or path default, applied by CLI parsing.
    pub const fn default(mut self, value: &'static str) -> Self {
        assert!(
            matches!(self.kind, ParamKind::Text | ParamKind::Path),
            "defaults require a scalar parameter"
        );
        self.default = Some(value);
        self.required = false;
        self
    }

    pub const fn short(mut self, name: char) -> Self {
        assert!(
            !self.positional,
            "a positional parameter cannot have a short option"
        );
        self.short = Some(name);
        self
    }

    pub const fn env(mut self, name: &'static str) -> Self {
        assert!(
            matches!(self.supply, Supply::Ambient),
            "only an ambient parameter can have an environment fallback"
        );
        self.env = Some(name);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Verb {
    pub name: &'static str,
    pub about: &'static str,
    pub params: &'static [Param],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Spec {
    pub name: &'static str,
    pub about: &'static str,
    pub version: Option<&'static str>,
    pub shared: &'static [Param],
    pub verbs: &'static [Verb],
}

impl Spec {
    pub fn verb(&self, name: &str) -> Option<&'static Verb> {
        self.verbs.iter().find(|verb| verb.name == name)
    }

    fn params_of(&self, verb: &'static Verb) -> impl Iterator<Item = &'static Param> {
        verb.params.iter().chain(self.shared.iter())
    }

    /// Reject declarations whose CLI names or aliases would be ambiguous.
    pub fn validate(&self) -> Result<()> {
        let mut shared = BTreeSet::new();
        let mut shared_short = BTreeSet::new();
        for param in self.shared {
            if param.positional {
                bail!(
                    "{} shared parameter {:?} cannot be positional",
                    self.name,
                    param.name
                );
            }
            if !shared.insert(param.name) {
                bail!(
                    "{} declares shared parameter {:?} twice",
                    self.name,
                    param.name
                );
            }
            if let Some(short) = param.short {
                if !shared_short.insert(short) {
                    bail!("{} declares short option -{short} twice", self.name);
                }
            }
        }
        let mut verbs = BTreeSet::new();
        for verb in self.verbs {
            if !verbs.insert(verb.name) {
                bail!("{} declares verb {:?} twice", self.name, verb.name);
            }
            let mut names = shared.clone();
            let mut short_names = shared_short.clone();
            for param in verb.params {
                if !names.insert(param.name) {
                    bail!(
                        "{} {} declares parameter {:?} twice",
                        self.name,
                        verb.name,
                        param.name
                    );
                }
                if let Some(short) = param.short {
                    if !short_names.insert(short) {
                        bail!(
                            "{} {} declares short option -{short} twice",
                            self.name,
                            verb.name
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Generate the complete CLI grammar from this declaration.
    pub fn to_clap(&self) -> Command {
        self.validate().expect("invalid faculty specification");
        let mut command = Command::new(self.name)
            .about(self.about)
            .subcommand_required(false)
            .arg_required_else_help(false);
        if let Some(version) = self.version {
            command = command.version(version);
        }
        for param in self.shared {
            command = command.arg(clap_arg(param, true));
        }
        for verb in self.verbs {
            let mut subcommand = Command::new(verb.name).about(verb.about);
            for param in verb.params {
                subcommand = subcommand.arg(clap_arg(param, false));
            }
            command = command.subcommand(subcommand);
        }
        command
    }

    pub fn lower_cli_from<I, T>(
        &'static self,
        arguments: I,
    ) -> std::result::Result<CliRequest, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let mut command = self.to_clap();
        let matches = command.clone().try_get_matches_from(arguments)?;
        let Some((verb_name, subcommand)) = matches.subcommand() else {
            return Ok(CliRequest::Help(command.render_help().to_string()));
        };
        let verb = self
            .verb(verb_name)
            .expect("clap emits only declared subcommands");
        let mut values = BTreeMap::new();
        for param in self.params_of(verb) {
            let value = match param.kind {
                ParamKind::Text => subcommand
                    .get_one::<String>(param.name)
                    .cloned()
                    .map(ArgumentValue::Text),
                ParamKind::Path => subcommand
                    .get_one::<PathBuf>(param.name)
                    .cloned()
                    .map(ArgumentValue::Path),
                ParamKind::Flag => Some(ArgumentValue::Flag(subcommand.get_flag(param.name))),
                ParamKind::Repeated => Some(ArgumentValue::Repeated(
                    subcommand
                        .get_many::<String>(param.name)
                        .map(|values| values.cloned().collect())
                        .unwrap_or_default(),
                )),
            };
            match value {
                Some(value) => {
                    values.insert(param.name, value);
                }
                // Clap cannot mark global arguments required while preserving
                // no-subcommand help. Enforce them only after a verb is selected.
                None if param.required => {
                    return Err(clap::Error::raw(
                        clap::error::ErrorKind::MissingRequiredArgument,
                        format!("{} {} requires {:?}", self.name, verb.name, param.name),
                    ));
                }
                None => {}
            }
        }
        Ok(CliRequest::Invoke(Invocation { verb, values }))
    }
}

fn clap_arg(param: &'static Param, global: bool) -> Arg {
    let mut argument = Arg::new(param.name).help(param.help);
    if param.positional {
        argument = argument.required(param.required);
    } else {
        argument = argument
            .long(param.name)
            .required(param.required && !global)
            .global(global);
    }
    if let Some(env) = param.env {
        argument = argument.env(env);
    }
    if let Some(short) = param.short {
        argument = argument.short(short);
    }
    if let Some(default) = param.default {
        argument = argument.default_value(default);
    }
    argument = match param.kind {
        ParamKind::Text => argument,
        ParamKind::Path => argument.value_parser(clap::value_parser!(PathBuf)),
        ParamKind::Flag => argument.action(ArgAction::SetTrue),
        ParamKind::Repeated => argument.action(ArgAction::Append),
    };
    argument
}

/// Values already parsed and type-checked by the CLI grammar.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ArgumentValue {
    Text(String),
    Path(PathBuf),
    Flag(bool),
    Repeated(Vec<String>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    verb: &'static Verb,
    values: BTreeMap<&'static str, ArgumentValue>,
}

impl Invocation {
    pub const fn verb(&self) -> &'static Verb {
        self.verb
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        match self.values.get(name) {
            Some(ArgumentValue::Text(value)) => Some(value),
            _ => None,
        }
    }

    pub fn require(&self, name: &str) -> Result<&str> {
        self.get(name)
            .ok_or_else(|| anyhow!("{} requires {name:?}", self.verb.name))
    }

    /// A native filesystem path without any UTF-8 conversion.
    pub fn path(&self, name: &str) -> Option<&Path> {
        match self.values.get(name) {
            Some(ArgumentValue::Path(value)) => Some(value.as_path()),
            _ => None,
        }
    }

    pub fn require_path(&self, name: &str) -> Result<&Path> {
        self.path(name)
            .ok_or_else(|| anyhow!("{} requires path {name:?}", self.verb.name))
    }

    /// Whether a declared flag is set. Omitted flags lower to false.
    pub fn flag(&self, name: &str) -> bool {
        matches!(self.values.get(name), Some(ArgumentValue::Flag(true)))
    }

    /// Ordered values of a repeated option, empty when omitted.
    pub fn values(&self, name: &str) -> &[String] {
        match self.values.get(name) {
            Some(ArgumentValue::Repeated(values)) => values,
            _ => &[],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliRequest {
    Help(String),
    Invoke(Invocation),
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: Spec = Spec {
        name: "example",
        about: "Example",
        version: None,
        shared: &[Param::caller("pile", "Pile").ambient()],
        verbs: &[Verb {
            name: "show",
            about: "Show one",
            params: &[Param::caller("id", "Identifier").positional()],
        }],
    };

    const OPTIONS_SPEC: Spec = Spec {
        name: "options",
        about: "CLI options",
        version: None,
        shared: &[
            Param::caller("pile", "Pile").ambient(),
            Param::caller("key", "Key").ambient().optional(),
        ],
        verbs: &[Verb {
            name: "fetch",
            about: "Fetch one",
            params: &[
                Param::caller("url", "URL").positional(),
                Param::caller("tag", "Tags").repeated(),
                Param::caller("dry-run", "Preview").flag(),
                Param::caller("limit", "Limit").default("10").short('n'),
                Param::caller("mime", "MIME").optional(),
            ],
        }],
    };

    const PATH_SPEC: Spec = Spec {
        name: "paths",
        about: "Native paths",
        version: None,
        shared: &[
            Param::caller("pile", "Pile").path().ambient(),
            Param::caller("key", "Key").ambient().optional().path(),
        ],
        verbs: &[Verb {
            name: "add",
            about: "Use a path",
            params: &[
                Param::caller("path", "Input path").positional().path(),
                Param::caller("base", "Base directory")
                    .path()
                    .default(".")
                    .short('b'),
            ],
        }],
    };

    fn invoke(spec: &'static Spec, arguments: &[&str]) -> Invocation {
        let CliRequest::Invoke(invocation) =
            spec.lower_cli_from(arguments.iter().copied()).unwrap()
        else {
            panic!("expected invocation");
        };
        invocation
    }

    #[test]
    fn cli_lowers_global_arguments_before_or_after_the_verb() {
        for arguments in [
            ["example", "--pile", "test.pile", "show", "abcd"],
            ["example", "show", "abcd", "--pile", "test.pile"],
        ] {
            let invocation = invoke(&SPEC, &arguments);
            assert_eq!(invocation.verb().name, "show");
            assert_eq!(invocation.require("id").unwrap(), "abcd");
            assert_eq!(invocation.require("pile").unwrap(), "test.pile");
            assert!(invocation.require("unknown").is_err());
        }
    }

    #[test]
    fn no_verb_returns_help_without_requiring_global_configuration() {
        let CliRequest::Help(help) = SPEC.lower_cli_from(["example"]).unwrap() else {
            panic!("expected help");
        };
        assert!(help.contains("show"));
        assert!(help.contains("--pile"));
        let error = SPEC.lower_cli_from(["example", "--help"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn required_arguments_and_unknown_cli_names_are_rejected() {
        for arguments in [
            vec!["example", "show", "abcd"],
            vec!["example", "--pile", "test.pile", "show"],
        ] {
            let error = SPEC.lower_cli_from(arguments).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
        }
        assert!(SPEC.lower_cli_from(["example", "unknown"]).is_err());
        assert!(SPEC
            .lower_cli_from([
                "example",
                "--pile",
                "test.pile",
                "show",
                "abcd",
                "--unknown"
            ])
            .is_err());
    }

    #[test]
    fn declaration_rejects_ambiguous_names_and_invalid_environment_sources() {
        assert!(std::panic::catch_unwind(|| Param::caller("x", "X").env("X")).is_err());
        assert!(
            std::panic::catch_unwind(|| Param::caller("x", "X").ambient().positional()).is_err()
        );

        const DUPLICATE_PARAMETER: Spec = Spec {
            shared: &[Param::caller("id", "Shared id")],
            ..SPEC
        };
        const DUPLICATE_SHARED: Spec = Spec {
            shared: &[
                Param::caller("pile", "First pile"),
                Param::caller("pile", "Second pile"),
            ],
            ..SPEC
        };
        const DUPLICATE_VERB: Spec = Spec {
            verbs: &[
                Verb {
                    name: "show",
                    about: "First",
                    params: &[],
                },
                Verb {
                    name: "show",
                    about: "Second",
                    params: &[],
                },
            ],
            ..SPEC
        };
        const SHARED_POSITIONAL: Spec = Spec {
            shared: &[Param::caller("pile", "Pile").positional()],
            ..SPEC
        };
        for spec in [
            DUPLICATE_PARAMETER,
            DUPLICATE_SHARED,
            DUPLICATE_VERB,
            SHARED_POSITIONAL,
        ] {
            assert!(spec.validate().is_err());
        }
    }

    #[test]
    fn flags_repeated_options_and_short_aliases_keep_their_shapes() {
        let invocation = invoke(
            &OPTIONS_SPEC,
            &[
                "options",
                "--pile",
                "configured",
                "fetch",
                "https://example.org/file",
                "--dry-run",
                "--tag",
                "first",
                "--tag",
                "first",
                "--tag",
                "second",
                "-n",
                "7",
            ],
        );
        assert!(invocation.flag("dry-run"));
        assert_eq!(invocation.values("tag"), ["first", "first", "second"]);
        assert_eq!(invocation.require("limit").unwrap(), "7");
        assert_eq!(
            invocation.require("url").unwrap(),
            "https://example.org/file"
        );
        assert!(invocation.get("tag").is_none());
        assert!(invocation.get("dry-run").is_none());
    }

    #[test]
    fn omitted_options_keep_defaults_and_optional_values_absent() {
        let invocation = invoke(
            &OPTIONS_SPEC,
            &["options", "--pile", "configured", "fetch", "url"],
        );
        assert!(!invocation.flag("dry-run"));
        assert!(invocation.values("tag").is_empty());
        assert_eq!(invocation.require("limit").unwrap(), "10");
        assert!(invocation.get("mime").is_none());
        assert!(invocation.get("key").is_none());
        assert!(invocation.require("mime").is_err());
    }

    #[test]
    fn scalar_values_stay_text_until_the_faculty_interprets_them() {
        for limit in ["7", "1e2", "not-a-number"] {
            let invocation = invoke(
                &OPTIONS_SPEC,
                &[
                    "options",
                    "--pile",
                    "configured",
                    "fetch",
                    "url",
                    "-n",
                    limit,
                ],
            );
            assert_eq!(invocation.require("limit").unwrap(), limit);
        }
        let invocation = invoke(
            &OPTIONS_SPEC,
            &[
                "options",
                "--pile",
                "configured",
                "fetch",
                "url",
                "--mime",
                "",
                "--tag",
                "",
            ],
        );
        assert_eq!(invocation.get("mime"), Some(""));
        assert_eq!(invocation.values("tag"), [""]);
    }

    #[test]
    fn scalar_duplicates_and_invalid_flag_syntax_are_not_silently_overwritten() {
        for tail in [
            vec!["--limit", "1", "--limit", "2"],
            vec!["--dry-run", "--dry-run"],
            vec!["--dry-run=false"],
            vec!["--tag"],
            vec!["--limit"],
        ] {
            let arguments = ["options", "--pile", "configured", "fetch", "url"]
                .into_iter()
                .chain(tail);
            assert!(OPTIONS_SPEC.lower_cli_from(arguments).is_err());
        }
    }

    #[test]
    fn invalid_option_shapes_and_alias_collisions_are_rejected() {
        assert!(std::panic::catch_unwind(|| Param::caller("x", "X").positional().flag()).is_err());
        assert!(std::panic::catch_unwind(|| Param::caller("x", "X").flag().positional()).is_err());
        assert!(
            std::panic::catch_unwind(|| Param::caller("x", "X").repeated().default("x")).is_err()
        );
        assert!(
            std::panic::catch_unwind(|| Param::caller("x", "X").default("true").flag()).is_err()
        );
        assert!(
            std::panic::catch_unwind(|| Param::caller("x", "X").positional().short('n')).is_err()
        );
        assert!(std::panic::catch_unwind(|| Param::caller("x", "X").path().flag()).is_err());
        assert!(std::panic::catch_unwind(|| Param::caller("x", "X").repeated().path()).is_err());
        const DUPLICATE_SHORT: Spec = Spec {
            shared: &[Param::caller("shared", "Shared").short('n').optional()],
            verbs: &[Verb {
                name: "show",
                about: "Show",
                params: &[Param::caller("limit", "Limit").short('n')],
            }],
            ..SPEC
        };
        assert!(DUPLICATE_SHORT.validate().is_err());
    }

    #[test]
    fn cli_help_describes_options_and_scalar_defaults() {
        let help = OPTIONS_SPEC
            .to_clap()
            .find_subcommand_mut("fetch")
            .unwrap()
            .render_help()
            .to_string();
        for text in ["--dry-run", "--tag", "-n", "--limit", "[default: 10]"] {
            assert!(help.contains(text), "{text}: {help}");
        }
    }

    #[test]
    fn cli_paths_keep_native_shapes_and_declared_defaults() {
        let invocation = invoke(
            &PATH_SPEC,
            &["paths", "--pile", "configured.pile", "add", "input.txt"],
        );
        assert_eq!(
            invocation.require_path("path").unwrap(),
            Path::new("input.txt")
        );
        assert_eq!(invocation.require_path("base").unwrap(), Path::new("."));
        assert_eq!(
            invocation.require_path("pile").unwrap(),
            Path::new("configured.pile")
        );
        assert!(invocation.path("key").is_none());
        assert!(invocation.get("path").is_none());
        assert!(invocation.require("pile").is_err());

        let explicit = invoke(
            &PATH_SPEC,
            &[
                "paths",
                "--pile",
                "configured.pile",
                "add",
                "input.txt",
                "-b",
                "root/é",
            ],
        );
        assert_eq!(explicit.require_path("base").unwrap(), Path::new("root/é"));
    }

    #[cfg(unix)]
    #[test]
    fn cli_paths_preserve_non_utf8_os_bytes() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let CliRequest::Invoke(invocation) = PATH_SPEC
            .lower_cli_from([
                OsString::from("paths"),
                OsString::from("--pile"),
                OsString::from_vec(b"pile-\xff".to_vec()),
                OsString::from("--key"),
                OsString::from_vec(b"key-\xfe".to_vec()),
                OsString::from("add"),
                OsString::from_vec(b"input-\xfd".to_vec()),
            ])
            .unwrap()
        else {
            panic!("expected invocation");
        };
        for (name, expected) in [
            ("pile", b"pile-\xff".as_slice()),
            ("key", b"key-\xfe".as_slice()),
            ("path", b"input-\xfd".as_slice()),
        ] {
            let path = invocation.require_path(name).unwrap();
            assert_eq!(path.as_os_str().as_bytes(), expected);
            assert!(path.to_str().is_none());
        }
    }

    #[test]
    fn ambient_environment_is_native_and_cli_flags_take_precedence() {
        const ENV_SPEC: Spec = Spec {
            shared: &[
                Param::caller("pile", "Pile")
                    .path()
                    .ambient()
                    .env("FACULTIES_SPEC_TEST_PILE"),
                Param::caller("key", "Key")
                    .path()
                    .ambient()
                    .optional()
                    .env("FACULTIES_SPEC_TEST_KEY"),
            ],
            ..PATH_SPEC
        };
        // Set environment only on a child, never in the multithreaded harness.
        if std::env::var_os("FACULTIES_SPEC_TEST_CHILD").is_none() {
            #[cfg(unix)]
            let value = {
                use std::os::unix::ffi::OsStringExt;
                OsString::from_vec(b"environment-\xff.pile".to_vec())
            };
            #[cfg(not(unix))]
            let value = OsString::from("environment-é.pile");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "spec::tests::ambient_environment_is_native_and_cli_flags_take_precedence",
                    "--nocapture",
                ])
                .env("FACULTIES_SPEC_TEST_CHILD", "1")
                .env("FACULTIES_SPEC_TEST_PILE", value)
                .env_remove("FACULTIES_SPEC_TEST_KEY")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            return;
        }
        let expected = std::env::var_os("FACULTIES_SPEC_TEST_PILE").unwrap();
        let invocation = invoke(&ENV_SPEC, &["paths", "add", "input.txt"]);
        assert_eq!(
            invocation.require_path("pile").unwrap().as_os_str(),
            expected.as_os_str()
        );
        assert!(invocation.path("key").is_none());
        let explicit = invoke(
            &ENV_SPEC,
            &["paths", "--pile", "cli.pile", "add", "input.txt"],
        );
        assert_eq!(
            explicit.require_path("pile").unwrap(),
            Path::new("cli.pile")
        );
    }
}
