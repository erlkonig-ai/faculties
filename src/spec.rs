//! One faculty declaration projected into CLI and MCP front-ends.
//!
//! A front-end lowers named native arguments into [`Invocation`]. Handlers see neither
//! `clap::ArgMatches` nor MCP transport values, and receive storage separately
//! through their context.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use clap::{Arg, ArgAction, Command};

use crate::out::Out;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Supply {
    Caller,
    Ambient,
}

/// Argument shapes shared by CLI parsing and native invocation.
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

    /// A filesystem path. CLI parsing preserves native OS bytes; MCP strings
    /// become paths during shared lowering.
    pub const fn path(mut self) -> Self {
        assert!(
            matches!(self.kind, ParamKind::Text),
            "a path must be a scalar parameter"
        );
        self.kind = ParamKind::Path;
        self
    }

    /// A bare CLI flag or MCP boolean. Missing flags lower to false.
    pub const fn flag(mut self) -> Self {
        assert!(
            !self.positional && self.default.is_none() && matches!(self.kind, ParamKind::Text),
            "a flag must be a non-positional scalar without a text default"
        );
        self.kind = ParamKind::Flag;
        self.required = false;
        self
    }

    /// A repeatable CLI option or MCP string array. Missing values lower to an
    /// empty array; order and duplicates are preserved.
    pub const fn repeated(mut self) -> Self {
        assert!(
            !self.positional && self.default.is_none() && matches!(self.kind, ParamKind::Text),
            "a repeated option must be a non-positional scalar without a text default"
        );
        self.kind = ParamKind::Repeated;
        self.required = false;
        self
    }

    /// A text or path default, applied by shared lowering on every frontend.
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

    /// Reject declarations whose name projection would be ambiguous.
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

    /// Generate the complete CLI grammar from the canonical declaration.
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

    /// Generate transport-neutral MCP descriptors. An outer adapter decides
    /// how these typed values are represented on the wire.
    pub fn mcp_tools(&self) -> Vec<McpTool> {
        self.validate().expect("invalid faculty specification");
        self.verbs
            .iter()
            .map(|verb| {
                let parameters = self
                    .params_of(verb)
                    .filter(|param| param.supply == Supply::Caller)
                    .map(|param| McpParameter {
                        name: param.name,
                        description: param.help,
                        required: param.required,
                        kind: param.kind,
                        default: param.default,
                    })
                    .collect();
                McpTool {
                    name: format!("{}_{}", self.name, verb.name),
                    description: verb.about,
                    parameters,
                }
            })
            .collect()
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
        let mut caller = Arguments::new();
        let mut ambient = Arguments::new();
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
                ParamKind::Repeated => subcommand
                    .get_many::<String>(param.name)
                    .map(|values| ArgumentValue::Repeated(values.cloned().collect())),
            };
            let Some(value) = value else {
                continue;
            };
            let target = match param.supply {
                Supply::Caller => &mut caller,
                Supply::Ambient => &mut ambient,
            };
            target.insert_value(param.name, value).map_err(|error| {
                clap::Error::raw(clap::error::ErrorKind::ArgumentConflict, error.to_string())
            })?;
        }
        let invocation = self.lower(verb_name, caller, ambient).map_err(|error| {
            clap::Error::raw(
                clap::error::ErrorKind::MissingRequiredArgument,
                error.to_string(),
            )
        })?;
        Ok(CliRequest::Invoke(invocation))
    }

    pub fn lower_mcp(
        &'static self,
        tool_name: &str,
        caller: Arguments,
        ambient: Arguments,
    ) -> Result<Invocation> {
        self.validate()?;
        let prefix = format!("{}_", self.name);
        let verb = tool_name
            .strip_prefix(&prefix)
            .ok_or_else(|| anyhow!("tool {tool_name:?} does not belong to {}", self.name))?;
        self.lower(verb, caller, ambient)
    }

    fn lower(
        &'static self,
        verb_name: &str,
        mut caller: Arguments,
        mut ambient: Arguments,
    ) -> Result<Invocation> {
        let verb = self
            .verb(verb_name)
            .ok_or_else(|| anyhow!("unknown {} verb {verb_name:?}", self.name))?;
        let declared = self
            .params_of(verb)
            .map(|param| (param.name, param))
            .collect::<BTreeMap<_, _>>();
        validate_origin(&caller, Supply::Caller, &declared)?;
        validate_origin(&ambient, Supply::Ambient, &declared)?;

        let mut values = BTreeMap::new();
        for param in self.params_of(verb) {
            let source = match param.supply {
                Supply::Caller => &mut caller.values,
                Supply::Ambient => &mut ambient.values,
            };
            // JSON paths arrive as strings, as do native Arguments::with calls.
            // A native Path never passes through a UTF-8 conversion.
            let supplied = match (param.kind, source.remove(param.name)) {
                (ParamKind::Path, Some(ArgumentValue::Text(value))) => {
                    Some(ArgumentValue::Path(PathBuf::from(value)))
                }
                (_, value) => value,
            };
            if let Some(value) = &supplied {
                if value.kind() != param.kind {
                    bail!(
                        "parameter {:?} requires {:?}, not {:?}",
                        param.name,
                        param.kind,
                        value.kind()
                    );
                }
            }
            let value = supplied.or_else(|| match param.kind {
                ParamKind::Text => param
                    .default
                    .map(|value| ArgumentValue::Text(value.to_owned())),
                ParamKind::Path => param
                    .default
                    .map(|value| ArgumentValue::Path(PathBuf::from(value))),
                ParamKind::Flag => Some(ArgumentValue::Flag(false)),
                ParamKind::Repeated => Some(ArgumentValue::Repeated(Vec::new())),
            });
            match value {
                Some(value) => {
                    values.insert(param.name, value);
                }
                None if param.required => bail!(
                    "{} {} requires {:?} from {:?}",
                    self.name,
                    verb.name,
                    param.name,
                    param.supply
                ),
                None => {}
            }
        }
        Ok(Invocation { verb, values })
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

fn validate_origin(
    arguments: &Arguments,
    expected: Supply,
    declared: &BTreeMap<&str, &Param>,
) -> Result<()> {
    for name in arguments.values.keys() {
        let parameter = declared
            .get(name.as_str())
            .ok_or_else(|| anyhow!("undeclared parameter {name:?}"))?;
        if parameter.supply != expected {
            bail!(
                "parameter {name:?} is {:?}, not {:?}",
                parameter.supply,
                expected
            );
        }
    }
    Ok(())
}

/// Native argument data, independent of any CLI or JSON representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArgumentValue {
    Text(String),
    Path(PathBuf),
    Flag(bool),
    Repeated(Vec<String>),
}

impl ArgumentValue {
    fn kind(&self) -> ParamKind {
        match self {
            Self::Text(_) => ParamKind::Text,
            Self::Path(_) => ParamKind::Path,
            Self::Flag(_) => ParamKind::Flag,
            Self::Repeated(_) => ParamKind::Repeated,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Arguments {
    values: BTreeMap<String, ArgumentValue>,
}

impl Arguments {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) -> Result<()> {
        self.insert_value(name, ArgumentValue::Text(value.into()))
    }

    pub fn insert_value(&mut self, name: impl Into<String>, value: ArgumentValue) -> Result<()> {
        let name = name.into();
        if self.values.contains_key(&name) {
            bail!("parameter {name:?} supplied twice");
        }
        self.values.insert(name, value);
        Ok(())
    }

    pub fn with(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.insert(name, value)
            .expect("Arguments builder inserts each name once");
        self
    }

    pub fn with_value(mut self, name: impl Into<String>, value: ArgumentValue) -> Self {
        self.insert_value(name, value)
            .expect("Arguments builder inserts each name once");
        self
    }
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
pub struct McpParameter {
    pub name: &'static str,
    pub description: &'static str,
    pub required: bool,
    pub kind: ParamKind,
    pub default: Option<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpTool {
    pub name: String,
    pub description: &'static str,
    pub parameters: Vec<McpParameter>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliRequest {
    Help(String),
    Invoke(Invocation),
}

pub struct Faculty<C> {
    pub spec: &'static Spec,
    handler: fn(&mut C, &Invocation, &mut Out<'_>) -> Result<()>,
}

impl<C> Faculty<C> {
    pub const fn new(
        spec: &'static Spec,
        handler: fn(&mut C, &Invocation, &mut Out<'_>) -> Result<()>,
    ) -> Self {
        Self { spec, handler }
    }

    /// Run the shared handler with the frontend's incremental emitter.
    ///
    /// Invocation is synchronous and does not collect output. A handler or
    /// emission error leaves previously accepted parts with the frontend.
    pub fn invoke(
        &self,
        context: &mut C,
        invocation: &Invocation,
        output: &mut Out<'_>,
    ) -> Result<()> {
        (self.handler)(context, invocation, output)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use crate::out::Part;

    use super::*;

    const SPEC: Spec = Spec {
        name: "example",
        about: "Example",
        version: None,
        shared: &[Param::caller("pile", "Pile").ambient().env("PILE")],
        verbs: &[Verb {
            name: "show",
            about: "Show one",
            params: &[Param::caller("id", "Identifier").positional()],
        }],
    };

    #[test]
    fn one_declaration_projects_both_frontends() {
        let request = SPEC
            .lower_cli_from(["example", "--pile", "test.pile", "show", "abcd"])
            .unwrap();
        let CliRequest::Invoke(invocation) = request else {
            panic!("expected invocation")
        };
        assert_eq!(invocation.require("id").unwrap(), "abcd");
        assert_eq!(invocation.require("pile").unwrap(), "test.pile");

        let tools = SPEC.mcp_tools();
        assert_eq!(tools[0].name, "example_show");
        assert_eq!(tools[0].parameters.len(), 1);
        assert_eq!(tools[0].parameters[0].name, "id");
    }

    #[test]
    fn caller_cannot_supply_ambient_values() {
        let error = SPEC
            .lower_mcp(
                "example_show",
                Arguments::new().with("id", "abcd").with("pile", "wrong"),
                Arguments::new().with("pile", "configured"),
            )
            .unwrap_err();
        assert!(error.to_string().contains("not Caller"), "{error:#}");
    }

    #[test]
    fn declaration_rejects_ambiguous_origins_and_names() {
        assert!(std::panic::catch_unwind(|| Param::caller("x", "X").env("X")).is_err());
        assert!(
            std::panic::catch_unwind(|| Param::caller("x", "X").ambient().positional()).is_err()
        );

        const DUPLICATE: Spec = Spec {
            name: "duplicate",
            about: "Duplicate",
            version: None,
            shared: &[Param::caller("id", "Shared id")],
            verbs: &[Verb {
                name: "show",
                about: "Show",
                params: &[Param::caller("id", "Verb id")],
            }],
        };
        assert!(DUPLICATE.validate().is_err());
    }

    const OPTIONS_SPEC: Spec = Spec {
        name: "options",
        about: "Native options",
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

    #[test]
    fn flags_repeated_options_and_short_aliases_lower_identically() {
        let CliRequest::Invoke(cli) = OPTIONS_SPEC
            .lower_cli_from([
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
            ])
            .unwrap()
        else {
            panic!("expected invocation");
        };
        let mcp = OPTIONS_SPEC
            .lower_mcp(
                "options_fetch",
                Arguments::new()
                    .with("url", "https://example.org/file")
                    .with_value("dry-run", ArgumentValue::Flag(true))
                    .with_value(
                        "tag",
                        ArgumentValue::Repeated(vec![
                            "first".into(),
                            "first".into(),
                            "second".into(),
                        ]),
                    )
                    .with("limit", "7"),
                Arguments::new().with("pile", "configured"),
            )
            .unwrap();
        assert_eq!(cli, mcp);
        assert!(mcp.flag("dry-run"));
        assert_eq!(mcp.values("tag"), ["first", "first", "second"]);
        assert_eq!(mcp.require("limit").unwrap(), "7");
        assert!(mcp.get("tag").is_none());
        assert!(mcp.get("dry-run").is_none());
    }

    #[test]
    fn omissions_and_explicit_empty_values_share_native_defaults() {
        let CliRequest::Invoke(cli) = OPTIONS_SPEC
            .lower_cli_from(["options", "--pile", "configured", "fetch", "url"])
            .unwrap()
        else {
            panic!("expected invocation");
        };
        let ambient = Arguments::new().with("pile", "configured");
        let omitted = OPTIONS_SPEC
            .lower_mcp(
                "options_fetch",
                Arguments::new().with("url", "url"),
                ambient.clone(),
            )
            .unwrap();
        let explicit = OPTIONS_SPEC
            .lower_mcp(
                "options_fetch",
                Arguments::new()
                    .with("url", "url")
                    .with_value("dry-run", ArgumentValue::Flag(false))
                    .with_value("tag", ArgumentValue::Repeated(Vec::new())),
                ambient,
            )
            .unwrap();
        assert_eq!(cli, omitted);
        assert_eq!(omitted, explicit);
        assert!(!omitted.flag("dry-run"));
        assert!(omitted.values("tag").is_empty());
        assert_eq!(omitted.require("limit").unwrap(), "10");
        assert!(omitted.get("mime").is_none());
        assert!(OPTIONS_SPEC
            .to_clap()
            .find_subcommand("fetch")
            .unwrap()
            .clone()
            .render_help()
            .to_string()
            .contains("[default: 10]"));
    }

    #[test]
    fn declared_argument_shapes_are_checked_before_invocation() {
        for (name, value) in [
            ("tag", ArgumentValue::Text("not an array".into())),
            ("dry-run", ArgumentValue::Text("true".into())),
            ("limit", ArgumentValue::Flag(false)),
            ("mime", ArgumentValue::Repeated(vec!["text/plain".into()])),
        ] {
            let error = OPTIONS_SPEC
                .lower_mcp(
                    "options_fetch",
                    Arguments::new().with("url", "url").with_value(name, value),
                    Arguments::new().with("pile", "configured"),
                )
                .unwrap_err();
            assert!(error.to_string().contains("requires"), "{error:#}");
        }
        let error = OPTIONS_SPEC
            .lower_mcp(
                "options_fetch",
                Arguments::new()
                    .with("url", "url")
                    .with_value("pile", ArgumentValue::Flag(false)),
                Arguments::new().with("pile", "configured"),
            )
            .unwrap_err();
        assert!(error.to_string().contains("not Caller"));
        let error = OPTIONS_SPEC
            .lower_mcp(
                "options_fetch",
                Arguments::new().with("url", "url"),
                Arguments::new().with_value("pile", ArgumentValue::Repeated(Vec::new())),
            )
            .unwrap_err();
        assert!(error.to_string().contains("requires Text"));
        assert!(OPTIONS_SPEC
            .lower_cli_from([
                "options",
                "--pile",
                "configured",
                "fetch",
                "url",
                "--dry-run=false",
            ])
            .is_err());
    }

    #[test]
    fn duplicate_arguments_do_not_replace_previously_supplied_values() {
        let mut arguments = Arguments::new().with("id", "abcd");
        assert!(arguments
            .insert_value("id", ArgumentValue::Flag(true))
            .is_err());
        let invocation = SPEC
            .lower_mcp(
                "example_show",
                arguments,
                Arguments::new().with("pile", "configured"),
            )
            .unwrap();
        assert_eq!(invocation.require("id").unwrap(), "abcd");
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
        const DUPLICATE_SHORT: Spec = Spec {
            name: "duplicate",
            about: "Duplicate",
            version: None,
            shared: &[Param::caller("shared", "Shared").short('n').optional()],
            verbs: &[Verb {
                name: "show",
                about: "Show",
                params: &[Param::caller("limit", "Limit").short('n')],
            }],
        };
        assert!(DUPLICATE_SHORT.validate().is_err());
    }

    #[test]
    fn native_descriptors_include_shapes_and_scalar_defaults() {
        let tools = OPTIONS_SPEC.mcp_tools();
        let params = &tools[0].parameters;
        assert_eq!(params[0].kind, ParamKind::Text);
        assert!(params[0].required);
        assert_eq!(params[1].kind, ParamKind::Repeated);
        assert!(!params[1].required);
        assert_eq!(params[2].kind, ParamKind::Flag);
        assert!(!params[2].required);
        assert_eq!(params[3].default, Some("10"));
        assert!(!params[3].required);
        assert!(params
            .iter()
            .all(|param| !matches!(param.name, "pile" | "key")));
    }

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

    #[test]
    fn string_paths_and_path_defaults_lower_identically() {
        let CliRequest::Invoke(cli) = PATH_SPEC
            .lower_cli_from(["paths", "--pile", "configured.pile", "add", "input.txt"])
            .unwrap()
        else {
            panic!("expected invocation");
        };
        let mcp = PATH_SPEC
            .lower_mcp(
                "paths_add",
                Arguments::new().with("path", "input.txt"),
                Arguments::new().with("pile", "configured.pile"),
            )
            .unwrap();
        assert_eq!(cli, mcp);
        assert_eq!(mcp.require_path("path").unwrap(), Path::new("input.txt"));
        assert_eq!(mcp.require_path("base").unwrap(), Path::new("."));
        assert_eq!(
            mcp.require_path("pile").unwrap(),
            Path::new("configured.pile")
        );
        assert!(mcp.path("key").is_none());
        assert!(mcp.get("path").is_none());
        assert!(mcp.require("pile").is_err());
        let tools = PATH_SPEC.mcp_tools();
        assert_eq!(tools[0].parameters[0].kind, ParamKind::Path);
        assert_eq!(tools[0].parameters[1].kind, ParamKind::Path);
        assert_eq!(tools[0].parameters[1].default, Some("."));
    }

    #[cfg(unix)]
    #[test]
    fn cli_and_native_paths_preserve_non_utf8_os_bytes() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let pile = OsString::from_vec(b"pile-\xff".to_vec());
        let key = OsString::from_vec(b"key-\xfe".to_vec());
        let path = OsString::from_vec(b"input-\xfd".to_vec());
        let CliRequest::Invoke(cli) = PATH_SPEC
            .lower_cli_from([
                OsString::from("paths"),
                OsString::from("--pile"),
                pile.clone(),
                OsString::from("--key"),
                key.clone(),
                OsString::from("add"),
                path.clone(),
            ])
            .unwrap()
        else {
            panic!("expected invocation");
        };
        let native = PATH_SPEC
            .lower_mcp(
                "paths_add",
                Arguments::new().with_value("path", ArgumentValue::Path(PathBuf::from(path))),
                Arguments::new()
                    .with_value("pile", ArgumentValue::Path(PathBuf::from(pile)))
                    .with_value("key", ArgumentValue::Path(PathBuf::from(key))),
            )
            .unwrap();
        assert_eq!(cli, native);
        for (name, expected) in [
            ("pile", b"pile-\xff".as_slice()),
            ("key", b"key-\xfe".as_slice()),
            ("path", b"input-\xfd".as_slice()),
        ] {
            let path = cli.require_path(name).unwrap();
            assert_eq!(path.as_os_str().as_bytes(), expected);
            assert!(path.to_str().is_none());
        }
    }

    #[test]
    fn paths_keep_declared_shapes_and_origin_guards() {
        for value in [ArgumentValue::Flag(false), ArgumentValue::Repeated(vec![])] {
            let error = PATH_SPEC
                .lower_mcp(
                    "paths_add",
                    Arguments::new().with_value("path", value),
                    Arguments::new().with("pile", "configured"),
                )
                .unwrap_err();
            assert!(error.to_string().contains("requires Path"), "{error:#}");
        }
        let error = PATH_SPEC
            .lower_mcp(
                "paths_add",
                Arguments::new()
                    .with("path", "input.txt")
                    .with_value("pile", ArgumentValue::Path("wrong".into())),
                Arguments::new().with("pile", "configured"),
            )
            .unwrap_err();
        assert!(error.to_string().contains("not Caller"), "{error:#}");
        let error = SPEC
            .lower_mcp(
                "example_show",
                Arguments::new().with_value("id", ArgumentValue::Path("abcd".into())),
                Arguments::new().with("pile", "configured"),
            )
            .unwrap_err();
        assert!(error.to_string().contains("requires Text"), "{error:#}");
        assert!(std::panic::catch_unwind(|| Param::caller("x", "X").path().flag()).is_err());
        assert!(std::panic::catch_unwind(|| Param::caller("x", "X").repeated().path()).is_err());
    }

    fn example_invocation() -> Invocation {
        SPEC.lower_mcp(
            "example_show",
            Arguments::new().with("id", "abcd"),
            Arguments::new().with("pile", "test.pile"),
        )
        .unwrap()
    }

    #[test]
    fn emission_is_observed_before_the_handler_continues() {
        let observed = Cell::new(0);
        let faculty = Faculty::new(&SPEC, |observed: &mut &Cell<usize>, _, output| {
            assert_eq!(observed.get(), 0);
            output.line("first")?;
            assert_eq!(observed.get(), 1);
            output.line("second")?;
            assert_eq!(observed.get(), 2);
            Ok(())
        });
        let mut emit = |_| {
            observed.set(observed.get() + 1);
            Ok(())
        };
        faculty
            .invoke(
                &mut &observed,
                &example_invocation(),
                &mut Out::new(&mut emit),
            )
            .unwrap();
        assert_eq!(observed.get(), 2);
    }

    #[test]
    fn emission_failure_preserves_prior_output_and_stops_production() {
        let faculty = Faculty::new(&SPEC, |produced: &mut usize, _, output| {
            for text in ["first", "rejected", "never produced"] {
                *produced += 1;
                output.line(text)?;
            }
            Ok(())
        });
        let mut parts = Vec::new();
        let mut produced = 0;
        let error = {
            let mut emit = |part| {
                if !parts.is_empty() {
                    bail!("output closed");
                }
                parts.push(part);
                Ok(())
            };
            faculty
                .invoke(
                    &mut produced,
                    &example_invocation(),
                    &mut Out::new(&mut emit),
                )
                .unwrap_err()
        };
        assert_eq!(error.to_string(), "output closed");
        assert_eq!(produced, 2);
        assert_eq!(
            parts,
            [Part::Text {
                text: "first\n".into()
            }]
        );
    }

    #[test]
    fn handler_error_preserves_partial_output_without_an_implicit_error_part() {
        let faculty = Faculty::new(&SPEC, |_: &mut (), _, output| {
            output.text("partial")?;
            bail!("handler failed");
        });
        let mut parts = Vec::new();
        let error = {
            let mut collect = |part| {
                parts.push(part);
                Ok(())
            };
            faculty
                .invoke(&mut (), &example_invocation(), &mut Out::new(&mut collect))
                .unwrap_err()
        };
        assert_eq!(error.to_string(), "handler failed");
        assert_eq!(
            parts,
            [Part::Text {
                text: "partial".into()
            }]
        );
    }

    #[test]
    fn an_empty_handler_does_not_emit() {
        let faculty = Faculty::new(&SPEC, |_: &mut (), _, _| Ok(()));
        let mut emit = |_| -> Result<()> { panic!("empty handler emitted output") };
        faculty
            .invoke(&mut (), &example_invocation(), &mut Out::new(&mut emit))
            .unwrap();
    }
}
