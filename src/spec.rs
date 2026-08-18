//! One faculty declaration projected into CLI and MCP front-ends.
//!
//! A front-end lowers named text into [`Invocation`]. Handlers see neither
//! `clap::ArgMatches` nor MCP transport values, and receive storage separately
//! through their context.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;

use anyhow::{anyhow, bail, Result};
use clap::{Arg, Command};

use crate::out::Out;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Supply {
    Caller,
    Ambient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Param {
    name: &'static str,
    help: &'static str,
    supply: Supply,
    required: bool,
    positional: bool,
    env: Option<&'static str>,
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
        self.positional = true;
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
        }
        let mut verbs = BTreeSet::new();
        for verb in self.verbs {
            if !verbs.insert(verb.name) {
                bail!("{} declares verb {:?} twice", self.name, verb.name);
            }
            let mut names = shared.clone();
            for param in verb.params {
                if !names.insert(param.name) {
                    bail!(
                        "{} {} declares parameter {:?} twice",
                        self.name,
                        verb.name,
                        param.name
                    );
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
            let Some(value) = subcommand.get_one::<String>(param.name) else {
                continue;
            };
            let target = match param.supply {
                Supply::Caller => &mut caller,
                Supply::Ambient => &mut ambient,
            };
            target.insert(param.name, value.clone()).map_err(|error| {
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
            match source.remove(param.name) {
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Arguments {
    values: BTreeMap<String, String>,
}

impl Arguments {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) -> Result<()> {
        let name = name.into();
        if self.values.insert(name.clone(), value.into()).is_some() {
            bail!("parameter {name:?} supplied twice");
        }
        Ok(())
    }

    pub fn with(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.insert(name, value)
            .expect("Arguments builder inserts each name once");
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invocation {
    verb: &'static Verb,
    values: BTreeMap<&'static str, String>,
}

impl Invocation {
    pub const fn verb(&self) -> &'static Verb {
        self.verb
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    pub fn require(&self, name: &str) -> Result<&str> {
        self.get(name)
            .ok_or_else(|| anyhow!("{} requires {name:?}", self.verb.name))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpParameter {
    pub name: &'static str,
    pub description: &'static str,
    pub required: bool,
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
    handler: fn(&mut C, &Invocation, &mut Out) -> Result<()>,
}

impl<C> Faculty<C> {
    pub const fn new(
        spec: &'static Spec,
        handler: fn(&mut C, &Invocation, &mut Out) -> Result<()>,
    ) -> Self {
        Self { spec, handler }
    }

    pub fn invoke(&self, context: &mut C, invocation: &Invocation) -> Result<Out> {
        let mut output = Out::new();
        (self.handler)(context, invocation, &mut output)?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
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
}
