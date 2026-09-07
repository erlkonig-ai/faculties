//! Atlas's CLI grammar and text projection. Rust callers use [`super::Store`]
//! directly; MCP has its own typed argument boundary in [`super::mcp`].

use anyhow::{bail, Result};

use super::{render, Store};
use crate::out::Out;
use crate::spec::{Invocation, Param, Spec, Verb};

pub static SPEC: Spec = Spec {
    name: "atlas",
    about: "Schema metadata inspection faculty",
    version: Some(crate::GIT_VERSION),
    shared: &[
        Param::caller("pile", "Path to the pile file to use")
            .path()
            .ambient()
            .env("PILE"),
        Param::caller(
            "key",
            "Existing durable signing-key file. Reads and writes never create it.",
        )
        .path()
        .ambient()
        .optional()
        .env("TRIBLESPACE_KEY"),
    ],
    verbs: &[
        Verb {
            name: "list",
            about: "List entities that have metadata::name entries",
            params: &[],
        },
        Verb {
            name: "show",
            about: "Show metadata for a single id prefix",
            params: &[Param::caller("id", "Entity id or unique prefix").positional()],
        },
    ],
};

/// Execute a parsed CLI request. Output routing belongs to `crate::cli`.
pub fn execute(invocation: &Invocation, output: &mut Out<'_>) -> Result<()> {
    let mut store = Store::open(invocation.require_path("pile")?, invocation.path("key"))?;
    let result = (|| {
        match invocation.verb().name {
            "list" => {
                for row in store.list()? {
                    output.line(render::list_line(&row))?;
                }
            }
            "show" => {
                for line in render::show_lines(&store.show(invocation.require("id")?)?) {
                    output.line(line)?;
                }
            }
            other => bail!("Atlas CLI has no verb {other:?}"),
        }
        Ok(())
    })();
    store.finish(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_retains_the_atlas_surface() {
        let command = SPEC.to_clap();
        assert_eq!(command.get_version(), Some(crate::GIT_VERSION));
        assert_eq!(
            command
                .get_subcommands()
                .map(|command| command.get_name())
                .collect::<Vec<_>>(),
            ["list", "show"]
        );
        for forbidden in ["scope", "branch", "branch_id", "head", "repair"] {
            assert!(!command
                .get_arguments()
                .any(|argument| argument.get_id() == forbidden));
        }
        assert!(command
            .get_arguments()
            .any(|argument| argument.get_id() == "key"));
    }
}
