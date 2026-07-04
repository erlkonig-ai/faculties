= Authoring a Faculty

You now know how to *use* faculties. This is how to *add* one.
A faculty is a normal contribution to the
#link("https://github.com/triblespace/faculties")[faculties]
repo: one new `src/bin/<verb>.rs` Cargo binary, plus a schema
module for its attribute ids. Nothing else registers it — the
binary next to the others on `PATH` *is* the faculty.

== 1. Mint the schema ids first

A faculty writes facts, and every fact kind needs a stable
128-bit id — [minted once, never guessed](wiki:4e19893b36bf37d471bb9ea968edac20).
Run `trible genid` for each attribute and kind marker, then
declare them in `src/schemas/<verb>.rs`:

```rust
pub const DEFAULT_BRANCH: &str = "myverb";
pub const KIND_NOTE: Id = id_hex!("<32 hex from trible genid>");

pub mod myverb {
    use super::*;
    attributes! {
        "<hex>" as text: inlineencodings::Handle<blobencodings::LongString>;
    }
}
```

Add `pub mod myverb;` to `src/schemas/mod.rs`. Reuse a
canonical attribute where one exists — tag facts with
`metadata::tag`, don't mint a second "tag".

== 2. Write the binary

The skeleton every faculty shares:

```rust
#[derive(Parser)]
#[command(name = "myverb", about = "…")]
struct Cli {
    #[arg(long, env = "PILE")]      // honour PILE, --pile overrides
    pile: PathBuf,
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    #[command(subcommand)]
    command: Command,
}
```

`#[arg(long, env = "PILE")]` gives you the
[PILE-then-`--pile`](wiki:25e8f009e33207755109f19f7a68dff5)
precedence for free. In `main`, dispatch on the subcommand;
with no subcommand, print help (`Cli::command().print_help()`)
— a bare invocation still links the schema, so the attribute
names stay discoverable.

== 3. Own a branch, write signed commits

Each faculty owns one branch and appends there:

```rust
let mut ws = repo.pull(branch_id)?;          // your branch
let change = entity! { &ufoid() @
    metadata::tag: KIND_NOTE,
    myverb::text: body,
};
ws.commit(change, "myverb note");
repo.push(&mut ws)?;                          // durable, signed
```

The commit *is* the record — no separate "log that I did
this" step. That is [work as its own ledger](wiki:996e648886cccb61d1afd48296b0a0cb):
provenance falls out of the write.

== 4. Install, iterate, land

  - *Install*: `cargo install --path faculties --bins` — your
    verb is now on `PATH` next to the rest.
  - *Iterate*: `cargo run --manifest-path=faculties/Cargo.toml
    --bin myverb -- <args>` runs source without reinstalling.
  - *Land it*: `git commit` + push. `faculties` is a standalone
    repo we own, so commit straight to main — no PR ceremony.

Reach for this when a recurring need has no verb yet. If the
job is one-off, the [tool-selection table](wiki:f4aff48fff04f313552f5b32244f9873)
already has a home for it — grow the surface only when a real
verb is missing.

Next stop: [Substrate 1/4: What Is a Trible](wiki:4e19893b36bf37d471bb9ea968edac20).
