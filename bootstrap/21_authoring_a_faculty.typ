= Authoring a Faculty

You now know how to *use* faculties. This is how to *add* one. A faculty is a
normal contribution to the
#link("https://github.com/erlkonig-ai/faculties")[faculties] repo: a thin
`src/bin/<verb>.rs` CLI, reusable domain construction and validation in a
library module, and a schema module when it introduces attributes. Nothing else
registers the command—the binary next to the others on `PATH` is its shell
surface.

== 1. Mint the schema ids first

A faculty writes facts, and every fact kind needs a stable
128-bit id — [minted once, never guessed](wiki:4e19893b36bf37d471bb9ea968edac20).
Run `trible genid` for each attribute and kind marker, then
declare them in `src/schemas/<verb>.rs`:

```rust
pub const DEFAULT_SCOPE_ID: Id = id_hex!("<32 hex from trible genid>");
pub const KIND_NOTE: Id = id_hex!("<32 hex from trible genid>");

pub mod myverb {
    use super::*;
    attributes! {
        "<hex>" as text: inlineencodings::Handle<blobencodings::UTF8String>;
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
    #[arg(long, env = "TRIBLESPACE_KEY")]
    key: Option<PathBuf>,            // existing durable signer; never mint here
    #[command(subcommand)]
    command: Option<Command>,
}
```

`#[arg(long, env = "PILE")]` gives you the
[PILE-then-`--pile`](wiki:25e8f009e33207755109f19f7a68dff5)
precedence for free. In `main`, dispatch on the subcommand;
with no subcommand, print help (`Cli::command().print_help()`)
so discovery remains useful without performing a write.

== 3. Publish through explicit collection boundaries

A simple faculty often has one fixed collection scope and publishes
self-contained fragments through the destination pile's existing durable
signer. This is the minimal shape:

```rust
let signer = load_signer(&cli.pile, cli.key.as_deref())?;
let mut pile = open_pile_strict(&cli.pile)?;
let collection = faculties::collection_names::open(
    &mut pile,
    DEFAULT_SCOPE_ID,
    signer.verifying_key(),
)?;

let mut change = Fragment::empty();
let body = change.put::<UTF8String, _>(body);
change += entity! {
    metadata::tag: &KIND_NOTE,
    myverb::text: body,
};
pile.commit(collection, &signer, change)?;
pile.close()?;
```

`collection_names::open` registers the canonical self-describing descriptor
and returns its content handle. The authority is mandatory descriptor data and
therefore already part of that handle; `snapshot` and `commit` need no separate
authority argument. `CollectionStoreExt::commit` and the explicit close are
substrate APIs. The typed constructor makes one self-contained fragment: its
intrinsic identity, facts, and attachment bytes travel together. Strict readers
validate the materialized domain model and payload closure; migrations validate
untrusted source data. Ordinary writes should not rescan the complete current
union merely to distrust the same constructor that just produced their
fragment. Add a pre-publication check only for a genuine cross-fragment
compatibility invariant.

Local publication is unconditional: the signer curates a fragment into its
local store. Authority is enforced when a snapshot or sync boundary decides
which resident commits contribute to the collection. The descriptor authority
is admitted directly; another signer needs an exact WRITE proof for this
collection. An ordinary faculty command never manufactures authority merely
because it attempted a write.

The fragment carries its facts, metadata, and attachment closure together. The
COMMIT *is* the curation record—no separate "log that I did this" step. Its
signer publishes the artifact but need not be the person named as its author.
An exact retry converges by content identity; distinct COMMITs coexist without
a branch head or compare-and-swap loop. That is
[work as its own ledger](wiki:996e648886cccb61d1afd48296b0a0cb): provenance
falls out of the write.

The scope follows semantic ownership, not binary count. A read-only faculty may
own no collection; a compound faculty may read or publish several fixed
collections. There is no staged atomic publication across those collections.
Construct every fragment first, publish in dependency-safe order, and make an
idempotent rerun finish any missing COMMITs after interruption. Never add a
caller-selected scope merely to make the CLI generic.

== 4. Install, iterate, land

  - *Install*: run `cargo build --manifest-path=faculties/Cargo.toml --release
    --workspace --bins --locked`, then
    `faculties/scripts/install-release-cohort faculties/target/release` so the
    complete binary cohort is activated atomically.
  - *Iterate*: `cargo run --manifest-path=faculties/Cargo.toml
    --bin myverb -- <args>` runs source without reinstalling.
  - *Land it*: `git commit` + push. `faculties` is a standalone
    repo we own, so commit straight to main — no PR ceremony.

Reach for this when a recurring need has no verb yet. If the
job is one-off, the [tool-selection table](wiki:f4aff48fff04f313552f5b32244f9873)
already has a home for it — grow the surface only when a real
verb is missing.

Next stop: [Substrate 1/4: What Is a Trible](wiki:4e19893b36bf37d471bb9ea968edac20).
