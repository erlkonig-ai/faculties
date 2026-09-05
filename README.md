# Faculties

An office suite for AI agents.

Faculties are small, self-contained CLI tools that give an agent a
stable workspace: a kanban board, a personal wiki, a file organizer,
a situation-awareness dashboard, direct messaging, and more. They
persist their state in a [TribleSpace](https://github.com/triblespace/triblespace-rs)
pile — typically `./self.pile` — so the agent owns its own history
across sessions.

![viewer composing activity, wiki, compass, and messages widgets](preview.png)

## Getting started

### Precompiled binaries (sandboxes, restricted envs)

Each tagged release attaches per-target tarballs containing every
faculty CLI (and the GUI viewer where it cross-compiles cleanly):

```sh
# pick the asset matching your platform — see github.com/erlkonig-ai/faculties/releases
curl -L https://github.com/erlkonig-ai/faculties/releases/latest/download/faculties-<TAG>-aarch64-apple-darwin.tar.gz \
  | tar -xz
export PATH="$PWD/faculties-<TAG>-aarch64-apple-darwin:$PATH"
```

### From source (dev environments)

Install a Rust toolchain (if you don't have one):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Faculties is developed with TribleSpace, Mary, Soma, and a small CubeCL fork as one
source cohort. Clone them as siblings, then install every faculty CLI (and the
GUI viewer) onto `$PATH`:

```sh
mkdir faculties-source && cd faculties-source
git clone https://github.com/erlkonig-ai/faculties
git clone https://github.com/triblespace/triblespace-rs
git clone https://github.com/erlkonig-ai/mary
git clone https://github.com/erlkonig-ai/soma
git clone --branch zero-copy-seam https://github.com/erlkonig-ai/cubecl cubecl-fork
git -C triblespace-rs checkout 97f85d5203930c8b7f0e07f749c5a3a37c1ef44e
git -C mary checkout ffc6fbf6647dab60da81d298067c09302a2517f4
git -C soma checkout ebbb149a3ae1c21b77b40aedfcd7a3d3ae09cd90
git -C cubecl-fork checkout 0c0972c1eb1da5e2d17cc6cc61b3f5e698e73793
cd faculties
cargo build --release --workspace --bins --locked
scripts/install-release-cohort target/release
cargo install --path ../triblespace-rs/trible --locked
```

The cohort installer publishes one content-verified, versioned generation
through `~/.local/bin`. Each generation path is write-once by the installer,
not protected by filesystem immutability or permission changes. Put that
directory before `~/.cargo/bin` on `PATH`. Do not also
run `cargo install --path . --bins`: that creates a second unmanaged Faculties
suite in `~/.cargo/bin`, where an older parser can shadow the active cohort and
misread newer pile records. The installer refuses activation when an earlier
`PATH` entry already provides one of its command names.

### Use it

Create an empty pile and add a few things:

```sh
trible pile create ./self.pile
trible pile signing-key init ./self.pile
export PILE=./self.pile

compass add "ship the demo" --status doing
wiki create "Hello" "First *typst* fragment."
viewer               # picks up PILE from the environment
```

### Reading cold blobs from peers

`message`, `orient`, `wiki`, `compass`, and ordinary `files` commands use a live
store for foreground acquisition. If an explicitly requested descriptor, fact
fragment, or selected payload is absent locally, they discover a provider
through the blob DHT and cache its bytes. Files similarity and embedding
commands retain their resident-only model/input paths for now.
Configure one or more bootstrap routes as comma-separated Iroh endpoint
tickets or endpoint IDs:

```sh
export TRIBLESPACE_PEERS='<bootstrap endpoint ticket or ID>'
message list assistant
```

These routes introduce the DHT; they are not a list of blob providers to probe
serially. A compatible running provider must hold and advertise the requested
bytes. With no bootstrap route, a fresh foreground process cannot discover
that application-level DHT merely from an Iroh relay address.

Local reads, writes, and snapshots start no network host. The first cold read
starts an ephemeral transport identity, separate from the pile signer and any
running replication daemon. The foreground client subscribes to no collection
gossip and advertises no providers. Exact blob handles remain the read
capability; acquisition neither authors a `WANT` nor follows every reference
inside a blob. `WANT` remains explicit durable delegation to another process.

Snapshot queries stay frozen: fetching a selected attachment may make its
bytes available, but cannot add concurrently arriving facts to that command's
answer. Output and publication occur outside acquisition retries. An
unavailable provider is not interpreted as empty text or an acknowledgement;
Orient wait keeps the news pending for a later poll.

This is an incremental command port, not permission to switch every deployment
to records-only repair: commands still using plain `Pile` require their
payloads to be resident. Keep those deployments' existing replication policy
until all readers they use have acquired a live boundary.

### For agent onboarding: the portable bootstrap

If you're an AI agent landing in this repo for the first time —
or setting one up — the `bootstrap` binary carries a curated onboarding
seed: 21 Wiki entries, fully cross-linked into a guided
tour (a start-here hub plus a "Next stop" spine), in four layers:

  1. **Foundations** (7) — faculty model and authoring, wiki
     authoring, compass workflow, the work-as-its-own-ledger
     principle, tool selection lookup, and the getting-started hub.
  2. **Specific faculties** (6) — files, teams, message,
     orient, relations, web — one fragment each, used when you
     reach for that faculty in practice.
  3. **Recipes and coordination** (4) — chained-faculty workflows:
     research (compass → web → files → wiki), multi-agent
     coordination (relations + message + orient + compass), harness
     hooks, and collection-policy grants plus `pile net` synchronization.
  4. **Substrate concepts** (4) — what a trible is, the pile,
     monotonic merge, and the architecture (why no faculty
     contains sync code) — Substrate 1/4 through 4/4.

Plus 7 `#bootstrap`-tagged compass goals walking through hands-on
faculty use (mint an id, create a fragment, archive a file, run
lint/check, mark a goal done with an outcome note).

Import it into the recipient's already initialized pile:

```sh
trible pile create ./self.pile
trible pile signing-key init ./self.pile
export PILE=./self.pile
bootstrap import

# Verify:
wiki list --tag bootstrap          # 21 fragments
compass list                       # 7 hands-on goals in TODO
```

The logical seed is built deterministically from the checked-in
`bootstrap/*.typ` sources. Bootstrap signs the Wiki and Compass content COMMITs
directly with the recipient's durable key into deterministic collections whose
READ and WRITE policies are rooted at that key. No release-builder signature,
authority census, branch identity, or seed private key is transplanted.
Re-running `bootstrap import` with the same key is exactly idempotent.

For each of the 21 Wiki entries, a later bootstrap generation advances only
the recognizable imported source strand. Recipient edits are never silently
superseded: they remain visible as frontier forks for explicit reconciliation.

Then start with `wiki show <id>` on the "Getting Started: Your
First Hour" fragment (tagged `start-here`) — that's the orientation
tour that points at every other piece.

The bootstrap is ordinary source: edit `bootstrap/*.typ` and the
declarative manifest in `src/bootstrap.rs`, then run
`bootstrap/build.sh`. The verifier imports into a throwaway recipient,
checks exact replay, and validates the Wiki and Compass projections.

## Why

LLM agents forget. They lose their place, repeat themselves, and can't
reliably reference what they did yesterday. Faculties give them somewhere
to put things — and, because the state lives in a content-addressed pile,
they give agents a history they can actually trust and share.

The design principle: **work is its own ledger**. Provenance and versioning
should be a side effect of using the tool, not a separate obligation. When
you move a goal to `doing`, you're not filing a status report — you're
telling the tool what to show you next, and the history falls out naturally.

## The faculties

| Faculty | Purpose |
|---|---|
| `compass` | Goal/status/priority board plus referenceable ledger notes |
| `wiki` | Personal wiki with typst fragments, links, full-text search, and a classified frontier link audit (`wiki links`) |
| `files` | File organizer backed by blob storage and tags |
| `orient` | Situation awareness and directed message/goal/note notifications |
| `atlas` | Cross-collection map of the pile's contents |
| `gauge` | Metrics and counters |
| `memory` | Long-term memory: compact history and salient fragments |
| `headspace` | Model/prompt configuration |
| `reason` | Record reasoning steps alongside actions |
| `patience` | Soft timers and pacing |
| `message` | Direct messaging between personas and humans |
| `relations` | People, affinity, contact info |
| `teams` | Microsoft Teams archive and bridge |
| `triage` | Workflow staging for inbound items |
| `archive` | Import external archives (chats, exports) into the pile |
| `web` | Web search and fetch with results recorded |

Each faculty's command surface lives under [`src/bin/`](src/bin/), while
shared schemas, collection semantics, validators, and reusable capabilities
live in the library.

## Notes on piles & collections

Every faculty reads `PILE` from the environment (via clap's native
env-var support). You can pass `--pile <path>` to override it for a
single call. Create a pile explicitly with `trible pile create new.pile`, then
initialize its durable signing key once with
`trible pile signing-key init new.pile`. Faculties publish independent signed
COMMITs into self-describing collections. A descriptor fixes the collection's
name, member encoding, and independent READ and WRITE admission policies; its
content handle is the collection identity. A snapshot admits exactly the
COMMITs whose signers satisfy that descriptor's WRITE policy using resident
capability-proof evidence. There is no ambient team, owner namespace, mutable
head, or CAS update, so independently extended pile copies converge by
concatenation, all backed by the same content-addressed blob store. Ordinary
runtime never probes historical Repository branches; the shipped migration is
an explicit re-seat between native collection-policy descriptor epochs.

Reads use maintained Succinct/Rank9 collections through immutable store
snapshots. The snapshot freezes both the stored prefix and its authorization
instant; reading it never fetches or derives missing data. A live store's
`ensure` fetches root dependencies, while `maintain_exact` carries one selected
support through each derived collection. Multi-collection readers select those
supports together and attach their query views to one final snapshot. Archive
uses this same generic collection snapshot rather than a separate decoded
catalog or COMMIT-list facade.

By default, a named faculty collection is rooted at the pile's durable signer.
An operator can instead select an already-resident exact descriptor for one
name with `TRIBLESPACE_COLLECTION_<NAME>` (64 hexadecimal digits, optionally
prefixed by `blake3:`). Hyphens become underscores, so examples are
`TRIBLESPACE_COLLECTION_WIKI` and
`TRIBLESPACE_COLLECTION_MEMORY_JOURNAL`. Each name has its own variable because
one binary may read several collections. The override changes only the
descriptor it opens: `TRIBLESPACE_KEY` remains the local COMMIT signer, and the
descriptor's resident policy and proof evidence decide admission. A missing,
malformed, wrongly typed, wrongly named, or non-writable exact descriptor is an
error before publication; Faculties never silently invents a signer-private
replacement or appends an inert COMMIT.

## GORBIE viewer

The installed `viewer` binary composes the full faculty dashboard —
activity, wiki, compass, messages, relations, archives, and
the other available panels — against a single pile. See the screenshot
above.

From a checkout:

```sh
cargo run --release --bin viewer -- ./self.pile
```

Standalone per-widget demos (showing how to embed a single widget
in your own [GORBIE] notebook) are in `examples/`: `compass_board.rs`,
`wiki_viewer.rs`, `messages_panel.rs`, `branch_timeline.rs`, and
`pile_inspector.rs` (a compact multi-widget composition example).

[GORBIE]: https://github.com/triblespace/GORBIE

## Contributing

Faculties are deliberately small at the command boundary. If you find yourself
adding abstraction layers, stop and ask whether the feature belongs in the
faculty at all or whether it would be better as a separate tool. Keep each
`src/bin/<name>.rs` a legible CLI over the shared semantic library rather than
duplicating storage or validation logic inside binaries.

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option.
