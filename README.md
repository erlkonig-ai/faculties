# Faculties

An office suite for AI agents.

Faculties are small, self-contained CLI tools that give an agent a
stable workspace: a kanban board, a personal wiki, a file organizer,
a situation-awareness dashboard, direct messaging, and more. They
persist their state in a [TribleSpace](https://github.com/triblespace/triblespace-rs)
pile — typically `./self.pile` — so the agent owns its own history
across sessions.

![faculties-viewer composing activity, wiki, compass, and messages widgets](preview.png)

## Getting started

### Precompiled binaries (sandboxes, restricted envs)

Each tagged release attaches per-target tarballs containing every
faculty CLI (and the GUI viewer where it cross-compiles cleanly):

```sh
# pick the asset matching your platform — see github.com/triblespace/faculties/releases
curl -L https://github.com/triblespace/faculties/releases/latest/download/faculties-<TAG>-aarch64-apple-darwin.tar.gz \
  | tar -xz
export PATH="$PWD/faculties-<TAG>-aarch64-apple-darwin:$PATH"
```

### From source (dev environments)

Install a Rust toolchain (if you don't have one):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install all faculty CLIs (and the GUI viewer) onto `$PATH`:

```sh
cargo install --git https://github.com/triblespace/faculties --bins
cargo install --git https://github.com/triblespace/faculties --features widgets --bin faculties-viewer
```

Or from a local checkout:

```sh
git clone https://github.com/triblespace/faculties
cd faculties
cargo install --path . --bins
cargo install --path . --features widgets --bin faculties-viewer
```

### Use it

Create an empty pile and add a few things:

```sh
touch ./self.pile
export PILE=./self.pile

compass add "ship the demo" --status doing
wiki create "Hello" "First *typst* fragment."
faculties-viewer               # picks up PILE from the environment
```

### For agent onboarding: the bootstrap pile

If you're an AI agent landing in this repo for the first time —
or setting one up — `bootstrap.pile` ships a curated onboarding
substrate: 19 wiki fragments, fully cross-linked into a guided
tour (a start-here hub plus a "Next stop" spine), in four layers:

  1. **Foundations** (6) — faculty model, wiki authoring,
     compass workflow, the work-as-its-own-ledger principle,
     tool selection lookup, and the getting-started hub.
  2. **Specific faculties** (6) — files, teams, local_messages,
     orient, relations, web — one fragment each, used when you
     reach for that faculty in practice.
  3. **Recipes** (3) — chained-faculty workflows: research
     (compass → web → files → wiki), multi-agent coordination
     (relations + local_messages + orient + compass), and team
     auth setup (`trible team` + `pile net`).
  4. **Substrate concepts** (4) — what a trible is, the pile,
     monotonic merge, and the architecture (why no faculty
     contains sync code) — Substrate 1/4 through 4/4.

Plus 6 `#bootstrap`-tagged compass goals walking through hands-on
faculty use (mint an id, create a fragment, archive a file, run
lint/check, mark a goal done with an outcome note).

Use it as the **basis** of a fresh agent's pile — release
tarballs ship it right next to the binaries:

```sh
cp bootstrap.pile ./self.pile
export PILE=./self.pile

# Verify:
wiki list --tag bootstrap          # 19 fragments
compass list                       # 6 hands-on goals in TODO
```

(To add the tour to an *existing* pile instead, append it:
`cat bootstrap.pile >> ./self.pile` — piles merge by
concatenation.)

Then start with `wiki show <id>` on the "Getting Started: Your
First Hour" fragment (tagged `start-here`) — that's the orientation
tour that points at every other piece.

The bootstrap pile is regenerable: edit `bootstrap/*.typ` sources
and re-run `bootstrap/build.sh`. The build script's sanity-check
phase asserts the expected fragment + goal counts, so silent
breakage gets caught at rebuild time. Goals can be added or
retired without invalidating prior agents' inherited state, since
piles are append-only and merge cleanly.

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
| `compass` | Kanban goal/task board with status, tags, notes, priorities |
| `wiki` | Personal wiki with typst fragments, links, and full-text search |
| `files` | File organizer backed by blob storage and tags |
| `orient` | Situation awareness dashboard — what's happening right now |
| `atlas` | Cross-branch map of the pile's contents |
| `gauge` | Metrics and counters |
| `memory` | Long-term memory: compact history and salient fragments |
| `headspace` | Model/prompt configuration |
| `reason` | Record reasoning steps alongside actions |
| `patience` | Soft timers and pacing |
| `local_messages` | Direct messaging between personas and humans |
| `relations` | People, affinity, contact info |
| `teams` | Microsoft Teams archive and bridge |
| `triage` | Workflow staging for inbound items |
| `archive` | Import external archives (chats, exports) into the pile |
| `web` | Web search and fetch with results recorded |

Each faculty's source is a single file under [`src/bin/`](src/bin/) —
copy one out and tweak it as a starting point for your own.

## Notes on pile & branches

Every faculty reads `PILE` from the environment (via clap's native
env-var support). You can pass `--pile <path>` to override it for a
single call. A pile is an append-only file — `touch new.pile` is
literally the whole seed. Faculties operate on named branches of
the pile and are designed to coexist; multiple faculties on the
same pile each own their own branch, all rooted in the same
content-addressed blob store.

## GORBIE viewer

The installed `faculties-viewer` binary composes all four widgets
(activity timeline, wiki graph, compass kanban, local-messages
thread) against a single pile — see the screenshot above.

From a checkout:

```sh
cargo run --release --features widgets --bin faculties-viewer -- ./self.pile
```

Standalone per-widget demos (showing how to embed a single widget
in your own [GORBIE] notebook) are in `examples/`: `compass_board.rs`,
`wiki_viewer.rs`, `messages_panel.rs`, `branch_timeline.rs`, and
`pile_inspector.rs` (source for the binary above).

[GORBIE]: https://github.com/triblespace/GORBIE

## Contributing

Faculties are deliberately simple. If you find yourself adding abstraction
layers, stop and ask whether the feature belongs in the faculty at all or
whether it would be better as a separate tool. Each `src/bin/<name>.rs`
should stand alone — you should be able to copy a faculty out into an
unrelated crate and have it work with the same union of root deps.

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE),
at your option.
