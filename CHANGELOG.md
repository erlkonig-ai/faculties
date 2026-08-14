# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- **Archive accelerators now use TribleSpace's native exact-ticket kernel.**
  Raw Succinct delegates directly to the canonical collection algebra without
  eagerly publishing unused Rank9 fibers. Archive BM25 supplies only its five
  attachment-aware algebra operations, while the shared kernel owns frozen
  ticket admission, overlap-aware physical covers, residual publication, and
  explicit dyadic target compaction. Complete retries remain write-free even
  when descriptor blobs were collected, no path adds a durability flush, and
  the now-unused Faculties `gpu-succinct` policy feature is removed.
- **Retired the unused branch-era persisted HNSW API.** The public
  `embedding_rollup`, `refresh_index`, and `nearest_via_index` helpers and their
  mutable-head tests are removed. Live Files, Wiki, and Memory similarity uses
  the in-memory `nearest` core; it now preserves distinct entities with
  byte-identical vectors and orders equal-score results canonically. A future
  persisted accelerator belongs in the collection `DERIVE`/`MERGE` algebra.
- **Onboarding is now a recipient-authored, portable bootstrap.** The
  `bootstrap import` command deterministically builds the curated Wiki and
  Compass seed under the destination pile's durable signer, validates both
  attachment closures before publication, and replays without appending.
  Release archives no longer carry a builder-signed `bootstrap.pile`.
- **Orient derives attention from Relations groups and explicit presence.**
  New goals and notes wake a persona when tagged with that person or any group
  containing it; forked group heads are conservatively unioned for this
  read-only projection so unrelated concurrent edits cannot disable watchers.
  The status roster now contains exactly the windows that have published a
  status, without a magic affinity or globally privileged tag. Codex hook
  helpers are persona-configurable, recognize the faculty's CLI/environment
  forms, canonicalize the pile path, and only reap provably orphaned watchers.
- **Wiki migration preserves deterministic-era reassertions.** Legacy version
  identities can carry several exact `created_at` observations because the old
  writer reasserted identical content with a fresh timestamp. The native read
  model retains and validates the complete set, while lineage positions each
  distinct state by its latest observation so `A -> B -> A` reverts keep `A`
  current. Every derived supersedes edge is owned by an authored source commit
  carrying that selected observation.
- **Archive full-text search is live on the descriptor-handle V4 algebra.**
  The frozen block-text recipe maps admitted SimpleArchive lattice elements
  into canonical portable exact-TF BM25 elements; byte-exact `DERIVE` and
  pointwise-maximum `MERGE` validators admit leaf-wise, merge-before-derive,
  or mixed resident covers without a branch, manifest, registry, timestamp
  winner, or legacy index trust. The `archive index` and `archive search`
  commands now build and query that cover. Recipe identity freezes the selected
  graph, occurrence aggregation / exact-TF law, tokenizer, and document/term
  schemas; derived `k1` / `b` query scoring policy is intentionally outside it.
  Archive reads bind facts, the exact authorized source commits, and their
  validating blob reader through one coherent collection snapshot; a split
  source without either complete leaf derivations or an admitted merge route
  fails before any index record is appended.
- **Viewer projections now preserve native ambiguity instead of inventing
  winners.** Files validates exact scalar records and uses neutral digest names
  for shared content; Atlas renders every metadata variant; Triage reduces
  causal attempt slots into disjoint current states while retaining historical
  forks and re-deriving staleness from wall time. Capture binaries load only
  their transitive semantic source closure, so malformed unrelated collections
  no longer prevent a focused capture.
- **The generic viewer and capture harnesses now consume immutable native
  collection snapshots.** A fixed catalog materializes descriptor-handle V4
  collections under the pile's durable signer and exposes keyed `DatasetView`
  values to reusable widgets without Repository branches, mutable Workspace
  heads, compatibility fallbacks, or read-side writes. Shared collections are
  loaded once and reused across semantic views. This is the shared storage
  cutover, not domain-renderer parity: legacy-shaped widget projections remain
  on independent semantic-port lanes, and Headspace remains on its independent
  native-cutover lane.
- **Headspace is now a fork-visible native configuration algebra.** One fixed
  collection holds complete intrinsic config snapshots and per-profile
  snapshot DAGs; concurrent equal values agree without losing provenance,
  divergent heads remain visible, and reconciliation supersedes every live
  head explicitly. Runtime credentials are exact immutable Secrets-version
  references rather than plaintext or latest-by-label lookups. The additive
  cutover keeps every legacy fact, identity, metafact, resident attachment,
  authored-empty commit, and merge lineage, while copied plaintext rows remain
  semantically inert until native state is deliberately bootstrapped.
- **Web now records observations in one fixed native collection and resolves
  credentials by exact identity.** Search and fetch commands commit complete
  intrinsic fragments directly, with no branch, head, CAS, ephemeral signer,
  or public scope selector. Tavily and Exa credentials come from the settled
  Headspace state as exact immutable Secrets-version references (unless the
  caller explicitly overrides them), never from plaintext config rows or a
  latest-by-label lookup. The stopped-world migration preserves every legacy
  fact, identity, metafact, resident attachment, and authored-empty commit
  exactly while retaining the old branch as inert evidence.
- **Triage is now a read-only diagnosis over fixed native collections.** One
  durable signer and one opened pile prefix feed the current Cognition,
  Headspace, Secrets, Memory, Relations, and Message validators; legacy
  branches, caller-selected heads/scopes, CAS repair, and timestamp winners
  cannot influence the view. Headspace forks and missing exact credential
  versions remain visible, and inspection never appends. Triage owns no data
  branch to migrate: the historical `cognition` branch belongs to the shared
  Cognition stopped-world migration, while any same-named legacy branch is
  inert to this reader.
- **Discord now records immutable observations and bounded coverage in one
  fixed native collection.** Message semantics ignore volatile delivery URLs
  and profile decoration, edits remain explicit observations, and interval
  receipts close pagination gaps without a mutable cursor. Credentials stay
  external. The stopped-world migration preserves old facts, identities,
  semantic metadata, resident closure, and authored-empty commits exactly,
  while every migrated token, cursor, and log row remains inert evidence.
- **Mail is now an immutable multi-collection evidence and intent ledger.**
  Accounts reference exact immutable Secrets versions; POP observations,
  parser projections, drafts, authorization attempts, SMTP acceptances, and
  reads are self-contained native records under fixed collection identities.
  POP commits before deletion, SMTP keeps its affine external-effect boundary
  explicit, and stopped-world migration preserves all historical facts,
  identities, semantic metadata, resident blobs, and authored-empty commits
  additively. Orient renders the native inbox and watches unread, non-spam
  `WireMessage` identities, so a new inbound wire wakes once while duplicate
  source observations, outgoing mail, and read-state removal stay quiet.
- **Atlas now reads one fixed native schema-metadata collection.** The CLI has
  no branch, head, CAS, repair, or public scope selector; it materializes the
  durable signer-owned descriptor directly and keeps attachment reads within
  the same pile lifetime. Its stopped-world migration preserves every legacy
  fact, entity id, semantic metafact, resident attachment, and authored-empty
  commit exactly, while contentless merges remain verified ancestry and the
  old pin remains inert evidence.
- **Cognition has a fixed descriptor-handle collection lane.** Reason and
  Patience now publish one validated, self-contained intrinsic event per
  signed commit under the shared durable Cognition identity, with no runtime
  repository, branch, head, CAS, or scope selector. A whole-dataset
  stopped-world migration preserves exact legacy facts, entity IDs, semantic
  metafacts, resident attachments, authored-empty commits, and the old pin.
  Triage now shares the canonical Cognition reducer with its viewer, and the
  Drive collection consumer is frozen on its own integration-ready branch.
- **Voice now has one fixed native collection and an explicit live boundary.**
  Route generations and utterances are complete intrinsic records committed
  under the durable pile signer, with no branch, CAS, ephemeral signer, or
  public scope knob. Hardware probing, synthesis, and playback remain outside
  the collection algebra. Its stopped-world migration validates the exact
  legacy Voice and Body pins, then reconstructs their historical speech under
  the current intrinsic identity and live marker. The rewrite uses the same
  native transaction boundary as live writes: source batches split into single
  utterances, per-device route commits coalesce into complete generations,
  authored-empty Voice commits remain fact-empty with exact source-coordinate
  provenance, and unrelated Body deltas do not manufacture Voice authority.
- **Secrets is a fixed native collection with reusable envelope semantics.**
  The capability algebra, strict catalog, attachment validation, and envelope
  operations live in `faculties-secrets`; the CLI loads one durable signer,
  opens the pile once per command, and commits one self-contained `Fragment`
  without Repository branches, CAS, signer rosters, or scope knobs. Its bounded
  stopped-world migration preserves canonical Secrets identities, facts,
  authored partitions, semantic metadata, attachment closure, and
  authored-empty commits. It separately validates and retires the exact
  historical Mail account/pointer shape found on the old Secrets branch, while
  retaining that branch as inert source evidence.
- **Decisions are collection-native and preserve concurrent resolution.** A
  stable decision anchor has one immutable intrinsic genesis, while factors are
  additive occurrence records and resolutions form intrinsic predecessor DAGs.
  Reads expose missing, unique, semantically agreed, forked, and invalid states
  without timestamp arbitration. Every non-forced resolution freezes the exact
  same-decision pro and con evidence it used; forcedness is an explicit bit,
  and agreement quotients heads only by outcome plus forcedness while retaining
  distinct evidence and history. Publication validates the exact ontology,
  attachments, closed acyclic history, and all-head reconciliation.
- **The reusable Secrets core loads its root password without exporting it to
  every child process.** `FACULTIES_SECRETS_PW` remains the first source, then
  `FACULTIES_SECRETS_PW_FILE` or the XDG configuration path is read on demand.
  Group- or world-readable files are refused and editor line endings are
  stripped. The Secrets CLI consumes this shared capability instead of owning
  another password loader.
- **Posture now runs on two fixed native collections.** Policy and scan
  fragments are committed through descriptor-handle V4 `Collection` records
  under one durable signer, with no live repository, branch, head, or CAS
  path. Scan, finding-occurrence, and decision-target identities are semantic
  and deterministic; PDF/OOXML/EXIF extraction and git auditing remain intact,
  and git hits now become durable findings whose exact occurrence IDs can be
  classified benign by resolved Decide decisions across scans. Git occurrence
  coordinates canonicalize the physical repository root and retain the full
  object ID plus per-occurrence position; hashes are abbreviated only when
  rendered. The stopped-world legacy policy migration is
  strictly additive, preserves exact authored facts, attachments, metadata,
  empty commits, and the old pin, and adds only canonical intrinsic shadows.
- **Archive and memory search attributes follow the exact-TF BM25 format.**
  Both typed index attributes have fresh IDs for the breaking
  `SuccinctBM25Blob` layout. Retired score-index facts remain inert; the normal
  `archive index` / `memory index` refresh paths rebuild under the new schema.
- **Status now runs directly on its native collection.** Immutable intrinsic
  events are published under one fixed scope with the durable pile signer;
  reads validate the complete event ontology and attachments, join labels from
  the native Relations collection, and choose current status by the canonical
  maximum `(point timestamp, event id)`. The stopped-world transform rewrites
  legacy random event IDs, collapses exact duplicate tuples, preserves commit
  metadata and resident payloads, and leaves the old branch untouched.
- **The shared Status board accepts a native read model.** Its narrow native
  source loads one durable signer, keeps one pile open, and delegates event
  arbitration to the Status API; the standalone capture is again only a tiny
  harness around that shared renderer. It no longer pulls or pushes a legacy
  branch merely to render a frame.
- **Body now runs directly on its native collection.** Deliberate captures and
  intents are immutable `Fragment` commits in the fixed Body scope, signed by
  the pile's durable key; live branch/head/CAS and ephemeral signing identities
  are gone. Reads materialize the signer-owned collection, and equal-time
  intents select the greater intrinsic event ID deterministically. A separate
  stopped-world migration preserves every legacy fact, entity ID, attachment,
  and semantic commit metafact without removing the old pin or enabling a dual
  runtime.
- **Files now runs directly on its native collection.** Read commands load the
  durable signer and materialize one immutable signer-owned view; append-only
  commands publish self-contained `Fragment` commits without reconstructing
  existing history, and dry runs touch no persistence. Runtime branch/head/CAS
  vocabulary is gone. The shared file constructor owns all three referenced
  blobs inside its returned fragment, including for Mail, Teams, and Discord
  callers.
- **Files has a strictly additive native-collection migration.** The
  stopped-world planner preserves every legacy fact and entity ID, derives
  only missing canonical media-type facts, and publishes authored commits
  through collection commits without target pins or compare-and-swap state.
- **Native collection publication has a central, pinless seam.** Faculties can
  discover scoped targets through `CollectionStore` and publish complete
  `Fragment` values through `Collection<Pile>::commit`, preserving facts,
  metafacts, and their shared attachments without a target head or CAS cell.
  Stopped-world migrations get a read-only frozen legacy-pin snapshot whose
  semantic fingerprint ignores physical pile history.
- **LinkedIn imports now speak the Relations collection algebra directly.**
  Each command reads and exactly validates one immutable Relations snapshot,
  plans the complete import in memory, and publishes one signed fragment
  through the durable commit-last path. Canonical profile URLs (or email as a
  fallback) derive stable person anchors; name-only rows honestly mint fresh
  anchors. Input rows first close as a set under shared canonical keys, settled
  same-person components are enriched together, repeated stable-key imports are
  true no-ops, and conflicting or unsettled evidence fails closed. Same-name
  review is derived from current labels and aliases plus the existing
  fork-visible verdict DAG rather than persisted as a second ontology. Dry runs
  perform the same union validation without writing, and the legacy
  repository/branch plus ephemeral-signer path is gone.
- **The nomic embedder's tokenizer loads from a native tokenizer GRAPH.**
  `load_text_embedder` constructs the `tokenizers::Tokenizer` directly from
  the tokenizer graph in the text model pile
  (`mary::persist::load_tokenizer_from_pile` → the `tokenizers` builders) —
  no tokenizer.json parse, no temp-file materialization, no network at
  runtime. The json blob import (`memory import-tokenizer`) is retained for
  provenance and now also builds the graph; the new `memory ingest-tokenizer`
  upgrades a blob-only pile in place (append-only, idempotent). Piles without
  a graph fall back to the blob with a stderr warning. Requires mary ≥
  8e0f023 (tokenizer-graph merge).
- **Compass is workflow-neutral again.** The never-released structured review
  gate has been removed wholesale: no review status coupling, request,
  attestation, verdict, settlement, override, watermark, or dedicated review
  panel remains. Compass once again accepts arbitrary status names and presents
  `todo`, `doing`, `blocked`, and `done` as its four defaults. Ordinary notes
  may now carry the same optional `$PERSONA` attribution as status events.
  Historical unknown facts remain preserved by the append-only pile.
- **Compass notes are addressable ledger records.** Note creation and `show`
  expose stable note IDs; repeatable tags, opaque exact references, and
  displayed `metadata::supersedes` edges add composable provenance without
  hiding history or creating workflow. Inline `faculty:hex` links materialize
  references as exhaust. Orient wakes once for newly visible foreign or
  unattributed notes on relevant goals (or directly tagged notes), keeps own
  notes quiet, upgrades legacy checkpoints without a flood, and unions seen
  note-ID deltas across persona checkpoints. This prevents later replay after
  divergent checkpoints are committed without claiming a simultaneous
  exactly-once delivery lock, and keeps persisted note history linear.
- **Codex can enforce orient-watcher continuity and ingest news while busy.**
  Versioned SessionStart, UserPromptSubmit, and Stop hook helpers under
  `hooks/codex/` report the configured persona watcher to each new primary
  thread, clear only provably orphaned invisible consumers, inject
  non-consuming `orient poll --peek` news at prompt boundaries, and require one
  rearm attempt before a turn can idle.
- **Group broadcasts are first-class inbox messages.** `message list` and
  `orient show` now include messages addressed to any group the reader belongs
  to, matching `orient wait` wakeups and keeping read acknowledgements scoped
  to the individual reader.
- **Widgets are enabled by default.** A stock `cargo build`, `cargo test`, or
  `cargo install --bins` now includes the GORBIE viewer/capture surface, so the
  shipped widget examples compile in the default configuration. Use
  `--no-default-features` for a CLI-only build.
- **Archive search indexes are commit-native, resumable LSM forests.** Each
  source commit becomes one logical Succinct + BM25 leaf (large commits may be
  physically sharded), and both manifests carry an atomic coverage certificate.
  Live writes maintain both indexes in the same branch repoint; an unhooked
  writer makes search fail stale instead of silently omitting messages.
  `archive index` now walks uncovered commit metadata parents-first, checkpoints
  after each commit, resumes after interruption, and is a true no-op once both
  indexes cover the archive HEAD. It discards uncertified legacy forests and
  rebuilds certified manifests whose segment blobs are unreadable. Search
  validates BM25 + Succinct coverage from one branch-head snapshot before any
  attachment and reads the succinct segments only when lexical hits need
  materialising; the legacy monolithic rollup is no longer rebuilt or consulted.
- **Archive list and search are indexed-only reads.** `archive list` now
  validates and attaches the branch-head Succinct manifest instead of checking
  out the entire raw archive, k-way merges each segment's reverse
  `created_at` AVE cursor, and stops after validating `--limit` complete
  messages. Author/content blobs are fetched only for those winners. Missing
  or stale coverage fails with an `archive index` repair hint. The
  archive-scale substring `search --exact` / `--case-sensitive` escape hatch
  is removed; search never silently or explicitly falls back to a full
  checkout.
- **Archive and memory BM25 search can retrieve standalone Unicode
  symbols.** The shared tokenizer now indexes non-ASCII symbol graphemes,
  so queries such as emoji take the normal indexed path instead of yielding
  no terms (or forcing a full exact scan). Run `archive index` / `memory
  index` once to add symbol postings to an existing pile.
- **`faculties-viewer` renamed to `viewer`.** Binary, `[[bin]]`
  target, and docs all follow; `--version` now prints
  `viewer X.Y.Z (<git hash>)`. No compat alias.
## 0.20.2 — 2026-06-10

- **Re-bundle `trible` CLI at 0.46.4** — publisher-first sync fix
  (closure walks no longer stall on unreachable DHT; the announcing
  peer is used directly), validated by the new deterministic sim
  suite upstream. This is the release that makes multi-peer sync
  work out of the tarball.
- **wiki: deterministic version + tag ids** — version ids minted from
  (fragment, title, content); tag ids content-derived from the
  lowercased name. Identical content converges across piles on merge
  instead of forking. `create --id <hex>` for pre-minted stable
  fragment ids; `--force` tolerates dangling links at write time.
- **bootstrap pile: fully-linked tour** — stable fragment ids, hub +
  next-stop navigation spine (0 orphans), new "Substrate 4/4: The
  Architecture — Zero Sync Code" fragment, substrate trio numbering
  1/4..4/4, codex fragment dropped (provider-specific advice removed
  from a provider-agnostic pile).
- **orient: per-process persona** — `--persona <label-or-hex>` /
  `$PERSONA` env; the pile-config persona path is removed (multiple
  agents share one pile but must not share one identity).
- **faculties-viewer**: widgets for every data-bearing faculty,
  reason+archive in the activity timeline, live NOW markers,
  sections start collapsed (headless captures force-open),
  `--pile` flag precedence: --pile > positional > PILE env > default.
- **mail/decide: i128::MIN negation overflow fixed** in sort keys.
- **GORBIE dependency: 0.18.1 from crates.io** — the temporary
  [patch.crates-io] path override is removed; `cargo install --git`
  works from any clone again.

## 0.20.1 — 2026-06-10

- **Re-bundle `trible` CLI at 0.46.3** (release tarballs pull latest
  from crates.io at build time). The v0.20.0 tarballs shipped trible
  0.46.0, which predates two join-handshake fixes:
  - CapDeliveryConfirmed lookup matches by sig handle, not cap
    handle (0.46.1) — `team request-join` confirmation no longer
    misses.
  - `team approve` + remaining team subcommands route through
    `with_pile` so `close()` runs on every exit path (0.46.3).
  No faculty-side code changes.
- **wiki: unknown tag in `list --tag` matches zero fragments**
  instead of silently degrading to an unfiltered listing. Same for
  `--with-backlink-tag`; unknown tags in `--without-backlink-tag`
  still correctly exclude nothing.
- **bootstrap: substrate-concepts trio** — three new onboarding
  fragments (Substrate 1/3 tribles, 2/3 pile, 3/3 monotonic merge)
  covering the "why does this work" layer behind the workflow
  fragments. Indexed from Getting Started; fragment count 16 → 19.

## 0.20.0 — 2026-06-05

- **Bump `triblespace` 0.45 → 0.46 and `GORBIE` 0.17 → 0.18.**
  Picks up the new `PinSnapshot` type and `PinStore::pin_snapshot()`
  trait method in triblespace-core (cheap O(refcount-bump)
  snapshot of the pin → head map via the Pile's internal PATCH),
  the snapshot-first publish ordering in triblespace-net (closes
  a race where a peer dialing in after a gossip hit a stale
  serving snapshot and got "out of scope" denials), and the
  OP_DELIVER_CAP swarm-fetch + dialer-equals-issuer verify path.
  No faculty-side code changes required.

## 0.19.0 — 2026-06-03

- **Bump `triblespace` 0.44 → 0.45 and `GORBIE` 0.16 → 0.17.**
  Picks up the PATCH `LocalLeaf` archive-leaf elimination in
  triblespace 0.45 (~47% memory savings on `SimpleArchive` ingest,
  archive ingest now at parity with or faster than the heap path
  at every scale tested), the `team revoke` removal (eviction is
  per-issuer non-renewal via `team retract`), and the GORBIE
  web-export proc macro for static-bundle notebook builds.
- **Widget batch.** New `atlas` (schema-catalog browser),
  `triage` (agent-activity diagnostic dashboard), `files` widget
  (import-history view), `gauge` (research-health dashboard),
  `memory` widget (recent-chunks viewer), `headspace`,
  `planner` (with now-line / full-width header polish),
  `discord` and `teams` widgets, plus `reason` and `archive`
  rendering in the timeline.
- **New `messages-capture` bin** for ingesting message streams.

## 0.18.0 — 2026-06-01

- **Loose-couple memory chunk provenance.** `memory create` no longer
  scans the cognition / archive branches and writes `about_exec_result`
  / `about_archive_message` references at chunk-write time. Provenance
  is now recovered by *temporal overlap* at read-time via the new
  `memory provenance <chunk-id>` subcommand, which lists every cognition
  exec result and archive message whose timestamps fall within the
  chunk's `[start_at, end_at]` interval. This means a chunk written
  before its source data is imported (e.g. a reflective summary written
  in one environment, with the matching .claude/chatgpt-data-dump
  imported later) automatically picks up its provenance when the data
  lands — no rewrite pass needed. The `ctx::about_exec_result` and
  `ctx::about_archive_message` attribute IDs remain declared in the
  schema so older chunks stay queryable and downstream consumers
  (`triage` etc.) keep working on legacy data.

## 0.17.0 — 2026-05-31

- **Bump `triblespace` 0.43 → 0.44 and `GORBIE` 0.15 → 0.16.**
  Picks up the descriptive-capabilities substrate in
  `triblespace-net` (cap blobs + chain proofs in sig blobs +
  `/triblespace/auth-handshake/1` ALPN + renewal daemon),
  the `BranchStore → PinStore` rename (Branch is now a
  specialization of Pin), `Repository::new` taking
  `F: Into<Fragment>`, and the engine improvements
  (NotAttr, full same-Variable handling, RegularPathConstraint
  symmetric end-bound proposal, path! infix `?`/`!`/`^`).
- **`triage`**: switch from `pile.branches()` to `pile.pins()`
  for the listing iterator; no behavioural change since the
  named-branch filtering happens downstream.

## 0.14.8 — 2026-05-17

- **Bump `triblespace` 0.41.3 → 0.41.4.** Two follow-on fixes
  surfaced by the first end-to-end sandbox-to-laptop sync:
  - **Trailing-dot leak through `ep.addr()`** — 0.14.7
    stripped dots from the outbound RelayMap but iroh's own
    `Endpoint::addr()` could still report the dotted form
    in our tickets. Outbound tickets are now dot-free; the
    `parse_peers` and `pile net pull <REMOTE>` paths also
    normalise inbound tickets so peers running unpatched
    builds get cleaned up at the receiving end.
  - **Connection reuse in `fetch_reachable`** — previously
    a BFS over a remote pile opened one ~600ms-auth
    connection per blob and per CHILDREN call, blowing the
    `pull_branch` 30s deadline on anything larger than ~30
    blobs. Now uses a single authed connection across the
    whole walk.

  Faculties source unchanged.

## 0.14.7 — 2026-05-17

- **Bump `triblespace` 0.41.2 → 0.41.3.** Picks up the
  trailing-FQDN-dot fix in `triblespace-net`. iroh's default
  relay hostnames (`*.iroh-canary.iroh.link.` — note the
  dot) were tripping strict WAFs that treat trailing-dot
  Host headers as bypass-attempt signatures (Anthropic web
  sandbox egress being the concrete case). `triblespace-net`
  now strips the dot before iroh constructs `RelayUrl`s,
  producing an HTTP-canonical Host header on the wire. Same
  relays, friendlier request shape.

  Practical effect: the bundled `trible` CLI in this release's
  precompiled tarballs should now successfully establish iroh
  relay sessions from inside Anthropic's web sandbox, which
  unblocks the gossip-mesh + DHT bootstrap path for live sync.
  Faculties source unchanged.

## 0.14.6 — 2026-05-17

- **Bump `triblespace` 0.41.1 → 0.41.2.** Picks up the
  StaticAddressLookup work in `triblespace-net`:
  `pile net sync --peers <EndpointTicket>` now bypasses
  iroh's discovery on the gossip/DHT bootstrap path, not
  just on `pile net pull`. Closes the
  "tickets-work-for-pull-but-not-sync" asymmetry from
  0.14.5. Faculties source unchanged.

  Practical effect for sandboxed users: the bundled `trible`
  CLI in this release's precompiled tarballs can now run a
  full bidirectional gossip sync against a ticketed peer
  without iroh discovery being reachable — relevant when
  iroh-canary 503s the discovery probes (claude.ai web
  sandbox shared-egress IP rate limiting) or DNS is
  filtered (corporate proxies).

## 0.14.5 — 2026-05-17

- **Bump `triblespace` 0.41.0 → 0.41.1.** Picks up the
  `EndpointTicket`-everywhere release in `triblespace-net` —
  the `Peer` API now accepts `impl Into<EndpointAddr>` on
  all peer-dialing methods, `trible pile net identity`
  prints an EndpointTicket, `trible pile net sync` prints a
  rich ticket at startup, and `trible pile net pull <REMOTE>`
  / `pile net sync --peers <STR>` accept tickets in addition
  to bare hex pubkeys.

  Practical effect for sandboxed `faculties` users: the
  precompiled `trible` CLI bundled in this release's
  tarballs can now dial peers directly via an EndpointTicket
  pasted into `--peers` (or as the `<REMOTE>` arg to pull),
  skipping iroh discovery entirely. That's the unblock for
  the Anthropic web sandbox where iroh-canary 503s the
  discovery probes (shared egress IP rate limiting).

  Source unchanged from 0.14.4.

## 0.14.4 — 2026-05-16

- **Bump `triblespace` 0.40 → 0.41, `GORBIE` 0.14.2 → 0.14.3.**
  Tracks the iroh-0.98 family upgrade in `triblespace-net
  0.41.0`, which is the proper upstream resolution for the
  ed25519-dalek 3.0.0-pre.1 / ed25519 3.0.0 compile failure
  that 0.14.3 worked around with a Cargo.lock pin in
  `trible 0.40.3`. Same end-user effect (sandbox-friendly
  precompiled binaries via the OS trust store), cleaner
  resolution path — fresh `cargo install trible` now picks a
  set that compiles end-to-end.

  Source identical to 0.14.3.

## 0.14.3 — 2026-05-16

- **Pick up `triblespace 0.40.2` + `GORBIE 0.14.2`.** Both
  bumps carry the same change end-to-end: the TLS roots that
  iroh's discovery layer trusts now come from the OS trust
  store (via `rustls-platform-verifier`) instead of the
  compiled-in Mozilla `webpki-roots` bundle. The previous
  webpki-roots default silently broke iroh's relay HTTPS
  probes and pkarr publish/lookup in corporate-proxy /
  sandbox environments that present a custom CA at egress —
  every probe returned `invalid peer certificate:
  UnknownIssuer` and discovery never got off the ground.

  Practical effect for sandboxed `faculties` users: the
  precompiled binaries produced from this tag's `release.yml`
  workflow can now reach iroh's public infrastructure from
  inside the Anthropic web sandbox (and similar
  TLS-intercepting environments). Normal environments are
  unaffected — the OS trust store already contains the
  Mozilla roots.

  Cargo.lock pins updated via
  `cargo update -p triblespace -p GORBIE`. Source unchanged.

## 0.14.0 — 2026-05-07

- **Bump `triblespace` 0.37 → 0.38, `GORBIE` 0.13 → 0.13.2.**
  Picks up the team-rooted-gossip release: the gossip mesh id
  is now derived directly from the team root pubkey, so users
  no longer pick + coordinate a separate `--topic` string with
  invitees. Bootstrap fragment 16 (auth setup recipe) updated
  in lock-step in a previous commit.
  Minor bump (pre-1.0 but breaking for downstreams pinning
  `faculties = "0.13"`) because the upstream change in
  `triblespace::net::peer::PeerConfig` re-exports through
  `faculties::widgets::storage` and the `--topic` flag removal
  is a user-facing change in the bundled `trible` CLI.

## 0.13.3 — 2026-05-07

- **README: fix stale `wiki create` example.** The CLI moved
  to positional `<TITLE> <CONTENT>` arguments; the README still
  showed the old `--title`/`--body` flag form. Other examples
  already match the current syntax.
- **Bundle the `trible` CLI in release tarballs.** Each
  per-target tarball now ships `trible` alongside the faculty
  bins (`compass`, `wiki`, `files`, …), so a single download
  delivers the whole pile-management toolkit. The release
  workflow `cargo install trible`s the latest crates.io
  version for the matrix target and copies the binary into
  the staging dir.

## 0.13.2 — 2026-05-07

- **CI-only fix.** v0.13.1's release workflow built past the
  wasm32 issue but tripped on `RUSTFLAGS: -D warnings` —
  pre-existing unused-import noise in the rust-script-ported
  bins (e.g. `src/bin/triage.rs::use std::fs;`) escalated to
  errors. Drop the deny; the release workflow's job is to ship
  working binaries, not enforce lint. A separate lint workflow
  can come back if/when we want to gate that on PRs.
  Lib source identical to v0.13.0.

## 0.13.1 — 2026-05-07

- **CI-only fix.** v0.13.0's release workflow died on every job
  with `wasm32-unknown-unknown target may not be installed`:
  triblespace 0.37 pulls `wasmi 0.31`, whose build script
  invokes rustc against `wasm32-unknown-unknown`. The workflow's
  rust-toolchain step only installed the per-target host
  triple. Fix:
  - add `wasm32-unknown-unknown` to the toolchain install,
  - swap `cross` for native arm64 Linux (GitHub now provides
    `ubuntu-24.04-arm` runners for free public repos), so the
    aarch64-linux job can install the wasm32 target via
    rustup like every other job.
  Lib source identical to v0.13.0; not republished to
  crates.io.

## 0.13.0 — 2026-05-07

- **Bump `triblespace` 0.36 → 0.37.** Aligns the CLI faculties
  + shared lib with the same triblespace release that GORBIE
  0.13 ships against — no more split between binaries on 0.36
  and the optional widgets stack pulling 0.37 transitively.
  Pre-1.0 minor bump, breaking for downstreams that pin
  `faculties = "0.12"`. (Bundles the v0.12.2 changes, which
  are not separately published.)

## 0.12.2 — 2026-05-07 (unpublished)

- **Bump optional `GORBIE` dep 0.12 → 0.13.** Picks up the
  GORBIE 0.13.x line: stacked floats no longer drag in
  lockstep, tall floats render at natural content height
  without a viewport-multiple cap, and the infinite-scroll
  feedback loop when a wiki/compass float was open is fixed.
  See GORBIE's CHANGELOG for the full notes.
- **Drop manual drag detection in `wiki` and `timeline`
  widgets.** Switch to egui's `Sense::click_and_drag` +
  z-aware `dragged()` / `drag_delta()`. Floats dragged
  across the wiki graph or the activity timeline no longer
  pan them in lockstep; the manual `primary_pressed && in_rect`
  + memory-id bookkeeping is gone.
- **Fix wiki graph label flip-overshoot.** When a node's
  label would overflow the right edge, the mirror-to-left
  path used `Align2::RIGHT_CENTER.anchor_rect` against an
  already-shifted origin — the label landed one whole
  galley-width further left than intended, sometimes
  clipping or appearing to wrap around to the viewport's
  left side. Pass the unshifted `left_anchor` so the
  label's right edge sits cleanly just left of the node.

## 0.12.1 — 2026-05-05

- **Drop stray `[patch.crates-io]` GORBIE local override.** v0.12.0
  shipped with `GORBIE = { path = "../GORBIE" }` in the manifest,
  which broke the release workflow (the GH runner has no sibling
  GORBIE checkout). Local dev overrides belong in
  `~/.cargo/config.toml` or a gitignored override file, not the
  published manifest. v0.12.0 source is identical otherwise; this
  is a CI-only fix.

## 0.12.0 — 2026-05-05

- **Faculties are real Cargo binaries now.** Every faculty moved
  from a `rust-script` shebang at the repo root into `src/bin/`,
  with the unioned dep set hoisted into `Cargo.toml`. Install
  with `cargo install --git ... --bins` (or grab a precompiled
  tarball from a tagged release). Invocation drops the `.rs`
  suffix: `wiki list`, `compass add ...`, etc. The `faculties`
  lib (schemas + widgets) is unchanged; binaries `use faculties::...`
  the same way external crates would.
- **GitHub Actions release workflow.** `v*` tags trigger per-target
  builds (`x86_64-linux-gnu`, `aarch64-linux-gnu` via cross,
  `x86_64-apple-darwin`, `aarch64-apple-darwin`) and attach
  tarballs + sha256s to the GH release. Restricted sandboxes can
  fetch binaries without a Rust toolchain.

## 0.11.2 — 2026-04-19

- **Theme-adaptive compass + messages.** `color_frame`, `card_bg`,
  `color_bubble`, `color_muted` now branch on `ui.visuals().dark_mode`
  so light-mode notebooks don't end up with dark-on-dark text.
- **Drags don't fight.** Both the wiki graph and the activity
  timeline only latch onto a drag whose press *started* inside
  their viewport — dragging a floating card across them no longer
  yanks the graph pan or the timeline offset.
- **Release hygiene.** LICENSE-MIT + LICENSE-APACHE committed,
  Cargo.toml gains authors/homepage/readme/keywords/categories,
  `.gitignore` excludes `*.pile` and `.bak-*` backups.

## 0.11.1 — 2026-04-19

- **`faculties-viewer` binary.** `cargo install faculties --features widgets`
  now installs a binary that composes all four widgets (activity
  timeline, wiki graph, compass kanban, local-messages) against a
  single pile. Mirror of `examples/pile_inspector.rs`.
- **Widgets polish.** Dozens of small rendering fixes for the demo:
  edge-to-edge viewports for the timeline and wiki graph; SPAN +
  zoom-hint overlay inside each viewport; colorhash-tinted fragment
  IDs, person chips, and tag chips; compass lanes now stack
  vertically; centered empty-state placeholders; search-miss banner.
- **GORBIE 0.12.** Bumps the optional GORBIE dep to 0.12.0 which
  pulls in the egui 0.34 hit-test workarounds.
- **CLI faculties on the published crate.** All rust-script
  faculties (`compass.rs`, `wiki.rs`, etc.) depend on
  `faculties = "0.11"` from crates.io instead of an absolute local
  path, so cloners build out of the box.

## 0.11.0

Previous releases were internal/path-based. See git history.
