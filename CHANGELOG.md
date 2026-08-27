# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- **Streamed Archive payloads now enter the artifact-serving protocol.** The
  Archive importer still validates and writes each source fragment's embedded
  blobs immediately, so large imports do not retain their bytes until the final
  collection commit. Those direct writes now pass through one operation-scoped
  `OfferCapture` and publish a canonical OFFER batch only after every put in the
  batch succeeds. OFFER grants neither authority nor retention, so an import
  rejected by later catalog validation remains semantically invisible and its
  orphan payloads remain collectible.

- **`duplex` stops owning the microphone, so it and `hear` can finally run at
  the same time.** A capture device can be held by exactly one process, and
  `duplex` opened CPAL itself while `hear` owned nothing and inherited Soma's
  one named device -- so the two could not run together at all. That was not an
  inconvenience but a structural impossibility, and it is why splitting hearing
  from speaking kept failing. Soma is now the single owner and fans one
  microphone out; `duplex` subscribes through `soma-client` like every other
  consumer. A live embedding stream for the thinking model AND a spoken channel,
  off the SAME frames, instead of choosing.

  The clock discipline is unchanged and slightly stronger: the ear thread blocks
  in `SomaCapture::next_frame` until the body has produced the next exact 80 ms
  frame and the generation loop blocks on the ear, so the period still comes
  from the hardware that will actually move the samples -- one layer removed,
  with no sleep, timer or polling interval anywhere on the path. The
  device-owning version polled its own capture ring every 4 ms; that is gone
  too. A loop slower than the world still skips FORWARD and counts it, because
  the model's step count is its clock and it cannot catch up by stepping faster.

  `--input <exact capture device name>` is REPLACED by `--soma <url>`, and
  `duplex devices` no longer lists capture devices: naming a second one would be
  offering back the thing that made the two faculties exclusive. The microphone
  is named once, in Soma. New `duplex ear` reads the body's frames through the
  same ear `run` uses, with no model at all -- the capture seam's gate, and the
  way to tell "the body is not producing audio" from "the model is not
  answering". New `duplex run --pause-file` holds the half-duplex pause file for
  exactly as long as this channel is AUDIBLE IN THE ROOM (the generation window
  plus whatever is still in flight to the speaker, which is later than the model
  is generating), so a `hear` reading the same body does not transcribe our own
  voice back to us. Inside `duplex` turn-taking still needs no file: `--gate`
  feeds the model digital silence while it speaks, in process, on the frame
  clock.

  REMOVES: `duplex`'s own device-rate resampler and channel downmix, which
  existed only because it opened an arbitrary capture device; Soma delivers
  canonical 24 kHz mono. The PLAYBACK device is deliberately still opened here
  by name -- it is multi-client on this hardware, so it never forced the
  exclusion the microphone did, and repointing an audio sink through another
  owner would move the say-privacy invariant across a process boundary before
  that owner enforces it.

- **`duplex run --spm` and a body frame in the clock line.** The weight pile's
  two halves have drifted apart -- the codec loader wants a `mary-model-bundles`
  collection, the pile-side SPM loader still wants the `mary-model-graph` the
  bundle migration replaced -- so no pile satisfies both and `duplex run` could
  not load at all. `--spm <path>` overrides the tokenizer from a file, the same
  flag `mary`'s own PersonaPlex bins take; whatever it loads is still checked
  against the model's `TEXT_CARD`, so a wrong tokenizer stays a loud failure.
  The periodic clock line now reports the BODY's frame index, which is the one a
  `hear` on the same microphone is counting too, so two logs can be laid side by
  side and read as one instant. The startup line no longer claims a join point
  it does not have yet: it printed "joined the body clock at frame 0" before any
  frame had arrived, which is exactly the thing a shared microphone makes untrue.

- **`hear`'s default `--model` could not select a model root.** It spelled the
  source `google/gemma-4-e4b-it`; the pile's root selection is case-sensitive
  and wants `google/gemma-4-E4B-it` (which is what `mary`'s own `gemma_hear`
  passes). The HF side files resolved either way because the macOS filesystem
  lookup is case-insensitive, so nothing showed until it was run against a real
  pile -- `hear listen` and `hear once` failed with "no model root matches" for
  every user who did not pass `--model` themselves.

- **The ears become a faculty, and they hand over embeddings.** `hear` replaces
  `converse`: it reads Soma's framed 80 ms capture stream through
  `soma-client`, segments utterances with an energy VAD, and hands over AUDIO
  EMBEDDINGS -- the rows Gemma-4's audio tower and multimodal embedder produce,
  in the decoder's own width, which is exactly what the model's own
  `understand` writes over its audio-soft-token positions before prefill. A
  transcript throws away tone, hesitation and mood at the greedy argmax, and
  that argmax is the last place anyone can still get them back; stopping one
  step earlier costs the consumer nothing, because splicing embeddings is the
  operation the model already performs. `--transcribe` still decodes text, as a
  debugging convenience rather than the handover. Soma opens the microphone by
  name in exactly one process and every consumer inherits that choice, so `hear`
  opens no device at all and reading the next record is the conversation clock.
  `hear once --wav` runs recorded clips through the same segmenter and the same
  embed path, which is how everything below the capture seam is tested without
  hardware.

- **`converse` is removed; its three guards are library code.** The bridge
  chained three models across three processes by tailing a jsonl file, and the
  chain is what `duplex` and `hear` replace. What it alone carried now lives in
  `faculties::turntaking`, with tests: the PAUSE-FILE protocol (a guard whose
  `Drop` is the release, so a crash mid-utterance cannot deafen the ears
  forever), the BARGE-IN overlap heuristic (an utterance stamped inside our own
  speech window is presumed self-echo even when the pause file missed it --
  the two guards fail differently, so keeping both is coverage, not
  redundancy), and the NO-SPEECH / PROMPT-PARROT filter (on empty or
  AEC-suppressed audio a decoder parrots its own prompt back as the transcript,
  and without the check a silent room makes the bot recite its instructions
  aloud). REMOVED WITH IT: the `--brain playground|echo` one-shot turn and the
  jsonl-tailing loop that joined an ear process to a mouth process. Nothing
  else used either.

- **`voice say|shout --pause-file`.** The mouth now holds the half-duplex pause
  file itself for its whole audible window, which is the half of the protocol
  `converse` used to supply. The listener never closes its microphone to
  observe it: closing a Bluetooth mic flips the endpoint between its handsfree
  and high-quality profiles and chops speech mid-sentence, so the hold is
  software-only and stops the model, never the person. The say-privacy
  invariant is untouched and still lives in code -- there is no path from
  `voice say` to a room speaker.

- **Migration generations now have stable semantic names and fitting execution
  boundaries.** The original
  pre-collection transition is `migrations legacy-branches plan|activate`;
  `plan-cutover` and `activate-cutover` are removed rather than retained as
  ambiguous aliases. The later unpublished subject-bearing Secrets envelope
  generation has its own `migrations secrets-direct-proofs plan|activate`
  bridge and a distinct retired wire tag. Its trust basis is the durable root's
  signature on delivery into that same root's deterministic private inbox, the
  recipient-sealed context, and the matching custody declaration in the
  existing root/root vault — never the retired proof signatures. Planning is
  read-only and classifies exact pending, complete, ambiguous, and malformed
  states. Activation is online and additive: it appends each fresh direct root
  proof's claims and native proof record, then one access-inbox COMMIT per
  pending vault, touches no vault COMMIT, and replans to zero pending work.

- **Faculty-authored chronology now fails closed on clock errors.** Clock reads
  that timestamp collection facts or operational records pass through one
  fallible shared capability. A failed read therefore aborts before a
  collection commit, credential update, or transcript append instead of
  becoming a signed 1970/TAI-zero observation. The affected read-only widgets
  represent an unavailable current instant as unknown or omit its age marker;
  source records with genuinely absent timestamps remain optional and
  unchanged.

- **`migrations legacy-branches plan` now recognizes an already-published native
  cutover.** Planning still derives the legacy projection from one frozen pile
  prefix, then deterministically replays each planned collection commit and
  Secrets access-envelope publication in bounded scratch storage and compares
  their exact records and blob closure with that same snapshot. The report
  distinguishes missing, partial, and already-complete publication per
  collection, ignores unrelated later commits, treats an authored empty
  fragment as a real commit, and flags vault custody or access drift. This
  keeps the read-only planner useful after a cutover without mistaking a
  completed live pile for work that should be activated a second time;
  `legacy-branches activate` remains the aggregate semantic validator. If one valid
  historical Secrets scope carries repeated creation observations, direct
  vault activation projects their earliest point as the immutable vault
  genesis; intrinsic scope identity was `(creator, name)`, and the preserved
  legacy prefix retains the complete observation set. Direct-recipient vaults
  created after that catalog generation are inventoried from the durable
  root's exact historical READ grants and materialized only from strictly
  verified root-authored commits; dormant foreign commits remain inert.

- **`converse` — a half-duplex talk-loop bridge.** Three seams that already
  existed are now joined into one spoken loop: a listener appends utterances
  to a jsonl log, `converse run` tails it, takes one brain turn per utterance,
  and speaks the reply through `voice say|shout`. Turn-taking is a PAUSE FILE
  held for the whole speech window rather than an open/close of the capture
  stream — closing a Bluetooth microphone renegotiates its profile and clips
  the next sentence, so the stream stays open and the listener discards audio
  while the file exists. The guard removes the file on drop, so an error path
  cannot leave the ears permanently deaf. `--brain echo` closes the loop with
  no model endpoint at all, which makes the plumbing testable from a file with
  no audio hardware; empty-segment artefacts (a transcript that parrots its
  own prompt, sub-second blips, one-character results) are filtered with the
  reason recorded per turn. Devices are named on both ends and neither end
  consults the system default: connecting a Bluetooth endpoint renumbers the
  device list, and an index or a default can silently land on a dead virtual
  channel.

- **Compass importance is one shared partial order.** `compass list` already
  understood explicit `prioritize` assertions, but its private topological
  sort assigned every unrelated goal a different rank, so the advertised
  recency tie-break almost never ran; Orient ignored the priority relation
  entirely. The collection model now derives the complete relation once,
  including the structural child-before-parent edge, and exposes shared
  topological tiers. Compass and Orient both sort by those tiers first,
  recency second, and entity id last. Unrelated maximal goals consequently
  remain peers instead of acquiring an accidental order from hash-map or id
  iteration, while every stated precedence still wins. Cycle rejection uses
  the same shared interpretation as display; a cycle introduced by concurrent
  replica writes degrades to one final peer tier rather than making reads
  unavailable.

- **A colleague's Teams reply now wakes the watcher.** `orient wait` blocked
  on peer messages, Mail, goals, status windows and habits — but not on
  Teams, so a reply from a real colleague landed in the pile with nothing
  watching it, and the only thing noticing was an ad-hoc polling loop. Teams
  is now part of Orient's news. It has no per-reader read state to diff, so
  attention is the *growth* of the set of present logical messages written by
  somebody other than us, checkpointed per persona exactly like unread Mail;
  an edit re-observes a message we already know and is therefore silent, and a
  deletion never announces a tombstone. Two things are deliberately not news.
  Our own sends come back through the next delta pull, and they are filtered
  by joining a message's author entity against the auth profile's Graph user
  id — the same own-action rule that keeps a persona's own peer sends and
  goal edits from waking its own watcher. Graph's authorless chat events
  (`<systemEventMessage/>` for a member added or a chat renamed) are not
  somebody writing to us, so an unattributed observation is never news. There
  is no per-persona gating: one tenant account serves every window sharing
  the pile, so a colleague's message is addressed to the pile rather than to
  one window, which is the same reading as a peer message sent to a group you
  are in.
  **Orient still never talks to Graph.** `wait` re-arms after every turn and a
  network round trip on that path would both slow the common case and
  rate-limit the tenant, so it reads only what the pile already holds — which
  means `teams read` remains the only thing that pulls new messages *into* the
  pile, and a Teams message nobody has synced still cannot wake anybody.
  Reading the Teams collection costs about 3 ms of materialization and 0.2 ms
  of projection on the live 12.8 GB pile, against ~5 s for the command as a
  whole. The Orient checkpoint view is now version 3; a version 1 or 2
  checkpoint still parses, and its empty Teams set means the first check after
  the upgrade reports the standing conversation once.

- **Secrets vaults now separate authority, custody, and private discovery.** One
  vault epoch is one capability-anchored private collection with a random
  custody key. Every immutable secret version has exactly one DEK wrap to that
  custody key, independent of the number of readers. Exact `READ` and unbounded
  `WRITE` proof identities are named in the recipient-sealed access envelope;
  their complete claims live in content-addressed blobs and their proofs in the
  native proof store. A recipient's private open-admission inbox is only an
  untrusted delivery index, and every candidate is independently authenticated
  and validated before it can admit commits or decrypt data. Grants are thus
  constant in vault size and do not enumerate membership. The live CLI manages
  explicit epochs with `secrets vault create|list|grant` and exact immutable
  versions with `secrets secret add|get|list`; the enumerable `members` and
  per-secret `share` surfaces are gone. The pre-collection migration preserves
  historical secret ids, encrypted bodies, and source evidence while re-sealing
  only each DEK into a capability-anchored custody successor; the later
  `secrets-direct-proofs` bridge changes only access evidence.

- **The Teams credentials the cutover retired are recoverable.** The collection
  cutover treats the legacy Teams OAuth rows as a bounded retired partition:
  verified as source evidence, never republished, because the native Teams
  collection never holds a secret in the clear. Live authentication was meant
  to restart at a source-scoped auth profile naming exact encrypted Secrets
  versions — and nothing built that restart, so on a migrated pile the Teams
  collection has no auth profile, and every `teams` command fails with `Teams auth-profile
  source ... is missing` while the credentials sit unreferenced on the legacy
  branch. `migrations
  teams-credentials` is the bridge. It reads the frozen legacy branch and
  reports every surviving credential row newest-first — kind, time, payload
  *lengths*, tenant, client id, the delegated scopes, and the signed-in
  account's directory id read from the newest access token's `oid` claim,
  which is the one value `teams auth set --user-id` cannot otherwise recover
  without a fresh login. With `--export <DIR>` it materializes the newest
  credential of each kind into `0600` files shaped for the two commands that
  own that write: `teams login --vault <id> --client-secret @file` and `secrets
  secret add --vault <id> --name <name> --value @file`. It never writes to the
  pile and never prints a secret — selecting an exact vault epoch and its
  capability/custody context belongs to the durable signer, not to a
  source-reading migration.

- **Compass's status register has an identity.** A goal's current status was
  the greatest `(created_at, event id)` among the status events hanging off
  `board::task`. That edge means *belongs to this goal* and notes and priority
  events carry it too, all timestamped — a grouping, not an identity, and a
  note is not a later version of a status event. New attribute
  `board::status_of` says the narrower thing, *this is a state of the status of
  goal G*, and `latest_status_event` is now the maximal state of that register
  (`StatedOrder` over `status_of` × `created_at`, id tie-break) rather than a
  hand-rolled `max_by`. Status events are written with `status_of` instead of
  `task`; `task` stays readable on the events that predate it, because a pile
  is append-only, but nothing reads it for status. `faculties-migrations`'
  `status_register` gives the identity to every complete legacy status event —
  a pure `TribleSet -> TribleSet` delta, so the live-pile gate applies it in
  memory and the migration and its proof are the same code. Events carrying no
  status or no time are deliberately left out: they name nothing to be current
  and Compass's read has always skipped them.

- **A Posture finding is located by content, and git decides what moved.**
  Identity was `(modality, path, commit:path:line, value)`, so commit surgery —
  rebase, cherry-pick, amend, scrub — gave the same material a new id and every
  Decide resolution silently stopped applying. It is now `(modality, carrier,
  inner locator)`, where the carrier is content-addressed and the coordinate is
  modality-dependent: a git blob and a byte range for source, the extracted
  member hashed by posture for a container, and the commit itself for a message,
  which has no blob. `finding` and `occurrence` collapse into one written
  entity; per-scan observations become `sighting` annotations carrying the
  document, the evidence and the commit the material was seen in — a rebuildable
  cache, never identity. The scanner asks `git blame -M -C` where a line was
  introduced rather than matching moved material itself, so an edit elsewhere in
  a file does not re-create a finding as new. Reads no longer validate all
  history against the current schema: `validate_scan_view` is gone, and
  validation runs where it belongs, on the fragment being written. Existing
  records stay exactly where they are; `migrations posture-findings` bridges the
  old occurrence ids onto the findings they turned out to be so resolved
  outcomes keep applying, and reports one by one the findings it cannot bridge
  (a repository no longer on this machine, a commit rewritten away, or a
  container member whose bytes a legacy record never stored).
- **Wiki and Memory frontiers come from the shared `latest` operation.** "Which
  states are current" was hand-rolled in nine faculties as *gather every
  superseded id, then subtract*. It is a lattice operation, not a per-faculty
  rule, and now lives in the query layer as
  `triblespace::core::query::frontier::latest(facts, observes, candidates)`.
  Wiki's entry frontier was an O(n²) member-vs-member scan and is now one call;
  `MemoryCatalog` resolves its head antichain once in `load_catalog`, against
  the same collection view every other fact came from, so `head_ids`,
  `live_chunk_ids` and `is_live` can no longer answer in a different frame
  (`is_live` also stops rebuilding the whole frontier per call).
  `memory_cover::superseded_ids` is replaced by `live_chunk_ids` and
  `live_among`. Verified over the live corpus (`examples/latest_frontier_gate.rs`,
  reads only): 11234 wiki revisions across 3096 entries and 3813 memory nodes
  (309 superseded) produce byte-identical sets to the deleted code, plus
  order-independence and frame-relativity checks on live data. Compass is
  censused, not converted: it carries supersedes edges on notes but resolves
  currency by timestamp, a different question.
- **The legacy Wiki anchor is retired: an id names a revision or it names
  nothing.** `attrs::fragment` is no longer read anywhere in the wiki — not by
  the read model, not by the CLI selector path, not by the viewer, not by
  `gauge`. `RevisionRecord::legacy_fragment`, `EntryRecord::legacy_fragments`
  and `RevisionReadModel::legacy_fragment_frontier` are gone; a legacy revision
  is now identified by the `native` flag the loader sets from its kind tag, and
  an entry is labelled by its root revision rather than by an anchor. The
  branch-era read helpers in `schemas::wiki` (`latest_versions`,
  `cover_fragments`, `read_title`, `read_content`, `tags_of`,
  `find_tag_by_name`) go with them — nothing had called them since the
  collection cutover. The anchor FACTS stay in every pile, because the store is
  append-only, and the additive migration still reads them as legacy input;
  what changed is that nothing resolves one.
  **This is irreversible in effect and it has a measured cost**: superseded
  revisions are content-addressed, so the anchor references inside them can
  never be rewritten. On the live corpus that is 12141 references across 2223
  superseded revisions (1166 distinct anchors) which now resolve to nothing.
  Run `wiki lint --fix` over a corpus BEFORE installing this — afterwards no
  build can resolve an anchor, and `wiki check` reports every remaining anchor
  reference as a broken link (7351 on an un-linted live pile, 0 after the fix).
  `examples/reference_census.rs` measures both halves; `examples/anchor_gate.rs`
  is deleted, its gate having already licensed the grouping change it measured.
- **`wiki lint` rewrites every `wiki:` reference to a revision id.** A revision
  id is a citation — immutable, pinned to what its author read; a legacy anchor
  is a live indirection that returns whatever is head today, so a citation
  written in March silently follows the page into August. Lint now resolves any
  anchor reference in content — link target, link label that repeats the id, or
  bare prose mention — to the anchor's CURRENT head revision, which is the
  faithful reading of what an anchor always said ("latest"), and expands
  unambiguous truncated prefixes on the way. References that already name a
  revision keep their exact bytes, and fenced code blocks are left verbatim, so
  a wiki of citations is a fixpoint. `--fix` mints successors as usual; the
  anchor-citing revisions stay immutable with their anchors intact. Measured on
  the live corpus (`examples/reference_census.rs`): 10094 anchor
  references in 1731 frontier revisions, 9092 of them in link syntax, resolving
  through 3035 anchors that each have exactly one head; a `--fix` on a
  copy-on-write clone left 0 anchor references in the frontier, 0 issues in
  `wiki check`, and was a fixpoint on the second pass.
- **Wiki entries are supersedes-connected components; the legacy anchor no
  longer groups.** The additive migration synthesized the supersedes chain from
  the anchor groups, so the anchor edge had become redundant. Verified over the
  live corpus before removal (by `examples/anchor_gate.rs`, since deleted along
  with the anchor itself): 11231 revisions across 3035 anchors partition into
  the same 3095 entries, identical membership, with and without it. Anchor facts
  stayed in the store and still resolved as selectors at the time; the entry
  above then retired that resolution too.
- **Wiki backlinks are revision-scoped.** `wiki links` incoming, and the
  `--with/--without-backlink-*` filters, now name the revision whose own text
  carries the citation, superseded revisions included, and attribute source tags
  to that revision rather than to its entry's frontier. A citation is a claim
  about what its author actually read; the entry-scoped answer asserted a
  citation that the page's current text may have dropped. Run
  `wiki show --latest <revision>` to see whether it survived.
- **Voice freezes one native Qwen3-TTS snapshot per utterance.** Exact base,
  shared codec, filtered f16 talker, and versioned folded f16 talker roots are
  selected together before synthesis. Runtime no longer opens Repository
  branches, resolves sibling piles, or admits a different model prefix for
  each component; the owned snapshot keeps every zero-copy mmap alive through
  generation and codec playback.
- **Imagine freezes one native FLUX model snapshot.** The text encoder,
  transformer, and VAE are selected as three explicit component roots from one
  coherent Mary collection view, while phase-wise materialization preserves
  the existing low-RAM execution. Runtime no longer reopens a legacy Repository
  pile for every phase, and `flux_persist` publishes the three ordinary native
  roots under stable source coordinates.
- **Nomic inference now reads native Mary collections directly.** Each text or
  vision model pile is frozen once, then its explicit source/quantization and
  tokenizer-name selectors operate on that one coherent snapshot. Runtime no
  longer opens Repository branches, writes ephemeral heads, falls back through
  tokenizer JSON/temp files, or exposes model-import commands through Memory;
  legacy import and migration live at Mary's control-plane boundary.
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
- **Historical Secrets is migration-local, not a second runtime.** The frozen
  wire schema, strict identity/scope/grant parser, attachment validation, DEK
  recovery, and KEM-only resealing live solely in `faculties-migrations`.
  `faculties-secrets` exposes only capability-gated custody vaults; there is no
  compatibility module, fixed Secrets collection, identity adoption, lockbox,
  or scope graph in the live API. Activation preserves the copied legacy prefix
  as source evidence and validates and retires the exact historical Mail
  account/pointer shape found on that branch.
- **Decisions are collection-native and preserve concurrent resolution.** A
  stable decision anchor has one immutable intrinsic genesis, while factors are
  additive occurrence records and resolutions form intrinsic predecessor DAGs.
  Reads expose missing, unique, semantically agreed, forked, and invalid states
  without timestamp arbitration. Every non-forced resolution freezes the exact
  same-decision pro and con evidence it used; forcedness is an explicit bit,
  and agreement quotients heads only by outcome plus forcedness while retaining
  distinct evidence and history. Publication validates the exact ontology,
  attachments, closed acyclic history, and all-head reconciliation.
- **Frozen legacy recovery loads its root password without exporting it to every
  child process.** `FACULTIES_SECRETS_PW` remains the first source, then
  `FACULTIES_SECRETS_PW_FILE` or the XDG configuration path is read on demand.
  Group- or world-readable files are refused and editor line endings are
  stripped. Only migration and recovery paths consume this capability; the
  Secrets CLI opens exact vault epochs with the durable signing key.
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
