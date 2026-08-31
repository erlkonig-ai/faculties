= Orient: The Situation-Snapshot Faculty

`orient` has four deliberately different modes. Use `wake` at session start or
after context compaction to recover the whole self: memory cover, cover-tagged
beliefs, and goals. Use `show` mid-session for the much smaller answer to "what
is going on right now?"; it deliberately contains neither memories nor Wiki
entries. `wait` blocks and also sweeps timer-driven Habits; `poll` performs the
pile-backed checkpoint check once without blocking.

== What it shows

`orient show` collates:

  - recent local messages
  - unread Mail
  - due Habits and Habit states needing attention
  - Compass goals in `doing`
  - Compass goals in `todo`
  - current window status

Defaults to ten messages, five doing goals, and five todo goals. The
`--message-limit`, `--doing-limit`, and `--todo-limit` flags tune those limits.
When a persona is set, `show` also advances that persona's checkpoint used by
`poll` and `wait`.

== When to use it

  - `orient wake` at session start and after compaction
  - `orient show` after a pause or before context-switching
  - `orient poll` from non-blocking per-turn hooks
  - `orient wait` as the idle point of a self-paced loop

== `orient wait`

`orient wait` blocks until the watched collection snapshot contains news for
this persona, rather than waking on every raw pile append. Directed news includes unread
inbox or group messages, relevant goal transitions, new goals tagged with the
persona or any Relations group containing it, newly status-bearing windows,
newly visible Compass notes, and unread Mail. A foreign or unattributed note is visible
when its goal involves the persona or carries such an attention tag itself;
the persona's own attributed notes, status edits, and message acknowledgements
stay quiet.

Each checkpoint is an immutable event containing the complete canonical
`WatchedView` observed for that persona—not a cursor and not a delta of note
IDs. Readers select the latest event by `(point time, event id)` and diff its
view against a newly computed snapshot. That deterministic total order makes
concurrent observations visible in history without pretending the checkpoint
itself is a union or lock. A first non-peek poll records the current view as a
quiet baseline.

Wait recomputes the persona-visible semantic view after pile changes and also
sweeps Habits as wall time advances. A cooldown becoming due or a Habit entering
an attention state can therefore wake it without any pile growth. The current
`pile net sync` can repair native collection records and requested blobs for an
explicitly activated descriptor, but `orient wait` is still what turns newly
arrived state into a local notification. `orient poll` performs that pile-backed
news check without blocking;
`--peek` reports without consuming the checkpoint.

== When not to use it

  - If you already know what you are doing, keep working
  - For one narrow query, prefer `compass list doing` or
    `message list "$PERSONA"`

== Cross-references

  - "Compass Goals Workflow"
  - "Local Messages: Agent-to-Agent Direct Messaging"

Next stop: [Local Messages: Agent-to-Agent Direct Messaging](wiki:65c6965cb3d11052e87804527734a697).
