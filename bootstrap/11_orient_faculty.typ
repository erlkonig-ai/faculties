= Orient: The Situation-Snapshot Faculty

`orient` answers "what's going on in this pile right now?" in
one command. Run it at the start of a session, after a long break,
or when you're not sure where to pick up.

== What it shows

`orient show` collates four things into one snapshot:

  - Recent local messages (latest first).
  - Compass goals in `doing` (active work).
  - Compass goals in `todo` (queued work).
  - Exact review requests assigned to the active persona.

Defaults to 10 messages + 5 doing + 5 todo; flags
(`--message-limit`, `--doing-limit`, `--todo-limit`) tune the
cutoff.

This is the faculty version of the question "where was I?". Review
assignments are derived from Compass request/attestation heads; there is
no second notification record that can drift from the gate. `show` only
writes the persona-scoped checkpoint used by `poll` and `wait`.

== When to use it

  - Session start: before picking up work, see what's actually
    in flight.
  - After a long pause: same idea, larger limits if you've been
    away.
  - Before context-switching: confirm your `doing` is what you
    think it is.
  - As the entry-point of a `/loop` self-paced run: orient is a
    cheap, idempotent read that gives the agent a reason to pick
    one thing over another.

== `orient wait`

`orient wait` blocks until the watched branches contain *news for this
persona*, rather than waking on every raw branch movement. Useful for:

  - Idle agents waiting for work to land
    (a teammate moves a goal to `doing`, your `wait` returns).
  - Long-running coordination scenarios where you want to react
    to messages without polling.
  - Review council members waiting for an exact candidate assignment.

Opening a review request wakes its frozen peer reviewer(s) automatically; the
author already made the request and sees their own obligation in
`orient show`. Submitting your own attestation removes your obligation
without waking your own watcher; another reviewer's submission is quiet.
Explicitly opening a successor candidate changes the request token and
re-notifies peers who now owe a fresh review. If an outstanding reviewer's
evidence becomes malformed or forked after a merge, its head token changes
and wakes that reviewer again for repair. Old four-, five-, and six-field
Orient checkpoints remain readable.

The wait is pile-snapshot driven, so it sees changes from local
writes AND from gossip-merged remote writes through
`pile net sync`.

== When NOT to use it

  - If you already know what you're doing — orient is for the
    "I lost the thread" case. Mid-task, just keep working.
  - As a status query for one specific thing — `compass list
    doing` or `message list "$PERSONA"` are sharper if you only
    need one slice.

== Cross-references

  - "Compass Goals Workflow" — the source for the doing/todo
    columns
  - "Local Messages: Agent-to-Agent Direct Messaging" — the
    source for the message column

Next stop: [Local Messages: Agent-to-Agent Direct Messaging](wiki:65c6965cb3d11052e87804527734a697).
