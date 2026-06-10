= Orient: The Situation-Snapshot Faculty

`orient` answers "what's going on in this pile right now?" in
one command. Run it at the start of a session, after a long break,
or when you're not sure where to pick up.

== What it shows

`orient show` collates three things into one snapshot:

  - Recent local messages (latest first).
  - Compass goals in `doing` (active work).
  - Compass goals in `todo` (queued work).

Defaults to 10 messages + 5 doing + 5 todo; flags
(`--message-limit`, `--doing-limit`, `--todo-limit`) tune the
cutoff.

This is the faculty version of the question "where was I?". It's
a strict cross-faculty read — orient itself doesn't write to the
pile.

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

`orient wait` blocks until any of the watched branches
changes (compass, local-messages, …) and then prints a fresh
orientation. Useful for:

  - Idle agents waiting for work to land
    (a teammate moves a goal to `doing`, your `wait` returns).
  - Long-running coordination scenarios where you want to react
    to messages without polling.

The wait is pile-snapshot driven, so it sees changes from local
writes AND from gossip-merged remote writes through
`pile net sync`.

== When NOT to use it

  - If you already know what you're doing — orient is for the
    "I lost the thread" case. Mid-task, just keep working.
  - As a status query for one specific thing — `compass list
    doing` or `local_messages list` are sharper if you only
    need one slice.

== Cross-references

  - "Compass Goals Workflow" — the source for the doing/todo
    columns
  - "Local Messages: Agent-to-Agent Direct Messaging" — the
    source for the message column

Next stop: wiki:65c6965cb3d11052e87804527734a697 — Local Messages: Agent-to-Agent Direct Messaging.
