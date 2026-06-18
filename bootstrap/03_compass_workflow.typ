= Compass Goals Workflow

`compass` is the goal/task tracker. Use it instead of
Claude Code's TaskCreate/TaskUpdate — compass goals persist
across sessions and merge between agents; the harness's task
list does neither.

== Statuses

  - `todo` — queued, not started
  - `doing` — actively in progress
  - `blocked` — waiting on something external
  - `done` — finished, with an outcome note

Stick to those four unless there's a strong reason to introduce
another.

== Daily flow

  + `compass list` — see your active goals
  + Pick one, `compass status <id> doing` — claim it
  + Add notes as you decide things: `compass note <id> "..."`
  + When finished: `compass status <id> done` then a final
    note recording the outcome
  + Repeat

== Hierarchy

`compass goal-create --parent <id>` creates a sub-goal. Use
this when a goal naturally breaks into 3+ steps you'll want to
track separately. Don't sub-goal trivial steps — the conversation
itself is the right level for "and now do X".

== Tags

Compass tags work like wiki tags. Common ones:
`#meta`, `#bootstrap`, `#parking` (see Scope Control below),
plus project-specific tags (`#liora` in the Liora project,
`#deploy` for ops work, etc.).

== Scope control: parking lot

Mid-task ideas that would take >2 minutes go in compass with
a `#parking` or `#later` tag. Then *return to the current goal*.
Near the end of a session, do a parking-lot sweep: promote
0–2 parked items to active, leave the rest.

The parking discipline keeps the agent from infinitely-context-
switching and producing nothing. Compass is the queue; the
conversation is the executor.

== When NOT to use compass

  - In-conversation TodoWrite-style step planning is fine for
    "the next 20 minutes" — compass is for goals you'd want to
    pick up later, including in a future session.
  - Pure scratch state ("what was I about to do") — that's the
    conversation itself.

Next stop: [Wiki Fragment Style Guide](wiki:82129c70b693f7e2d781d78ac5efbb86).
