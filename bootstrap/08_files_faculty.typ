= Files Faculty: Archiving and Citing Artefacts

`files` is the content-addressed file store. Use it for any
binary or large-text artefact you'll want to cite from a wiki
fragment later: PDFs, datasets, screenshots, codex output dumps,
downloaded papers.

== Why this exists

  - The pile is the single source of truth — putting an artefact
    in `/tmp` means it's gone next session.
  - Content-addressing means the same bytes always hash to the
    same handle. Two agents with the same paper in their files
    branch can cite the same `files:<hash>` and the cite resolves
    on either side.
  - Wiki fragments cite files by handle, not by path; an
    archived file is durable across machines, sessions, and
    pile renames.

== Usage

```sh
# Archive a single file
files add ~/Downloads/some_paper.pdf
# → files:<hash>   (use this handle in wiki fragments)

# Fetch from a URL straight into the pile (avoids the tmp step)
files fetch https://arxiv.org/pdf/2305.12345.pdf

# List what you've archived
files list

# Search by name or tag
files search "succinct"
files list --tag paper

# Pull a file back out
files get <hash> ~/Desktop/recovered.pdf

# Pipe to stdout (works with binary)
files get <hash> @- > /tmp/check.pdf
```

== Tagging and search

  - `files tag <hash> <tagname>` adds a tag.
  - Tags compose: a paper might be tagged `paper`, `arxiv`,
    `compression`, `benchmark`. Each new tag is queryable
    independently.
  - Tag conventions: keep tags lowercase, short, durable.
    Topic tags (`compression`, `auth`) live longer than
    project tags (`liora-q2-experiment`).

== When NOT to use files

  - Source code under git — that's already content-addressed
    by the commit hash.
  - Tiny text snippets — those go in wiki fragments directly.
  - Anything you'd want to read with `wiki show` later —
    fragments render in GORBIE; files don't.

== Citation pattern

In a wiki fragment:

```typ
The convergence rate proof appears in
[Mezard 2009, section 4](files:<hash>).
```

GORBIE renders this as a clickable link (labelled
"Mezard 2009, section 4") that opens the archived PDF in a
viewer. Always cite with the `[label](files:<hash>)` form: a
*bare* `files:<hash>` in prose does NOT become a link (the
wiki warns you if you write one), and the label reads far
better than a raw hash.

Next stop: [Orient: The Situation-Snapshot Faculty](wiki:ff27b500d93e1d545b7465438a0146e1).
