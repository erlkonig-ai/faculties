#!/usr/bin/env python3
"""Read-only, race-detecting evidence for branch and worktree hygiene.

The JSON Lines interface is versioned by ``FORMAT_VERSION``.  This program is
deliberately incapable of cleanup: its only commands are ``report`` and
``due``, and every Git operation is checked against a read-only allow-list.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Iterable


FORMAT_NAME = "faculties.worktree-audit"
FORMAT_VERSION = 1
INDETERMINATE = 126
PATCH_COMMIT_LIMIT = 256
READ_ONLY_GIT_COMMANDS = frozenset(
    {
        "cherry",
        "for-each-ref",
        "merge-base",
        "rev-list",
        "rev-parse",
        "status",
        "worktree",
    }
)


class AuditFailure(RuntimeError):
    state = "INDETERMINATE"


class AuditRace(AuditFailure):
    state = "RACED"


def display_bytes(value: bytes) -> str:
    return os.fsdecode(value)


def quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


class Git:
    def __init__(self, repository: Path) -> None:
        self.repository = repository
        # `git -C` does not override repository-selection variables inherited
        # from the caller.  A stray GIT_DIR/GIT_WORK_TREE (or alternate object
        # database/index) could therefore make an audit named for repository A
        # inspect repository B.  Start from the ordinary process environment,
        # but make every Git-specific input an explicit choice below.
        self.environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        self.environment["GIT_OPTIONAL_LOCKS"] = "0"
        # A partial clone may otherwise fetch an absent object as a side effect
        # of an apparently read-only ancestry/tree query.
        self.environment["GIT_NO_LAZY_FETCH"] = "1"
        self.environment["GIT_NO_REPLACE_OBJECTS"] = "1"
        self.environment["LC_ALL"] = "C"

    def run(
        self,
        *arguments: str,
        at: Path | None = None,
        allowed: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess[bytes]:
        if not arguments or arguments[0] not in READ_ONLY_GIT_COMMANDS:
            raise AssertionError(f"non-read-only Git command refused: {arguments!r}")
        if arguments[0] == "worktree" and arguments[1:2] != ("list",):
            raise AssertionError(
                f"mutating Git worktree command refused: {arguments!r}"
            )
        location = at if at is not None else self.repository
        try:
            result = subprocess.run(
                ["git", "-C", os.fspath(location), *arguments],
                env=self.environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as error:
            raise AuditFailure(f"could not run git: {error}") from error
        if result.returncode not in allowed:
            detail = result.stderr.decode("utf-8", "replace").strip()
            rendered = " ".join(arguments)
            raise AuditFailure(
                f"git {rendered} failed with {result.returncode}"
                + (f": {detail}" if detail else "")
            )
        return result

    def refs(self) -> dict[str, dict[str, str | None]]:
        result = self.run(
            "for-each-ref",
            "--format=%(refname)%09%(objectname)%09%(symref)",
            "refs/heads",
            "refs/remotes",
        )
        refs: dict[str, dict[str, str | None]] = {}
        for raw_line in result.stdout.splitlines():
            fields = raw_line.split(b"\t")
            if len(fields) != 3 or not fields[0] or not fields[1]:
                raise AuditFailure("git for-each-ref returned malformed output")
            ref = display_bytes(fields[0])
            if ref in refs:
                raise AuditFailure(f"git for-each-ref repeated {ref!r}")
            refs[ref] = {
                "sha": fields[1].decode("ascii", "strict"),
                "symref": display_bytes(fields[2]) if fields[2] else None,
            }
        return refs

    def worktrees_raw(self) -> bytes:
        return self.run("worktree", "list", "--porcelain", "-z").stdout


def parse_worktrees(raw: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    record: dict[str, Any] = {}
    for field in raw.split(b"\0"):
        if not field:
            if record:
                if "path" not in record:
                    raise AuditFailure("worktree record has no path")
                if not record.get("bare") and "head" not in record:
                    raise AuditFailure("non-bare worktree record has no HEAD")
                records.append(record)
                record = {}
            continue
        key_bytes, separator, value = field.partition(b" ")
        try:
            key = key_bytes.decode("ascii")
        except UnicodeDecodeError as error:
            raise AuditFailure("worktree record has a non-ASCII field name") from error
        if key == "worktree" and separator:
            if record:
                raise AuditFailure("worktree record is missing its separator")
            record["path"] = display_bytes(value)
        elif key == "HEAD" and separator:
            record["head"] = value.decode("ascii", "strict")
        elif key == "branch" and separator:
            record["branch"] = display_bytes(value)
        elif key == "detached" and not separator:
            record["detached"] = True
        elif key == "bare" and not separator:
            record["bare"] = True
        elif key in {"locked", "prunable"}:
            record[key] = display_bytes(value) if separator else True
        else:
            raise AuditFailure(f"unknown git worktree field {display_bytes(field)!r}")
    if record:
        raise AuditFailure("unterminated git worktree record")
    return records


def resolve_explicit_base(git: Git, value: str) -> tuple[str, str, str | None]:
    expression = f"{value}^{{commit}}"
    result = git.run(
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        expression,
        allowed=(0, 1),
    )
    if result.returncode != 0:
        raise AuditFailure(f"explicit base {value!r} does not resolve to a commit")
    sha = result.stdout.decode("ascii", "strict").strip()
    symbolic = git.run(
        "rev-parse",
        "--symbolic-full-name",
        "--verify",
        "--quiet",
        "--end-of-options",
        value,
        allowed=(0, 1),
    )
    resolved_ref = symbolic.stdout.decode("utf-8", "surrogateescape").strip() or None
    return value, sha, resolved_ref


def select_base(
    git: Git, refs: dict[str, dict[str, str | None]], explicit: str | None
) -> dict[str, Any]:
    if explicit is not None:
        observed, sha, resolved = resolve_explicit_base(git, explicit)
        return {
            "ref": observed,
            "resolved_ref": resolved,
            "sha": sha,
            "selection": "explicit",
            "freshness": "not_checked",
        }

    remote_heads = sorted(
        ref
        for ref, entry in refs.items()
        if ref.startswith("refs/remotes/")
        and ref.endswith("/HEAD")
        and entry["symref"] is not None
        and ref != "refs/remotes/origin/HEAD"
    )
    remote_mains = sorted(
        ref
        for ref in refs
        if ref.startswith("refs/remotes/")
        and ref.endswith("/main")
        and ref != "refs/remotes/origin/main"
    )
    remote_masters = sorted(
        ref
        for ref in refs
        if ref.startswith("refs/remotes/")
        and ref.endswith("/master")
        and ref != "refs/remotes/origin/master"
    )
    precedence = [
        "refs/remotes/origin/HEAD",
        *remote_heads,
        "refs/remotes/origin/main",
        "refs/heads/main",
        *remote_mains,
        "refs/remotes/origin/master",
        "refs/heads/master",
        *remote_masters,
    ]
    for ref in precedence:
        if ref in refs:
            return {
                "ref": ref,
                "resolved_ref": refs[ref]["symref"] or ref,
                "sha": refs[ref]["sha"],
                "selection": "automatic",
                "freshness": "not_checked",
            }
    raise AuditFailure(
        "base unresolved (tried every remote HEAD plus conventional main/master refs)"
    )


def primary_local_ref(base: dict[str, Any]) -> str | None:
    ref = base.get("resolved_ref") or base["ref"]
    if ref.startswith("refs/heads/"):
        return ref
    prefix = "refs/remotes/"
    if ref.startswith(prefix):
        remote_and_branch = ref[len(prefix) :]
        _, separator, branch = remote_and_branch.partition("/")
        if separator:
            return "refs/heads/" + branch
    return None


def dirty_state(git: Git, worktree: dict[str, Any]) -> dict[str, Any]:
    if worktree.get("bare"):
        return {"status": "not_applicable", "dirty": None}
    if "prunable" in worktree:
        return {
            "status": "unavailable",
            "dirty": None,
            "reason": "registered worktree is marked prunable",
        }
    output = git.run(
        "status",
        "--porcelain=v2",
        "-z",
        "--untracked-files=normal",
        at=Path(worktree["path"]),
    ).stdout
    return {"status": "observed", "dirty": bool(output)}


def is_ancestor(git: Git, older: str, newer: str) -> bool:
    result = git.run("merge-base", "--is-ancestor", older, newer, allowed=(0, 1))
    return result.returncode == 0


def tree_of(git: Git, sha: str) -> str:
    result = git.run("rev-parse", "--verify", "--end-of-options", f"{sha}^{{tree}}")
    return result.stdout.decode("ascii", "strict").strip()


PATCH_CAVEAT = (
    "git cherry patch equivalence is non-definitive: it does not establish "
    "semantic equivalence, preserve commit narrative, or authorize disposition"
)


def patch_evidence(git: Git, base: str, subject: str) -> dict[str, Any]:
    if base == subject:
        return {
            "status": "not_applicable",
            "reason": "subject is the exact base commit",
            "definitive_landed_disposition": False,
            "caveat": PATCH_CAVEAT,
        }
    # Cap the census itself. An omitted patch comparison must not first walk an
    # unbounded history merely to discover that it should be omitted.
    census_cap = PATCH_COMMIT_LIMIT + 1
    subject_only = int(
        git.run(
            "rev-list",
            "--count",
            f"--max-count={census_cap}",
            f"{base}..{subject}",
        ).stdout.strip()
        or b"0"
    )
    if subject_only == 0:
        return {
            "status": "not_applicable",
            "reason": "exact ancestry leaves no subject-only commits",
            "subject_only_commits": 0,
            "definitive_landed_disposition": False,
            "caveat": PATCH_CAVEAT,
        }
    base_only = int(
        git.run(
            "rev-list",
            "--count",
            f"--max-count={census_cap}",
            f"{subject}..{base}",
        ).stdout.strip()
        or b"0"
    )
    if subject_only + base_only > PATCH_COMMIT_LIMIT:
        return {
            "status": "not_checked",
            "reason": (
                f"comparison spans at least {subject_only + base_only} one-sided commits, "
                f"over the {PATCH_COMMIT_LIMIT}-commit audit bound"
            ),
            "subject_only_commits": subject_only,
            "base_only_commits": base_only,
            "definitive_landed_disposition": False,
            "caveat": PATCH_CAVEAT,
        }
    result = git.run("cherry", base, subject)
    equivalent: list[str] = []
    distinct: list[str] = []
    for line in result.stdout.splitlines():
        if len(line) < 3 or line[:1] not in {b"+", b"-"} or line[1:2] != b" ":
            raise AuditFailure("git cherry returned malformed output")
        sha = line[2:].decode("ascii", "strict")
        (equivalent if line[:1] == b"-" else distinct).append(sha)
    return {
        "status": "observed",
        "method": "git cherry with exact observed base and subject SHAs",
        "subject_only_commits": subject_only,
        "base_only_commits": base_only,
        "patch_equivalent_subject_commits": equivalent,
        "patch_distinct_subject_commits": distinct,
        "definitive_landed_disposition": False,
        "caveat": PATCH_CAVEAT,
    }


def lineage_state(
    subject: str, base: str, subject_is_ancestor: bool, base_is_ancestor: bool
) -> str:
    if subject == base:
        return "exact_base"
    if subject_is_ancestor:
        return "ancestor_of_base"
    if base_is_ancestor:
        return "descendant_of_base"
    return "diverged"


def make_subjects(
    refs: dict[str, dict[str, str | None]], worktrees: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    subjects: list[dict[str, Any]] = []
    for ref in sorted(name for name in refs if name.startswith("refs/heads/")):
        subjects.append({"kind": "local_head", "name": ref, "sha": refs[ref]["sha"]})
    for index, worktree in enumerate(worktrees):
        if worktree.get("bare"):
            continue
        subjects.append(
            {
                "kind": "worktree_head",
                "name": f"HEAD@{index}",
                "path": worktree["path"],
                "branch": worktree.get("branch"),
                "detached": bool(worktree.get("detached")),
                "sha": worktree["head"],
            }
        )
    return subjects


def audit_repository(repository: Path, explicit_base: str | None) -> dict[str, Any]:
    git = Git(repository)
    refs_before = git.refs()
    worktrees_raw_before = git.worktrees_raw()
    worktrees = parse_worktrees(worktrees_raw_before)
    base = select_base(git, refs_before, explicit_base)

    custody: list[dict[str, Any]] = []
    for worktree in worktrees:
        observed = dict(worktree)
        observed["dirty"] = dirty_state(git, worktree)
        custody.append(observed)

    subjects = make_subjects(refs_before, worktrees)
    all_shas = {subject["sha"] for subject in subjects}
    all_shas.update(entry["sha"] for entry in refs_before.values())
    all_shas.add(base["sha"])
    trees = {sha: tree_of(git, sha) for sha in sorted(all_shas)}

    refs_by_sha: dict[str, list[str]] = {}
    refs_by_tree: dict[str, list[str]] = {}
    for ref, entry in refs_before.items():
        refs_by_sha.setdefault(str(entry["sha"]), []).append(ref)
        refs_by_tree.setdefault(trees[str(entry["sha"])], []).append(ref)
    worktrees_by_sha: dict[str, list[str]] = {}
    worktrees_by_tree: dict[str, list[str]] = {}
    for worktree in worktrees:
        if worktree.get("bare"):
            continue
        worktrees_by_sha.setdefault(worktree["head"], []).append(worktree["path"])
        worktrees_by_tree.setdefault(trees[worktree["head"]], []).append(
            worktree["path"]
        )

    ancestry_cache: dict[str, tuple[bool, bool]] = {}
    patch_cache: dict[str, dict[str, Any]] = {}
    lineage: list[dict[str, Any]] = []
    for subject in subjects:
        sha = subject["sha"]
        if sha not in ancestry_cache:
            ancestry_cache[sha] = (
                is_ancestor(git, sha, base["sha"]),
                is_ancestor(git, base["sha"], sha),
            )
        if sha not in patch_cache:
            patch_cache[sha] = patch_evidence(git, base["sha"], sha)
        subject_is_ancestor, base_is_ancestor = ancestry_cache[sha]
        item = dict(subject)
        item.update(
            {
                "state": lineage_state(
                    sha, base["sha"], subject_is_ancestor, base_is_ancestor
                ),
                "subject_is_ancestor_of_base": subject_is_ancestor,
                "base_is_ancestor_of_subject": base_is_ancestor,
                "exact_sha_witnesses": {
                    "refs": sorted(refs_by_sha.get(sha, [])),
                    "worktrees": sorted(worktrees_by_sha.get(sha, [])),
                },
                "tree": trees[sha],
                "exact_tree_witnesses": {
                    "base": trees[sha] == trees[base["sha"]],
                    "refs": sorted(refs_by_tree.get(trees[sha], [])),
                    "worktrees": sorted(worktrees_by_tree.get(trees[sha], [])),
                },
                "patch_evidence": patch_cache[sha],
            }
        )
        lineage.append(item)

    refs_after = git.refs()
    worktrees_raw_after = git.worktrees_raw()
    if refs_after != refs_before or worktrees_raw_after != worktrees_raw_before:
        raise AuditRace("refs or registered worktree HEADs changed during the audit")
    worktrees_after = parse_worktrees(worktrees_raw_after)
    dirty_after = [dirty_state(git, worktree) for worktree in worktrees_after]
    dirty_before = [worktree["dirty"] for worktree in custody]
    if dirty_after != dirty_before:
        raise AuditRace("worktree or index dirtiness changed during the audit")
    if explicit_base is not None:
        _, final_sha, final_ref = resolve_explicit_base(git, explicit_base)
        if final_sha != base["sha"] or final_ref != base["resolved_ref"]:
            raise AuditRace("explicit base changed during the audit")

    primary = primary_local_ref(base)
    attention: list[str] = []
    for worktree in custody:
        dirty = worktree["dirty"]
        if dirty["status"] == "unavailable":
            attention.append(f"unavailable custody at {worktree['path']!r}")
        elif dirty.get("dirty"):
            attention.append(f"dirty custody at {worktree['path']!r}")
        if worktree.get("detached"):
            attention.append(f"detached HEAD at {worktree['path']!r}")
    for subject in lineage:
        if subject["kind"] != "local_head":
            continue
        if subject["name"] == primary and subject["sha"] == base["sha"]:
            continue
        attention.append(
            f"local head {subject['name']} is {subject['state']} relative to base"
        )

    repository_name = worktrees[0]["path"] if worktrees else os.fspath(repository)
    return {
        "schema": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "type": "repository",
        "repository": repository_name,
        "state": "ATTENTION" if attention else "QUIET",
        "base": base,
        "remote_freshness": {
            "status": "not_checked",
            "reason": "the audit never fetches or contacts a remote",
        },
        "live_process_custody": {
            "status": "not_checked",
            "reason": "portable live-process ownership is not inferred from Git metadata",
        },
        "custody": custody,
        "lineage": lineage,
        "attention": attention,
    }


def discover_repositories(root: Path, explicit: Iterable[str]) -> list[Path]:
    supplied = [Path(path).expanduser() for path in explicit]
    if supplied:
        return supplied
    root = root.expanduser()
    if (root / ".git").exists():
        return [root]
    try:
        children = sorted(root.iterdir(), key=lambda path: os.fsencode(path.name))
    except OSError as error:
        raise AuditFailure(f"cannot inspect audit root {root}: {error}") from error
    # Default workspace discovery intentionally selects main checkouts. Linked
    # worktrees normally carry a .git *file* and are inventoried by their main
    # repository's `git worktree list`, avoiding duplicate audits.
    repositories = [child for child in children if (child / ".git").is_dir()]
    if not repositories:
        raise AuditFailure(f"no Git repositories found directly under {root}")
    return repositories


def failure_record(repository: Path | None, error: AuditFailure) -> dict[str, Any]:
    return {
        "schema": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "type": "repository" if repository is not None else "audit",
        "repository": os.fspath(repository) if repository is not None else None,
        "state": error.state,
        "diagnostic": str(error),
    }


def emit_jsonl(records: list[dict[str, Any]]) -> None:
    for record in records:
        print(
            json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        )


def emit_human(records: list[dict[str, Any]]) -> None:
    print(f"worktree-audit format v{FORMAT_VERSION} (strictly read-only)")
    for record in records:
        repository = record.get("repository")
        print()
        print(
            f"repository {quote(repository) if repository is not None else '<audit>'}"
        )
        print(f"  state: {record['state']}")
        if record["state"] in {"INDETERMINATE", "RACED"}:
            print(f"  diagnostic: {record['diagnostic']}")
            continue
        base = record["base"]
        print(
            f"  base: {base['ref']} @ {base['sha']}"
            + (
                f" (resolved {base['resolved_ref']})"
                if base["resolved_ref"] != base["ref"]
                else ""
            )
        )
        print("  remote freshness: NOT CHECKED (this audit never fetches)")
        print("  live-process custody: NOT CHECKED")
        print("  custody:")
        for custody in record["custody"]:
            dirty = custody["dirty"]
            if dirty["status"] == "observed":
                condition = "DIRTY" if dirty["dirty"] else "clean"
            else:
                condition = dirty["status"].upper()
            branch = custody.get("branch") or "(detached)"
            print(
                f"    {condition:11} {branch} @ {custody.get('head', '-')} "
                f"path={quote(custody['path'])}"
            )
        print("  lineage (custody-independent):")
        for subject in record["lineage"]:
            identity = subject["name"]
            if subject["kind"] == "worktree_head":
                identity += f" path={quote(subject['path'])}"
            print(f"    {subject['state']:18} {identity} @ {subject['sha']}")
            sha_refs = subject["exact_sha_witnesses"]["refs"]
            tree_refs = subject["exact_tree_witnesses"]["refs"]
            print(f"      exact-SHA ref witnesses: {', '.join(sha_refs) or 'none'}")
            print(
                f"      tree {subject['tree']} · exact-tree ref witnesses: "
                f"{', '.join(tree_refs) or 'none'}"
            )
            patch = subject["patch_evidence"]
            if patch["status"] == "observed":
                print(
                    "      patch evidence (NON-DEFINITIVE): "
                    f"{len(patch['patch_equivalent_subject_commits'])} equivalent, "
                    f"{len(patch['patch_distinct_subject_commits'])} distinct"
                )
            else:
                print(
                    f"      patch evidence (NON-DEFINITIVE): {patch['status']} — "
                    f"{patch['reason']}"
                )
        if record["attention"]:
            print("  attention:")
            for reason in record["attention"]:
                print(f"    - {reason}")


def build_parser() -> argparse.ArgumentParser:
    class AuditArgumentParser(argparse.ArgumentParser):
        def error(self, message: str) -> None:
            raise AuditFailure(f"invalid arguments: {message}")

    parser = AuditArgumentParser(
        description="Produce read-only branch/worktree custody and lineage evidence"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("report", "due"):
        command = commands.add_parser(name)
        command.add_argument(
            "--jsonl", action="store_true", help="emit versioned JSON Lines"
        )
        command.add_argument(
            "--base",
            help="explicit base revision (otherwise use the documented precedence)",
        )
        command.add_argument(
            "--root",
            default=os.environ.get("WORKTREE_AUDIT_ROOT", "."),
            help="workspace root used when no repositories are named (default: current directory)",
        )
        command.add_argument("repositories", nargs="*")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except AuditFailure as error:
        print(f"worktree-audit: {error}", file=sys.stderr)
        return INDETERMINATE
    records: list[dict[str, Any]] = []
    try:
        repositories = discover_repositories(Path(args.root), args.repositories)
    except AuditFailure as error:
        records.append(failure_record(None, error))
    else:
        for repository in repositories:
            try:
                records.append(audit_repository(repository, args.base))
            except AuditFailure as error:
                records.append(failure_record(repository, error))
            except (OSError, UnicodeError, ValueError) as error:
                records.append(
                    failure_record(
                        repository,
                        AuditFailure(
                            f"could not interpret repository evidence: {error}"
                        ),
                    )
                )

    if args.jsonl:
        emit_jsonl(records)
    elif args.command == "report":
        emit_human(records)

    if any(record["state"] in {"INDETERMINATE", "RACED"} for record in records):
        return INDETERMINATE
    if args.command == "due":
        return 0 if any(record["state"] == "ATTENTION" for record in records) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
