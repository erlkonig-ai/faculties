#!/usr/bin/env python3

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("worktree-audit.py")
REAL_GIT = shutil.which("git")


class WorktreeAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.git("init", "-q", "-b", "main", str(self.repo), cwd=self.root)
        self.git("config", "user.email", "audit-test@example.invalid")
        self.git("config", "user.name", "Audit Test")
        (self.repo / "tracked").write_text("initial\n")
        self.git("add", "tracked")
        self.git("commit", "-qm", "initial")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *args: str, cwd: Path | None = None) -> str:
        return subprocess.run(
            [REAL_GIT or "git", *args],
            cwd=cwd or self.repo,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()

    def invoke(
        self, command: str, *extra: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        invocation_env = os.environ.copy()
        if env:
            invocation_env.update(env)
        return subprocess.run(
            [str(SCRIPT), command, *extra, str(self.repo)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=invocation_env,
        )

    def json_records(
        self, *extra: str, env: dict[str, str] | None = None
    ) -> tuple[subprocess.CompletedProcess[str], list[dict]]:
        result = self.invoke("report", "--jsonl", *extra, env=env)
        return result, [json.loads(line) for line in result.stdout.splitlines()]

    def test_quiet_due_and_versioned_report(self) -> None:
        due = self.invoke("due")
        self.assertEqual(due.returncode, 1, due.stderr)
        self.assertEqual(due.stdout, "")

        report, records = self.json_records()
        self.assertEqual(report.returncode, 0, report.stderr)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["schema"], "faculties.worktree-audit")
        self.assertEqual(record["version"], 1)
        self.assertEqual(record["state"], "QUIET")
        self.assertEqual(record["base"]["ref"], "refs/heads/main")
        self.assertEqual(record["base"]["freshness"], "not_checked")
        self.assertEqual(record["remote_freshness"]["status"], "not_checked")
        self.assertEqual(record["live_process_custody"]["status"], "not_checked")
        self.assertEqual(
            {item["kind"] for item in record["lineage"]},
            {"local_head", "worktree_head"},
        )

    def test_reports_custody_sha_tree_aliases_and_nondefinitive_patch_evidence(
        self,
    ) -> None:
        initial = self.git("rev-parse", "HEAD")
        self.git("branch", "same-sha", initial)
        self.git("update-ref", "refs/remotes/origin/witness", initial)

        self.git("checkout", "-qb", "patch", initial)
        (self.repo / "patch").write_text("equivalent change\n")
        self.git("add", "patch")
        self.git("commit", "-qm", "subject patch")
        patch_sha = self.git("rev-parse", "HEAD")
        self.git("checkout", "-q", "main")
        (self.repo / "unrelated").write_text("base-only\n")
        self.git("add", "unrelated")
        self.git("commit", "-qm", "unrelated base change")
        self.git("cherry-pick", patch_sha)
        base = self.git("rev-parse", "HEAD")
        self.git("branch", "same-tree")
        self.git("checkout", "-q", "same-tree")
        self.git("commit", "--allow-empty", "-qm", "different narrative, exact tree")
        self.git("checkout", "-q", "main")

        unusual = self.root / "detached space\nline"
        self.git("worktree", "add", "-q", "--detach", str(unusual), base)
        (unusual / "dirty untracked").write_text("custody\n")

        due = self.invoke("due")
        self.assertEqual(due.returncode, 0, due.stderr)
        report, records = self.json_records()
        self.assertEqual(report.returncode, 0, report.stderr)
        record = records[0]
        self.assertEqual(record["state"], "ATTENTION")
        self.assertFalse(
            any(item["kind"] == "remote_ref" for item in record["lineage"])
        )

        same_sha = next(
            item for item in record["lineage"] if item["name"] == "refs/heads/same-sha"
        )
        self.assertIn(
            "refs/remotes/origin/witness", same_sha["exact_sha_witnesses"]["refs"]
        )

        same_tree = next(
            item for item in record["lineage"] if item["name"] == "refs/heads/same-tree"
        )
        self.assertTrue(same_tree["exact_tree_witnesses"]["base"])
        self.assertNotEqual(same_tree["sha"], record["base"]["sha"])

        patch = next(
            item for item in record["lineage"] if item["name"] == "refs/heads/patch"
        )["patch_evidence"]
        self.assertEqual(patch["status"], "observed")
        self.assertIn(patch_sha, patch["patch_equivalent_subject_commits"])
        self.assertFalse(patch["definitive_landed_disposition"])
        self.assertIn("non-definitive", patch["caveat"])

        detached = next(
            item for item in record["custody"] if item["path"] == str(unusual.resolve())
        )
        self.assertTrue(detached["detached"])
        self.assertTrue(detached["dirty"]["dirty"])
        human = self.invoke("report")
        self.assertIn("detached space\\nline", human.stdout)

    def test_origin_head_precedence_is_exact_and_freshness_is_not_checked(self) -> None:
        head = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", head)
        self.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
        report, records = self.json_records()
        self.assertEqual(report.returncode, 0, report.stderr)
        base = records[0]["base"]
        self.assertEqual(base["ref"], "refs/remotes/origin/HEAD")
        self.assertEqual(base["resolved_ref"], "refs/remotes/origin/main")
        self.assertEqual(base["sha"], head)
        self.assertEqual(base["freshness"], "not_checked")

    def test_non_origin_remote_head_is_a_portable_fork_base(self) -> None:
        head = self.git("rev-parse", "HEAD")
        self.git("branch", "-m", "main", "topic")
        self.git("update-ref", "refs/remotes/fork/main", head)
        self.git("symbolic-ref", "refs/remotes/fork/HEAD", "refs/remotes/fork/main")

        report, records = self.json_records()
        self.assertEqual(report.returncode, 0, report.stderr)
        base = records[0]["base"]
        self.assertEqual(base["ref"], "refs/remotes/fork/HEAD")
        self.assertEqual(base["resolved_ref"], "refs/remotes/fork/main")
        self.assertEqual(base["sha"], head)

    def test_complete_base_precedence_and_explicit_override(self) -> None:
        head = self.git("rev-parse", "HEAD")
        self.git("branch", "master", head)
        self.git("update-ref", "refs/remotes/origin/master", head)
        self.git("update-ref", "refs/remotes/origin/main", head)

        report, records = self.json_records()
        self.assertEqual(report.returncode, 0, report.stderr)
        self.assertEqual(records[0]["base"]["ref"], "refs/remotes/origin/main")

        explicit, records = self.json_records("--base", "refs/heads/master")
        self.assertEqual(explicit.returncode, 0, explicit.stderr)
        self.assertEqual(records[0]["base"]["ref"], "refs/heads/master")
        self.assertEqual(records[0]["base"]["selection"], "explicit")

        self.git("update-ref", "-d", "refs/remotes/origin/main")
        report, records = self.json_records()
        self.assertEqual(report.returncode, 0, report.stderr)
        self.assertEqual(records[0]["base"]["ref"], "refs/heads/main")

        self.git("branch", "-m", "main", "topic")
        report, records = self.json_records()
        self.assertEqual(report.returncode, 0, report.stderr)
        self.assertEqual(records[0]["base"]["ref"], "refs/remotes/origin/master")

        self.git("update-ref", "-d", "refs/remotes/origin/master")
        report, records = self.json_records()
        self.assertEqual(report.returncode, 0, report.stderr)
        self.assertEqual(records[0]["base"]["ref"], "refs/heads/master")

    def test_unresolved_base_is_indeterminate(self) -> None:
        other = self.root / "no-base"
        self.git("init", "-q", "-b", "topic", str(other), cwd=self.root)
        self.git("config", "user.email", "audit-test@example.invalid", cwd=other)
        self.git("config", "user.name", "Audit Test", cwd=other)
        (other / "file").write_text("one\n")
        self.git("add", "file", cwd=other)
        self.git("commit", "-qm", "topic", cwd=other)
        result = subprocess.run(
            [str(SCRIPT), "report", "--jsonl", str(other)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 126)
        record = json.loads(result.stdout)
        self.assertEqual(record["state"], "INDETERMINATE")
        self.assertIn("base unresolved", record["diagnostic"])

    def test_malformed_arguments_are_indeterminate_not_silently_not_due(self) -> None:
        result = self.invoke("due", "--definitely-not-an-option")
        self.assertEqual(result.returncode, 126)
        self.assertEqual(result.stdout, "")
        self.assertIn("invalid arguments", result.stderr)

    def test_ambient_git_repository_selection_is_ignored(self) -> None:
        other = self.root / "ambient"
        self.git("init", "-q", "-b", "main", str(other), cwd=self.root)
        self.git("config", "user.email", "audit-test@example.invalid", cwd=other)
        self.git("config", "user.name", "Audit Test", cwd=other)
        (other / "tracked").write_text("ambient clean\n")
        self.git("add", "tracked", cwd=other)
        self.git("commit", "-qm", "ambient", cwd=other)
        (self.repo / "dirty-target").write_text("must be observed\n")

        report, records = self.json_records(
            env={
                "GIT_DIR": str(other / ".git"),
                "GIT_WORK_TREE": str(other),
                "GIT_INDEX_FILE": str(other / ".git" / "index"),
            }
        )
        self.assertEqual(report.returncode, 0, report.stderr)
        self.assertEqual(records[0]["repository"], str(self.repo.resolve()))
        self.assertEqual(records[0]["state"], "ATTENTION")
        target = next(
            item
            for item in records[0]["custody"]
            if item["path"] == str(self.repo.resolve())
        )
        self.assertTrue(target["dirty"]["dirty"])

    def test_ref_race_is_reported_and_exits_126(self) -> None:
        shim = self.root / "shim"
        shim.mkdir()
        counter = self.root / "ref-count"
        head = self.git("rev-parse", "HEAD")
        wrapper = shim / "git"
        wrapper.write_text(
            "#!/bin/sh\n"
            "[ \"${GIT_OPTIONAL_LOCKS:-}\" = 0 ] || exit 98\n"
            f"real={shlex.quote(REAL_GIT or 'git')}\n"
            f"counter={shlex.quote(str(counter))}\n"
            "case \" $* \" in\n"
            "  *\\ for-each-ref\\ *)\n"
            "    n=0; [ ! -f \"$counter\" ] || n=$(cat \"$counter\")\n"
            "    n=$((n + 1)); printf '%s' \"$n\" > \"$counter\"\n"
            "    \"$real\" \"$@\"; rc=$?\n"
            f"    [ \"$n\" -lt 2 ] || printf 'refs/heads/raced\\t{head}\\t\\n'\n"
            "    exit \"$rc\";;\n"
            "esac\n"
            "exec \"$real\" \"$@\"\n"
        )
        wrapper.chmod(0o755)
        env = {"PATH": os.pathsep.join([str(shim), os.environ.get("PATH", "")])}
        report, records = self.json_records(env=env)
        self.assertEqual(report.returncode, 126, report.stderr)
        self.assertEqual(records[0]["state"], "RACED")

    def test_worktree_dirtiness_race_is_reported_and_exits_126(self) -> None:
        shim = self.root / "status-shim"
        shim.mkdir()
        counter = self.root / "status-count"
        wrapper = shim / "git"
        wrapper.write_text(
            "#!/bin/sh\n"
            f"real={shlex.quote(REAL_GIT or 'git')}\n"
            f"counter={shlex.quote(str(counter))}\n"
            "case \" $* \" in\n"
            "  *\\ status\\ *)\n"
            "    n=0; [ ! -f \"$counter\" ] || n=$(cat \"$counter\")\n"
            "    n=$((n + 1)); printf '%s' \"$n\" > \"$counter\"\n"
            "    if [ \"$n\" -eq 2 ]; then printf '? raced\\0'; exit 0; fi;;\n"
            "esac\n"
            "exec \"$real\" \"$@\"\n"
        )
        wrapper.chmod(0o755)
        env = {"PATH": os.pathsep.join([str(shim), os.environ.get("PATH", "")])}
        report, records = self.json_records(env=env)
        self.assertEqual(report.returncode, 126, report.stderr)
        self.assertEqual(records[0]["state"], "RACED")
        self.assertIn("dirtiness changed", records[0]["diagnostic"])

    def test_every_git_command_has_optional_locks_disabled_and_is_read_only(
        self,
    ) -> None:
        shim = self.root / "logging-shim"
        shim.mkdir()
        log = self.root / "git-log"
        wrapper = shim / "git"
        wrapper.write_text(
            "#!/bin/sh\n"
            "[ \"${GIT_OPTIONAL_LOCKS:-}\" = 0 ] || exit 98\n"
            "[ \"${GIT_NO_LAZY_FETCH:-}\" = 1 ] || exit 97\n"
            f"printf '%s\\0' \"$@\" >> {shlex.quote(str(log))}\n"
            f"printf '\\n' >> {shlex.quote(str(log))}\n"
            f"exec {shlex.quote(REAL_GIT or 'git')} \"$@\"\n"
        )
        wrapper.chmod(0o755)
        env = {"PATH": os.pathsep.join([str(shim), os.environ.get("PATH", "")])}
        report = self.invoke("report", "--jsonl", env=env)
        self.assertEqual(report.returncode, 0, report.stderr)
        allowed = {
            "cherry",
            "for-each-ref",
            "merge-base",
            "rev-list",
            "rev-parse",
            "status",
            "worktree",
        }
        for raw_invocation in log.read_bytes().split(b"\n"):
            arguments = [part.decode() for part in raw_invocation.split(b"\0") if part]
            if not arguments:
                continue
            self.assertEqual(arguments[0], "-C")
            self.assertIn(arguments[2], allowed)
            if arguments[2] == "worktree":
                self.assertEqual(arguments[3], "list")


if __name__ == "__main__":
    unittest.main()
