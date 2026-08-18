#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("install-release-cohort")


class ReleaseCohortTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        (self.source / "src").mkdir(parents=True)
        (self.source / "Cargo.toml").write_text(
            '[package]\nname = "cohort-fixture"\nversion = "0.1.0"\nedition = "2021"\n'
        )
        (self.source / "src" / "main.rs").write_text("fn main() {}\n")
        subprocess.run(
            ["cargo", "generate-lockfile", "--offline"], cwd=self.source, check=True
        )
        subprocess.run(["git", "init", "-q"], cwd=self.source, check=True)
        subprocess.run(
            ["git", "config", "user.email", "release-test@example.invalid"],
            cwd=self.source,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Release Test"], cwd=self.source, check=True
        )
        subprocess.run(["git", "add", "."], cwd=self.source, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=self.source, check=True)
        self.build = self.root / "build"
        self.build.mkdir()
        self.prefix = self.root / "home" / ".local"
        self.binary("migrations", "fixture migrations")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def binary(self, name: str, content: str) -> None:
        path = self.build / name
        path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{content}'\n")
        path.chmod(0o755)

    def invoke(
        self, generation: str, *extra: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        invocation_env = os.environ.copy()
        invocation_env["PATH"] = os.pathsep.join(
            [str(self.prefix / "bin"), invocation_env.get("PATH", "")]
        )
        if env is not None:
            invocation_env.update(env)
        return subprocess.run(
            [
                str(SCRIPT),
                str(self.build),
                "--source-dir",
                str(self.source),
                "--prefix",
                str(self.prefix),
                "--generation",
                generation,
                "--no-default-features",
                *extra,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=invocation_env,
        )

    def activate(
        self, generation: str, *, path: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = path or os.pathsep.join(
            [str(self.prefix / "bin"), env.get("PATH", "")]
        )
        return subprocess.run(
            [
                str(SCRIPT),
                "--prefix",
                str(self.prefix),
                "--activate-staged",
                generation,
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

    def test_stages_manifest_links_and_atomic_generation_switch(self) -> None:
        self.binary("orient", "first orient")
        self.binary("mail", "first mail")
        staged = self.invoke("first", "--stage-only")
        self.assertEqual(staged.returncode, 0, staged.stderr)

        release = self.prefix / "lib" / "faculties" / "releases" / "first"
        current = self.prefix / "lib" / "faculties" / "current"
        self.assertFalse(os.path.lexists(current))
        activated = self.activate("first")
        self.assertEqual(activated.returncode, 0, activated.stderr)
        self.assertEqual(os.readlink(current), "releases/first")
        self.assertEqual(
            os.readlink(self.prefix / "bin" / "orient"),
            "../lib/faculties/current/bin/orient",
        )
        self.assertEqual(
            os.readlink(self.prefix / "bin" / "faculties-mail"),
            "../lib/faculties/current/bin/mail",
        )
        self.assertFalse(os.path.lexists(self.prefix / "bin" / "mail"))

        manifest = json.loads((release / "manifest.json").read_text())
        self.assertFalse(manifest["cargo"]["default_features"])
        self.assertEqual(manifest["cargo"]["features"], [])
        self.assertEqual(len(manifest["sources"]), 1)
        self.assertEqual(len(manifest["sources"][0]["revision"]), 40)
        self.assertEqual(len(manifest["sources"][0]["tree"]), 40)
        for binary in manifest["binaries"]:
            payload = (release / "bin" / binary["name"]).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), binary["sha256"])

        for path in self.build.iterdir():
            path.unlink()
        self.binary("migrations", "second migrations")
        self.binary("orient", "second orient")
        self.assertEqual(self.invoke("second").returncode, 0)
        self.assertEqual(os.readlink(current), "releases/second")
        self.assertFalse(os.path.lexists(self.prefix / "bin" / "faculties-mail"))
        output = subprocess.run(
            [str(self.prefix / "bin" / "orient")],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertEqual(output, "second orient\n")

    def test_dry_run_writes_nothing(self) -> None:
        self.binary("orient", "dry")
        result = self.invoke("dry", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["generation"], "dry")
        self.assertFalse(self.prefix.exists())

    def test_refuses_build_directory_without_migrations(self) -> None:
        (self.build / "migrations").unlink()
        self.binary("orient", "incomplete")
        result = self.invoke("incomplete", "--dry-run")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required cohort binary is absent", result.stderr)
        self.assertIn("cargo build --release --workspace --bins", result.stderr)
        self.assertFalse(self.prefix.exists())

    def test_refuses_dirty_sources_and_unmanaged_commands(self) -> None:
        self.binary("orient", "one")
        (self.source / "src" / "main.rs").write_text("fn main() { panic!() }\n")
        dirty = self.invoke("dirty")
        self.assertNotEqual(dirty.returncode, 0)
        self.assertIn("source repository is dirty", dirty.stderr)

        (self.source / "src" / "main.rs").write_text("fn main() {}\n")
        (self.prefix / "bin").mkdir(parents=True)
        (self.prefix / "bin" / "orient").write_text("mine\n")
        collision = self.invoke("collision")
        self.assertNotEqual(collision.returncode, 0)
        self.assertIn("refusing to replace unmanaged command", collision.stderr)

    def test_ignores_untracked_build_and_worktree_litter(self) -> None:
        self.binary("orient", "one")
        target = self.source / "target" / "debug"
        target.mkdir(parents=True)
        (target / "generated").write_text("litter\n")
        worktree = self.source / ".claude" / "worktrees" / "agent"
        worktree.mkdir(parents=True)
        (worktree / "scratch.rs").write_text("outside selected checkout\n")
        clean = self.invoke("litter", "--dry-run")
        self.assertEqual(clean.returncode, 0, clean.stderr)

    def test_refuses_activation_when_an_earlier_path_entry_shadows_cohort(self) -> None:
        self.binary("orient", "managed orient")
        staged = self.invoke("shadowed", "--stage-only")
        self.assertEqual(staged.returncode, 0, staged.stderr)

        stale_bin = self.root / "home" / ".cargo" / "bin"
        stale_bin.mkdir(parents=True)
        stale_orient = stale_bin / "orient"
        stale_orient.write_text("#!/bin/sh\nprintf 'stale orient\\n'\n")
        stale_orient.chmod(0o755)
        path = os.pathsep.join(
            [str(stale_bin), str(self.prefix / "bin"), os.environ.get("PATH", "")]
        )

        activated = self.activate("shadowed", path=path)
        self.assertNotEqual(activated.returncode, 0)
        self.assertIn("PATH shadows managed Faculties command 'orient'", activated.stderr)
        self.assertIn(str(stale_orient), activated.stderr)
        self.assertFalse(
            os.path.lexists(self.prefix / "lib" / "faculties" / "current")
        )


if __name__ == "__main__":
    unittest.main()
