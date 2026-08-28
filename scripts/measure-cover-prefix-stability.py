#!/usr/bin/env python3
"""Measure context-cover prefix retention under recent-edge journal writes.

Every renderer observes an APFS clone of the same frozen pile state.  Writes go
only to a private sequence clone; renderer piles are replaced from that source
after every write.  This makes differences attributable to the cover algorithm,
not to the live pile moving or independently timestamped commits.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import tempfile


RANGE_LINE = re.compile(
    r"^ {0,2}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"\.\.\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$"
)


class CoverCapacityError(RuntimeError):
    """The mandatory coarsest antichain no longer fits the requested budget."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-pile", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument(
        "--arm",
        action="append",
        required=True,
        metavar="NAME=MEMORY_BIN",
        help="renderer label and exact memory binary; repeatable",
    )
    parser.add_argument("--writer-memory", type=Path, required=True)
    parser.add_argument("--budget", type=int, action="append", required=True)
    parser.add_argument("--writes", type=int, default=30)
    parser.add_argument("--summary-chars", type=int, default=1_300)
    parser.add_argument("--start", default="2026-09-01T00:00:00")
    parser.add_argument("--keep", action="store_true")
    return parser.parse_args()


def clone(source: Path, destination: Path) -> None:
    if destination.exists():
        destination.unlink()
    attempts = [
        ["cp", "-c", str(source), str(destination)],
        ["cp", "--reflink=auto", str(source), str(destination)],
        ["cp", str(source), str(destination)],
    ]
    for command in attempts:
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            return
    raise RuntimeError(
        "could not clone pile: " + attempts[-1][0] + ": " + result.stderr.strip()
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_arm(raw: str) -> tuple[str, Path]:
    name, separator, binary = raw.partition("=")
    if not separator or not name or not binary:
        raise ValueError(f"invalid --arm {raw!r}; expected NAME=MEMORY_BIN")
    return name, Path(binary).resolve(strict=True)


def render(
    binary: Path, pile: Path, key: Path, budget: int
) -> tuple[str, list[str]]:
    before = pile.stat().st_size
    result = subprocess.run(
        [
            str(binary),
            "--pile",
            str(pile),
            "--key",
            str(key),
            "context",
            str(budget),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        if "incomplete cover:" in result.stderr:
            raise CoverCapacityError(result.stderr.strip())
        raise RuntimeError(
            f"{binary} context {budget} failed: {result.stderr.strip()}"
        )
    after = pile.stat().st_size
    if after != before:
        raise RuntimeError(f"read-only render changed {pile}: {before} -> {after}")
    return result.stdout, chunks(result.stdout)


def chunks(rendered: str) -> list[str]:
    lines = rendered.splitlines(keepends=True)
    starts = [index for index, line in enumerate(lines) if RANGE_LINE.fullmatch(line.rstrip("\n"))]
    if not starts:
        raise RuntimeError("cover contains no recognizable range chunks")
    parsed = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        parsed.append("".join(lines[start:end]).rstrip("\n"))
    return parsed


def leading_equal(left: list[str], right: list[str]) -> int:
    retained = 0
    for before, after in zip(left, right):
        if before != after:
            break
        retained += 1
    return retained


def summary(index: int, length: int) -> str:
    prefix = f"cover prefix stability probe {index:02}: "
    if length < len(prefix):
        raise ValueError("--summary-chars is shorter than the probe prefix")
    filler = "0123456789abcdef"
    needed = length - len(prefix)
    return prefix + (filler * ((needed + len(filler) - 1) // len(filler)))[:needed]


def stamp(value: dt.datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S")


def create(
    binary: Path,
    pile: Path,
    key: Path,
    start: dt.datetime,
    index: int,
    length: int,
) -> None:
    end = start + dt.timedelta(seconds=1)
    before = pile.stat().st_size
    result = subprocess.run(
        [
            str(binary),
            "--pile",
            str(pile),
            "--key",
            str(key),
            "create",
            f"{stamp(start)}..{stamp(end)}",
            summary(index, length),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"memory create {index} failed: {result.stderr.strip()}")
    after = pile.stat().st_size
    if after <= before:
        raise RuntimeError(f"memory create {index} appended no bytes")


def describe(
    samples: list[dict[str, object]],
    capacity_failure: dict[str, object] | None,
) -> dict[str, object]:
    percentages = [float(sample["percent"]) for sample in samples]
    result: dict[str, object] = {
        "writes": len(samples),
        "free_writes": sum(bool(sample["free"]) for sample in samples),
        "samples": samples,
    }
    if samples:
        result.update(
            {
                "median_percent": statistics.median(percentages),
                "mean_percent": statistics.fmean(percentages),
                "minimum_percent": min(percentages),
                "minimum_write": min(
                    samples, key=lambda sample: float(sample["percent"])
                )["write"],
            }
        )
    if capacity_failure is not None:
        result["terminal_capacity_failure"] = capacity_failure
    return result


def main() -> int:
    args = parse_args()
    if args.writes <= 0 or args.summary_chars <= 0:
        raise ValueError("--writes and --summary-chars must be positive")
    if any(budget <= 0 for budget in args.budget):
        raise ValueError("--budget must be positive")

    base = args.base_pile.resolve(strict=True)
    key = args.key.resolve(strict=True)
    writer = args.writer_memory.resolve(strict=True)
    arms = dict(parse_arm(raw) for raw in args.arm)
    if len(arms) != len(args.arm):
        raise ValueError("--arm labels must be unique")
    start = dt.datetime.fromisoformat(args.start)

    work = Path(tempfile.mkdtemp(prefix="cover-prefix-stability-"))
    print(f"work directory: {work}", file=sys.stderr, flush=True)
    try:
        frozen = work / "frozen.pile"
        sequence = work / "sequence.pile"
        clone(base, frozen)
        clone(frozen, sequence)
        arm_piles = {name: work / f"{name}.pile" for name in arms}
        for pile in arm_piles.values():
            clone(frozen, pile)

        covers: dict[tuple[str, int], list[str]] = {}
        samples: dict[tuple[str, int], list[dict[str, object]]] = {}
        capacity_failures: dict[tuple[str, int], dict[str, object]] = {}
        for name, binary in arms.items():
            for budget in args.budget:
                first_text, first = render(binary, arm_piles[name], key, budget)
                second_text, second = render(binary, arm_piles[name], key, budget)
                if first_text != second_text or first != second:
                    raise RuntimeError(
                        f"determinism control failed for {name} at budget {budget}"
                    )
                covers[name, budget] = first
                samples[name, budget] = []

        for index in range(1, args.writes + 1):
            create(
                writer,
                sequence,
                key,
                start + dt.timedelta(seconds=2 * (index - 1)),
                index,
                args.summary_chars,
            )
            for pile in arm_piles.values():
                clone(sequence, pile)
            for name, binary in arms.items():
                for budget in args.budget:
                    if (name, budget) in capacity_failures:
                        continue
                    before = covers[name, budget]
                    try:
                        _, after = render(binary, arm_piles[name], key, budget)
                    except CoverCapacityError as error:
                        capacity_failures[name, budget] = {
                            "write": index,
                            "before_chunks": len(before),
                            "error": str(error),
                        }
                        continue
                    retained = leading_equal(before, after)
                    percent = 100.0 if not before else 100.0 * retained / len(before)
                    samples[name, budget].append(
                        {
                            "write": index,
                            "retained": retained,
                            "before_chunks": len(before),
                            "after_chunks": len(after),
                            "percent": percent,
                            "free": retained == len(before),
                        }
                    )
                    covers[name, budget] = after
            progress_items = []
            for budget in args.budget:
                for name in arms:
                    failure = capacity_failures.get((name, budget))
                    if failure is not None:
                        progress_items.append(
                            f"{name}/{budget}=CAPACITY@{failure['write']}"
                        )
                    else:
                        progress_items.append(
                            f"{name}/{budget}={samples[name, budget][-1]['percent']:.2f}%"
                        )
            progress = ", ".join(progress_items)
            print(f"write {index:02}/{args.writes}: {progress}", file=sys.stderr, flush=True)

        report = {
            "base_pile": str(base),
            "base_size": frozen.stat().st_size,
            "writes": args.writes,
            "summary_chars": args.summary_chars,
            "start": args.start,
            "budgets": args.budget,
            "arms": {name: str(binary) for name, binary in arms.items()},
            "binary_sha256": {
                "writer": sha256(writer),
                "arms": {name: sha256(binary) for name, binary in arms.items()},
            },
            "controls": {
                "all_arms_begin_from_identical_clone": True,
                "two_exact_renders_equal_before_writes": True,
                "renders_preserved_pile_size": True,
                "live_pile_never_written": True,
            },
            "results": {
                name: {
                    str(budget): describe(
                        samples[name, budget], capacity_failures.get((name, budget))
                    )
                    for budget in args.budget
                }
                for name in arms
            },
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    finally:
        if args.keep:
            print(f"kept work directory: {work}", file=sys.stderr)
        else:
            shutil.rmtree(work)


if __name__ == "__main__":
    raise SystemExit(main())
