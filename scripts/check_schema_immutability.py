#!/usr/bin/env python3
"""Enforces that a published capability output schema
(`capabilities/*/schemas/<name>.v<N>.json`) never changes or disappears once
it exists. A shape change is a NEW file at the next version, with the
manifest's `schema:` ref moved to it -- see README.md's "Schemas label" for
why: the catalog (cc-catalog-svc) keeps every version an image ever
published, so an old published schema must stay byte-for-byte (modulo
whitespace) resolvable forever.

Two independent checks:

1. Naming -- every file under `capabilities/*/schemas/` in the WORKING TREE
   must match `<name>.v<N>.json` (`N` >= 1). A file that predates this rule
   (an unversioned name) is only allowed to disappear, never to persist
   unrenamed; see `check_naming`.
2. Immutability -- every versioned file that exists at `--base` must still
   exist in the working tree with the same content, compared as canonical
   JSON (`json.dumps(..., sort_keys=True, separators=(",", ":"))`) so a
   whitespace-only reformat is not a violation. Base files that don't match
   the versioned naming pattern are exempt -- that is what lets the first
   versioning change retire the old unversioned names.

An empty, all-zero (`git push` of a brand new branch), or otherwise
unresolvable `--base` is not a failure: there is nothing to compare against,
so this prints a notice and passes.

Usage: python3 scripts/check_schema_immutability.py --base <git-ref>
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# `N` >= 1: v0 is not a valid version, and a leading zero (v01) is rejected
# by [1-9][0-9]* too.
VERSIONED_SCHEMA_NAME = re.compile(r"^[a-z0-9_]+\.v[1-9][0-9]*\.json$")


def canonical_json(text: str) -> str:
    """The comparison form for two schema files' content: same value ==
    identical output, regardless of key order or whitespace."""
    return json.dumps(json.loads(text), sort_keys=True, separators=(",", ":"))


def _git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo_root, capture_output=True, text=True, check=True
    )
    return result.stdout


def resolve_base(base: str, repo_root: Path = REPO_ROOT) -> str | None:
    """Resolves `base` to a commit sha, or None if it is empty, all-zero
    (git's "no commit" sentinel for a new/deleted ref), or not a commit this
    checkout has."""
    if not base or set(base) == {"0"}:
        return None
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def check_naming(repo_root: Path = REPO_ROOT) -> list[str]:
    """Every file under capabilities/*/schemas/ in the working tree must be
    named `<name>.v<N>.json`. Returns one failure message per offender."""
    failures = []
    for path in sorted((repo_root / "capabilities").glob("*/schemas/*")):
        if not path.is_file():
            continue
        if not VERSIONED_SCHEMA_NAME.match(path.name):
            failures.append(
                f"{path.relative_to(repo_root)}: schema filenames must match "
                "<name>.v<N>.json (e.g. findings.v1.json), N >= 1 -- add a "
                "new versioned file rather than shipping an unversioned name"
            )
    return failures


def base_schema_files(base_sha: str, repo_root: Path = REPO_ROOT) -> dict[str, str]:
    """{repo-relative path: file content at base_sha} for every
    capabilities/*/schemas/<name>.v<N>.json file that exists at base_sha.
    Files at base_sha that don't match the versioned naming pattern are
    exempt -- they were never a published, immutable schema."""
    listing = _git(repo_root, "ls-tree", "-r", "--name-only", base_sha, "--", "capabilities")
    files: dict[str, str] = {}
    for line in listing.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("/")
        if len(parts) == 4 and parts[2] == "schemas" and VERSIONED_SCHEMA_NAME.match(parts[3]):
            files[line] = _git(repo_root, "show", f"{base_sha}:{line}")
    return files


def check_immutability(base: str, repo_root: Path = REPO_ROOT) -> list[str]:
    """Runs both checks against repo_root and returns the combined list of
    human-readable failures -- empty means the check passes."""
    failures = check_naming(repo_root)

    base_sha = resolve_base(base, repo_root)
    if base_sha is None:
        print(
            f"check_schema_immutability: base {base!r} is empty, all-zero, or unresolvable "
            "-- nothing to compare against, passing"
        )
        return failures

    for rel_path, base_content in base_schema_files(base_sha, repo_root).items():
        working_path = repo_root / rel_path
        if not working_path.is_file():
            failures.append(
                f"{rel_path}: published schema was deleted -- a published schema file "
                f"never changes or disappears; restore it and add a new "
                f"<name>.v<N+1>.json for the new shape instead"
            )
            continue
        working_content = working_path.read_text(encoding="utf-8")
        if canonical_json(base_content) != canonical_json(working_content):
            failures.append(
                f"{rel_path}: published schema changed -- a published schema file never "
                f"changes; add a new <name>.v<N+1>.json for the new shape instead"
            )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base", required=True, help="git ref/sha to compare the working tree's schemas against"
    )
    parser.add_argument(
        "--repo-root",
        default=str(REPO_ROOT),
        help="repo root to check (default: this script's own repo)",
    )
    args = parser.parse_args(argv)

    failures = check_immutability(args.base, Path(args.repo_root))
    if failures:
        print("check_schema_immutability: FAILED", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("check_schema_immutability: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
