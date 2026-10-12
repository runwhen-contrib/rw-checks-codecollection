#!/usr/bin/env python3
"""Exports JSON Schema from the SDK's pydantic models into each capability's
schemas/ directory. Per docs/static-checks/CAPABILITY-CONTRACT.md Part 1:
"Schema is exported, not hand-written -- generated from the SDK's models at
build time so it cannot drift from the code."

Usage: python3 scripts/export_schemas.py   (or `make schemas`)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "sdk"))

from pydantic import TypeAdapter  # noqa: E402
from runwhen_capability.models import (  # noqa: E402
    FindingsResult,
    GrepResult,
    LsResult,
    QueryResult,
    ReadResult,
)

# Schema version for each exported model -- the number in the file's own
# name (`<name>.v<N>.json`) and in the manifest's `schema:` ref that points
# at it. Bump the constant for a model whose shape changed in a way a
# schema consumer must handle differently; the export below then writes a
# NEW file at the next version, and the manifest's `schema:` ref moves to
# it. The old `<name>.v<N>.json` is never edited or deleted once published
# -- see scripts/check_schema_immutability.py, which enforces exactly that
# in CI. This is also where a developer changing one of these models sees
# the version they need to consider bumping.
FINDINGS_RESULT_SCHEMA_VERSION = 1
READ_RESULT_SCHEMA_VERSION = 1
GREP_RESULT_SCHEMA_VERSION = 1
LS_RESULT_SCHEMA_VERSION = 1
QUERY_RESULT_SCHEMA_VERSION = 1

# Which schema files each capability needs, by capability id -- one entry
# per `tasks[].outputs.<name>.schema` the manifest declares. Every task in
# rw-checks declares `outputs.findings.kind: rw.findings.v1, schema:
# ./schemas/findings.v1.json` -- the output is a FindingsResult envelope
# ({findings, truncated}), not a bare list of Finding, so a capped result
# can say so. rw-worktree's read/grep/ls each declare a single `result`
# output with their own kind and schema file, and so does `query`.
CAPABILITY_SCHEMAS: dict[str, dict[str, object]] = {
    "rw-checks": {
        f"findings.v{FINDINGS_RESULT_SCHEMA_VERSION}.json": TypeAdapter(
            FindingsResult
        ).json_schema(),
    },
    "rw-worktree": {
        f"read.v{READ_RESULT_SCHEMA_VERSION}.json": TypeAdapter(ReadResult).json_schema(),
        f"grep.v{GREP_RESULT_SCHEMA_VERSION}.json": TypeAdapter(GrepResult).json_schema(),
        f"ls.v{LS_RESULT_SCHEMA_VERSION}.json": TypeAdapter(LsResult).json_schema(),
        f"query.v{QUERY_RESULT_SCHEMA_VERSION}.json": TypeAdapter(QueryResult).json_schema(),
    },
}


def export_capability_schemas(capability_dir: Path, schemas: dict[str, object]) -> list[Path]:
    out_dir = capability_dir / "schemas"
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for filename, schema in schemas.items():
        out_path = out_dir / filename
        out_path.write_text(json.dumps(schema, indent=2) + "\n")
        written.append(out_path)
    return written


def main() -> None:
    manifests = sorted((REPO_ROOT / "capabilities").glob("*/manifest.yaml"))
    if not manifests:
        print("no capabilities found under capabilities/*/manifest.yaml", file=sys.stderr)
        sys.exit(1)
    for manifest_path in manifests:
        capability_dir = manifest_path.parent
        schemas = CAPABILITY_SCHEMAS.get(capability_dir.name)
        if not schemas:
            print(f"no schemas registered for {capability_dir.name!r}, skipping", file=sys.stderr)
            continue
        for out_path in export_capability_schemas(capability_dir, schemas):
            print(f"wrote {out_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
