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
    Finding,
    GrepResult,
    LsResult,
    ReadResult,
)

# Which schema files each capability needs, by capability id -- one entry
# per `tasks[].outputs.<name>.schema` the manifest declares. Every task in
# rw-checks declares `outputs.findings.kind: rw.findings.v1, schema:
# ./schemas/findings.json` -- the output is a list of Finding. rw-worktree's
# read/grep/ls each declare a single `result` output with their own kind
# and schema file.
CAPABILITY_SCHEMAS: dict[str, dict[str, object]] = {
    "rw-checks": {
        "findings.json": TypeAdapter(list[Finding]).json_schema(),
    },
    "rw-worktree": {
        "read.json": TypeAdapter(ReadResult).json_schema(),
        "grep.json": TypeAdapter(GrepResult).json_schema(),
        "ls.json": TypeAdapter(LsResult).json_schema(),
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
