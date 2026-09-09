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
from runwhen_capability.models import Finding  # noqa: E402

# Every task in every capability declares `outputs.findings.kind:
# rw.findings.v1`, schema `./schemas/findings.json` -- the output is a list
# of Finding.
FINDINGS_SCHEMA = TypeAdapter(list[Finding]).json_schema()


def export_findings_schema(capability_dir: Path) -> Path:
    out_dir = capability_dir / "schemas"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "findings.json"
    out_path.write_text(json.dumps(FINDINGS_SCHEMA, indent=2) + "\n")
    return out_path


def main() -> None:
    manifests = sorted((REPO_ROOT / "capabilities").glob("*/manifest.yaml"))
    if not manifests:
        print("no capabilities found under capabilities/*/manifest.yaml", file=sys.stderr)
        sys.exit(1)
    for manifest_path in manifests:
        out_path = export_findings_schema(manifest_path.parent)
        print(f"wrote {out_path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
