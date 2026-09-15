"""Guards docs/static-checks/CAPABILITY-CONTRACT.md Part 1's "schema is
exported, not hand-written -- generated from the SDK's models at build time
so it cannot drift from the code" contract: every checked-in
capabilities/*/schemas/*.json file must match what
scripts/export_schemas.py would generate from the SDK's models right now.
Without this, a model change (e.g. GrepMatch gaining before/after) can
ship without the `make schemas` re-run it requires.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from export_schemas import CAPABILITY_SCHEMAS  # noqa: E402


def test_checked_in_schemas_match_the_current_models():
    stale = []
    for capability, schemas in CAPABILITY_SCHEMAS.items():
        for filename, schema in schemas.items():
            path = REPO_ROOT / "capabilities" / capability / "schemas" / filename
            on_disk = json.loads(path.read_text())
            if on_disk != schema:
                stale.append(str(path.relative_to(REPO_ROOT)))
    assert stale == [], f"schema(s) out of date with the models, run `make schemas`: {stale}"


def test_every_manifest_schema_reference_is_registered_in_capability_schemas():
    """The drift check above only walks CAPABILITY_SCHEMAS -- it has nothing
    to say about a `tasks[].outputs.*.schema` a manifest references but
    export_schemas.py never generates. A hand-written schema file would
    pass that check by simply never being compared against anything, so
    this walks the manifests the other way round instead."""
    unregistered = []
    for manifest_path in sorted((REPO_ROOT / "capabilities").glob("*/manifest.yaml")):
        capability = manifest_path.parent.name
        registered = CAPABILITY_SCHEMAS.get(capability, {})
        manifest = yaml.safe_load(manifest_path.read_text())
        for task in manifest.get("tasks", []):
            for output in task.get("outputs", {}).values():
                schema_ref = output.get("schema")
                if schema_ref and Path(schema_ref).name not in registered:
                    unregistered.append(
                        f"{capability}/manifest.yaml task {task['name']!r}: {schema_ref}"
                    )
    assert unregistered == [], (
        f"schema(s) referenced by a manifest but not in CAPABILITY_SCHEMAS: {unregistered}"
    )
