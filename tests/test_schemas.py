"""A schema is exported, not hand-written -- generated from the SDK's models
so it cannot drift from the code: every schema file listed under
[tool.rwtask.schemas] in pyproject.toml must match what `rwtask schemas`
would write right now. Without this, a model change (e.g. GrepMatch gaining
before/after) can ship without the `make schemas` re-run it requires.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

import yaml
from runwhen_capability.schemas import load_targets, render

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGETS = load_targets(REPO_ROOT)

# capability name -> the schema file names configured for it
CAPABILITY_SCHEMAS: dict[str, set[str]] = defaultdict(set)
for _target in TARGETS:
    CAPABILITY_SCHEMAS[Path(_target.capability_dir).name].add(_target.filename)

VERSIONED_SCHEMA_NAME = re.compile(r"^[a-z0-9_]+\.v[1-9][0-9]*\.json$")


def test_export_schemas_writes_versioned_filenames():
    """`rwtask schemas` must write <name>.v<N>.json -- the naming
    scripts/check_schema_immutability.py enforces never changes once
    published (see README.md's "Schemas label")."""
    for capability, schemas in CAPABILITY_SCHEMAS.items():
        for filename in schemas:
            assert VERSIONED_SCHEMA_NAME.match(filename), (
                f"{capability}: {filename!r} is not a versioned schema filename"
            )


def test_checked_in_schemas_match_the_current_models():
    stale = []
    for target in TARGETS:
        path = REPO_ROOT / target.relpath
        if not path.is_file() or path.read_text() != render(target, REPO_ROOT):
            stale.append(target.relpath)
    assert stale == [], f"schema(s) out of date with the models, run `make schemas`: {stale}"


def test_every_manifest_schema_reference_is_registered_in_capability_schemas():
    """The drift check above only walks CAPABILITY_SCHEMAS -- it has nothing
    to say about a `tasks[].outputs.*.schema` a manifest references but
    `rwtask schemas` never generates. A hand-written schema file would
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
        f"schema(s) a manifest references but [tool.rwtask.schemas] omits: {unregistered}"
    )
