"""Guards docs/static-checks/CAPABILITY-CONTRACT.md Part 1's "schema is
exported, not hand-written -- generated from the SDK's models at build time
so it cannot drift from the code" contract: every checked-in
capabilities/*/schemas/*.json file must match what
scripts/export_schemas.py would generate from the SDK's models right now.
Without this, a model change (e.g. GrepMatch gaining before/after,
RW-1416 cost P2) can ship without the `make schemas` re-run it requires.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

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
