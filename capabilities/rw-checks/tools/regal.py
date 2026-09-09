"""regal -- Rego (OPA policy) lint."""

from __future__ import annotations

import sys
from pathlib import Path

import _common
import adapters
from runwhen_capability import Context

SEVERITY = adapters.REGAL_SEVERITY
FILES = ("*.rego",)
CONFIG = "optional"
CI_BINARY = "regal"
GUARD = None


def detect(tree: Path) -> list[Path]:
    # regal only ever reads this one fixed location relative to the tree
    # it's run against -- nothing to recurse for.
    config = tree / ".regal" / "config.yaml"
    return [config.parent] if config.is_file() else []


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []
    # "." replaces capture.log's fixture-specific "policy" dir.
    proc = ctx.run(["regal", "lint", "--format", "json", "."], cwd=tree)
    return _common.emit(ctx, adapters.regal(proc.stdout), tree, changed, diff_filter=True)
