"""regal -- Rego (OPA policy) lint."""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common

SEVERITY = {"error": "error", "warning": "warning"}
FILES = ("*.rego",)
CONFIG = "optional"
CI_BINARY = "regal"
GUARD = None
# tests/fixtures/tools/capture.log: exit 3 with findings present -- not a
# tool failure.
EXPECT_EXIT = (0, 3)


def detect(tree: Path) -> list[Path]:
    # regal only ever reads this one fixed location relative to the tree
    # it's run against -- nothing to recurse for.
    config = tree / ".regal" / "config.yaml"
    return [config.parent] if config.is_file() else []


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings
    # "." replaces capture.log's fixture-specific "policy" dir.
    proc = ctx.run(["regal", "lint", "--format", "json", "."], cwd=tree)
    fail = _common.check_exit(ctx, tree, "regal", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.emit(ctx, adapters.regal(proc.stdout, SEVERITY), tree, changed, diff_filter=True)
