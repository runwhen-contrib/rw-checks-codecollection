"""yamllint -- YAML lint.

yamllint recurses on its own, so unlike shellcheck/hadolint it is simply
pointed at the repo root; FILES only gates applicability.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common

SEVERITY = {"error": "error", "warning": "warning"}
FILES = ("*.yml", "*.yaml")
CONFIG = "optional"
CI_BINARY = "yamllint"
GUARD = None
EXPECT_EXIT = (0, 1)


def detect(tree: Path) -> list[Path]:
    return [
        p.parent for p in _common.config_files(tree, ".yamllint", ".yamllint.yml", ".yamllint.yaml")
    ]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings
    # capture.log's `.` is already repo-wide; no fixture-specific path here.
    proc = ctx.run(["yamllint", "-f", "parsable", "."], cwd=tree)
    fail = _common.check_exit(ctx, tree, "yamllint", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.emit(
        ctx, adapters.yamllint(proc.stdout, SEVERITY), tree, changed, diff_filter=True
    )
