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

SEVERITY = adapters.YAMLLINT_SEVERITY
FILES = ("*.yml", "*.yaml")
CONFIG = "optional"
CI_BINARY = "yamllint"
GUARD = None


def detect(tree: Path) -> list[Path]:
    return [
        p.parent for p in _common.config_files(tree, ".yamllint", ".yamllint.yml", ".yamllint.yaml")
    ]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []
    # capture.log's `.` is already repo-wide; no fixture-specific path here.
    proc = ctx.run(["yamllint", "-f", "parsable", "."], cwd=tree)
    return _common.emit(ctx, adapters.yamllint(proc.stdout), tree, changed, diff_filter=True)
