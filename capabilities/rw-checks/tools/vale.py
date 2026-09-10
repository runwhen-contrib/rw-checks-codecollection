"""vale -- prose lint for docs.

CONFIG is required: vale ships with almost no built-in rules -- without a
`.vale.ini` naming a styles package, there is nothing to actually check.
Its own config is also a fetch-and-execute vector: a non-empty `Packages`
key downloads and installs a style package from a URL -- see guards.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
import guards
from runwhen_capability import Context

from . import _common

SEVERITY = {"error": "error", "warning": "warning", "suggestion": "note"}
FILES = ("*.md", "*.markdown", "*.txt")
CONFIG = "required"
CI_BINARY = "vale"
# A non-empty `Packages` key makes vale download and install a style
# package from a URL before it lints anything.
GUARD = guards.vale
EXPECT_EXIT = (0, 1)


def detect(tree: Path) -> list[Path]:
    return [p.parent for p in _common.config_files(tree, ".vale.ini", "_vale.ini", "vale.ini")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings

    # "." replaces capture.log's fixture-specific "docs" dir.
    proc = ctx.run(["vale", "--output=JSON", "."], cwd=tree)
    fail = _common.check_exit(ctx, tree, "vale", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.emit(ctx, adapters.vale(proc.stdout, SEVERITY), tree, changed)
