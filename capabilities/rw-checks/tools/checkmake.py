"""checkmake -- Makefile lint.

File-gated like shellcheck/hadolint: checkmake lints exactly one file per
invocation and has no directory mode. Unlike those two, this stays pointed
at the conventional top-level Makefile rather than discovering every
Makefile in the tree -- capture.log's `Makefile` is not a fixture-specific
path to generalise away.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common

# checkmake has no severity vocabulary at all -- adapters.checkmake() maps
# every rule to `note` directly. Declared here only to satisfy the
# package-wide contract; adapters.py is the actual source of truth.
SEVERITY = {"": "note"}
FILES = ("Makefile",)
CONFIG = "optional"
CI_BINARY = "checkmake"
GUARD = None


def detect(tree: Path) -> list[Path]:
    return [p.parent for p in _common.config_files(tree, "checkmake.yml", "checkmake.yaml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []
    proc = ctx.run(
        [
            "checkmake",
            # NOTE: a real newline, not "\\n". checkmake applies the template PER
            # ITEM and emits nothing between items, so without a trailing
            # newline every violation lands on one line and the adapter
            # parses exactly one mangled record.
            "--format={{.Rule}}|{{.FileName}}|{{.LineNumber}}|{{.Violation}}\n",
            "Makefile",
        ],
        cwd=tree,
    )
    return _common.emit(ctx, adapters.checkmake(proc.stdout), tree, changed, diff_filter=True)
