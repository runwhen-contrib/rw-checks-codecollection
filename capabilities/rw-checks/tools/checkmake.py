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

# checkmake has no severity vocabulary at all -- every rule is a style
# convention about Makefile structure, so this is the whole (degenerate)
# vocabulary.
SEVERITY = {"": "note"}
FILES = ("Makefile",)
CONFIG = "optional"
CI_BINARY = "checkmake"
GUARD = None
# tests/fixtures/tools/capture.log: exit 3 with findings present -- not a
# tool failure.
EXPECT_EXIT = (0, 3)


def detect(tree: Path) -> list[Path]:
    return [p.parent for p in _common.config_files(tree, "checkmake.yml", "checkmake.yaml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings
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
    fail = _common.check_exit(ctx, tree, "checkmake", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.emit(
        ctx, adapters.checkmake(proc.stdout, SEVERITY), tree, changed, diff_filter=True
    )
