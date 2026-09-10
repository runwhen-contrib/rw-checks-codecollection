"""ShellCheck -- shell script defects.

File-gated: shellcheck has no directory-recursion mode, so it must be handed
every target explicitly, and a repo with no shell scripts is simply not
applicable.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common

# `style` and `info` are advisory -- promoting them would fail a check run on
# a nit. Note hadolint's `info` is NOT this `info`: hence a map per tool.
SEVERITY = {"error": "error", "warning": "warning", "info": "note", "style": "note"}
FILES = ("*.sh", "*.bash", "*.ksh")
CONFIG = "optional"
CI_BINARY = "shellcheck"
GUARD = None
EXPECT_EXIT = (0, 1)


def detect(tree: Path) -> list[Path]:
    return [p.parent for p in _common.config_files(tree, ".shellcheckrc")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings
    scripts = _common.find_files(tree, *FILES)
    if not scripts:
        return []
    # json1, not json: json1 is the stable documented shape ({"comments": []}).
    proc = ctx.run(["shellcheck", "-f", "json1", *scripts], cwd=tree)
    fail = _common.check_exit(ctx, tree, "shellcheck", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.emit(ctx, adapters.shellcheck(proc.stdout, SEVERITY), tree, changed)
