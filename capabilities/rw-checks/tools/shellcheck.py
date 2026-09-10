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
SEVERITY = adapters.SHELLCHECK_SEVERITY
FILES = ("*.sh", "*.bash", "*.ksh")
CONFIG = "optional"
CI_BINARY = "shellcheck"
GUARD = None


def detect(tree: Path) -> list[Path]:
    return [p.parent for p in _common.config_files(tree, ".shellcheckrc")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []
    scripts = _common.find_files(tree, *FILES)
    if not scripts:
        return []
    # json1, not json: json1 is the stable documented shape ({"comments": []}).
    proc = ctx.run(["shellcheck", "-f", "json1", *scripts], cwd=tree)
    return _common.emit(ctx, adapters.shellcheck(proc.stdout), tree, changed, diff_filter=True)
