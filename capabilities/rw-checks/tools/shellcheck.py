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

from . import _common, _plan, _runner

# `style` and `info` are advisory -- promoting them would fail a check run on
# a nit. Note hadolint's `info` is NOT this `info`: hence a map per tool.
SEVERITY = {"error": "error", "warning": "warning", "info": "note", "style": "note"}
NAME = "shellcheck"
KIND = "shell script"
FILES = ("*.sh", "*.bash", "*.ksh")
CONFIG = "optional"
CONFIG_NAMES = (_plan.ConfigName(".shellcheckrc"),)
CI_BINARY = "shellcheck"
GUARD = None
LANE = "A"  # shellcheck resolves each script's nearest .shellcheckrc itself (verified)
EXPECT_EXIT = (0, 1)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    # json1, not json: json1 is the stable documented shape ({"comments": []}).
    proc = _runner.run(
        ctx, ["shellcheck", "-f", "json1", *_runner.files_arg(inv)], cwd=_runner.cwd_path(tree, inv)
    )
    fail = _common.check_exit(ctx, tree, "shellcheck", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(ctx, tree, inv, adapters.shellcheck(proc.stdout, SEVERITY))
