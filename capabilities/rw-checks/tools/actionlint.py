"""actionlint -- GitHub Actions workflow lint.

Each changed workflow file is handed to actionlint explicitly; the root
.github/actionlint.yaml (if present) is passed via -config-file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common, _plan, _runner

# actionlint has no severity vocabulary at all -- every lint it reports is
# an error-level finding, so this is the whole (degenerate) vocabulary.
SEVERITY = {"error": "error"}
NAME = "actionlint"
KIND = "workflow"
FILES = (".github/workflows/*.yml", ".github/workflows/*.yaml")
CONFIG = "optional"
CONFIG_NAMES = (_plan.ConfigName(".github/actionlint.yaml"),)
CONFIG_SCOPE = "root"
CI_BINARY = "actionlint"
GUARD = None
LANE = "A"  # config is fixed-location; actionlint needs .git in the tree (checkout provides it)
EXPECT_EXIT = (0, 1)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = ["actionlint", "-format", "{{json .}}", "-no-color"]
    if inv.config:
        argv += ["-config-file", inv.config]
    proc = _runner.run(ctx, [*argv, *_runner.files_arg(inv)], cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "actionlint", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.realign_paths(
        _runner.records_to_findings(ctx, tree, inv, adapters.actionlint(proc.stdout, SEVERITY)), inv
    )
