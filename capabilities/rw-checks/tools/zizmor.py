"""zizmor -- GitHub Actions workflow security scanning.

Diff-scoped by _plan: only the changed workflow files are ever handed to zizmor.
"""

from __future__ import annotations

import sys
from pathlib import Path

import severity
from runwhen_capability import Context

from . import _common, _plan, _runner

# tests/fixtures/tools/zizmor.sarif: a security tool whose SARIF levels are
# actually meaningful -- both "warning" and "error" are present across its
# 4 rules. `_POLICY` (severity.from_level) trusts them as-is.
SEVERITY = {"error": "error", "warning": "warning", "note": "note"}
NAME = "zizmor"
KIND = "workflow"
FILES = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    "action.yml",
    "action.yaml",
)
CONFIG = "optional"
CONFIG_NAMES = (_plan.ConfigName("zizmor.yml"), _plan.ConfigName(".github/zizmor.yml"))
CONFIG_SCOPE = "root"
CI_BINARY = "zizmor"
GUARD = None
LANE = "A"
# tests/fixtures/tools/capture.log captured this exact invocation exiting 0
# despite both warning- and error-level findings present in its SARIF --
# zizmor's default persona does not fail the process on findings. Permissive
# nonetheless: zizmor's own docs do not guarantee that holds for every
# finding/config combination, and a false "failed to run" is worse than a
# missed one.
EXPECT_EXIT = (0, 1)

_POLICY = severity.from_level(SEVERITY)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    proc = _runner.run(
        ctx,
        ["zizmor", "--format", "sarif", "--no-progress", *_runner.files_arg(inv)],
        cwd=_runner.cwd_path(tree, inv),
    )
    fail = _common.check_exit(ctx, tree, "zizmor", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    # zizmor's SARIF URIs are relative to each input's directory, not the run directory.
    return _runner.realign_paths(
        _runner.sarif_to_findings(ctx, tree, inv, proc.stdout, _POLICY), inv
    )
