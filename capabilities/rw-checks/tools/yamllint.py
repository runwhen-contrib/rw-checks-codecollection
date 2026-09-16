"""yamllint -- YAML lint.

Config-gated per directory (DIFF-SCOPED-CHECKS.md §3): each changed YAML
file runs under the nearest `.yamllint`/`.yamllint.yml`/`.yamllint.yaml`,
cwd set to that directory -- unlike the old whole-repo `.` invocation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common, _plan, _runner

SEVERITY = {"error": "error", "warning": "warning"}
NAME = "yamllint"
KIND = "YAML"
FILES = ("*.yml", "*.yaml")
CONFIG = "required"
CONFIG_NAMES = (
    _plan.ConfigName(".yamllint"),
    _plan.ConfigName(".yamllint.yml"),
    _plan.ConfigName(".yamllint.yaml"),
)
CI_BINARY = "yamllint"
GUARD = None
LANE = "B"  # cwd-only discovery (verified)
EXPECT_EXIT = (0, 1)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = ["yamllint", "-f", "parsable", "-c", _runner.config_arg(inv), *_runner.files_arg(inv)]
    proc = _runner.run(ctx, argv, cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "yamllint", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(ctx, tree, inv, adapters.yamllint(proc.stdout, SEVERITY))
