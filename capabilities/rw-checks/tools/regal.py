"""regal -- Rego (OPA policy) lint.

Config-gated per `.regal/` root: files under a different `.regal/config.yaml`
each get their own run, cwd set to that root.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common, _plan, _runner

SEVERITY = {"error": "error", "warning": "warning"}
NAME = "regal"
KIND = "Rego"
FILES = ("*.rego",)
CONFIG = "required"
CONFIG_NAMES = (_plan.ConfigName(".regal/config.yaml"),)
CI_BINARY = "regal"
GUARD = None
LANE = "B"  # one config per run: files under different .regal roots must not share a run (verified)
# tests/fixtures/tools/capture.log: exit 3 with findings present -- not a
# tool failure.
EXPECT_EXIT = (0, 3)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = [
        "regal",
        "lint",
        "--format",
        "json",
        "-c",
        _runner.config_arg(inv),
        *_runner.files_arg(inv),
    ]
    proc = _runner.run(ctx, argv, cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "regal", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(ctx, tree, inv, adapters.regal(proc.stdout, SEVERITY))
