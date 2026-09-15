"""hadolint -- Dockerfile defects.

Always-on: hadolint lints exactly one Dockerfile per invocation and has no
directory mode, so unlike shellcheck it is not file-gated on a config -- a
Dockerfile with no `.hadolint.yaml`/`.hadolint.yml` still runs, on defaults.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common, _plan, _runner

SEVERITY = {"error": "error", "warning": "warning", "info": "note", "style": "note"}
NAME = "hadolint"
KIND = "Dockerfile"
FILES = ("Dockerfile*", "*.dockerfile")
CONFIG = "optional"
CONFIG_NAMES = (_plan.ConfigName(".hadolint.yaml"), _plan.ConfigName(".hadolint.yml"))
CI_BINARY = "hadolint"
GUARD = None
LANE = "B"
EXPECT_EXIT = (0, 1)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = ["hadolint", "-f", "json"]
    if inv.config:
        argv += ["-c", _runner.config_arg(inv)]
    proc = _runner.run(ctx, [*argv, *_runner.files_arg(inv)], cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "hadolint", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(ctx, tree, inv, adapters.hadolint(proc.stdout, SEVERITY))
