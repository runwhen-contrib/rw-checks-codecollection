"""pylint -- deeper Python analysis than ruff, and slower.

The most complex of the tools: config is REQUIRED, discovery is recursive, and
its config is an arbitrary-code-execution vector.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
import guards
from runwhen_capability import Context

from . import _common, _plan, _runner

SEVERITY = {
    "fatal": "error",
    "error": "error",
    "warning": "warning",
    "convention": "note",
    "refactor": "note",
    "info": "note",
}
NAME = "pylint"
KIND = "Python"
FILES = ("*.py",)
# CONFIG required, following CodeRabbit: an opinionated linter run WITHOUT the
# repository's own config reports findings the repo never asked for. ruff is
# `optional` for the opposite reason -- its defaults are broadly agreeable.
CONFIG = "required"
CONFIG_NAMES = (
    _plan.ConfigName(".pylintrc"),
    _plan.ConfigName("pylintrc"),
    _plan.ConfigName(".pylintrc.toml"),
    _plan.ConfigName("pylintrc.toml"),
    _plan.ConfigName("pyproject.toml", ("tool", "pylint")),
    _plan.ConfigName("setup.cfg", ("pylint",)),
)
CI_BINARY = "pylint"
GUARD = guards.pylint  # `.pylintrc` init-hook / load-plugins execute code in our pod
LANE = "B"  # cwd-only discovery (verified): run from the config's directory with --rcfile
# --exit-zero (below) forces exit 0 regardless of findings -- anything else
# is a genuine failure to run.
EXPECT_EXIT = (0,)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = [
        "pylint",
        "--output-format=json",
        "--exit-zero",
        "--rcfile",
        _runner.config_arg(inv),
        *_runner.files_arg(inv),
    ]
    proc = _runner.run(ctx, argv, cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "pylint", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(ctx, tree, inv, adapters.pylint(proc.stdout, SEVERITY))
