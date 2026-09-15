"""flake8 -- fast Python lint, ahead of pylint's deeper (slower) pass.

CONFIG required, following CodeRabbit: an opinionated linter run WITHOUT the
repository's own config reports findings the repo never asked for -- same
reasoning as pylint.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

import tools.ruff

from . import _common, _plan, _runner

# F (pyflakes) real defects, E/W (pycodestyle) style, C (mccabe)/N
# (pep8-naming) nits.
SEVERITY = {
    "F": "error",
    "E": "warning",
    "W": "warning",
    "C": "note",
    "N": "note",
}
NAME = "flake8"
KIND = "Python"
FILES = ("*.py",)
CONFIG = "required"
CONFIG_NAMES = (
    _plan.ConfigName(".flake8"),
    _plan.ConfigName("setup.cfg", ("flake8",)),
    _plan.ConfigName("tox.ini", ("flake8",)),
)
CI_BINARY = "flake8"
GUARD = None
LANE = "B"  # cwd-only discovery (verified)
EXPECT_EXIT = (0, 1)
_FORMAT = "--format=%(path)s:%(row)d:%(col)d:%(code)s:%(text)s"


def narrow(ctx, tree, changed, groups):
    """ruff reimplements flake8 and emits its rule IDs: drop files ruff checks."""
    ruff_files = {
        f for inv in tools.ruff.applicable(ctx, tree, changed).invocations for f in inv.files
    }
    kept = {r: [f for f in fs if f not in ruff_files] for r, fs in groups.items()}
    kept = {r: fs for r, fs in kept.items() if fs}
    dropped = sum(len(fs) for fs in groups.values()) - sum(len(fs) for fs in kept.values())
    total = sum(len(fs) for fs in groups.values())
    note = f"{dropped} of {total} changed Python files are covered by ruff" if dropped else None
    return kept, note


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = ["flake8", "--config", _runner.config_arg(inv), _FORMAT, *_runner.files_arg(inv)]
    proc = _runner.run(ctx, argv, cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "flake8", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(ctx, tree, inv, adapters.flake8(proc.stdout, SEVERITY))
