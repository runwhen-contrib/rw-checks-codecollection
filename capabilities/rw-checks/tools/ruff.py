"""ruff -- fast Python linting.

Config-gated (DIFF-SCOPED-CHECKS.md §3).
"""

from __future__ import annotations

import sys
from pathlib import Path

import severity
from runwhen_capability import Context

from . import _common, _plan, _runner

# tests/fixtures/tools/ruff.sarif: all 3 result-bearing rules carry SARIF
# level "error" -- ruff does not use `level` to distinguish severity at all.
# The rule CODE PREFIX is pyflakes/ruff's own vocabulary instead: F/S are
# real defects, E/W/B are style, everything else (I isort, D, N, UP, C, PL,
# ...) is a nit -- `_POLICY` (severity.by_rule_prefix) applies this map by
# prefix, "note" for anything the map doesn't name.
SEVERITY = {"F": "error", "S": "error", "E": "warning", "W": "warning", "B": "warning", "I": "note"}
NAME = "ruff"
KIND = "Python"
FILES = ("*.py",)
CONFIG = "required"
CONFIG_NAMES = (
    _plan.ConfigName("ruff.toml"),
    _plan.ConfigName(".ruff.toml"),
    _plan.ConfigName("pyproject.toml", ("tool", "ruff")),
)
CI_BINARY = "ruff"
GUARD = None
LANE = "A"  # ruff resolves each file's nearest config itself (verified)
EXPECT_EXIT = (0, 1)

_POLICY = severity.by_rule_prefix(SEVERITY)


# legacy: used only by flake8's supersession gate until Task 7 converts flake8; delete then
def detect(tree: Path) -> list[Path]:
    """Every directory where ruff is configured: a root/nested ruff.toml,
    .ruff.toml, or a pyproject.toml with a [tool.ruff] table."""
    roots: set[Path] = set()
    for p in _common.config_files(tree, "ruff.toml", ".ruff.toml"):
        roots.add(p.parent)
    for p in _common.config_files(tree, "pyproject.toml"):
        if _common.toml_table(p, "tool", "ruff") is not None:
            roots.add(p.parent)
    return sorted(roots)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    # --force-exclude: explicit file arguments must still honour the repo's exclude settings.
    argv = ["ruff", "check", "--output-format=sarif", "--force-exclude", *_runner.files_arg(inv)]
    proc = _runner.run(ctx, argv, cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "ruff", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.sarif_to_findings(ctx, tree, inv, proc.stdout, _POLICY)
