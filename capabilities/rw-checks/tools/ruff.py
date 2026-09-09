"""ruff -- fast Python linting.

CONFIG is optional, unlike pylint's required: ruff's defaults are broadly
agreeable, so an opinionated linter run without the repository's own config
still reports findings worth surfacing here -- see pylint.py for the
opposite case.
"""

from __future__ import annotations

import sys
from pathlib import Path

import _common
import severity
from runwhen_capability import Context

# tests/fixtures/tools/ruff.sarif: all 3 result-bearing rules carry SARIF
# level "error" -- ruff does not use `level` to distinguish severity at all.
# The rule CODE PREFIX is pyflakes/ruff's own vocabulary instead (F/S real
# defects, E/W/B style, everything else a nit) -- this map documents that
# vocabulary for the package-wide test; severity.ruff (called below) is the
# actual policy.
SEVERITY = {"F": "error", "S": "error", "E": "warning", "W": "warning", "B": "warning", "I": "note"}
FILES = ("*.py",)
# CONFIG optional: see module docstring.
CONFIG = "optional"
CI_BINARY = "ruff"
GUARD = None


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


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []

    # ruff resolves its own (possibly nested) config for every file it
    # walks under ".", so one repo-wide invocation is enough -- no need to
    # run once per root the way pylint.py must.
    proc = ctx.run(["ruff", "check", "--output-format=sarif", "."], cwd=tree)
    findings = ctx.sarif.parse(proc.stdout, root=tree, severity=severity.ruff)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return findings
