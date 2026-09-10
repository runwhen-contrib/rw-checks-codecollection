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

from . import _common

SEVERITY = adapters.FLAKE8_SEVERITY
FILES = ("*.py",)
CONFIG = "required"
CI_BINARY = "flake8"
GUARD = None


def detect(tree: Path) -> list[Path]:
    roots: set[Path] = set()
    for p in _common.config_files(tree, ".flake8"):
        roots.add(p.parent)
    for p in _common.config_files(tree, "setup.cfg", "tox.ini"):
        if _common.ini_section(p, "flake8") is not None:
            roots.add(p.parent)
    return sorted(roots)


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []
    # "." replaces capture.log's fixture-specific "src" dir; unlike pylint,
    # flake8 walks directories on its own without an extra flag.
    proc = ctx.run(["flake8", "--format=%(path)s:%(row)d:%(col)d:%(code)s:%(text)s", "."], cwd=tree)
    return _common.emit(ctx, adapters.flake8(proc.stdout), tree, changed, diff_filter=True)
