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

# F (pyflakes) real defects, E/W (pycodestyle) style, C (mccabe)/N
# (pep8-naming) nits.
SEVERITY = {
    "F": "error",
    "E": "warning",
    "W": "warning",
    "C": "note",
    "N": "note",
}
FILES = ("*.py",)
CONFIG = "required"
CI_BINARY = "flake8"
GUARD = None
EXPECT_EXIT = (0, 1)


def detect(tree: Path) -> list[Path]:
    roots: set[Path] = set()
    for p in _common.config_files(tree, ".flake8"):
        roots.add(p.parent)
    for p in _common.config_files(tree, "setup.cfg", "tox.ini"):
        if _common.ini_section(p, "flake8") is not None:
            roots.add(p.parent)
    return sorted(roots)


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings
    # "." replaces capture.log's fixture-specific "src" dir; unlike pylint,
    # flake8 walks directories on its own without an extra flag.
    proc = ctx.run(["flake8", "--format=%(path)s:%(row)d:%(col)d:%(code)s:%(text)s", "."], cwd=tree)
    fail = _common.check_exit(ctx, tree, "flake8", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.emit(
        ctx, adapters.flake8(proc.stdout, SEVERITY), tree, changed, diff_filter=True
    )
