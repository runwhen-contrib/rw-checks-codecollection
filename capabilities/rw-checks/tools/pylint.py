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

from . import _common

SEVERITY = {
    "fatal": "error",
    "error": "error",
    "warning": "warning",
    "convention": "note",
    "refactor": "note",
    "info": "note",
}
FILES = ("*.py",)
# CONFIG required, following CodeRabbit: an opinionated linter run WITHOUT the
# repository's own config reports findings the repo never asked for. ruff is
# `optional` for the opposite reason -- its defaults are broadly agreeable.
CONFIG = "required"
CI_BINARY = "pylint"
# `.pylintrc` may set init-hook, which executes arbitrary Python in our pod.
GUARD = guards.pylint
# --exit-zero (below) forces exit 0 regardless of findings -- anything else
# is a genuine failure to run.
EXPECT_EXIT = (0,)


def detect(tree: Path) -> list[Path]:
    """Every directory where pylint is configured.

    Returns a LIST because a monorepo genuinely wants pylint run once per
    package, from each configured root, with each config. That is ordinary
    Python and an awkward schema -- the reason these are modules, not data.
    """
    roots: set[Path] = set()
    for p in _common.config_files(tree, ".pylintrc", "pylintrc", ".pylintrc.toml", "pylintrc.toml"):
        roots.add(p.parent)
    for p in _common.config_files(tree, "pyproject.toml"):
        if _common.toml_table(p, "tool", "pylint") is not None:
            roots.add(p.parent)
    for p in _common.config_files(tree, "setup.cfg"):
        if _common.ini_section(p, "pylint") is not None:
            roots.add(p.parent)
    return sorted(roots)


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings

    records = []
    for root in detect(tree):
        # --recursive=y is required for a bare "." to walk subdirectories that
        # are not packages (no __init__.py). --exit-zero because pylint exits
        # non-zero on findings, which is not a task failure.
        proc = ctx.run(
            ["pylint", "--output-format=json", "--exit-zero", "--recursive=y", "."],
            cwd=root,
        )
        fail = _common.check_exit(ctx, tree, "pylint", proc, sys.modules[__name__])
        if fail is not None:
            return fail
        rel = root.relative_to(tree)
        for rec in adapters.pylint(proc.stdout, SEVERITY):
            # Paths come back relative to the root pylint ran in, not the repo.
            rec["path"] = (rel / rec["path"]).as_posix() if rel.parts else rec["path"]
            records.append(rec)
    return _common.emit(ctx, records, tree, changed)
