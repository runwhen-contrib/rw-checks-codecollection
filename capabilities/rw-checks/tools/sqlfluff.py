"""sqlfluff -- SQL lint.

CONFIG is optional (sqlfluff's default dialect/rules are broadly agreeable,
unlike pylint's/flake8's), but its own config is an arbitrary-code-execution
vector through the jinja templater's `library_path` -- see guards.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
import guards
from runwhen_capability import Context

from . import _common

SEVERITY = adapters.SQLFLUFF_SEVERITY
FILES = ("*.sql",)
CONFIG = "optional"
CI_BINARY = "sqlfluff"
# `.sqlfluff`/pyproject.toml/setup.cfg/tox.ini may set the jinja templater's
# library_path, which sqlfluff imports Python modules from.
GUARD = guards.sqlfluff


def detect(tree: Path) -> list[Path]:
    roots: set[Path] = set()
    for p in _common.config_files(tree, ".sqlfluff"):
        roots.add(p.parent)
    for p in _common.config_files(tree, "pyproject.toml"):
        if _common.toml_table(p, "tool", "sqlfluff") is not None:
            roots.add(p.parent)
    for p in _common.config_files(tree, "setup.cfg", "tox.ini"):
        if _common.ini_section(p, "sqlfluff") is not None:
            roots.add(p.parent)
    return sorted(roots)


def check(ctx: Context, tree: Path, changed: list[str] | None):
    skip = _common.gate(tree, sys.modules[__name__])
    if skip and skip.startswith("unsafe-config:"):
        return _common.unsafe_config_finding(ctx, tree, skip.split(":", 1)[1])
    if skip:
        return []

    # "." replaces capture.log's fixture-specific "db" dir; sqlfluff lint
    # recurses into whatever path it is given.
    proc = ctx.run(["sqlfluff", "lint", "--format", "json", "."], cwd=tree)
    return _common.emit(ctx, adapters.sqlfluff(proc.stdout), tree, changed, diff_filter=True)
