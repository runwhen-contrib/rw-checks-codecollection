"""sqlfluff -- SQL lint.

CONFIG is REQUIRED, unlike most tools here. sqlfluff has no default dialect
and refuses to lint without one:

    User Error: No dialect was specified. You must configure a dialect or
    specify one on the command line using --dialect

That is exit 2, which is not in EXPECT_EXIT, so every repository holding a
`.sql` file but no sqlfluff config produced a `check-failed` finding on every
review -- noise attributable to us, not to the code under review. This file
previously claimed "sqlfluff's default dialect/rules are broadly agreeable";
there is no default dialect, so that premise was simply wrong.

Gating on config instead of guessing a dialect is deliberate. `--dialect ansi`
would let every review run, but ansi silently mis-parses the dialect-specific
SQL most repositories actually write, so the findings would be confidently
wrong rather than absent -- and a wrong finding on someone's pull request
costs more than a skipped check. A repository that wants SQL linting says
which dialect it speaks, in any of the three places `detect` already reads.

Its own config is also an arbitrary-code-execution vector through the jinja
templater's `library_path` -- see guards.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
import guards
from runwhen_capability import Context

from . import _common

# sqlfluff has no error/warning/info vocabulary of its own -- `warning` is a
# bool distinguishing advisory formatting rules from ones that would fail a
# build, so it is the whole map.
SEVERITY = {True: "warning", False: "note"}
FILES = ("*.sql",)
CONFIG = "required"
CI_BINARY = "sqlfluff"
# `.sqlfluff`/pyproject.toml/setup.cfg/tox.ini may set the jinja templater's
# library_path, which sqlfluff imports Python modules from.
GUARD = guards.sqlfluff
EXPECT_EXIT = (0, 1)


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
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings

    # "." replaces capture.log's fixture-specific "db" dir; sqlfluff lint
    # recurses into whatever path it is given.
    proc = ctx.run(["sqlfluff", "lint", "--format", "json", "."], cwd=tree)
    fail = _common.check_exit(ctx, tree, "sqlfluff", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.emit(ctx, adapters.sqlfluff(proc.stdout, SEVERITY), tree, changed)
