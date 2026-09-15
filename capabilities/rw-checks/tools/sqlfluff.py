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
which dialect it speaks, in one of the places CONFIG_NAMES below lists.

Its own config is also an arbitrary-code-execution vector through the jinja
templater's `library_path` -- see guards.py. GUARD_CHAIN below reflects that
sqlfluff MERGES every ancestor config into one, so a root config's
library_path is in effect even for a file linted under its own nested
`.sqlfluff` -- the guard must see the whole chain, not just the nearest file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
import guards
from runwhen_capability import Context

from . import _common, _plan, _runner

# sqlfluff has no error/warning/info vocabulary of its own -- `warning` is a
# bool distinguishing advisory formatting rules from ones that would fail a
# build, so it is the whole map.
SEVERITY = {True: "warning", False: "note"}
NAME = "sqlfluff"
KIND = "SQL"
FILES = ("*.sql",)
CONFIG = "required"
CONFIG_NAMES = (
    _plan.ConfigName(".sqlfluff"),
    _plan.ConfigName("pyproject.toml", ("tool", "sqlfluff")),
    _plan.ConfigName("setup.cfg", ("sqlfluff",)),
    _plan.ConfigName("tox.ini", ("sqlfluff",)),
)
CI_BINARY = "sqlfluff"
# `.sqlfluff`/pyproject.toml/setup.cfg/tox.ini may set the jinja templater's
# library_path, which sqlfluff imports Python modules from.
GUARD = guards.sqlfluff
GUARD_CHAIN = True  # sqlfluff merges every config from the root down to the file's directory
LANE = "A"  # per-file-nearest (verified); sqlfluff has no --config flag
EXPECT_EXIT = (0, 1)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    proc = _runner.run(
        ctx,
        ["sqlfluff", "lint", "--format", "json", *_runner.files_arg(inv)],
        cwd=_runner.cwd_path(tree, inv),
    )
    fail = _common.check_exit(ctx, tree, "sqlfluff", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(ctx, tree, inv, adapters.sqlfluff(proc.stdout, SEVERITY))
