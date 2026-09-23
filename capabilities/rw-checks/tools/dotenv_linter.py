"""dotenv-linter -- .env file lint.

No config file of its own -- every check it runs is a CLI flag/default, so
CONFIG_NAMES is empty.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common, _plan, _runner

# dotenv-linter emits no severity of its own: DuplicatedKey (a later key
# silently wins) is a real defect, every other rule (casing, ordering
# conventions) is a nit, the `""` key its default.
SEVERITY = {"DuplicatedKey": "warning", "": "note"}
NAME = "dotenv-linter"
KIND = ".env"
FILES = (".env", ".env.*")
CONFIG = "optional"
CONFIG_NAMES = ()  # dotenv-linter has no config file (verified)
CI_BINARY = "dotenv-linter"
GUARD = None
LANE = "A"
EXPECT_EXIT = (0, 1)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    proc = _runner.run(
        ctx, ["dotenv-linter", *_runner.files_arg(inv)], cwd=_runner.cwd_path(tree, inv)
    )
    fail = _common.check_exit(ctx, tree, "dotenv-linter", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(
        ctx, tree, inv, adapters.dotenv_linter(proc.stdout, SEVERITY)
    )
