"""dotenv-linter -- .env file lint.

No config file of its own -- every check it runs is a CLI flag/default, so
detect() has nothing to look for and always returns [].
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common

# dotenv-linter emits no severity of its own: DuplicatedKey (a later key
# silently wins) is a real defect, every other rule (casing, ordering
# conventions) is a nit, the `""` key its default.
SEVERITY = {"DuplicatedKey": "warning", "": "note"}
FILES = (".env", ".env.*")
CONFIG = "optional"
CI_BINARY = "dotenv-linter"
GUARD = None
EXPECT_EXIT = (0, 1)


def detect(tree: Path) -> list[Path]:
    return []


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings
    # "." replaces capture.log's fixture-specific ".env" file; dotenv-linter
    # walks a directory looking for every .env* file on its own.
    proc = ctx.run(["dotenv-linter", "."], cwd=tree)
    fail = _common.check_exit(ctx, tree, "dotenv-linter", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.emit(
        ctx, adapters.dotenv_linter(proc.stdout, SEVERITY), tree, changed, diff_filter=True
    )
