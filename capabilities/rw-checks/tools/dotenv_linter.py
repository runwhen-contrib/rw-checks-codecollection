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

# dotenv-linter emits no severity of its own; adapters.dotenv_linter() maps
# DuplicatedKey (a later key silently wins) to `warning` and every other
# rule (casing, ordering conventions) to `note`. Declared here only to
# satisfy the package-wide contract; adapters.py is the actual source of
# truth.
SEVERITY = {"DuplicatedKey": "warning", "": "note"}
FILES = (".env", ".env.*")
CONFIG = "optional"
CI_BINARY = "dotenv-linter"
GUARD = None


def detect(tree: Path) -> list[Path]:
    return []


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []
    # "." replaces capture.log's fixture-specific ".env" file; dotenv-linter
    # walks a directory looking for every .env* file on its own.
    proc = ctx.run(["dotenv-linter", "."], cwd=tree)
    return _common.emit(ctx, adapters.dotenv_linter(proc.stdout), tree, changed, diff_filter=True)
