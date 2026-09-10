"""actionlint -- GitHub Actions workflow lint.

actionlint's own project detection (walks up to the enclosing repo) finds
and lints every workflow under .github/workflows on its own, so it is
pointed at the repo root rather than any one workflow file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common

SEVERITY = adapters.ACTIONLINT_SEVERITY
FILES = (".github/workflows/*.yml", ".github/workflows/*.yaml")
CONFIG = "optional"
CI_BINARY = "actionlint"
GUARD = None


def detect(tree: Path) -> list[Path]:
    # actionlint only ever reads this one fixed location -- unlike the other
    # optional-config tools, there is nothing to recurse for.
    config = tree / ".github" / "actionlint.yaml"
    return [config.parent] if config.is_file() else []


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []
    # No workflow file given: actionlint's own project detection (walks up
    # to the enclosing repo -- tests/fixtures/tools/README.md) finds and
    # lints every workflow under .github/workflows on its own, which is the
    # repo-wide equivalent of capture.log's single hardcoded ci.yml.
    proc = ctx.run(["actionlint", "-format", "{{json .}}", "-no-color"], cwd=tree)
    return _common.emit(ctx, adapters.actionlint(proc.stdout), tree, changed, diff_filter=True)
