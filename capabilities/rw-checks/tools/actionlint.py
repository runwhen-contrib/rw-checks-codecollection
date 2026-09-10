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

# actionlint has no severity vocabulary at all -- every lint it reports is
# an error-level finding, so this is the whole (degenerate) vocabulary.
SEVERITY = {"error": "error"}
FILES = (".github/workflows/*.yml", ".github/workflows/*.yaml")
CONFIG = "optional"
CI_BINARY = "actionlint"
GUARD = None
EXPECT_EXIT = (0, 1)


def detect(tree: Path) -> list[Path]:
    # actionlint only ever reads this one fixed location -- unlike the other
    # optional-config tools, there is nothing to recurse for.
    config = tree / ".github" / "actionlint.yaml"
    return [config.parent] if config.is_file() else []


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings
    # No workflow file given: actionlint's own project detection (walks up
    # to the enclosing repo -- tests/fixtures/tools/README.md) finds and
    # lints every workflow under .github/workflows on its own, which is the
    # repo-wide equivalent of capture.log's single hardcoded ci.yml.
    proc = ctx.run(["actionlint", "-format", "{{json .}}", "-no-color"], cwd=tree)
    fail = _common.check_exit(ctx, tree, "actionlint", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.emit(ctx, adapters.actionlint(proc.stdout, SEVERITY), tree, changed)
