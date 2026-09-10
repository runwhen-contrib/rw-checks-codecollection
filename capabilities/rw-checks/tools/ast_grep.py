"""ast-grep -- structural code search/lint against the repo's OWN rules.

CONFIG is required: ast-grep ships no rules of its own -- without
`sgconfig.yml` it has nothing to run at all. CI_BINARY is None: the whole
point is the repo's own custom rules, which a repo's own CI running
ast-grep does not make redundant the way a duplicate shellcheck run would.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common

SEVERITY = adapters.AST_GREP_SEVERITY
FILES = ()
CONFIG = "required"
CI_BINARY = None
GUARD = None


def detect(tree: Path) -> list[Path]:
    return [p.parent for p in _common.config_files(tree, "sgconfig.yml", "sgconfig.yaml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []
    # No path argument in capture.log either: `ast-grep scan` already scans
    # the whole project rooted at cwd by default.
    proc = ctx.run(["ast-grep", "scan", "--json"], cwd=tree)
    return _common.emit(ctx, adapters.ast_grep(proc.stdout), tree, changed, diff_filter=True)
