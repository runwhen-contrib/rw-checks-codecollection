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
import guards
from runwhen_capability import Context

from . import _common, _plan, _runner

SEVERITY = {"error": "error", "warning": "warning", "info": "note", "hint": "note"}
NAME = "ast-grep"
KIND = "source"
FILES = ()  # rules decide languages; every changed file under an sgconfig is eligible
CONFIG = "required"
CONFIG_NAMES = (_plan.ConfigName("sgconfig.yml"), _plan.ConfigName("sgconfig.yaml"))
CI_BINARY = None
# sgconfig.yml's customLanguages.<lang>.libraryPath makes ast-grep dlopen a
# repo-committed native library -- see guards.py.
GUARD = guards.ast_grep
LANE = "B"  # cwd-only discovery; ruleDirs are relative to sgconfig (verified)
EXPECT_EXIT = (0, 1)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = ["ast-grep", "scan", "--json", "-c", _runner.config_arg(inv), *_runner.files_arg(inv)]
    proc = _runner.run(ctx, argv, cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "ast-grep", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(ctx, tree, inv, adapters.ast_grep(proc.stdout, SEVERITY))
