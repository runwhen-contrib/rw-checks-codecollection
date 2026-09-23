"""gitleaks -- committed-credential scanning.

Always applicable: a secret does not stop being a secret because the repo has
no `.gitleaks.toml`, and CI_BINARY is None because we want this even when the
repo already scans for secrets itself. Diff-scoped like every other check:
gitleaks accepts a single target only, so `check()` scans a scratch view
(_runner.scratch_view) holding just the changed files rather than the tree.
"""

from __future__ import annotations

import sys
from pathlib import Path

import severity
from runwhen_capability import Context

from . import _common, _plan, _runner

# gitleaks' SARIF carries NO `level` field at all, so the SDK's default
# mapping made every committed credential a `note` -- and a check run fails
# only on `error`. The single value below is the whole (empty) vocabulary;
# `_POLICY` (severity.constant) forces every result to it.
SEVERITY = {"": "error"}
NAME = "gitleaks"
KIND = "text"
FILES = ()  # every changed file
CONFIG = "optional"
CONFIG_NAMES = (_plan.ConfigName(".gitleaks.toml"), _plan.ConfigName("gitleaks.toml"))
CONFIG_SCOPE = "root"  # gitleaks reads its target directory's config only (verified)
CI_BINARY = None  # secrets are wanted regardless of CI
GUARD = None
LANE = "C"  # one target path only: scan a view holding just the changed files
# `--exit-code 0` (below) forces exit 0 regardless of leaks found -- anything
# else is a genuine failure to run.
EXPECT_EXIT = (0,)

_POLICY = severity.constant(SEVERITY)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    view = _runner.scratch_view(ctx, tree, inv, "gitleaks")
    # `--report-path /dev/stdout` writes zero bytes through a pipe while
    # still finding leaks, so ctx.sarif.parse("") raised. Report to a file in
    # ctx.workdir (NOT /tmp -- that's what gets wiped between requests) and
    # read it back. Do not "simplify" this back to /dev/stdout.
    report = ctx.workdir / "gitleaks.sarif"
    argv = [
        "gitleaks",
        "dir",
        str(view),
        "--report-format",
        "sarif",
        "--report-path",
        str(report),
        "--no-banner",
        "--exit-code",
        "0",
    ]
    if inv.config:
        argv += ["-c", str(view / inv.config)]
    try:
        text = _runner.run_to_file(ctx, argv, cwd=view, report=report, module=sys.modules[__name__])
    except _common.ToolFailed as exc:
        return _common.check_failed_finding(ctx, tree, "gitleaks", exc.exit_code, exc.detail)
    # The view mirrors repo-relative paths, so SARIF parsed with root=view is
    # already repo-relative.
    return [f for f in ctx.sarif.parse(text, root=view, severity=_POLICY)]
