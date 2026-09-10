"""gitleaks -- committed-credential scanning.

Always applicable: a secret does not stop being a secret because the repo has
no `.gitleaks.toml`, and CI_BINARY is None because we want this even when the
repo already scans for secrets itself. Diff-scoped like every other
check: see _common.scoped.
"""

from __future__ import annotations

import sys
from pathlib import Path

import severity
from runwhen_capability import Context

from . import _common

# gitleaks' SARIF carries NO `level` field at all, so the SDK's default
# mapping made every committed credential a `note` -- and a check run fails
# only on `error`. The single value below is the whole (empty) vocabulary;
# `_POLICY` (severity.constant) forces every result to it.
SEVERITY = {"": "error"}
FILES = ()
CONFIG = "optional"
CI_BINARY = None
GUARD = None
# `--exit-code 0` (below) forces exit 0 regardless of leaks found -- anything
# else is a genuine failure to run.
EXPECT_EXIT = (0,)

_POLICY = severity.constant(SEVERITY)


def detect(tree: Path) -> list[Path]:
    """gitleaks reads a root `.gitleaks.toml` if present; it needs none."""
    return [p.parent for p in _common.config_files(tree, ".gitleaks.toml", "gitleaks.toml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings

    # `--report-path /dev/stdout` writes zero bytes through a pipe while still
    # finding leaks, so ctx.sarif.parse("") raised. Report to a file in the
    # per-request scope dir (NOT /tmp -- the scope dir is what gets wiped) and
    # read it back. Do not "simplify" this back to /dev/stdout.
    report = ctx.workdir / "gitleaks.sarif"
    try:
        text = _common.run_to_file(
            ctx,
            [
                "gitleaks",
                "dir",
                ".",
                "--report-format",
                "sarif",
                "--report-path",
                str(report),
                "--no-banner",
                "--exit-code",
                "0",
            ],
            tree,
            report,
            sys.modules[__name__],
        )
    except _common.ToolFailed as exc:
        return _common.check_failed_finding(ctx, tree, "gitleaks", exc.exit_code, exc.detail)
    return _common.scoped(ctx, ctx.sarif.parse(text, root=tree, severity=_POLICY), changed)
