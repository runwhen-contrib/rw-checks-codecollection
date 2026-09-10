"""gitleaks -- committed-credential scanning.

Always applicable: a secret does not stop being a secret because the repo has
no `.gitleaks.toml`, and CI_BINARY is None because we want this even when the
repo already scans for secrets itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

import severity
from runwhen_capability import Context

from . import _common

# gitleaks' SARIF carries NO `level` field at all, so the SDK's default
# mapping made every committed credential a `note` -- and a check run fails
# only on `error`. severity.gitleaks forces error; this map documents the
# tool's own (empty) vocabulary for the package-wide test.
SEVERITY = {"": "error"}
FILES = ()
CONFIG = "optional"
CI_BINARY = None
GUARD = None


def detect(tree: Path) -> list[Path]:
    """gitleaks reads a root `.gitleaks.toml` if present; it needs none."""
    return [p.parent for p in _common.config_files(tree, ".gitleaks.toml", "gitleaks.toml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []

    # `--report-path /dev/stdout` writes zero bytes through a pipe while still
    # finding leaks, so ctx.sarif.parse("") raised. Report to a file in the
    # per-request scope dir (NOT /tmp -- the scope dir is what gets wiped) and
    # read it back. Do not "simplify" this back to /dev/stdout.
    report = ctx.workdir / "gitleaks.sarif"
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
    )
    if not text.strip():
        return []
    # Never diff-filtered: see _common.emit.
    return ctx.sarif.parse(text, root=tree, severity=severity.gitleaks)
