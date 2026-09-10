"""osv-scanner -- dependency (lockfile) vulnerability scanning.

CI_BINARY is None: dependency scanning is wanted regardless of what the
repo's own CI already runs, same as gitleaks. Diff-scoped like every
other check (see _common.scoped): scoping is per FILE, so a PR that edits
a lockfile at all gets every advisory in it -- which is what you want when
reviewing a dependency bump.
"""

from __future__ import annotations

import sys
from pathlib import Path

import severity
from runwhen_capability import Context

from . import _common

# tests/fixtures/tools/osv-scanner.sarif: all 17 rules carry SARIF level
# "warning" and no severity metadata in `properties` at all -- unlike
# trivy, there is nothing here to discriminate a critical CVE from a low
# one. The single value below is the whole (empty) vocabulary; `_POLICY`
# (severity.constant) forces every result to it.
SEVERITY = {"": "warning"}
FILES = (
    "requirements.txt",
    "package-lock.json",
    "go.mod",
    "Cargo.lock",
    "poetry.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Gemfile.lock",
    "composer.lock",
)
CONFIG = "optional"
CI_BINARY = None
GUARD = None
# osv-scanner exits 1 when it finds vulnerabilities (capture.log: exit 1,
# 197930B of valid SARIF) -- not a tool failure.
EXPECT_EXIT = (0, 1)

_POLICY = severity.constant(SEVERITY)


def detect(tree: Path) -> list[Path]:
    """osv-scanner reads a root/nested osv-scanner.toml if present; it
    needs none."""
    return [p.parent for p in _common.config_files(tree, "osv-scanner.toml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings

    # osv-scanner exits 1 when it finds vulnerabilities (capture.log: exit
    # 1, 197930B of valid SARIF) -- ctx.run does not raise on non-zero exit,
    # and that is correct here: a non-zero exit is the tool reporting
    # findings, not a tool failure (see EXPECT_EXIT above).
    proc = ctx.run(["osv-scanner", "--format", "sarif", "-r", "."], cwd=tree)
    fail = _common.check_exit(ctx, tree, "osv-scanner", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.scoped(ctx, ctx.sarif.parse(proc.stdout, root=tree, severity=_POLICY), changed)
