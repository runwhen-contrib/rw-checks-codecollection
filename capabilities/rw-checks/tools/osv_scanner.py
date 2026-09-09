"""osv-scanner -- dependency (lockfile) vulnerability scanning.

CI_BINARY is None: dependency scanning is wanted regardless of what the
repo's own CI already runs, same as gitleaks. Not diff-filtered: a
vulnerable dependency doesn't stop being vulnerable because this diff
didn't touch the lockfile.
"""

from __future__ import annotations

import sys
from pathlib import Path

import _common
import severity
from runwhen_capability import Context

# tests/fixtures/tools/osv-scanner.sarif: all 17 rules carry SARIF level
# "warning" and no severity metadata in `properties` at all -- unlike
# trivy, there is nothing here to discriminate a critical CVE from a low
# one, so severity.osv_scanner (called below) maps every result to
# "warning" uniformly. This map documents that (empty) vocabulary for the
# package-wide test.
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


def detect(tree: Path) -> list[Path]:
    """osv-scanner reads a root/nested osv-scanner.toml if present; it
    needs none."""
    return [p.parent for p in _common.config_files(tree, "osv-scanner.toml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []

    # osv-scanner exits 1 when it finds vulnerabilities (capture.log: exit
    # 1, 197930B of valid SARIF) -- ctx.run does not raise on non-zero exit,
    # and that is correct here: a non-zero exit is the tool reporting
    # findings, not a tool failure. Dependency vulns are not diff-filtered,
    # for the same reason as gitleaks/trivy above.
    proc = ctx.run(["osv-scanner", "--format", "sarif", "-r", "."], cwd=tree)
    # Never diff-filtered: see _common.emit.
    return ctx.sarif.parse(proc.stdout, root=tree, severity=severity.osv_scanner)
