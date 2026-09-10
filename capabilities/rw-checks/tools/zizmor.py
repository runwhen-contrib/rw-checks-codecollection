"""zizmor -- GitHub Actions workflow security scanning.

Not diff-filtered: a vulnerable workflow doesn't stop being vulnerable
because this diff didn't touch it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import severity
from runwhen_capability import Context

from . import _common

# tests/fixtures/tools/zizmor.sarif: a security tool whose SARIF levels are
# actually meaningful -- both "warning" and "error" are present across its
# 4 rules. severity.zizmor (called below) trusts them as-is; this map
# documents that vocabulary for the package-wide test.
SEVERITY = {"error": "error", "warning": "warning", "note": "note"}
FILES = (".github/workflows/*.yml", ".github/workflows/*.yaml")
CONFIG = "optional"
CI_BINARY = "zizmor"
GUARD = None


def detect(tree: Path) -> list[Path]:
    """zizmor reads a root zizmor.yml or a .github/zizmor.yml if present;
    it needs none."""
    return [p.parent for p in _common.config_files(tree, "zizmor.yml", ".github/zizmor.yml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []

    # GitHub Actions security scan: not diff-filtered, same reasoning as
    # gitleaks/trivy/osv-scanner/checkov above.
    proc = ctx.run(
        ["zizmor", "--format", "sarif", "--no-progress", ".github/workflows"],
        cwd=tree,
    )
    # Never diff-filtered: see _common.emit.
    return ctx.sarif.parse(proc.stdout, root=tree, severity=severity.zizmor)
