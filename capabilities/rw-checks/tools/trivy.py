"""trivy -- vulnerability / misconfig / secret scanning across IaC and
container-adjacent files.

Not diff-filtered: an existing vulnerability doesn't stop being one just
because this diff didn't touch the affected file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import severity
from runwhen_capability import Context

from . import _common

# tests/fixtures/tools/trivy.sarif: CVE rules carry a `security-severity`
# property (GitHub code-scanning's own numeric-string convention); severity.
# trivy (called below) prefers that over SARIF `level`. This map documents
# the GitHub security-severity bands it thresholds on for the package-wide
# test.
SEVERITY = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
FILES = ("*.tf", "Dockerfile*", "*.yaml", "*.yml")
CONFIG = "optional"
CI_BINARY = "trivy"
GUARD = None


def detect(tree: Path) -> list[Path]:
    """trivy reads a root/nested trivy.yaml if present; it needs none."""
    return [p.parent for p in _common.config_files(tree, "trivy.yaml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []

    # Vulnerability/misconfig/secret scan: not diff-filtered, same reasoning
    # as gitleaks -- an existing vulnerability doesn't stop being one just
    # because this diff didn't touch the affected file.
    proc = ctx.run(
        ["trivy", "fs", "--format", "sarif", "--quiet", "--scanners", "vuln,misconfig,secret", "."],
        cwd=tree,
    )
    # Never diff-filtered: see _common.emit.
    return ctx.sarif.parse(proc.stdout, root=tree, severity=severity.trivy)
