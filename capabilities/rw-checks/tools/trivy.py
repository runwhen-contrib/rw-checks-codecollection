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
# property (GitHub code-scanning's own numeric-string convention); `_POLICY`
# (severity.by_cvss) prefers that over SARIF `level`, banding it per GitHub's
# own security-severity convention and looking the band up here.
SEVERITY = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
FILES = ("*.tf", "Dockerfile*", "*.yaml", "*.yml")
CONFIG = "optional"
CI_BINARY = "trivy"
GUARD = None
# No --exit-code flag is passed below, so trivy always exits 0 for scan
# results regardless of findings -- a well-documented default. Anything
# else is a genuine failure to run.
EXPECT_EXIT = (0,)

_POLICY = severity.by_cvss(SEVERITY)


def detect(tree: Path) -> list[Path]:
    """trivy reads a root/nested trivy.yaml if present; it needs none."""
    return [p.parent for p in _common.config_files(tree, "trivy.yaml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings

    # Vulnerability/misconfig/secret scan: not diff-filtered, same reasoning
    # as gitleaks -- an existing vulnerability doesn't stop being one just
    # because this diff didn't touch the affected file.
    proc = ctx.run(
        ["trivy", "fs", "--format", "sarif", "--quiet", "--scanners", "vuln,misconfig,secret", "."],
        cwd=tree,
    )
    fail = _common.check_exit(ctx, tree, "trivy", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    # Never diff-filtered: see _common.emit.
    return ctx.sarif.parse(proc.stdout, root=tree, severity=_POLICY)
