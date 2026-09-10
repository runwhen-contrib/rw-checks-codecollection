"""trivy -- dependency vulnerability scanning.

NARROWED TO `--scanners vuln` ON PURPOSE. trivy also scans IaC
misconfiguration and secrets, and doing so made it a generalist competing
with four specialists in this same capability: on tests/fixtures it
reported Dockerfile:8 "last USER is not root" alongside hadolint DL3002
AND checkov CKV_DOCKER_8, and duplicated checkov across infra/main.tf.
One defect under three vocabularies reads to a pull request author as
three defects.

The families are split so exactly one tool owns each: hadolint owns
Dockerfiles, checkov owns IaC, gitleaks owns secrets, and trivy owns
dependencies -- it wins that one because its finding names the version
that fixes the CVE ("Installed 2.19.0 ... Fixed Version: 2.20.0"), which
osv-scanner (SUPERSEDED_BY this module) does not report.

Diff-scoped like every other check: see _common.scoped.
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
# Dependency manifests and lockfiles only -- the same trigger set as
# osv_scanner, which this module supersedes. It deliberately no longer
# lists *.tf/Dockerfile*/*.yaml: those belong to checkov and hadolint now.
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

    proc = ctx.run(
        ["trivy", "fs", "--format", "sarif", "--quiet", "--scanners", "vuln", "."],
        cwd=tree,
    )
    fail = _common.check_exit(ctx, tree, "trivy", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.scoped(ctx, ctx.sarif.parse(proc.stdout, root=tree, severity=_POLICY), changed)
