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
# 4 rules. `_POLICY` (severity.from_level) trusts them as-is.
SEVERITY = {"error": "error", "warning": "warning", "note": "note"}
FILES = (".github/workflows/*.yml", ".github/workflows/*.yaml")
CONFIG = "optional"
CI_BINARY = "zizmor"
GUARD = None
# tests/fixtures/tools/capture.log captured this exact invocation exiting 0
# despite both warning- and error-level findings present in its SARIF --
# zizmor's default persona does not fail the process on findings. Permissive
# nonetheless: zizmor's own docs do not guarantee that holds for every
# finding/config combination, and a false "failed to run" is worse than a
# missed one.
EXPECT_EXIT = (0, 1)

_POLICY = severity.from_level(SEVERITY)


def detect(tree: Path) -> list[Path]:
    """zizmor reads a root zizmor.yml or a .github/zizmor.yml if present;
    it needs none."""
    return [p.parent for p in _common.config_files(tree, "zizmor.yml", ".github/zizmor.yml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings

    # GitHub Actions security scan: not diff-filtered, same reasoning as
    # gitleaks/trivy/osv-scanner/checkov above.
    proc = ctx.run(
        ["zizmor", "--format", "sarif", "--no-progress", ".github/workflows"],
        cwd=tree,
    )
    fail = _common.check_exit(ctx, tree, "zizmor", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    # Never diff-filtered: see _common.emit.
    return ctx.sarif.parse(proc.stdout, root=tree, severity=_POLICY)
