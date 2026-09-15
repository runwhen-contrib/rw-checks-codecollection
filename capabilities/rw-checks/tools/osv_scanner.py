"""osv-scanner -- dependency (lockfile) vulnerability scanning.

CI_BINARY is None: dependency scanning is wanted regardless of what the
repo's own CI already runs, same as gitleaks. Diff-scoped by _plan: scoping
is per FILE, so a PR that edits a lockfile at all gets every advisory in it
-- which is what you want when reviewing a dependency bump.
"""

from __future__ import annotations

import sys
from pathlib import Path

import severity
from runwhen_capability import Context

from . import _common, _plan, _runner

# tests/fixtures/tools/osv-scanner.sarif: all 17 rules carry SARIF level
# "warning" and no severity metadata in `properties` at all -- unlike
# trivy, there is nothing here to discriminate a critical CVE from a low
# one. The single value below is the whole (empty) vocabulary; `_POLICY`
# (severity.constant) forces every result to it.
SEVERITY = {"": "warning"}
NAME = "osv-scanner"
KIND = "lockfile"
FILES = (
    "requirements*.txt",
    "poetry.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
)
CONFIG = "optional"
CONFIG_NAMES = ()
CI_BINARY = None
GUARD = None
LANE = "A"
OSV_ENDPOINT = "https://api.osv.dev/"
UNREACHABLE = "dependency scan unavailable: api.osv.dev unreachable"
# osv-scanner exits 1 when it finds vulnerabilities (capture.log: exit 1,
# 197930B of valid SARIF) -- not a tool failure.
EXPECT_EXIT = (0, 1)

_POLICY = severity.constant(SEVERITY)


def narrow(ctx, tree, changed, groups):
    """Eligible only when osv.dev answers (DIFF-SCOPED-CHECKS.md §9)."""
    if _runner.endpoint_reachable(ctx, OSV_ENDPOINT):
        return groups, None
    return {}, UNREACHABLE


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = ["osv-scanner", "--format", "sarif"]
    for f in _runner.files_arg(inv):
        argv += ["-L", f]
    proc = _runner.run(ctx, argv, cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "osv-scanner", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.sarif_to_findings(ctx, tree, inv, proc.stdout, _POLICY)
