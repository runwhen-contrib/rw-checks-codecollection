"""checkov -- IaC misconfiguration scanning.

SECURITY: checkov's own config can point it at an external directory or git
repo of check PLUGINS it imports and runs (see guards.py's module
docstring) -- GUARD refuses to invoke checkov at all rather than run it
against an untrusted repo's config and hope external-checks-dir/
external-checks-git are absent. Diff-scoped like every other check: _plan
groups changed files by their nearest .checkov.yaml/.checkov.yml, passing
`-f <file>` explicitly rather than scanning the repo with `-d .`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import guards
import severity
from runwhen_capability import Context

from . import _common, _plan, _runner

# tests/fixtures/tools/checkov.sarif: all 39 results are marked SARIF level
# "error" -- passing that through would fail every IaC repo checkov ever
# runs against, and checkov's OSS output carries no severity metadata to
# discriminate on. The single value below is the whole (empty) vocabulary --
# `_POLICY` (severity.constant) closes over it uniformly.
SEVERITY = {"": "warning"}
NAME = "checkov"
KIND = "IaC"
# Dockerfile* deliberately absent: hadolint owns Dockerfiles (see the
# --skip-framework below, which is what actually enforces it).
FILES = ("*.tf", "*.yaml", "*.yml")
CONFIG = "optional"
CONFIG_NAMES = (_plan.ConfigName(".checkov.yaml"), _plan.ConfigName(".checkov.yml"))
CI_BINARY = "checkov"
# checkov's own config can point it at external check plugins it imports and
# runs -- see guards.py's module docstring for the confirmed exploit shape.
GUARD = guards.checkov
# checkov exits 1 when it reports failed checks -- not a soft-fail run
# (no --soft-fail), so 0 (clean) and 1 (findings) both mean "ran fine".
EXPECT_EXIT = (0, 1)
LANE = "B"  # checkov never reads repo config without --config-file (verified)

_POLICY = severity.constant(SEVERITY)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = ["checkov"]
    for f in _runner.files_arg(inv):
        argv += ["-f", f]
    out_dir = ctx.workdir / "checkov-out"
    argv += [
        "--skip-framework",
        "dockerfile",
        "--output",
        "sarif",
        "--output-file-path",
        str(out_dir),
    ]
    if inv.config:
        argv += ["--config-file", _runner.config_arg(inv)]
    try:
        text = _runner.run_to_file(
            ctx,
            argv,
            cwd=_runner.cwd_path(tree, inv),
            report=out_dir / "results_sarif.sarif",
            module=sys.modules[__name__],
        )
    except _common.ToolFailed as exc:
        return _common.check_failed_finding(ctx, tree, "checkov", exc.exit_code, exc.detail)
    return _runner.sarif_to_findings(ctx, tree, inv, text, _POLICY)
