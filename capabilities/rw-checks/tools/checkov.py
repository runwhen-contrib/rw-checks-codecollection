"""checkov -- IaC misconfiguration scanning.

SECURITY: checkov's own config can point it at an external directory or git
repo of check PLUGINS it imports and runs (see guards.py's module
docstring) -- GUARD refuses to invoke checkov at all rather than run it
against an untrusted repo's config and hope external-checks-dir/
external-checks-git are absent. Not diff-filtered: an IaC misconfiguration
doesn't stop being one because this diff didn't touch the affected file.
"""

from __future__ import annotations

import sys
from pathlib import Path

import guards
import severity
from runwhen_capability import Context

from . import _common

# tests/fixtures/tools/checkov.sarif: all 39 results are marked SARIF level
# "error" -- passing that through would fail every IaC repo checkov ever
# runs against, and checkov's OSS output carries no severity metadata to
# discriminate on. The single value below is the whole (empty) vocabulary --
# `_POLICY` (severity.constant) closes over it uniformly.
SEVERITY = {"": "warning"}
FILES = ("*.tf", "Dockerfile*", "*.yaml", "*.yml")
CONFIG = "optional"
CI_BINARY = "checkov"
# checkov's own config can point it at external check plugins it imports and
# runs -- see guards.py's module docstring for the confirmed exploit shape.
GUARD = guards.checkov
# checkov exits 1 when it reports failed checks -- not a soft-fail run
# (no --soft-fail), so 0 (clean) and 1 (findings) both mean "ran fine".
EXPECT_EXIT = (0, 1)

_POLICY = severity.constant(SEVERITY)


def detect(tree: Path) -> list[Path]:
    """checkov reads a root/nested .checkov.yaml/.checkov.yml if present;
    it needs none."""
    return [p.parent for p in _common.config_files(tree, ".checkov.yaml", ".checkov.yml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings

    # checkov's `-o/--output sarif` prints a banner to stdout and writes
    # nothing there -- the SARIF report lands on disk at
    # <--output-file-path>/results_sarif.sarif (tests/fixtures/tools/
    # capture.log). Write into a dir under ctx.workdir (the per-request
    # scope dir, wiped every request -- NOT /tmp) and read that file back.
    # checkov can exit non-zero when it reports findings; that is not a
    # task failure (see EXPECT_EXIT above).
    out_dir = ctx.workdir / "checkov-out"
    try:
        text = _common.run_to_file(
            ctx,
            ["checkov", "-d", ".", "--output", "sarif", "--output-file-path", str(out_dir)],
            tree,
            out_dir / "results_sarif.sarif",
            sys.modules[__name__],
        )
    except _common.ToolFailed as exc:
        return _common.check_failed_finding(ctx, tree, "checkov", exc.exit_code, exc.detail)
    # Never diff-filtered: see _common.emit.
    return ctx.sarif.parse(text, root=tree, severity=_POLICY)
