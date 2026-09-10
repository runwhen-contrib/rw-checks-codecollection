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
# discriminate on. severity.checkov (called below) maps every result to
# "warning" uniformly; this map documents that (empty) vocabulary for the
# package-wide test.
SEVERITY = {"": "warning"}
FILES = ("*.tf", "Dockerfile*", "*.yaml", "*.yml")
CONFIG = "optional"
CI_BINARY = "checkov"
# checkov's own config can point it at external check plugins it imports and
# runs -- see guards.py's module docstring for the confirmed exploit shape.
GUARD = guards.checkov


def detect(tree: Path) -> list[Path]:
    """checkov reads a root/nested .checkov.yaml/.checkov.yml if present;
    it needs none."""
    return [p.parent for p in _common.config_files(tree, ".checkov.yaml", ".checkov.yml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    skip = _common.gate(tree, sys.modules[__name__])
    if skip and skip.startswith("unsafe-config:"):
        return _common.unsafe_config_finding(ctx, tree, skip.split(":", 1)[1])
    if skip:
        return []

    # checkov's `-o/--output sarif` prints a banner to stdout and writes
    # nothing there -- the SARIF report lands on disk at
    # <--output-file-path>/results_sarif.sarif (tests/fixtures/tools/
    # capture.log). Write into a dir under ctx.workdir (the per-request
    # scope dir, wiped every request -- NOT /tmp) and read that file back.
    # checkov can exit non-zero when it reports findings; that is not a
    # task failure.
    out_dir = ctx.workdir / "checkov-out"
    text = _common.run_to_file(
        ctx,
        ["checkov", "-d", ".", "--output", "sarif", "--output-file-path", str(out_dir)],
        tree,
        out_dir / "results_sarif.sarif",
    )
    if not text.strip():
        return []
    # Never diff-filtered: see _common.emit.
    return ctx.sarif.parse(text, root=tree, severity=severity.checkov)
