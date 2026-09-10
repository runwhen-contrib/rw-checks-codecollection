"""tflint -- Terraform linting.

Diff-scoped like every other check: see _common.scoped.

tasks.py's original argv hardcoded `--chdir infra`, tests/fixtures/
sample-repo's own layout, not a real target repo's -- tflint has no
recursive mode of its own, so each directory actually containing `*.tf` is
discovered (via FILES / _common.find_files below, not detect() -- detect()
here answers a different question, "where is tflint configured", used for
applicability) and run separately, once per directory.

Path remapping (the concern pylint.py's own comment raises: "paths come
back relative to the root [the tool] ran in, not the repo") turns out to be
unnecessary here: tests/fixtures/tools/tflint.sarif -- captured from exactly
this invocation shape, `tflint --format sarif --chdir infra` run with
cwd=tree -- reports `"uri": "infra/main.tf"`, already prefixed with the
--chdir argument and therefore already repo-relative. Running each
discovered directory the same way (cwd=tree, `--chdir <repo-relative dir>`)
carries that property forward, so ctx.sarif.parse(root=tree, ...) resolves
every path correctly with no rec["path"] rewrite step.
"""

from __future__ import annotations

import sys
from pathlib import Path

import severity
from runwhen_capability import Context

from . import _common

# tests/fixtures/tools/tflint.sarif: same reasoning as zizmor -- trust the
# level tflint reports rather than inventing a rule-id-based policy it gives
# no evidence for. `_POLICY` (severity.from_level) applies this map as-is.
SEVERITY = {"error": "error", "warning": "warning", "note": "note"}
FILES = ("*.tf",)
CONFIG = "optional"
CI_BINARY = "tflint"
GUARD = None
# tflint exits 2 when it reports findings (capture.log: exit 2, 2384B of
# valid SARIF) -- not a tool failure.
EXPECT_EXIT = (0, 2)

_POLICY = severity.from_level(SEVERITY)


def detect(tree: Path) -> list[Path]:
    """Every directory where tflint is configured: a root/nested
    .tflint.hcl. CONFIG is optional -- tflint runs on its own defaults just
    fine -- so this is applicability signalling only; check() below finds
    the directories to actually RUN in separately, by *.tf presence, not by
    this (a terraform root need not have its own .tflint.hcl at all)."""
    return [p.parent for p in _common.config_files(tree, ".tflint.hcl")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    gated_findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return gated_findings

    tf_dirs: set[Path] = set()
    for f in _common.find_files(tree, *FILES):
        tf_dirs.add((tree / f).parent)

    findings = []
    for tf_dir in sorted(tf_dirs):
        rel = tf_dir.relative_to(tree)
        # tflint exits 2 when it reports findings (capture.log: exit 2,
        # 2384B of valid SARIF) -- ctx.run does not raise on non-zero exit,
        # and that is correct here: a non-zero exit is the tool reporting
        # findings, not a tool failure (see EXPECT_EXIT above).
        proc = ctx.run(["tflint", "--format", "sarif", "--chdir", rel.as_posix()], cwd=tree)
        fail = _common.check_exit(ctx, tree, "tflint", proc, sys.modules[__name__])
        if fail is not None:
            return fail
        if not proc.stdout.strip():
            continue
        findings.extend(ctx.sarif.parse(proc.stdout, root=tree, severity=_POLICY))

    return _common.scoped(ctx, findings, changed)
