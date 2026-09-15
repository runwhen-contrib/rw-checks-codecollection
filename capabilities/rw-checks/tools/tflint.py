"""tflint -- Terraform linting.

tflint has no recursive mode of its own and no batch --filter of its own
verified shape, so a module (the directory holding its `.tflint.hcl`) is the
unit of work, and `group()` below runs one invocation per changed file inside
that module -- CONFIG is `required` because `check()` needs a resolved config
directory to `--chdir` into.

tests/fixtures/tools/tflint.sarif -- captured from exactly this invocation
shape, `tflint --format sarif --chdir infra` run with cwd=tree -- reports
`"uri": "infra/main.tf"`, already prefixed with the --chdir argument and
therefore already repo-relative. `ctx.sarif.parse(root=tree, ...)` resolves
every path correctly with no rewrite needed; `_runner.realign_paths` below is
only a backstop for a tool that reports a bare basename instead.
"""

from __future__ import annotations

import sys
from pathlib import Path, PurePosixPath

import severity
from runwhen_capability import Context

from . import _common, _plan, _runner

# tests/fixtures/tools/tflint.sarif: same reasoning as zizmor -- trust the
# level tflint reports rather than inventing a rule-id-based policy it gives
# no evidence for. `_POLICY` (severity.from_level) applies this map as-is.
SEVERITY = {"error": "error", "warning": "warning", "note": "note"}
NAME = "tflint"
KIND = "Terraform"
FILES = ("*.tf",)
CONFIG = "required"
CONFIG_NAMES = (_plan.ConfigName(".tflint.hcl"),)
CI_BINARY = "tflint"
GUARD = None
LANE = "D"  # a module is tflint's unit: run in the changed file's module, keep that file's findings
# tflint exits 2 when it reports findings (capture.log: exit 2, 2384B of
# valid SARIF) -- not a tool failure.
EXPECT_EXIT = (0, 2)

_POLICY = severity.from_level(SEVERITY)


def group(tree, groups):
    """One invocation per changed file: repeated --filter flags are unverified."""
    return tuple(
        _plan.Invocation(files=(f,), config=resolved.path, cwd="")
        for resolved, files in sorted(groups.items(), key=lambda kv: kv[0].path)
        for f in sorted(files)
    )


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    rel = PurePosixPath(inv.files[0])
    argv = [
        "tflint",
        "--format",
        "sarif",
        "--chdir",
        rel.parent.as_posix() or ".",
        "-c",
        str(tree / inv.config),
        "--filter",
        rel.name,
    ]
    proc = _runner.run(ctx, argv, cwd=tree)
    fail = _common.check_exit(ctx, tree, "tflint", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    if not proc.stdout.strip():
        return []
    return _runner.realign_paths(ctx.sarif.parse(proc.stdout, root=tree, severity=_POLICY), inv)
