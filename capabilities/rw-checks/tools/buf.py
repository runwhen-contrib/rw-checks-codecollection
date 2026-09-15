"""buf -- protobuf lint.

buf resolves its module from `buf.yaml`/`buf.work.yaml` relative to cwd on
its own, so `group()` below runs from each `buf.work.yaml` workspace root
(falling back to the module itself when there is none) and passes every
changed file as an explicit `--path`, rather than letting buf discover files
on its own and reporting on files nobody changed.
"""

from __future__ import annotations

import sys
from pathlib import Path, PurePosixPath

import adapters
from runwhen_capability import Context

from . import _common, _plan, _runner

# buf lint findings are all failures of the configured rule set; there is no
# severity axis to map, so this is the whole (degenerate) vocabulary.
SEVERITY = {"": "warning"}
NAME = "buf"
KIND = "protobuf"
FILES = ("*.proto",)
CONFIG = "required"
CONFIG_NAMES = (_plan.ConfigName("buf.yaml"), _plan.ConfigName("buf.yml"))
CI_BINARY = "buf"
GUARD = None
LANE = "D"
# tests/fixtures/tools/capture.log: buf lint findings exit 100 -- buf's own
# convention -- not a tool failure.
EXPECT_EXIT = (0, 100)


def _workspace_root(tree: Path, module_base: str) -> str:
    """The nearest ancestor holding buf.work.yaml, else the module itself."""
    current = PurePosixPath(module_base) if module_base else PurePosixPath(".")
    while True:
        if (tree / current / "buf.work.yaml").is_file():
            return "" if current == PurePosixPath(".") else current.as_posix()
        if current == PurePosixPath("."):
            return module_base
        current = current.parent


def group(tree, groups):
    by_root: dict[str, list[str]] = {}
    for resolved, files in groups.items():
        by_root.setdefault(_workspace_root(tree, resolved.base), []).extend(files)
    return tuple(
        _plan.Invocation(files=tuple(sorted(fs)), config=None, cwd=root)
        for root, fs in sorted(by_root.items())
    )


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = ["buf", "lint", "--error-format=json"]
    for f in _runner.files_arg(inv):
        argv += ["--path", f]
    proc = _runner.run(ctx, argv, cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "buf", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(ctx, tree, inv, adapters.buf(proc.stdout, SEVERITY))
