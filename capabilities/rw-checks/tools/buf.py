"""buf -- protobuf lint."""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common

# buf lint findings are all failures of the configured rule set; there is no
# severity axis to map, so this is the whole (degenerate) vocabulary.
SEVERITY = {"": "warning"}
FILES = ("*.proto",)
CONFIG = "optional"
CI_BINARY = "buf"
GUARD = None
# tests/fixtures/tools/capture.log: buf lint findings exit 100 -- buf's own
# convention -- not a tool failure.
EXPECT_EXIT = (0, 100)


def detect(tree: Path) -> list[Path]:
    return [p.parent for p in _common.config_files(tree, "buf.yaml", "buf.yml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings
    # No path argument in capture.log either: buf resolves its module from
    # buf.yaml/buf.work.yaml relative to cwd on its own.
    proc = ctx.run(["buf", "lint", "--error-format=json"], cwd=tree)
    fail = _common.check_exit(ctx, tree, "buf", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.emit(ctx, adapters.buf(proc.stdout, SEVERITY), tree, changed)
