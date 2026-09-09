"""buf -- protobuf lint."""

from __future__ import annotations

import sys
from pathlib import Path

import _common
import adapters
from runwhen_capability import Context

# buf lint findings are all failures of the configured rule set; there is no
# severity axis to map. adapters.buf() hardcodes `warning`. Declared here
# only to satisfy the package-wide contract; adapters.py is the actual
# source of truth.
SEVERITY = {"": "warning"}
FILES = ("*.proto",)
CONFIG = "optional"
CI_BINARY = "buf"
GUARD = None


def detect(tree: Path) -> list[Path]:
    return [p.parent for p in _common.config_files(tree, "buf.yaml", "buf.yml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []
    # No path argument in capture.log either: buf resolves its module from
    # buf.yaml/buf.work.yaml relative to cwd on its own.
    proc = ctx.run(["buf", "lint", "--error-format=json"], cwd=tree)
    return _common.emit(ctx, adapters.buf(proc.stdout), tree, changed, diff_filter=True)
