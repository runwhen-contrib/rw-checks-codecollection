"""hadolint -- Dockerfile defects.

File-gated: hadolint lints exactly one Dockerfile per invocation and has no
directory mode, so like shellcheck it must be handed every target
explicitly, and a repo with no Dockerfiles is simply not applicable.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common

SEVERITY = {"error": "error", "warning": "warning", "info": "note", "style": "note"}
FILES = ("Dockerfile*", "*.dockerfile")
CONFIG = "optional"
CI_BINARY = "hadolint"
GUARD = None
EXPECT_EXIT = (0, 1)


def detect(tree: Path) -> list[Path]:
    return [p.parent for p in _common.config_files(tree, ".hadolint.yaml", ".hadolint.yml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings
    # Same reasoning as shellcheck: hadolint lints exactly one Dockerfile per
    # invocation and has no directory mode, so every Dockerfile/Dockerfile.*
    # in the tree is discovered and passed explicitly.
    dockerfiles = _common.find_files(tree, *FILES)
    if not dockerfiles:
        return []
    proc = ctx.run(["hadolint", "-f", "json", *dockerfiles], cwd=tree)
    fail = _common.check_exit(ctx, tree, "hadolint", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.emit(ctx, adapters.hadolint(proc.stdout, SEVERITY), tree, changed)
