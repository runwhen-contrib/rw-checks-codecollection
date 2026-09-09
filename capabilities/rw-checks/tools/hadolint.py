"""hadolint -- Dockerfile defects.

File-gated: hadolint lints exactly one Dockerfile per invocation and has no
directory mode, so like shellcheck it must be handed every target
explicitly, and a repo with no Dockerfiles is simply not applicable.
"""

from __future__ import annotations

import sys
from pathlib import Path

import _common
import adapters
from runwhen_capability import Context

SEVERITY = adapters.HADOLINT_SEVERITY
FILES = ("Dockerfile*", "*.dockerfile")
CONFIG = "optional"
CI_BINARY = "hadolint"
GUARD = None


def detect(tree: Path) -> list[Path]:
    return [p.parent for p in _common.config_files(tree, ".hadolint.yaml", ".hadolint.yml")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []
    # Same reasoning as shellcheck: hadolint lints exactly one Dockerfile per
    # invocation and has no directory mode, so every Dockerfile/Dockerfile.*
    # in the tree is discovered and passed explicitly.
    dockerfiles = _common.find_files(tree, *FILES)
    if not dockerfiles:
        return []
    proc = ctx.run(["hadolint", "-f", "json", *dockerfiles], cwd=tree)
    return _common.emit(ctx, adapters.hadolint(proc.stdout), tree, changed, diff_filter=True)
