"""biome -- JS/TS/JSON/CSS lint.

Config is nearest-wins, monorepo-style (a package's own biome.json shadows
one further up), the same shape as pylint's per-root config -- so like
pylint, detect() returns every configured root and check() runs once per
root, remapping paths back to repo-relative.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common

SEVERITY = {"error": "error", "warning": "warning", "information": "note", "hint": "note"}
FILES = ("*.js", "*.jsx", "*.ts", "*.tsx", "*.json", "*.css")
CONFIG = "optional"
CI_BINARY = "biome"
GUARD = None
EXPECT_EXIT = (0, 1)


def detect(tree: Path) -> list[Path]:
    return [p.parent for p in _common.config_files(tree, "biome.json", "biome.jsonc")]


def check(ctx: Context, tree: Path, changed: list[str] | None):
    gated_findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return gated_findings

    # capture.log captured `biome lint`, not `biome ci` (adapters.py's
    # docstring names `ci` as the conceptual equivalent) -- `lint` is what
    # was actually proven to emit this JSON shape, so that is what runs
    # here. No configured root found: still run once at the repo root with
    # biome's own defaults, same as capture.log's fixture-specific "src"
    # dir generalised to ".".
    roots = detect(tree) or [tree]
    records = []
    for root in roots:
        proc = ctx.run(["biome", "lint", "--reporter=json", "."], cwd=root)
        fail = _common.check_exit(ctx, tree, "biome", proc, sys.modules[__name__])
        if fail is not None:
            return fail
        rel = root.relative_to(tree)
        for rec in adapters.biome(proc.stdout, SEVERITY):
            # Paths come back relative to the root biome ran in, not the repo.
            rec["path"] = (rel / rec["path"]).as_posix() if rel.parts else rec["path"]
            records.append(rec)
    return _common.emit(ctx, records, tree, changed, diff_filter=True)
