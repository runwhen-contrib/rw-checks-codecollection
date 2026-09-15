"""biome -- JS/TS/JSON/CSS lint.

Config is nearest-wins, monorepo-style (a package's own biome.json shadows
one further up) -- one run per resolved root, cwd set to that root so biome
reads its own config the way it would from a real invocation there. Two
root biome.json files sharing one run hard-errors, which is why this is
LANE B rather than a single whole-tree invocation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common, _plan, _runner

SEVERITY = {"error": "error", "warning": "warning", "information": "note", "hint": "note"}
NAME = "biome"
KIND = "JS/TS/JSON/CSS"
FILES = ("*.js", "*.jsx", "*.ts", "*.tsx", "*.json", "*.css")
CONFIG = "required"
CONFIG_NAMES = (_plan.ConfigName("biome.json"), _plan.ConfigName("biome.jsonc"))
CI_BINARY = "biome"
GUARD = None
LANE = "B"  # two root biome.json files in one run hard-error (verified); biome reads the cwd config
EXPECT_EXIT = (0, 1)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = ["biome", "lint", "--reporter=json", *_runner.files_arg(inv)]
    proc = _runner.run(ctx, argv, cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "biome", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(ctx, tree, inv, adapters.biome(proc.stdout, SEVERITY))
