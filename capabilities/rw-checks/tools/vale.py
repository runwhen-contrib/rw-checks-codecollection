"""vale -- prose lint for docs.

CONFIG is required: vale ships with almost no built-in rules -- without a
`.vale.ini` naming a styles package, there is nothing to actually check.
Its own config is also a fetch-and-execute vector: a non-empty `Packages`
key downloads and installs a style package from a URL -- see guards.py.
Config-gated per directory: each changed file runs under the nearest
`.vale.ini`/`_vale.ini`/`vale.ini`, cwd set to that directory (StylesPath
is relative to the config).
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
import guards
from runwhen_capability import Context

from . import _common, _plan, _runner

SEVERITY = {"error": "error", "warning": "warning", "suggestion": "note"}
NAME = "vale"
KIND = "Markdown or text"
FILES = ("*.md", "*.markdown", "*.txt")
CONFIG = "required"
CONFIG_NAMES = (
    _plan.ConfigName(".vale.ini"),
    _plan.ConfigName("_vale.ini"),
    _plan.ConfigName("vale.ini"),
)
CI_BINARY = "vale"
GUARD = guards.vale  # a non-empty Packages downloads and installs from a URL
LANE = "B"  # cwd-only discovery; StylesPath is relative to the config (verified)
EXPECT_EXIT = (0, 1)


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = ["vale", "--output=JSON", "--config", _runner.config_arg(inv), *_runner.files_arg(inv)]
    proc = _runner.run(ctx, argv, cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "vale", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(ctx, tree, inv, adapters.vale(proc.stdout, SEVERITY))
