"""flake8 -- fast Python lint, ahead of pylint's deeper (slower) pass.

CONFIG required, following CodeRabbit: an opinionated linter run WITHOUT the
repository's own config reports findings the repo never asked for -- same
reasoning as pylint.py.

Its own config is also an arbitrary-code-execution vector: a non-empty
`paths`, `extension` or `report` under `[flake8:local-plugins]` adds `paths`
to `sys.path` and imports the named entry points -- see guards.py. flake8
reads only the file passed with `--config`, never merges ancestor configs,
so no GUARD_CHAIN.
"""

from __future__ import annotations

import fnmatch
import sys
from pathlib import Path, PurePosixPath

import adapters
import guards
from runwhen_capability import Context

import tools.ruff

from . import _common, _plan, _runner

# F (pyflakes) real defects, E/W (pycodestyle) style, C (mccabe)/N
# (pep8-naming) nits.
SEVERITY = {
    "F": "error",
    "E": "warning",
    "W": "warning",
    "C": "note",
    "N": "note",
}
NAME = "flake8"
KIND = "Python"
FILES = ("*.py",)
CONFIG = "required"
CONFIG_NAMES = (
    _plan.ConfigName(".flake8"),
    _plan.ConfigName("setup.cfg", ("flake8",)),
    _plan.ConfigName("tox.ini", ("flake8",)),
)
CI_BINARY = "flake8"
GUARD = guards.flake8  # `[flake8:local-plugins]` imports and runs Python from the repo
LANE = "B"  # cwd-only discovery (verified)
EXPECT_EXIT = (0, 1)
_FORMAT = "--format=%(path)s:%(row)d:%(col)d:%(code)s:%(text)s"


def _split_patterns(raw: str) -> list[str]:
    """Comma- and/or newline-separated glob patterns, stripped, empties dropped."""
    return [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]


def _exclude_patterns(tree: Path, resolved: _plan.Resolved) -> list[str]:
    section = _common.ini_section(tree / resolved.path, "flake8") or {}
    patterns: list[str] = []
    for key in ("exclude", "extend-exclude"):
        if section.get(key):
            patterns += _split_patterns(section[key])
    return patterns


def _excluded(rel: str, base: str, patterns: list[str]) -> bool:
    """flake8 semantics: a pattern matches the basename, the whole path
    relative to the config's directory, or any parent directory of that
    relative path -- by name or by its own relative path."""
    rel_to_base = PurePosixPath(rel).relative_to(base).as_posix() if base else rel
    parts = PurePosixPath(rel_to_base).parts
    for pattern in patterns:
        if fnmatch.fnmatchcase(parts[-1], pattern) or fnmatch.fnmatchcase(rel_to_base, pattern):
            return True
        for i in range(1, len(parts)):
            if fnmatch.fnmatchcase(parts[i - 1], pattern) or fnmatch.fnmatchcase(
                "/".join(parts[:i]), pattern
            ):
                return True
    return False


def narrow(ctx, tree, changed, groups):
    """ruff reimplements flake8 and emits its rule IDs: drop files ruff checks.
    Then drop files the repo's own [flake8] exclude/extend-exclude would skip --
    flake8 ignores those excludes when given explicit file arguments, so the
    planner applies them itself (spec §8)."""
    ruff_files = {
        f for inv in tools.ruff.applicable(ctx, tree, changed).invocations for f in inv.files
    }
    kept = {r: [f for f in fs if f not in ruff_files] for r, fs in groups.items()}
    kept = {r: fs for r, fs in kept.items() if fs}
    dropped = sum(len(fs) for fs in groups.values()) - sum(len(fs) for fs in kept.values())
    total = sum(len(fs) for fs in groups.values())
    ruff_note = (
        f"{dropped} of {total} changed Python files are covered by ruff" if dropped else None
    )

    excluded = 0
    after_excludes: dict[_plan.Resolved, list[str]] = {}
    for resolved, files in kept.items():
        patterns = _exclude_patterns(tree, resolved)
        remaining = (
            [f for f in files if not _excluded(f, resolved.base, patterns)] if patterns else files
        )
        excluded += len(files) - len(remaining)
        if remaining:
            after_excludes[resolved] = remaining
    exclude_note = (
        f"{excluded} of {total} changed Python files are excluded by flake8 config"
        if excluded
        else None
    )

    notes = [n for n in (ruff_note, exclude_note) if n]
    return after_excludes, "; ".join(notes) if notes else None


def applicable(ctx: Context, tree: Path, changed: list[str] | None) -> _plan.Applicability:
    return _plan.plan(ctx, tree, changed, sys.modules[__name__])


def check(ctx: Context, tree: Path, inv: _plan.Invocation):
    argv = ["flake8", "--config", _runner.config_arg(inv), _FORMAT, *_runner.files_arg(inv)]
    proc = _runner.run(ctx, argv, cwd=_runner.cwd_path(tree, inv))
    fail = _common.check_exit(ctx, tree, "flake8", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _runner.records_to_findings(ctx, tree, inv, adapters.flake8(proc.stdout, SEVERITY))
