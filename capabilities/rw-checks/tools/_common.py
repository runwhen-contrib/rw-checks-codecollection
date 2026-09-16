"""Shared plumbing for the per-tool modules in this package.

Each tool gets its own module here, owning everything about that tool: its
severity map, where its config lives, whether it applies, and how to run it.
That is deliberate -- an earlier design described tools as declarative data
and ran them through one generic runner, which breaks the moment a tool needs
something the schema cannot express. Config discovery in particular is
open-ended: it recurses, it reads three file formats, and every tool spells it
differently.

What lives HERE is only what is genuinely identical across tools, and nothing
that constrains what a module may do.

This used to also carry the whole-tree applicability contract (`gate`/
`gated`/`supersession_skip`/`scoped`/`emit`/`run_to_file`, plus the
FILES/CONFIG/CI_BINARY/SUPERSEDED_BY vocabulary and a one-walk-per-tree file
cache) that every `check()` ran through before deciding whether and how to
invoke its tool. Every tool module is diff-scoped now: applicability, config
discovery and invocation planning live in `_plan.py`, and running a planned
invocation and turning its output into findings lives in `_runner.py`. That
whole-tree path was deleted in Task 11 of rw-1416; see git history for it.

What remains here is what both `_plan.py`/`_runner.py` and the tool modules
still share: INI/TOML config readers, the CI-already-runs check, and the
never-empty synthetic findings for a refused or failed run -- including
`ToolFailed`, which `_runner.run_to_file` raises for a tool that writes its
report to a file rather than stdout.
"""

from __future__ import annotations

import configparser
import io
import re
import tomllib
from pathlib import Path
from typing import Any

from runwhen_capability.findings import normalize_uri

# --- config readers ---------------------------------------------------------


def parse_ini(text: str) -> configparser.ConfigParser:
    """INI, tolerating keys that appear before any [section] header.

    vale's `.vale.ini` puts `StylesPath` and `Packages` at the top with no
    section, which configparser rejects outright.
    """
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read_file(io.StringIO("[__preamble__]\n" + text))
    return parser


def ini_section(tree_file: Path, section: str) -> dict[str, str] | None:
    """One INI section's items, or None if the file is unreadable/unparseable."""
    try:
        parser = parse_ini(tree_file.read_text(errors="replace"))
    except (OSError, configparser.Error, RecursionError):
        return None
    return dict(parser[section]) if parser.has_section(section) else None


def toml_table(path: Path, *keys: str) -> Any:
    """A dotted TOML table (`toml_table(p, "tool", "ruff")`), or None.

    Called during ELIGIBILITY (`_plan._counts`), before any guard runs --
    H6: a pyproject.toml that blows tomllib's own parser recursion must
    come back as "not a config" here, not escape as an uncaught
    RecursionError and crash the whole task. A file that fails this way
    still exists on disk (`is_file()`), so `_plan.guard_paths` still puts
    it on a guard's chain, and the guard's own parsing (which already
    catches RecursionError) turns it into a refusal instead."""
    try:
        doc: Any = tomllib.loads(path.read_text(errors="replace"))
    except (OSError, tomllib.TOMLDecodeError, RecursionError, UnicodeDecodeError):
        return None
    for key in keys:
        if not isinstance(doc, dict) or key not in doc:
            return None
        doc = doc[key]
    return doc


# --- applicability ----------------------------------------------------------


# An unquoted `#` (start-of-line or preceded by whitespace, outside a quoted
# string) begins a YAML comment; everything from there to end-of-line is not
# live config. `ci_already_runs` strips this before matching so a comment
# like "# we dropped ruff last year" can never satisfy the check it is
# describing the absence of.
def _strip_yaml_comments(text: str) -> str:
    out_lines = []
    for line in text.splitlines():
        quote = None
        cut = len(line)
        for i, ch in enumerate(line):
            if quote:
                if ch == quote:
                    quote = None
            elif ch in ("'", '"'):
                quote = ch
            elif ch == "#" and (i == 0 or line[i - 1].isspace()):
                cut = i
                break
        out_lines.append(line[:cut])
    return "\n".join(out_lines)


def ci_already_runs(tree: Path, binary: str) -> str | None:
    """Whether the repository's own CI already runs `binary`.

    Re-reporting what a repo's CI already reports on the same pull request is
    pure noise -- CodeRabbit skips 17 of its 20 tools on exactly this signal.
    Secret and dependency scanning deliberately opt out (CI_BINARY = None):
    those are wanted regardless of what CI does.

    Word-boundary match against workflow files, comments stripped first. The
    trailing boundary is `(?!\\w)`, not `(?![\\w-])`: a hyphenated action name
    like `astral-sh/ruff-action@v1` -- the most common way a repo runs ruff in
    CI -- must still match. The leading boundary stays `(?<![\\w-])` so
    `myruff` does not. Deliberately shallow otherwise: a false positive costs
    a check we would mostly duplicate, a false negative costs nothing but
    noise we already have.
    """
    pattern = re.compile(rf"(?<![\w-]){re.escape(binary)}(?!\w)")
    for wf in tree.glob(".github/workflows/*.y*ml"):
        try:
            text = _strip_yaml_comments(wf.read_text(errors="replace"))
        except OSError:
            continue
        if pattern.search(text):
            return f"{binary} already runs in {wf.relative_to(tree).as_posix()}"
    return None


# --- results ----------------------------------------------------------------

#: A finding location that is never dropped by `from_records`' path
#: normalisation: it is not empty, not absolute, and does not collapse to
#: "." or ".." (both of which `normalize_uri` rejects as escaping the
#: worktree root -- verified against the SDK directly, see this package's
#: tests). Used when a finding is about the CHECK ITSELF, not about any one
#: file the tool happened to be pointed at.
WHOLE_REPO_PATH = "<repository>"


def unsafe_config_finding(ctx, tree: Path, reason: str):
    """One visible finding for a check refused by its security guard.

    Silently returning nothing would look identical to "this repository is
    clean", which is worse than reporting nothing at all. `reason` normally
    begins "<repo-relative path>: ...", so the finding usually lands on the
    config that tripped it -- but `from_records` drops any path that does
    not resolve under `tree` (an absolute path, an empty string, or one that
    normalises to "." or ".."), which would silently turn a refusal into
    zero findings. The derived path is never trusted blindly: it is only
    used when it demonstrably survives that normalisation, and
    `WHOLE_REPO_PATH` otherwise -- this function must never return an empty
    list. Never diff-filtered -- an unsafe config already in the repo is
    exactly as dangerous when the PR did not touch it.
    """
    path, sep, _ = reason.partition(": ")
    if not sep or not path or not normalize_uri(path, str(tree))[1]:
        path = WHOLE_REPO_PATH
    return ctx.findings.from_records(
        [
            {
                "path": path,
                "rule": "rw-checks/unsafe-config",
                "line": 0,
                "severity": "warning",
                "message": f"{reason}; check skipped",
            }
        ],
        root=tree,
    )


def check_failed_finding(ctx, tree: Path, tool: str, exit_code: int, detail: str):
    """One visible finding for a tool that failed to RUN, as opposed to one
    that ran and reported defects. Many of these tools exit non-zero because
    they found something (pylint, sqlfluff, tflint, buf, ...) -- that is not
    a failure, which is the whole reason each module declares its own
    EXPECT_EXIT rather than this function guessing. A tool that crashed,
    timed out, or produced no usable report must be as visible as any other
    finding: silently returning `[]` looks identical to a clean scan.
    `path=WHOLE_REPO_PATH` because this finding is about the run, not about
    any one file.
    """
    detail = (detail or "").strip() or "no output"
    return ctx.findings.from_records(
        [
            {
                "path": WHOLE_REPO_PATH,
                "rule": "rw-checks/check-failed",
                "line": 0,
                "severity": "warning",
                "message": f"{tool} exited {exit_code} unexpectedly: {detail}",
            }
        ],
        root=tree,
    )


class ToolFailed(Exception):
    """Raised by `_runner.run_to_file` when the tool it ran did not succeed
    -- either its exit code fell outside the module's EXPECT_EXIT, or it
    wrote no usable report. Caught by the two `check()`s that go through
    `_runner.run_to_file` (gitleaks, checkov) and turned into a
    `check_failed_finding`."""

    def __init__(self, exit_code: int, detail: str) -> None:
        self.exit_code = exit_code
        self.detail = detail
        super().__init__(detail)


def check_exit(ctx, tree: Path, tool: str, proc, module: Any) -> list | None:
    """None when `proc.returncode` is within `module.EXPECT_EXIT`; otherwise
    the visible check-failed finding for that exit code. The one branch
    every `check()` that calls `ctx.run` directly (i.e. every one but
    gitleaks/checkov, which go through `_runner.run_to_file` instead) needs
    after running its tool."""
    expect = getattr(module, "EXPECT_EXIT", (0,))
    if proc.returncode in expect:
        return None
    return check_failed_finding(ctx, tree, tool, proc.returncode, proc.stderr)
