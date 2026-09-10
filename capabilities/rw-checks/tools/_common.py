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

A tool module declares:

    SEVERITY    dict, REQUIRED -- the tool's own vocabulary -> error|warning|note.
                The ONLY definition: adapters/severity.py take it as a
                parameter rather than hardcoding their own copy, so a module
                cannot declare a map that disagrees with what actually runs.
    FILES       tuple of globs; empty means "applies regardless of files present"
    CONFIG      "required" (skip when unconfigured) | "optional" (use defaults)
    CI_BINARY   skip when the repo's own CI already runs this; None to never skip
    GUARD       callable(tree) -> reason|None, for configs that can execute code
    EXPECT_EXIT tuple of exit codes, REQUIRED -- codes that mean "ran
                fine", including ones that mean "ran fine and found things"
                (pylint's --exit-zero forces 0; tflint reports findings via
                exit 2). Anything else is a failed RUN, surfaced as a visible
                `rw-checks/check-failed` finding rather than swallowed as an
                empty result -- see check_exit()/run_to_file() below.

and defines:

    detect(tree) -> list[Path]        every directory where the tool is configured
    check(ctx, tree, changed) -> list[Finding]

`detect()` is shared between applicability and invocation ON PURPOSE. The
discovery task will call it to decide whether a check is offered at all, and
`check()` calls it to decide where to run. One definition of "where is this
tool configured" means the two cannot drift apart.
"""

from __future__ import annotations

import configparser
import io
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from runwhen_capability.findings import normalize_uri

# --- file discovery ---------------------------------------------------------

# One walk per tree, not one per glob per tool. `gate()` runs once per tool
# (22 of them, several calling find_files/config_files more than once each
# via FILES/detect()) -- without this, a single request re-walks the whole
# repository dozens of times over. Keyed by the `tree` Path itself: every
# tool in one request is handed the same checked-out worktree.
_TREE_FILES_CACHE: dict[Path, list[Path]] = {}


def _all_files(tree: Path) -> list[Path]:
    """Every file under `tree`, `.git` excluded, walked once and cached."""
    cached = _TREE_FILES_CACHE.get(tree)
    if cached is None:
        cached = [
            p for p in tree.rglob("*") if p.is_file() and ".git" not in p.relative_to(tree).parts
        ]
        _TREE_FILES_CACHE[tree] = cached
    return cached


def find_files(tree: Path, *patterns: str) -> list[str]:
    """Repo-relative POSIX paths matching any glob, `.git` excluded.

    For tools with no directory-recursion mode of their own (shellcheck,
    hadolint, checkmake), which must be handed every target explicitly.
    """
    found: set[str] = set()
    for p in _all_files(tree):
        rel = p.relative_to(tree).as_posix()
        if any(PurePosixPath(rel).match(pattern) for pattern in patterns):
            found.add(rel)
    return sorted(found)


def config_files(tree: Path, *names: str) -> list[Path]:
    """Every file in the tree whose name matches, `.git` excluded.

    Recursive, not root-only: most of these tools read the nearest config to
    the file being linted, so a nested `.pylintrc` or `biome.json` is live.
    """
    wanted = set(names)
    return sorted({p for p in _all_files(tree) if p.name in wanted})


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
    except (OSError, configparser.Error):
        return None
    return dict(parser[section]) if parser.has_section(section) else None


def toml_table(path: Path, *keys: str) -> Any:
    """A dotted TOML table (`toml_table(p, "tool", "ruff")`), or None."""
    try:
        doc: Any = tomllib.loads(path.read_text(errors="replace"))
    except (OSError, tomllib.TOMLDecodeError):
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


@dataclass(frozen=True)
class Skip:
    """Why a tool did not run. `unsafe` is True only for a GUARD refusal --
    the one case that must surface as a visible finding rather than silently
    skip, so `gated()` below can tell the two apart without either side
    re-parsing a string."""

    reason: str
    unsafe: bool = False


def gate(tree: Path, module: Any) -> Skip | None:
    """Why this tool should not run here, or None to run it.

    Order matters: the security guard is checked FIRST, so a config that can
    execute code is refused even when every other gate would have skipped the
    tool anyway.
    """
    guard = getattr(module, "GUARD", None)
    if guard is not None:
        reason = guard(tree)
        if reason:
            return Skip(reason, unsafe=True)

    files = getattr(module, "FILES", ())
    if files and not find_files(tree, *files):
        return Skip("no matching files")

    if getattr(module, "CONFIG", "optional") == "required" and not module.detect(tree):
        return Skip("not configured in this repository")

    binary = getattr(module, "CI_BINARY", None)
    if binary:
        ci = ci_already_runs(tree, binary)
        if ci:
            return Skip(ci)
    return None


def gated(ctx, tree: Path, module: Any) -> tuple[list, bool]:
    """(findings, should_stop) -- the one branch every `check()` needs.

    On a guard refusal, `findings` is the visible unsafe-config finding and
    `should_stop` is True. On any other skip, `findings` is `[]` and
    `should_stop` is True. When the tool should run, returns `([], False)`.
    """
    skip = gate(tree, module)
    if skip is None:
        return [], False
    if skip.unsafe:
        return unsafe_config_finding(ctx, tree, skip.reason), True
    return [], True


# --- results ----------------------------------------------------------------

#: A finding location that is never dropped by `from_records`' path
#: normalisation: it is not empty, not absolute, and does not collapse to
#: "." or ".." (both of which `normalize_uri` rejects as escaping the
#: worktree root -- verified against the SDK directly, see this package's
#: tests). Used when a finding is about the CHECK ITSELF, not about any one
#: file the tool happened to be pointed at.
WHOLE_REPO_PATH = "<repository>"


def scoped(ctx, findings, changed: list[str] | None):
    """Reduce findings to the files this pull request touched.

    EVERY check is diff-scoped, security scanners included. This capability
    runs as part of a code review, and a review asks "does this change
    introduce a problem?", not "what is wrong with this repository?". An
    exhaustive scan is a different product on a different cadence: it
    belongs on a schedule against the default branch, where its backlog can
    be worked down deliberately instead of landing on whoever happens to
    open the next unrelated pull request.

    `changed` is the PR's cumulative diff against its base, so a secret
    added in the first commit of a twelve-commit branch is still in scope.
    What drops out is only what was already on the base branch.

    A falsy `changed` means there is no diff to scope to -- a non-PR
    invocation -- and the full result set is returned UNFILTERED, not
    empty. `filter_changed` allows nothing through when `changed` is empty,
    so this guard is the only thing keeping a whole-repo run from silently
    reporting clean.

    Scoping is deliberately not applied to the synthetic findings raised by
    `gate` and `check_exit`: a refused config or a tool that failed to run
    is a fact about the CHECK, not about a file, carries WHOLE_REPO_PATH,
    and would be dropped by any path-based filter. Those return early,
    before this is reached.
    """
    if not changed:
        return findings
    return ctx.findings.filter_changed(findings, changed)


def emit(ctx, records, tree: Path, changed: list[str] | None):
    """Adapter records -> Findings, scoped to the diff. See `scoped`."""
    return scoped(ctx, ctx.findings.from_records(records, root=tree), changed)


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
    """Raised by `run_to_file` when the tool it ran did not succeed --
    either its exit code fell outside the module's EXPECT_EXIT, or it wrote
    no usable report. Caught by the two `check()`s that use `run_to_file`
    (gitleaks, checkov) and turned into a `check_failed_finding`."""

    def __init__(self, exit_code: int, detail: str) -> None:
        self.exit_code = exit_code
        self.detail = detail
        super().__init__(detail)


def run_to_file(ctx, argv: list[str], tree: Path, report: Path, module: Any) -> str:
    """Run a tool that writes its report to a FILE and read it back.

    Two tools need this and for different reasons: gitleaks writes ZERO bytes
    to `--report-path /dev/stdout` through a pipe (which is what ctx.run
    gives it) while still finding leaks, and checkov prints an ASCII banner to
    stdout and puts the SARIF somewhere else entirely. Both were caught by
    running them, not by reading their docs.

    Raises `ToolFailed` -- never returns silently -- when the process exited
    outside `module.EXPECT_EXIT`, or when the report is missing/empty: an
    empty report used to be read as "this tool found nothing," which is
    exactly as wrong when the tool never actually ran.
    """
    report.parent.mkdir(parents=True, exist_ok=True)
    proc = ctx.run(argv, cwd=tree)
    try:
        text = report.read_text()
    except OSError:
        text = ""
    expect = getattr(module, "EXPECT_EXIT", (0,))
    if proc.returncode not in expect:
        raise ToolFailed(proc.returncode, proc.stderr)
    if not text.strip():
        raise ToolFailed(proc.returncode, "produced no report")
    return text


def check_exit(ctx, tree: Path, tool: str, proc, module: Any) -> list | None:
    """None when `proc.returncode` is within `module.EXPECT_EXIT`; otherwise
    the visible check-failed finding for that exit code. The one branch
    every `check()` that calls `ctx.run` directly (i.e. every one but
    gitleaks/checkov, which go through `run_to_file` instead) needs after
    running its tool."""
    expect = getattr(module, "EXPECT_EXIT", (0,))
    if proc.returncode in expect:
        return None
    return check_failed_finding(ctx, tree, tool, proc.returncode, proc.stderr)
