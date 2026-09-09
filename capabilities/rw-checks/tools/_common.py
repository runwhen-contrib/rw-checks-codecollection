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

    SEVERITY    dict, REQUIRED -- the tool's own vocabulary -> error|warning|note
    FILES       tuple of globs; empty means "applies regardless of files present"
    CONFIG      "required" (skip when unconfigured) | "optional" (use defaults)
    CI_BINARY   skip when the repo's own CI already runs this; None to never skip
    GUARD       callable(tree) -> reason|None, for configs that can execute code

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
from pathlib import Path
from typing import Any

# --- file discovery ---------------------------------------------------------


def find_files(tree: Path, *patterns: str) -> list[str]:
    """Repo-relative POSIX paths matching any glob, `.git` excluded.

    For tools with no directory-recursion mode of their own (shellcheck,
    hadolint, checkmake), which must be handed every target explicitly.
    """
    found: set[str] = set()
    for pattern in patterns:
        for p in tree.rglob(pattern):
            if p.is_file() and ".git" not in p.relative_to(tree).parts:
                found.add(p.relative_to(tree).as_posix())
    return sorted(found)


def config_files(tree: Path, *names: str) -> list[Path]:
    """Every file in the tree whose name matches, `.git` excluded.

    Recursive, not root-only: most of these tools read the nearest config to
    the file being linted, so a nested `.pylintrc` or `biome.json` is live.
    """
    out: list[Path] = []
    for name in names:
        for p in tree.rglob(name):
            if p.is_file() and ".git" not in p.relative_to(tree).parts:
                out.append(p)
    return sorted(set(out))


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


def ci_already_runs(tree: Path, binary: str) -> str | None:
    """Whether the repository's own CI already runs `binary`.

    Re-reporting what a repo's CI already reports on the same pull request is
    pure noise -- CodeRabbit skips 17 of its 20 tools on exactly this signal.
    Secret and dependency scanning deliberately opt out (CI_BINARY = None):
    those are wanted regardless of what CI does.

    Word-boundary match against workflow files. Deliberately shallow: a false
    positive costs a check we would mostly duplicate, a false negative costs
    nothing but noise we already have.
    """
    pattern = re.compile(rf"(?<![\w-]){re.escape(binary)}(?![\w-])")
    for wf in tree.glob(".github/workflows/*.y*ml"):
        try:
            if pattern.search(wf.read_text(errors="replace")):
                return f"{binary} already runs in {wf.relative_to(tree).as_posix()}"
        except OSError:
            continue
    return None


def gate(tree: Path, module: Any) -> str | None:
    """Why this tool should not run here, or None to run it.

    Order matters: the security guard is checked FIRST, so a config that can
    execute code is refused even when every other gate would have skipped the
    tool anyway.
    """
    guard = getattr(module, "GUARD", None)
    if guard is not None:
        reason = guard(tree)
        if reason:
            return f"unsafe-config:{reason}"

    files = getattr(module, "FILES", ())
    if files and not find_files(tree, *files):
        return "no matching files"

    if getattr(module, "CONFIG", "optional") == "required" and not module.detect(tree):
        return "not configured in this repository"

    binary = getattr(module, "CI_BINARY", None)
    if binary:
        ci = ci_already_runs(tree, binary)
        if ci:
            return ci
    return None


# --- results ----------------------------------------------------------------


def emit(ctx, records, tree: Path, changed: list[str] | None, *, diff_filter: bool):
    """records -> Findings, optionally reduced to the pull request's diff.

    `diff_filter` is a per-tool decision, never a default: lint findings are
    about the change, security findings are about the repository. A secret
    committed three months ago is still live whether or not this PR touched
    that file.
    """
    findings = ctx.findings.from_records(records, root=tree)
    if diff_filter and changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return findings


def unsafe_config_finding(ctx, tree: Path, reason: str):
    """One visible finding for a check refused by its security guard.

    Silently returning nothing would look identical to "this repository is
    clean", which is worse than reporting nothing at all. `reason` always
    begins "<repo-relative path>: ...", so the finding lands on the config
    that tripped it. Never diff-filtered -- an unsafe config already in the
    repo is exactly as dangerous when the PR did not touch it.
    """
    path, _, _ = reason.partition(": ")
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


def run_to_file(ctx, argv: list[str], tree: Path, report: Path) -> str:
    """Run a tool that writes its report to a FILE and read it back.

    Two tools need this and for different reasons: gitleaks writes ZERO bytes
    to `--report-path /dev/stdout` through a pipe (which is what ctx.run
    gives it) while still finding leaks, and checkov prints an ASCII banner to
    stdout and puts the SARIF somewhere else entirely. Both were caught by
    running them, not by reading their docs.
    """
    report.parent.mkdir(parents=True, exist_ok=True)
    ctx.run(argv, cwd=tree)
    try:
        return report.read_text()
    except OSError:
        return ""
