"""Finding fingerprint and changed-files filter, ported byte-identical from
the Go implementation (internal/rwcheck/fingerprint, internal/rwcheck/diff in
runwhen-runner) per docs/static-checks/CONTRACT.md:

    fingerprint = hex(sha256("v1|" + capability + "|" + operation + "|" +
                              rule_id + "|" + path + "|" + normalized_context))[:32]

papi trusts this value; it must never be recomputed downstream of this SDK.
"""

from __future__ import annotations

import hashlib
import os
import posixpath
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

from .models import Finding
from .pathsafe import safe_path

FINGERPRINT_LENGTH = 32

#: The only severities a Finding may carry (models.Severity).
_SEVERITIES = frozenset({"error", "warning", "note"})

_WHITESPACE_RUN = re.compile(r"\s+")


def normalize_path(path: str) -> str:
    """CONTRACT's path rule: repo-relative, forward slashes, no leading './'."""
    p = path.replace("\\", "/")
    return p[2:] if p.startswith("./") else p


def normalize_context(context: str) -> str:
    """CONTRACT's normalized_context rule: leading/trailing whitespace
    stripped, internal whitespace runs (tabs, CRLF, repeated spaces)
    collapsed to a single space. The line number is never part of this
    string -- callers must not fold it in."""
    trimmed = context.strip()
    return _WHITESPACE_RUN.sub(" ", trimmed)


def compute(capability: str, operation: str, rule: str, path: str, context: str) -> str:
    """The CONTRACT fingerprint. path and context are normalized internally
    so callers can pass raw SARIF values straight through."""
    raw = (
        "v1|"
        + capability
        + "|"
        + operation
        + "|"
        + rule
        + "|"
        + normalize_path(path)
        + "|"
        + normalize_context(context)
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:FINGERPRINT_LENGTH]


# --- shared path / context resolution ---------------------------------------
# Lives here rather than in sarif.py because EVERY adapter -- SARIF or not --
# must normalise paths and resolve context identically: `context` feeds the
# fingerprint, so any divergence between the SARIF path and a JSON/text
# adapter would produce two different fingerprints for the same defect, and
# `resolve_finding` would stop matching across runs. sarif.py re-exports
# `normalize_uri` for backwards compatibility with its existing importers.


def normalize_uri(uri: str, worktree_root: str) -> tuple[str, bool]:
    """A tool-reported location -> the CONTRACT path shape: repo-relative,
    forward slashes, no leading './'. Returns ("", False) when `uri` is
    empty, names a scheme this does not understand (anything but "file" or
    no scheme at all), or resolves outside `worktree_root` -- callers must
    DROP such a finding rather than fingerprint or diff-filter it against a
    path that can never match."""
    if not uri:
        return "", False

    p = uri
    try:
        parsed = urlparse(uri)
    except ValueError:
        parsed = None
    if parsed is not None:
        if parsed.scheme in ("", "file"):
            if parsed.path:
                p = unquote(parsed.path)
        else:
            return "", False
    p = p.replace("\\", "/")

    if not posixpath.isabs(p):
        stripped = p[2:] if p.startswith("./") else p
        clean = posixpath.normpath(stripped) if stripped else "."
        if clean in (".", "..") or clean.startswith("../"):
            return "", False
        return clean, True

    abs_root = os.path.abspath(worktree_root).replace("\\", "/")
    try:
        rel = posixpath.relpath(p, abs_root)
    except ValueError:
        return "", False
    if rel == ".." or rel.startswith("../"):
        return "", False
    return rel[2:] if rel.startswith("./") else rel, True


def resolve_base_uri(loc: Mapping, bases: Mapping) -> str:
    """Resolves an artifactLocation's uriBaseId against the run's
    originalUriBaseIds (SARIF spec). Returns the raw uri unresolved when
    there is no uriBaseId, the name is unknown, or a URI fails to parse."""
    uri = loc.get("uri", "") or ""
    base_id = loc.get("uriBaseId")
    if not base_id:
        return uri
    base = bases.get(base_id)
    if not base or not base.get("uri"):
        return uri
    try:
        return urljoin(base["uri"], uri)
    except ValueError:
        return uri


def read_line(path: Path, n: int) -> str:
    data = path.read_text(errors="replace")
    lines = data.split("\n")
    if n < 1 or n > len(lines):
        raise ValueError("line out of range")
    return lines[n - 1].rstrip("\r")


def resolve_context(
    worktree: Path,
    path: str,
    line: int,
    snippet: str = "",
    op_name: str = "",
    log=None,
) -> str:
    """CONTRACT's normalized_context source rule: prefer a tool-supplied
    snippet, otherwise read the anchored line out of the worktree, otherwise
    "". Never raises -- an unreadable file yields "" so one bad path cannot
    fail a whole task."""
    if snippet:
        return snippet
    if line <= 0 or not path:
        return ""
    safe = safe_path(worktree, normalize_path(path))
    if safe is None:
        if log is not None:
            log.warning("%s: rejected path outside worktree: %r", op_name, path)
        return ""
    try:
        return read_line(safe, line)
    except (OSError, ValueError):
        return ""


class FindingsClient:
    """`ctx.findings` -- the contract-defined finding operations."""

    def __init__(self, ctx) -> None:
        self._ctx = ctx

    def filter_changed(self, findings: list[Finding], changed: list[str] | None) -> list[Finding]:
        """CONTRACT's changed_files.json filter: emit only findings whose
        path is in `changed`. `changed` is the list ctx.git.changed_files()
        returned -- already reduced to paths with status != removed. A None
        or empty `changed` allows nothing through by design; callers only
        call this when they have a real diff (see the SDK example: `if
        changed: findings = ctx.findings.filter_changed(...)`)."""
        allowed = set(changed or [])
        return [f for f in findings if f.path in allowed]

    def from_records(
        self,
        records: Iterable[Mapping],
        *,
        root: Path | str,
        severity_map: Mapping[str, str] | None = None,
        default_severity: str = "warning",
    ) -> list[Finding]:
        """The non-SARIF adapter path: tool-shaped records -> Findings.

        Each record is a mapping with the keys an adapter has already
        extracted from its tool's output:

            path      required -- dropped if it does not resolve under `root`
            rule      required -- the tool's own rule/check id
            line      optional, default 0
            severity  optional -- looked up in `severity_map`, else
                      `default_severity`. Mapping to our three-value
                      vocabulary is the CAPABILITY's job: every tool has its
                      own severity words and none of them mean the same
                      thing (CHECKS-COVERAGE.md "severity has no common
                      meaning").
            message   optional, default ""
            snippet   optional -- when the tool supplies the offending text,
                      it is preferred over re-reading the line from disk.

        Findings are returned UNFINGERPRINTED, exactly like
        `ctx.sarif.parse` -- callers run `.fingerprint()` themselves so
        there is one place where that happens for every adapter.
        """
        root = Path(root)
        smap = severity_map or {}
        out: list[Finding] = []
        for rec in records:
            raw_path = rec.get("path", "") or ""
            normalized, ok = normalize_uri(raw_path, str(root))
            if not ok:
                if self._ctx.log is not None:
                    self._ctx.log.warning(
                        "%s: skipped finding with unresolvable location: %r",
                        self._ctx.operation,
                        raw_path,
                    )
                continue
            line = int(rec.get("line", 0) or 0)
            context = resolve_context(
                root,
                normalized,
                line,
                str(rec.get("snippet", "") or ""),
                self._ctx.operation,
                self._ctx.log,
            )
            raw_sev = str(rec.get("severity", "") or "").lower()
            out.append(
                Finding(
                    capability=self._ctx.capability,
                    operation=self._ctx.operation,
                    rule=str(rec.get("rule", "") or ""),
                    path=normalized,
                    line=line,
                    # An adapter that already speaks our vocabulary passes
                    # through untouched. `severity_map` is for the other shape --
                    # a record carrying the tool's RAW severity word. Without
                    # this passthrough an already-mapped value misses `smap`
                    # entirely and silently becomes `default_severity`, which
                    # flattens every tool to one level.
                    severity=(
                        raw_sev if raw_sev in _SEVERITIES else smap.get(raw_sev, default_severity)
                    ),
                    message=str(rec.get("message", "") or ""),
                    context=normalize_context(context),
                )
            )
        return out

    def fingerprint(self, findings: list[Finding]) -> list[Finding]:
        """Fills in `fingerprint` on each finding using the CONTRACT formula.
        Returns new Finding instances (Finding is immutable-by-convention
        here); does not mutate the input list."""
        out = []
        for f in findings:
            fp = compute(f.capability, f.operation, f.rule, f.path, f.context)
            out.append(f.model_copy(update={"fingerprint": fp}))
        return out
