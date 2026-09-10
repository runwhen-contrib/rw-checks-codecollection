"""SARIF -> Finding, ported from internal/rwcheck/sarif (and the
resolveContext/SafePath helpers in internal/rwcheck/runner) in runwhen-runner.
Only understands the SARIF 2.1.0 shape rwcheck/this SDK needs
(runs[].results[]) -- not a general-purpose SARIF library.

Path normalisation mirrors the Go implementation exactly: an absolute
`file://` artifactLocation.uri (ruff among the tools that emit one) is only
trustworthy against the worktree root the operation actually ran in, so a
location that does not resolve under `root` is DROPPED (logged, not silently
passed through with an unnormalized path) -- such a path can never match the
changed-files filter or be fingerprinted meaningfully.
"""

from __future__ import annotations

import itertools
import json
import os
import posixpath
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from .findings import MAX_FINDINGS_PER_RESULT, normalize_context, normalize_path
from .models import Finding
from .pathsafe import safe_path

_READ_LINE_TIMEOUT_MSG = "line out of range"


@dataclass
class _RawFinding:
    rule_id: str
    level: str
    message: str
    path: str  # "" if no location
    line: int  # 0 if no region
    snippet: str  # "" if the result carries no region.snippet.text


def severity(level: str) -> str:
    """SARIF `level` -> CONTRACT frame severity: error -> error,
    warning -> warning, note/none/absent -> note."""
    lvl = (level or "").lower()
    if lvl == "error":
        return "error"
    if lvl == "warning":
        return "warning"
    return "note"


def normalize_uri(uri: str, worktree_root: str) -> tuple[str, bool]:
    """Converts a SARIF artifactLocation URI (after any uriBaseId
    resolution) into the CONTRACT.md path shape: repo-relative, forward
    slashes, no leading './'. Returns ("", False) when uri is empty, names a
    scheme this does not understand (anything but "file" or no scheme at
    all), or resolves outside worktree_root -- callers must drop the finding
    rather than fingerprint or diff-filter it against such a path."""
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
                p = unquote(parsed.path)  # percent-decoded, mirrors url.Parse
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


def _resolve_base_uri(loc: dict, bases: dict[str, dict]) -> str:
    """Resolves an artifactLocation's uriBaseId against the enclosing run's
    originalUriBaseIds, per the SARIF spec: uriBaseId names an entry whose
    own uri is the base a relative artifactLocation.uri is resolved against.
    Returns the raw uri unresolved when there is no uriBaseId, the name is
    unknown, or either URI fails to parse."""
    uri = loc.get("uri", "") or ""
    base_id = loc.get("uriBaseId")
    if not base_id:
        return uri
    base = bases.get(base_id)
    if not base or not base.get("uri"):
        return uri
    try:
        from urllib.parse import urljoin

        return urljoin(base["uri"], uri)
    except ValueError:
        return uri


def _flatten(report: dict, worktree_root: str, log) -> Iterator[_RawFinding]:
    """A generator, not a list-builder: `SarifClient.parse` wraps this in
    `itertools.islice(..., MAX_FINDINGS_PER_RESULT + 1)`, which stops
    calling `next()` -- and therefore stops this function ever touching
    `report["runs"][*]["results"]` past that point -- once the ceiling is
    hit. That is what keeps a genuine runaway report from materialising a
    full _RawFinding (or downstream Finding) list before the safety valve
    ever gets a chance to act; see MAX_FINDINGS_PER_RESULT's docstring and
    parse()'s comment below."""
    for run in report.get("runs", []) or []:
        bases = run.get("originalUriBaseIds") or {}
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId", "") or ""
            level = res.get("level", "") or ""
            message = (res.get("message") or {}).get("text", "") or ""
            locations = res.get("locations") or []
            if not locations:
                yield _RawFinding(rule_id, level, message, "", 0, "")
                continue

            phys = (locations[0] or {}).get("physicalLocation") or {}
            artifact = phys.get("artifactLocation") or {}
            region = phys.get("region") or {}
            raw_uri = _resolve_base_uri(artifact, bases)
            normalized, ok = normalize_uri(raw_uri, worktree_root)
            if not ok:
                _warn_skipped_location(log, rule_id, artifact.get("uri", ""))
                continue

            snippet = ((region.get("snippet") or {}).get("text", "")) or ""
            yield _RawFinding(
                rule_id=rule_id,
                level=level,
                message=message,
                path=normalized,
                line=region.get("startLine", 0) or 0,
                snippet=snippet,
            )


def _warn_skipped_location(log, rule_id: str, raw_uri: str) -> None:
    if log is None:
        return
    log.warning("sarif: %s: skipped finding with unresolvable location: %r", rule_id, raw_uri)


def _warn_rejected_path(log, op_name: str, path: str) -> None:
    if log is None:
        return
    log.warning("sarif: %s: rejected path outside worktree: %r", op_name, path)


class _LineReader:
    """One-entry memo for reading a line out of a worktree file, scoped to a
    single SarifClient.parse() call. Without this, `_resolve_context` (the
    no-snippet fallback -- gitleaks' normal case) re-read and re-split the
    WHOLE file from disk for every finding that anchors to it: measured 2.2s
    for 20k findings over 200 x ~90 KB files, ~29s extrapolated at
    MAX_FINDINGS_PER_RESULT, against a lint phase that is itself ~8s (see
    FAILURE-POLICY.md's measured characteristics). SARIF results group
    per-file (a tool emits all of one file's findings together), so
    remembering only the most-recently-read file's lines -- not every file
    this parse touches -- captures most of the repeat reads while keeping
    memory bounded to one file at a time. A path miss evicts the memo
    (last-write-wins, not an LRU): correctness for interleaved paths, not
    maximum hit rate, is the requirement -- see
    test_sarif.py's interleaved-paths test."""

    def __init__(self) -> None:
        self._path: Path | None = None
        self._lines: list[str] | None = None

    def read_line(self, path: Path, n: int) -> str:
        if path != self._path:
            # Raises before self._path is updated, so a failed read is
            # never cached as if it had succeeded.
            lines = path.read_text(errors="replace").split("\n")
            self._path = path
            self._lines = lines
        assert self._lines is not None
        if n < 1 or n > len(self._lines):
            raise ValueError(_READ_LINE_TIMEOUT_MSG)
        return self._lines[n - 1].rstrip("\r")


def _resolve_context(
    rf: _RawFinding, worktree: Path, op_name: str, log, line_reader: _LineReader
) -> str:
    """CONTRACT's normalized_context source rule: prefer the SARIF snippet,
    otherwise read the anchored line from the worktree, otherwise ""."""
    if rf.snippet:
        return rf.snippet
    if rf.line <= 0 or not rf.path:
        return ""
    safe = safe_path(worktree, normalize_path(rf.path))
    if safe is None:
        _warn_rejected_path(log, op_name, rf.path)
        return ""
    try:
        return line_reader.read_line(safe, rf.line)
    except OSError:
        return ""
    except ValueError:
        return ""


class SarifClient:
    """`ctx.sarif` -- SARIF -> findings, tagged with the owning Context's
    capability and operation."""

    def __init__(self, ctx) -> None:
        self._ctx = ctx

    def parse(self, text: str, root: Path | str) -> list[Finding]:
        """Bounded at MAX_FINDINGS_PER_RESULT + 1 findings -- one past
        ctx.findings.cap()'s ceiling, so that call still sees `len(findings)
        > MAX_FINDINGS_PER_RESULT` and reports `truncated` correctly,
        without this function ever having built more than a ceiling's worth
        of _RawFinding/Finding objects along the way. `_flatten` is a
        generator specifically so `itertools.islice` bounds it lazily: on a
        genuine runaway (hundreds of thousands of SARIF results), this never
        touches the results past the +1st, rather than flattening all of
        them and discarding the excess only at the very end (cap() running
        last, after every copy in the pipeline had already paid for the
        full size -- see MAX_FINDINGS_PER_RESULT's docstring). Real results
        (measured: 6.3 MB / ~18,700 findings) stay far under the ceiling and
        pass through whole, byte for byte -- islice only ever bites on the
        pathological case this ceiling exists for."""
        root = Path(root)
        report = json.loads(text)
        raw_findings = itertools.islice(
            _flatten(report, str(root), self._ctx.log), MAX_FINDINGS_PER_RESULT + 1
        )

        line_reader = _LineReader()
        findings: list[Finding] = []
        for rf in raw_findings:
            context = _resolve_context(rf, root, self._ctx.operation, self._ctx.log, line_reader)
            findings.append(
                Finding(
                    capability=self._ctx.capability,
                    operation=self._ctx.operation,
                    rule=rf.rule_id,
                    path=rf.path,
                    line=rf.line,
                    severity=severity(rf.level),
                    message=rf.message,
                    context=normalize_context(context),
                )
            )
        return findings
