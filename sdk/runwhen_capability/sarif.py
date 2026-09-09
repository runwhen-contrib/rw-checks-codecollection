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

import json
import os
import posixpath
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

from .findings import normalize_context, normalize_path
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


def _flatten(report: dict, worktree_root: str, log) -> list[_RawFinding]:
    out: list[_RawFinding] = []
    for run in report.get("runs", []) or []:
        bases = run.get("originalUriBaseIds") or {}
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId", "") or ""
            level = res.get("level", "") or ""
            message = (res.get("message") or {}).get("text", "") or ""
            locations = res.get("locations") or []
            if not locations:
                out.append(_RawFinding(rule_id, level, message, "", 0, ""))
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
            out.append(
                _RawFinding(
                    rule_id=rule_id,
                    level=level,
                    message=message,
                    path=normalized,
                    line=region.get("startLine", 0) or 0,
                    snippet=snippet,
                )
            )
    return out


def _warn_skipped_location(log, rule_id: str, raw_uri: str) -> None:
    if log is None:
        return
    log.warning("sarif: %s: skipped finding with unresolvable location: %r", rule_id, raw_uri)


def _warn_rejected_path(log, op_name: str, path: str) -> None:
    if log is None:
        return
    log.warning("sarif: %s: rejected path outside worktree: %r", op_name, path)


def _read_line(path: Path, n: int) -> str:
    data = path.read_text(errors="replace")
    lines = data.split("\n")
    if n < 1 or n > len(lines):
        raise ValueError(_READ_LINE_TIMEOUT_MSG)
    return lines[n - 1].rstrip("\r")


def _resolve_context(rf: _RawFinding, worktree: Path, op_name: str, log) -> str:
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
        return _read_line(safe, rf.line)
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
        root = Path(root)
        report = json.loads(text)
        raw_findings = _flatten(report, str(root), self._ctx.log)

        findings: list[Finding] = []
        for rf in raw_findings:
            context = _resolve_context(rf, root, self._ctx.operation, self._ctx.log)
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
