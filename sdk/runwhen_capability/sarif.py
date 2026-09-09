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
from dataclasses import dataclass
from pathlib import Path

from .findings import (
    normalize_context,
    normalize_uri,  # noqa: F401 -- re-exported: `sarif.normalize_uri` is a public import path
    resolve_base_uri,
    resolve_context,
)
from .models import Finding


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
            raw_uri = resolve_base_uri(artifact, bases)
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
            context = resolve_context(root, rf.path, rf.line, rf.snippet, self._ctx.operation, self._ctx.log)
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
