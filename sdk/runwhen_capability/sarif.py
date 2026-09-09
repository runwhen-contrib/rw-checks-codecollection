"""SARIF -> Finding, ported from internal/rwcheck/sarif (and the
resolveContext/SafePath helpers in internal/rwcheck/runner) in runwhen-runner.
Only understands the SARIF 2.1.0 shape rwcheck/this SDK needs
(runs[].results[]) -- not a general-purpose SARIF library.

Path normalisation mirrors the Go implementation exactly: an absolute
`file://` artifactLocation.uri (ruff among the tools that emit one) is only
trustworthy against the worktree root the operation actually ran in, so a
location that does not resolve under `root` is DROPPED (logged, not silently
passed through with an unnormalized path) -- such a path can never match the
changed-files filter.
"""

from __future__ import annotations

import json
from collections.abc import Callable
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
    severity: str  # already mapped -- see `severity_fn` in _flatten
    message: str
    path: str  # "" if no location
    line: int  # 0 if no region
    column: int  # 0 if region carries no startColumn
    end_line: int  # 0 if region carries no endLine (or no region)
    end_column: int  # 0 if region carries no endColumn
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


# `SarifClient.parse`'s own `severity` parameter (below) shadows this
# function inside that method -- this alias is how `parse` still reaches
# today's default mapping without renaming the public `sarif.severity`
# helper tests/test_sarif.py already imports directly.
_default_severity_from_level = severity


def _rule_properties(run: dict) -> dict[str, dict]:
    """ruleId -> that rule's `properties` dict, from
    runs[].tool.driver.rules[] -- the only place a SARIF report carries
    structured per-rule metadata (e.g. trivy's `security-severity`) beyond
    the bare `level` string on each result. {} for a rule with no
    `properties`, or one `results[].ruleId` never lists in `rules` at all
    (gitleaks: 222 rules, none of them carry properties)."""
    driver = ((run.get("tool") or {}).get("driver")) or {}
    out: dict[str, dict] = {}
    for rule in driver.get("rules") or []:
        rid = rule.get("id")
        if rid:
            out[rid] = rule.get("properties") or {}
    return out


def _flatten(
    report: dict,
    worktree_root: str,
    log,
    severity_fn: Callable[[str, str, dict], str],
) -> list[_RawFinding]:
    out: list[_RawFinding] = []
    for run in report.get("runs", []) or []:
        bases = run.get("originalUriBaseIds") or {}
        rule_props = _rule_properties(run)
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId", "") or ""
            level = res.get("level", "") or ""
            sev = severity_fn(rule_id, level, rule_props.get(rule_id, {}))
            message = (res.get("message") or {}).get("text", "") or ""
            locations = res.get("locations") or []
            if not locations:
                out.append(_RawFinding(rule_id, sev, message, "", 0, 0, 0, 0, ""))
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
                    severity=sev,
                    message=message,
                    path=normalized,
                    line=region.get("startLine", 0) or 0,
                    column=region.get("startColumn", 0) or 0,
                    end_line=region.get("endLine", 0) or 0,
                    end_column=region.get("endColumn", 0) or 0,
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

    def parse(
        self,
        text: str,
        root: Path | str,
        severity: Callable[[str, str, dict], str] | None = None,
    ) -> list[Finding]:
        """`severity`, when given, is called per result as
        `severity(rule_id, sarif_level, rule_properties)` -- `rule_properties`
        is that result's rule's `properties` dict from
        runs[].tool.driver.rules[] (matched by id), or {} when absent -- and
        must return "error"|"warning"|"note". This is a per-CAPABILITY
        policy (capabilities/rw-checks/severity.py), not an SDK default: SARIF
        `level` means a different thing for every tool -- see that module's
        docstring for what each of the 7 SARIF tools actually emits. `None`
        keeps today's behaviour exactly: `level` mapped by the module-level
        `severity()` function above, ignoring `rule_id`/`rule_properties`.
        """
        root = Path(root)
        report = json.loads(text)
        severity_fn = (
            severity
            if severity is not None
            else (lambda rule_id, level, props: _default_severity_from_level(level))
        )
        raw_findings = _flatten(report, str(root), self._ctx.log, severity_fn)

        findings: list[Finding] = []
        for rf in raw_findings:
            context = resolve_context(
                root, rf.path, rf.line, rf.snippet, self._ctx.operation, self._ctx.log
            )
            findings.append(
                Finding(
                    capability=self._ctx.capability,
                    operation=self._ctx.operation,
                    rule=rf.rule_id,
                    path=rf.path,
                    line=rf.line,
                    column=rf.column,
                    end_line=rf.end_line,
                    end_column=rf.end_column,
                    severity=rf.severity,
                    message=rf.message,
                    context=normalize_context(context),
                )
            )
        return findings
