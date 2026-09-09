"""Finding fingerprint and changed-files filter, ported byte-identical from
the Go implementation (internal/rwcheck/fingerprint, internal/rwcheck/diff in
runwhen-runner) per docs/static-checks/CONTRACT.md:

    fingerprint = hex(sha256("v1|" + capability + "|" + operation + "|" +
                              rule_id + "|" + path + "|" + normalized_context))[:32]

papi trusts this value; it must never be recomputed downstream of this SDK.
"""

from __future__ import annotations

import hashlib
import re

from .models import Finding, FindingsResult

FINGERPRINT_LENGTH = 32

_WHITESPACE_RUN = re.compile(r"\s+")

# findings: a safety valve against a pathological blowup, NOT a presentation
# limit -- unlike repo_fs.py's read/grep/ls caps (MAX_READ_RESPONSE_BYTES,
# HARD_GREP_MAX_MATCHES, MAX_LS_ENTRIES), which bound what a human/agent reads
# in one call, this result is the *only* durable record a static-check task
# ever produces: papi stores it verbatim in capability_runs.result (JSONB),
# there is no findings table, and whatever this cap drops is gone forever --
# `truncated: true` records that data was lost, not what. Human-scale
# truncation belongs at papi's Check Run; agent-scale truncation belongs at
# papi's findings catalog. Do not lower this to make either of those nicer.
#
# Sized off the transport that actually carries it, not a round number: the
# runner-control ingress this result passes through is being raised to 64m
# (nginx MiB units: 64 * 1,048,576 = 67,108,864 bytes). Budgeting half of
# that to the findings payload -- 33,554,432 bytes -- and leaving the other
# half as headroom for JSON envelope overhead and per-finding size variance,
# against the ~330 bytes/finding measured on the field failure this exists to
# prevent (a run against the 468-platform monorepo: 19,527 raw ruff findings,
# ~6.3 MB, the "several MB" result papi 413'd three times before max_attempts
# failed the run -- back when the ingress was nginx's 1 MB default) gives
# 33,554,432 // 330 = 101,679, rounded down to a clean 100,000. That leaves
# generous headroom above any realistic PR-scoped result, and even lets a
# monorepo-wide run like the 19,527-finding case above pass through whole --
# this cap only bites on a genuine runaway well past that.
MAX_FINDINGS_PER_RESULT = 100_000


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

    def fingerprint(self, findings: list[Finding]) -> list[Finding]:
        """Fills in `fingerprint` on each finding using the CONTRACT formula.
        Returns new Finding instances (Finding is immutable-by-convention
        here); does not mutate the input list."""
        out = []
        for f in findings:
            fp = compute(f.capability, f.operation, f.rule, f.path, f.context)
            out.append(f.model_copy(update={"fingerprint": fp}))
        return out

    def cap(self, findings: list[Finding]) -> FindingsResult:
        """Caps `findings` at MAX_FINDINGS_PER_RESULT and reports whether it
        did -- the same honesty ctx.repo_fs.grep already gives a capped
        match list. This is a safety valve against a genuine runaway, not
        routine truncation -- any realistic run, even an undiffed one
        against a large repo, should pass through untouched. See
        MAX_FINDINGS_PER_RESULT for the byte-budget arithmetic. Call this
        last, after filter_changed/fingerprint, so the cap applies to the
        exact list the task is about to return."""
        truncated = len(findings) > MAX_FINDINGS_PER_RESULT
        return FindingsResult(findings=findings[:MAX_FINDINGS_PER_RESULT], truncated=truncated)
