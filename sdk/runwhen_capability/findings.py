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

from .models import Finding

FINGERPRINT_LENGTH = 32

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
