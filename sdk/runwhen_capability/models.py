"""Pydantic models for the wire envelopes this package speaks.

Two contracts, both in runwhen-auto's docs/static-checks/:

- CAPABILITY-CONTRACT.md Part 3 and EXECUTOR-CONTRACT.md "Wire 3" define the
  papi<->capability request/result envelope: RequestEnvelope/ResultEnvelope
  (and their setup/task sub-shapes).
- EXECUTOR-CONTRACT.md "Wire 2" defines the runner<->executor GetTask/PutResult
  shapes: TaskHostRequest is the `POST /v1/tasks/next` 200 body, TaskHostResult
  is the `POST /v1/tasks/{requestId}/result` body.

Finding is the shape defined in docs/static-checks/CONTRACT.md's `finding`
NDJSON frame -- carried over unchanged, just as a typed model instead of a
frame.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["error", "warning", "note"]


class Finding(BaseModel):
    """One static-check finding.

    column/end_line/end_column exist for one reason: GitHub check-run
    annotations accept `start_column`/`end_column` (only meaningful when
    `end_line` equals `start_line`) plus `end_line` itself, and without them
    a finding highlights the WHOLE line instead of the offending token.
    Every tool this package wraps reports at least some of this; discarding
    it here would mean discarding it everywhere downstream too.
    """

    capability: str
    operation: str
    rule: str
    path: str  # repo-relative, forward slashes, no leading "./"
    line: int = 0  # 0 if the finding carries no location
    column: int = 0  # 1-based; 0 = not reported
    end_line: int = 0  # 0 = single-line finding
    end_column: int = 0  # 1-based; 0 = not reported
    severity: Severity
    message: str = ""
    context: str = ""  # normalized_context; "" if no region/line


class FindingsResult(BaseModel):
    """Output of a `kind: rw.findings.v1` task (ruff, gitleaks). An
    envelope, not a bare list of Finding -- same reasoning as
    GrepResult/LsResult below: `truncated` is the only way a consumer can
    tell a capped list from a complete one. See findings.py's
    MAX_FINDINGS_PER_RESULT for the cap and the byte budget behind it."""

    findings: list[Finding] = Field(default_factory=list)
    truncated: bool = False


# --- rw-worktree task outputs -----------------------------------------------
# Wire-3 output shapes for the rw-worktree capability's read/grep/ls tasks,
# ported from internal/rwcheck/serve/{read,grep,ls}.go's response structs in
# runwhen-runner (the v1 worktree host). Field names are camelCase directly
# on the model (no snake_case + alias) -- same convention as
# TaskHostRequest/TaskHostResult below -- because these are the exact field
# names agentfarm's agents/pr_review_agent/tools.py reads out of papi's
# unwrapped worktree-invoke `result` (read_repo_file / grep_repo /
# list_repo_dir): "startLine"/"endLine" for read, "matches"/"truncated" for
# grep, "entries"/"truncated" for ls. `matches`/`entries` default to `[]`, never omitted
# or null -- agentfarm's tools treat a missing/non-list value as a malformed
# response, not an empty result (a previously-fixed bug in exactly this
# shape is what that guard exists to catch).
#
# `unreadable`/`unreadableTruncated` on GrepResult/LsResult (grep and ls both
# walk a subtree; read only ever touches the one path the caller named) carry
# paths *encountered* during that walk but not readable -- permission denied,
# a TOCTOU race, etc. Distinct from `truncated`, which means "there was more
# of what you asked for": `unreadable` means "part of what you asked for
# could not be read at all", and collapsing the two into one flag would lose
# that distinction. An absent `unreadable` (an older host predating this
# field) must read as "nothing reported unreadable", never as an error --
# agentfarm's tools treat it the same way they already treat an absent
# `truncated`.


class ReadResult(BaseModel):
    """Output of the `read` task."""

    path: str
    content: str
    startLine: int
    endLine: int
    totalLines: int
    truncated: bool = False


class GrepMatch(BaseModel):
    # before/after: the `context`-line window around this match, in file
    # order -- empty (the default) when the caller didn't ask for context,
    # so an existing caller that never passes `context` sees no shape
    # change (RW-1416 cost P2, CAP-1: I3's query task `grep`/`defs`/`refs`
    # ops all carry context).
    path: str
    line: int
    text: str
    before: list[str] = Field(default_factory=list)
    after: list[str] = Field(default_factory=list)


class GrepResult(BaseModel):
    """Output of the `grep` task."""

    matches: list[GrepMatch] = Field(default_factory=list)
    truncated: bool = False
    unreadable: list[str] = Field(default_factory=list)
    unreadableTruncated: bool = False


class ReadRange(BaseModel):
    """One merged range in a `read_ranges` result."""

    start: int
    end: int
    content: str


class ReadRangesResult(BaseModel):
    """Output of `read_ranges` -- the multi-range counterpart to
    ReadResult, backing I3's query task `read` op (`ranges` and `around`
    both resolve to this shape; RW-1416 cost P2, CAP-1)."""

    path: str
    ranges: list[ReadRange] = Field(default_factory=list)
    totalLines: int
    truncated: bool = False


class LsEntry(BaseModel):
    path: str
    type: Literal["file", "dir", "other"]
    size: int = 0


class LsResult(BaseModel):
    """Output of the `ls` task."""

    entries: list[LsEntry] = Field(default_factory=list)
    truncated: bool = False
    unreadable: list[str] = Field(default_factory=list)
    unreadableTruncated: bool = False


class QueryError(BaseModel):
    """A per-op failure in a `query` result. `code` is one of repo_fs's
    error codes (repo_fs.error_code: PATH_ESCAPES_TREE, NOT_FOUND,
    NOT_A_DIRECTORY, BINARY_FILE, INVALID_PATTERN, UNREADABLE) or one of
    the query task's own (INVALID_OP, RESPONSE_BUDGET) -- a plain string
    rather than an enum so a new code is not a schema break for a caller."""

    code: str
    message: str


class QueryOpResult(BaseModel):
    """One op's entry in a `query` result, at its request `index`. Exactly
    one of `result`/`error` is non-null; both are always present."""

    index: int
    op: str | None = None  # null only when the op named no known operation
    result: GrepResult | ReadRangesResult | LsResult | None = None
    error: QueryError | None = None


class QueryResult(BaseModel):
    """Output of the `query` task (RW-1416 cost P2, CAP-3; I3): one entry
    per op, in request order. `truncated` is set when the response budget
    cut an op short or turned later ops into RESPONSE_BUDGET errors."""

    results: list[QueryOpResult] = Field(default_factory=list)
    truncated: bool = False


# --- Wire 3 (papi <-> capability): the request/result envelope -------------


class SetupSpec(BaseModel):
    task: str
    inputs: dict[str, Any] = Field(default_factory=dict)


class TaskSpec(BaseModel):
    task: str
    inputs: dict[str, Any] = Field(default_factory=dict)


class RequestEnvelope(BaseModel):
    version: int = 1
    setup: SetupSpec | None = None
    tasks: list[TaskSpec] = Field(default_factory=list)


class SetupResult(BaseModel):
    """`status`, in full:

    - `ok` -- setup executed on this request and succeeded.
    - `cached` -- setup was NOT re-executed; its outputs were reused from
      an earlier request against this same scope (EXECUTOR-CONTRACT.md
      "Addressing and caching"). `outputs` is honest either way -- a
      `cached` result still carries the real, usable outputs, just not
      freshly produced.
    - `not_materialized` -- setup was not cached for this scope AND could
      not be (re-)run because a required credential is missing: the
      mcp.v1 sync path's shape (it carries no credentials, by design).
      Distinct from `failed` so the runner/papi can recover by enqueuing
      the leased (credentialed) row and retrying once, instead of
      treating this as an ordinary, non-recoverable failure.
    - `failed` -- setup executed and raised for any other reason (unknown
      setup task, a real checkout failure, etc.) -- unchanged from before.
    """

    status: Literal["ok", "failed", "cached", "not_materialized"]
    outputs: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class TaskResult(BaseModel):
    task: str
    status: Literal["ok", "failed"]
    outputs: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class ResultEnvelope(BaseModel):
    version: int = 1
    setup: SetupResult | None = None
    tasks: list[TaskResult] = Field(default_factory=list)


# --- Wire 2 (runner <-> executor): the relay HTTP contract ------------------


class TaskHostRequest(BaseModel):
    """The 200 response body of `POST {relay}/v1/tasks/next`."""

    requestId: str
    request: RequestEnvelope
    credentials: dict[str, str] = Field(default_factory=dict)
    scopeId: str
    deadlineMs: int


class TaskHostResult(BaseModel):
    """The body of `POST {relay}/v1/tasks/{requestId}/result`."""

    status: Literal["ok", "failed", "timeout"]
    result: ResultEnvelope | None = None
    error: str | None = None
