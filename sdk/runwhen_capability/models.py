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
    """One static-check finding. `fingerprint` is None until
    Context.findings.fingerprint() has run over it -- see CONTRACT.md's
    fingerprint formula, ported byte-identical in findings.py."""

    fingerprint: str | None = None
    capability: str
    operation: str
    rule: str
    path: str  # repo-relative, forward slashes, no leading "./"
    line: int = 0  # 0 if the finding carries no location
    severity: Severity
    message: str = ""
    context: str = ""  # normalized_context; "" if no region/line


# --- rw-worktree task outputs -----------------------------------------------
# Wire-3 output shapes for the rw-worktree capability's read/grep/ls tasks,
# ported from internal/rwcheck/serve/{read,grep,ls}.go's response structs in
# runwhen-runner (the v1 worktree host). Field names are camelCase directly
# on the model (no snake_case + alias) -- same convention as
# TaskHostRequest/TaskHostResult below -- because these are the exact field
# names agentfarm's agents/pr_review_agent/tools.py reads out of papi's
# unwrapped worktree-invoke `result` (read_repo_file / grep_repo /
# list_repo_dir): "startLine"/"endLine" for read, "matches"/"truncated" for
# grep, "entries" for ls. `matches`/`entries` default to `[]`, never omitted
# or null -- agentfarm's tools treat a missing/non-list value as a malformed
# response, not an empty result (a previously-fixed bug in exactly this
# shape is what that guard exists to catch).


class ReadResult(BaseModel):
    """Output of the `read` task."""

    path: str
    content: str
    startLine: int
    endLine: int
    totalLines: int
    truncated: bool = False


class GrepMatch(BaseModel):
    path: str
    line: int
    text: str


class GrepResult(BaseModel):
    """Output of the `grep` task."""

    matches: list[GrepMatch] = Field(default_factory=list)
    truncated: bool = False


class LsEntry(BaseModel):
    path: str
    type: Literal["file", "dir", "other"]
    size: int = 0


class LsResult(BaseModel):
    """Output of the `ls` task."""

    entries: list[LsEntry] = Field(default_factory=list)


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
