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
    status: Literal["ok", "failed"]
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
