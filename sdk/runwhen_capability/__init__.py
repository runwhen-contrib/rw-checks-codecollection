"""runwhen_capability -- the SDK a capability repo's tasks are written against.

See docs/static-checks/CAPABILITY-CONTRACT.md (Part 2) in runwhen-auto for the
binding contract this package implements. Tasks are plain Python functions;
the SDK owns every boundary -- inputs, outputs, credentials, subprocesses,
storage.
"""

from .context import Context
from .decorators import setup, task
from .models import (
    Finding,
    GrepMatch,
    GrepResult,
    LsEntry,
    LsResult,
    ReadResult,
    RequestEnvelope,
    ResultEnvelope,
    SetupResult,
    SetupSpec,
    TaskHostRequest,
    TaskHostResult,
    TaskResult,
    TaskSpec,
)

__all__ = [
    "Context",
    "setup",
    "task",
    "Finding",
    "GrepMatch",
    "GrepResult",
    "LsEntry",
    "LsResult",
    "ReadResult",
    "RequestEnvelope",
    "ResultEnvelope",
    "SetupResult",
    "SetupSpec",
    "TaskHostRequest",
    "TaskHostResult",
    "TaskResult",
    "TaskSpec",
]
