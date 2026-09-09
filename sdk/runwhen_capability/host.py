"""The task host's core engine: run one RequestEnvelope's setup then tasks
against a capability's registered functions, in manifest/request order,
resolving `${setup.<name>}` references, and aggregate into a ResultEnvelope.

Shared by both `rwtask serve` (host.py:serve) and `rwtask run` (the local
reference implementation) -- same code path, per CAPABILITY-CONTRACT.md Part 2.

Never raises out of run_request(): a setup/task exception becomes a
failed setup/task entry in the result, and the rest of the request still
runs to completion.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from .context import Context
from .errors import UnknownTaskError
from .loader import LoadedCapability
from .models import RequestEnvelope, ResultEnvelope, SetupResult, TaskResult

_PLACEHOLDER_RE = re.compile(r"^\$\{setup\.(\w+)\}$")
_CAMEL_RE = re.compile(r"(?<!^)(?=[A-Z])")


def _camel_to_snake(name: str) -> str:
    return _CAMEL_RE.sub("_", name).lower()


def _kwargs_from_inputs(inputs: dict[str, Any]) -> dict[str, Any]:
    return {_camel_to_snake(k): v for k, v in inputs.items()}


def _resolve_placeholders(inputs: dict[str, Any], setup_outputs: dict[str, Any]) -> dict[str, Any]:
    resolved = {}
    for key, value in inputs.items():
        if isinstance(value, str):
            m = _PLACEHOLDER_RE.match(value)
            if m:
                name = m.group(1)
                if name not in setup_outputs:
                    raise UnknownTaskError(
                        f"input {key!r} references unknown setup output '${{setup.{name}}}'"
                    )
                resolved[key] = setup_outputs[name]
                continue
        resolved[key] = value
    return resolved


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "model_dump"):  # pydantic model, e.g. Finding
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {k: _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(v) for v in value]
    return value


def run_request(
    capability: LoadedCapability,
    request: RequestEnvelope,
    credentials: dict[str, str],
    scope_dir: Path,
    log: logging.Logger | None = None,
    allow_anonymous_credentials: bool = False,
) -> ResultEnvelope:
    log = log or logging.getLogger("runwhen_capability.host")
    result = ResultEnvelope()
    setup_outputs: dict[str, Any] = {}

    if request.setup is not None:
        setup_def = capability.registry.setups.get(request.setup.task)
        if setup_def is None:
            result.setup = SetupResult(
                status="failed", error=f"unknown setup task {request.setup.task!r}"
            )
        else:
            ctx = Context(
                capability=capability.capability_id,
                operation=request.setup.task,
                workdir=scope_dir,
                credentials=credentials,
                log=log.getChild(request.setup.task),
                allow_anonymous_credentials=allow_anonymous_credentials,
            )
            try:
                kwargs = _kwargs_from_inputs(request.setup.inputs)
                outputs = setup_def.func(ctx, **kwargs) or {}
                setup_outputs = outputs
                result.setup = SetupResult(status="ok", outputs=_to_jsonable(outputs))
            except Exception as exc:  # noqa: BLE001 -- a task's own bug must not crash the host
                log.exception("setup %r failed", request.setup.task)
                result.setup = SetupResult(status="failed", error=str(exc))

    for task_spec in request.tasks:
        task_def = capability.registry.tasks.get(task_spec.task)
        if task_def is None:
            result.tasks.append(
                TaskResult(
                    task=task_spec.task, status="failed", error=f"unknown task {task_spec.task!r}"
                )
            )
            continue

        ctx = Context(
            capability=capability.capability_id,
            operation=task_spec.task,
            workdir=scope_dir,
            credentials=credentials,
            log=log.getChild(task_spec.task),
            allow_anonymous_credentials=allow_anonymous_credentials,
        )
        try:
            resolved_inputs = _resolve_placeholders(task_spec.inputs, setup_outputs)
            kwargs = _kwargs_from_inputs(resolved_inputs)
            outputs = task_def.func(ctx, **kwargs) or {}
            result.tasks.append(
                TaskResult(task=task_spec.task, status="ok", outputs=_to_jsonable(outputs))
            )
        except Exception as exc:  # noqa: BLE001 -- one task failing must not lose the others
            log.exception("task %r failed", task_spec.task)
            result.tasks.append(TaskResult(task=task_spec.task, status="failed", error=str(exc)))

    return result
