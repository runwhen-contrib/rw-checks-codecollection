"""host.run_request: ${setup.<name>} resolution, camelCase input -> snake_case
kwarg mapping, and the "one task raising must not lose the others" guarantee.
"""

from __future__ import annotations

from pathlib import Path

from runwhen_capability.host import run_request
from runwhen_capability.loader import load_capability
from runwhen_capability.models import RequestEnvelope

FIXTURES = Path(__file__).parent / "fixtures" / "capabilities"


def test_setup_output_resolution_and_camel_case_inputs(tmp_path):
    capability = load_capability(FIXTURES / "echo")
    request = RequestEnvelope.model_validate(
        {
            "version": 1,
            "setup": {"task": "prep", "inputs": {"userName": "world"}},
            "tasks": [
                {
                    "task": "echo",
                    "inputs": {"greeting": "${setup.greeting}", "items": "${setup.items}"},
                }
            ],
        }
    )

    result = run_request(capability, request, credentials={}, scope_dir=tmp_path)

    assert result.setup.status == "ok"
    assert result.setup.outputs == {"greeting": "hello world", "items": ["a", "b"]}

    assert len(result.tasks) == 1
    assert result.tasks[0].status == "ok"
    assert result.tasks[0].outputs == {"result": "hello world:a,b"}


def test_unresolved_placeholder_fails_only_that_task(tmp_path):
    capability = load_capability(FIXTURES / "echo")
    request = RequestEnvelope.model_validate(
        {
            "version": 1,
            "setup": {"task": "prep", "inputs": {"userName": "world"}},
            "tasks": [
                {"task": "echo", "inputs": {"greeting": "${setup.nope}", "items": "${setup.items}"}}
            ],
        }
    )

    result = run_request(capability, request, credentials={}, scope_dir=tmp_path)

    assert result.setup.status == "ok"
    assert result.tasks[0].status == "failed"
    assert "nope" in result.tasks[0].error


def test_a_task_raising_becomes_a_failed_entry_and_the_loop_survives(tmp_path):
    capability = load_capability(FIXTURES / "fails")
    request = RequestEnvelope.model_validate(
        {
            "version": 1,
            "tasks": [
                {"task": "boom", "inputs": {}},
                {"task": "good", "inputs": {}},
            ],
        }
    )

    result = run_request(capability, request, credentials={}, scope_dir=tmp_path)

    assert result.setup is None
    assert len(result.tasks) == 2

    boom, good = result.tasks
    assert boom.task == "boom"
    assert boom.status == "failed"
    assert "kaboom" in boom.error

    assert good.task == "good"
    assert good.status == "ok"
    assert good.outputs == {"ok": "fine"}


def test_unknown_task_becomes_a_failed_entry(tmp_path):
    capability = load_capability(FIXTURES / "fails")
    request = RequestEnvelope.model_validate(
        {"version": 1, "tasks": [{"task": "does-not-exist", "inputs": {}}]}
    )

    result = run_request(capability, request, credentials={}, scope_dir=tmp_path)

    assert result.tasks[0].status == "failed"
    assert "unknown task" in result.tasks[0].error


def test_unresolved_required_credential_fails_the_task_naming_it(tmp_path):
    """Part 1 fix: an unresolved, non-optional credential is a hard
    failure -- the task's error must name the credential, and the request
    must not silently proceed anonymously."""
    capability = load_capability(FIXTURES / "needs_credential")
    request = RequestEnvelope.model_validate(
        {"version": 1, "tasks": [{"task": "need_token", "inputs": {}}]}
    )

    result = run_request(capability, request, credentials={}, scope_dir=tmp_path)

    assert result.tasks[0].status == "failed"
    assert "token" in result.tasks[0].error


def test_allow_anonymous_credentials_degrades_an_unresolved_credential(tmp_path):
    """rwtask run --allow-anonymous (run_request(allow_anonymous_credentials=True))
    is the only path that may turn an unresolved REQUIRED credential into
    None instead of failing the task -- a deliberate local-dev override."""
    capability = load_capability(FIXTURES / "needs_credential")
    request = RequestEnvelope.model_validate(
        {"version": 1, "tasks": [{"task": "need_token", "inputs": {}}]}
    )

    result = run_request(
        capability,
        request,
        credentials={},
        scope_dir=tmp_path,
        allow_anonymous_credentials=True,
    )

    assert result.tasks[0].status == "ok"
    assert result.tasks[0].outputs == {"token": None}
