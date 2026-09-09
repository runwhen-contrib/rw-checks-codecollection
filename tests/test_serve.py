"""rwtask serve's long-poll loop against a fake relay, mocked with
`responses`. Exercises the exact wire contract in serve.py's module
docstring: POST {relay}/v1/tasks/next -> 200|204, POST
{relay}/v1/tasks/{requestId}/result.
"""

from __future__ import annotations

import logging
from pathlib import Path

import responses
from runwhen_capability.serve import serve

FIXTURES = Path(__file__).parent / "fixtures" / "capabilities"
RELAY = "http://relay.example.internal"


def _token_file(tmp_path: Path, token: str = "test-token") -> Path:
    token_file = tmp_path / "token"
    token_file.write_text(token)
    return token_file


@responses.activate
def test_serve_processes_one_request_and_posts_the_result(tmp_path):
    responses.add(
        responses.POST,
        f"{RELAY}/v1/tasks/next",
        json={
            "requestId": "req-1",
            "request": {
                "version": 1,
                "setup": {"task": "prep", "inputs": {"userName": "world"}},
                "tasks": [
                    {
                        "task": "echo",
                        "inputs": {"greeting": "${setup.greeting}", "items": "${setup.items}"},
                    }
                ],
            },
            "credentials": {},
            "scopeId": "scope-1",
            "deadlineMs": 60000,
        },
        status=200,
    )
    responses.add(responses.POST, f"{RELAY}/v1/tasks/req-1/result", json={}, status=200)

    workdir = tmp_path / "work"
    serve(
        relay=RELAY,
        pool_id="pool-1",
        workdir=workdir,
        capability_dir=FIXTURES / "echo",
        token_file=_token_file(tmp_path),
        max_iterations=1,
    )

    assert len(responses.calls) == 2
    next_call, result_call = responses.calls

    assert next_call.request.url == f"{RELAY}/v1/tasks/next"
    import json as _json

    assert _json.loads(next_call.request.body) == {"poolId": "pool-1"}

    result_body = _json.loads(result_call.request.body)
    assert result_body["status"] == "ok"
    assert result_body["result"]["setup"]["outputs"] == {
        "greeting": "hello world",
        "items": ["a", "b"],
    }
    assert result_body["result"]["tasks"][0]["outputs"] == {"result": "hello world:a,b"}

    # The scope directory is wiped after the request completes.
    assert not (workdir / "scope-1").exists()


@responses.activate
def test_serve_idle_204_polls_again_without_posting_a_result(tmp_path):
    responses.add(responses.POST, f"{RELAY}/v1/tasks/next", status=204)

    workdir = tmp_path / "work"
    serve(
        relay=RELAY,
        pool_id="pool-1",
        workdir=workdir,
        capability_dir=FIXTURES / "echo",
        token_file=_token_file(tmp_path),
        max_iterations=1,
    )

    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == f"{RELAY}/v1/tasks/next"


@responses.activate
def test_serve_a_failing_task_still_posts_status_ok_with_the_failed_entry(tmp_path):
    responses.add(
        responses.POST,
        f"{RELAY}/v1/tasks/next",
        json={
            "requestId": "req-2",
            "request": {"version": 1, "tasks": [{"task": "boom", "inputs": {}}]},
            "credentials": {},
            "scopeId": "scope-2",
            "deadlineMs": 60000,
        },
        status=200,
    )
    responses.add(responses.POST, f"{RELAY}/v1/tasks/req-2/result", json={}, status=200)

    workdir = tmp_path / "work"
    serve(
        relay=RELAY,
        pool_id="pool-1",
        workdir=workdir,
        capability_dir=FIXTURES / "fails",
        token_file=_token_file(tmp_path),
        max_iterations=1,
    )

    import json as _json

    result_body = _json.loads(responses.calls[1].request.body)
    assert result_body["status"] == "ok"
    assert result_body["result"]["tasks"][0]["status"] == "failed"
    assert "kaboom" in result_body["result"]["tasks"][0]["error"]


@responses.activate
def test_serve_sends_bearer_token_from_the_token_file_on_both_relay_calls(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("secret-token\n")

    responses.add(
        responses.POST,
        f"{RELAY}/v1/tasks/next",
        json={
            "requestId": "req-1",
            "request": {"version": 1, "tasks": [{"task": "echo", "inputs": {}}]},
            "credentials": {},
            "scopeId": "scope-1",
            "deadlineMs": 60000,
        },
        status=200,
    )
    responses.add(responses.POST, f"{RELAY}/v1/tasks/req-1/result", json={}, status=200)

    workdir = tmp_path / "work"
    serve(
        relay=RELAY,
        pool_id="pool-1",
        workdir=workdir,
        capability_dir=FIXTURES / "echo",
        token_file=token_file,
        max_iterations=1,
    )

    next_call, result_call = responses.calls
    assert next_call.request.headers["Authorization"] == "Bearer secret-token"
    assert result_call.request.headers["Authorization"] == "Bearer secret-token"


@responses.activate
def test_serve_rereads_the_token_file_on_each_poll_so_a_rotation_is_picked_up(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("token-a")
    workdir = tmp_path / "work"

    responses.add(responses.POST, f"{RELAY}/v1/tasks/next", status=204)
    serve(
        relay=RELAY,
        pool_id="pool-1",
        workdir=workdir,
        capability_dir=FIXTURES / "echo",
        token_file=token_file,
        max_iterations=1,
    )
    assert responses.calls[0].request.headers["Authorization"] == "Bearer token-a"

    token_file.write_text("token-b")
    responses.add(responses.POST, f"{RELAY}/v1/tasks/next", status=204)
    serve(
        relay=RELAY,
        pool_id="pool-1",
        workdir=workdir,
        capability_dir=FIXTURES / "echo",
        token_file=token_file,
        max_iterations=1,
    )
    assert responses.calls[1].request.headers["Authorization"] == "Bearer token-b"


@responses.activate
def test_serve_missing_token_file_logs_and_keeps_polling_without_a_request(
    tmp_path, monkeypatch, caplog
):
    monkeypatch.setattr("runwhen_capability.serve.time.sleep", lambda _seconds: None)

    workdir = tmp_path / "work"
    missing_token_file = tmp_path / "does-not-exist" / "token"

    with caplog.at_level(logging.ERROR):
        serve(
            relay=RELAY,
            pool_id="pool-1",
            workdir=workdir,
            capability_dir=FIXTURES / "echo",
            token_file=missing_token_file,
            max_iterations=1,
        )

    # No relay call is made -- serve() never falls back to an unauthenticated request.
    assert len(responses.calls) == 0
    assert "could not read executor token" in caplog.text
