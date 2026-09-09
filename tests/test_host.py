"""host.run_request: ${setup.<name>} resolution, camelCase input -> snake_case
kwarg mapping, and the "one task raising must not lose the others" guarantee.
"""

from __future__ import annotations

import shutil
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


# -- setup-output caching: the mcp.v1 sync read path (EXECUTOR-CONTRACT.md
# "Addressing and caching", CAPABILITY-CONTRACT.md Part 3 step 15) --------

_WORKTREE_REQUEST = {
    "version": 1,
    "setup": {
        "task": "open",
        "inputs": {"repoUrl": "https://example.invalid/repo.git", "sha": "deadbeef"},
    },
    "tasks": [{"task": "read", "inputs": {"tree": "${setup.tree}"}}],
}


def test_sync_request_reuses_cached_setup_and_does_not_re_run_it(tmp_path):
    """A sync-shaped request (setup present, no credentials) against a
    scope whose setup already ran (the leased row's own request, which
    does carry credentials) must reuse the cached outputs rather than
    re-running setup -- re-running would hard-fail on the missing
    credential (Context.credential() has no other behaviour)."""
    capability = load_capability(FIXTURES / "worktree_sync")
    request = RequestEnvelope.model_validate(_WORKTREE_REQUEST)

    leased = run_request(capability, request, credentials={"repo": "tok"}, scope_dir=tmp_path)
    assert leased.setup.status == "ok"

    synced = run_request(capability, request, credentials={}, scope_dir=tmp_path)

    assert synced.setup.status == "cached"
    assert synced.tasks[0].status == "ok"
    assert synced.tasks[0].outputs == {
        "content": "hello from https://example.invalid/repo.git@deadbeef"
    }


def test_sync_request_against_a_fresh_scope_fails_not_materialized(tmp_path):
    """No prior request has materialised this scope (a fresh or evicted
    pod) -- setup must actually attempt to run, and since the sync path
    carries no credentials, it must fail with the distinct
    'not_materialized' status the runner/papi recover from by retrying via
    the leased (credentialed) row -- never a generic failure, and never a
    leaked exception-class string."""
    capability = load_capability(FIXTURES / "worktree_sync")
    request = RequestEnvelope.model_validate(_WORKTREE_REQUEST)

    result = run_request(capability, request, credentials={}, scope_dir=tmp_path)

    assert result.setup.status == "not_materialized"
    assert "CredentialNotFoundError" not in result.setup.error
    assert result.tasks[0].status == "failed"


def test_cache_miss_when_the_request_names_a_different_repo_or_sha(tmp_path):
    """A cached setup for one (repoUrl, sha) must never be served to a
    request naming a different one -- that would be plausible content from
    the wrong commit. A mismatch is a cache miss like any other: setup is
    attempted again, which (with no credentials on this call) fails
    not_materialized rather than silently reusing the wrong tree."""
    capability = load_capability(FIXTURES / "worktree_sync")
    first = RequestEnvelope.model_validate(_WORKTREE_REQUEST)
    leased = run_request(capability, first, credentials={"repo": "tok"}, scope_dir=tmp_path)
    assert leased.setup.status == "ok"

    other = RequestEnvelope.model_validate(
        {
            "version": 1,
            "setup": {
                "task": "open",
                "inputs": {"repoUrl": "https://example.invalid/repo.git", "sha": "other-sha"},
            },
            "tasks": [{"task": "read", "inputs": {"tree": "${setup.tree}"}}],
        }
    )

    result = run_request(capability, other, credentials={}, scope_dir=tmp_path)

    assert result.setup.status == "not_materialized"


def test_cache_miss_when_the_cached_tree_has_been_deleted(tmp_path):
    """PROD-1416: a cache recording outputs.tree as an absolute path that
    no longer exists (pod replaced, scope reaped, fresh volume) must be
    treated as a miss, not served as 'cached' -- a `cached` result whose
    tree is gone is exactly the state that let a review agent's grep_repo
    report a false 'no matches' and mislead the agent into claiming code
    didn't exist. With no credentials on the sync path, the retry must
    fail not_materialized rather than lie about a stale cache being good."""
    capability = load_capability(FIXTURES / "worktree_sync")
    request = RequestEnvelope.model_validate(_WORKTREE_REQUEST)

    leased = run_request(capability, request, credentials={"repo": "tok"}, scope_dir=tmp_path)
    assert leased.setup.status == "ok"

    shutil.rmtree(tmp_path / "tree")

    synced = run_request(capability, request, credentials={}, scope_dir=tmp_path)

    assert synced.setup.status == "not_materialized"


def test_stateless_leased_requests_are_unaffected_by_setup_caching(tmp_path):
    """rw-checks-shaped usage: each leased request carries its own setup
    and credentials against its own scope. Setup-output caching must not
    change that -- two independent scopes never share a cache, so both
    still execute setup fresh."""
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
    scope_a = tmp_path / "a"
    scope_a.mkdir()
    scope_b = tmp_path / "b"
    scope_b.mkdir()

    result_a = run_request(capability, request, credentials={}, scope_dir=scope_a)
    result_b = run_request(capability, request, credentials={}, scope_dir=scope_b)

    assert result_a.setup.status == "ok"
    assert result_b.setup.status == "ok"
