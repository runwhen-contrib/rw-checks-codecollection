"""rw-worktree's `query` task: its schema, its manifest entry, and its wiring
through the task host (input names, and the TREE_NOT_MATERIALIZED ->
not_materialized conversion the platform retries on). The batch engine
itself, `run_query`, is tested in the runwhen-capability SDK.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from runwhen_capability.host import run_request
from runwhen_capability.loader import load_capability
from runwhen_capability.models import QueryResult, RequestEnvelope
from runwhen_capability.repo_query import run_query

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKTREE_CAPABILITY = REPO_ROOT / "capabilities" / "rw-worktree"


def make_tree(tmp_path: Path, files: dict[str, str | bytes]) -> Path:
    tree = tmp_path / "tree"
    tree.mkdir()
    for rel, content in files.items():
        full = tree / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            full.write_bytes(content)
        else:
            full.write_text(content)
    return tree


def query(tree: Path, ops: list) -> dict:
    return run_query(tree, ops).model_dump(mode="json")


SOURCE = "import os\n\ndef foo():\n    return 1\n\nx = foo()\n"


# --- schema and manifest ---------------------------------------------------------


def test_query_schema_is_valid_json_and_matches_a_sample_output(tmp_path):
    schema = json.loads((WORKTREE_CAPABILITY / "schemas" / "query.v1.json").read_text())
    assert schema["title"] == "QueryResult"
    assert {"results", "truncated"} <= set(schema["properties"])

    tree = make_tree(tmp_path, {"a.py": SOURCE})
    out = query(tree, [{"op": "defs", "symbol": "foo"}, {"op": "nope"}])

    # `jsonschema` isn't a dependency: round-trip the sample through the
    # model the schema is exported from (tests/test_schemas.py pins the two).
    assert QueryResult.model_validate(json.loads(json.dumps(out))).model_dump(mode="json") == out


def test_manifest_declares_the_query_task():
    manifest = yaml.safe_load((WORKTREE_CAPABILITY / "manifest.yaml").read_text())
    task = next(t for t in manifest["tasks"] if t["name"] == "query")

    assert task["inputs"] == {"tree": {"from": "${setup.tree}"}, "ops": {"from": "request"}}
    assert task["outputs"] == {
        "result": {"kind": "rw.repo_query.v1", "schema": "./schemas/query.v1.json"}
    }


# --- through the task host ----------------------------------------------------------


def _query_request(tree: Path, ops: list) -> RequestEnvelope:
    return RequestEnvelope.model_validate(
        {"version": 1, "tasks": [{"task": "query", "inputs": {"tree": str(tree), "ops": ops}}]}
    )


def test_the_query_task_runs_through_the_host(tmp_path):
    capability = load_capability(WORKTREE_CAPABILITY)
    tree = make_tree(tmp_path, {"a.py": SOURCE})
    scope = tmp_path / "scope"
    scope.mkdir()

    result = run_request(
        capability, _query_request(tree, [{"op": "defs", "symbol": "foo"}]), {}, scope
    )

    assert result.tasks[0].status == "ok"
    output = result.tasks[0].outputs["result"]
    assert output["truncated"] is False
    assert output["results"][0]["result"]["matches"][0]["line"] == 3


def test_the_query_task_reports_an_unmaterialized_tree_as_a_miss(tmp_path):
    capability = load_capability(WORKTREE_CAPABILITY)
    scope = tmp_path / "scope"
    scope.mkdir()

    result = run_request(capability, _query_request(tmp_path / "gone", [{"op": "ls"}]), {}, scope)

    assert result.tasks[0].status == "failed"
    assert result.setup is not None
    assert result.setup.status == "not_materialized"
