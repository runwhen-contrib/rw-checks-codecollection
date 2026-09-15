"""rw-worktree's `query` task (RW-1416 cost P2, CAP-3; I3): a batch of
grep/read/ls/defs/refs ops against one checked-out tree, answered in request
order under one 256 KiB response budget.

The task itself is a thin wrapper, so almost everything here exercises the
pure `run_query(worktree, ops)` in sdk/runwhen_capability/repo_query.py; the
host-level tests at the bottom prove the wiring (the task's input names and
the TREE_NOT_MATERIALIZED -> not_materialized conversion papi retries on).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml
from runwhen_capability.host import run_request
from runwhen_capability.loader import load_capability
from runwhen_capability.models import QueryResult, RequestEnvelope
from runwhen_capability.repo_fs import MAX_READ_RESPONSE_BYTES, TreeNotMaterializedError
from runwhen_capability.repo_query import MAX_QUERY_OPS, QUERY_BUDGET, run_query

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


def wire_size(value: dict) -> int:
    # The same encoding `requests.post(json=...)` puts on the wire (serve.py).
    return len(json.dumps(value).encode("utf-8"))


SOURCE = "import os\n\ndef foo():\n    return 1\n\nx = foo()\n"


# --- ops run in request order ------------------------------------------------


def test_mixed_ops_return_one_result_per_op_in_request_order(tmp_path):
    tree = make_tree(tmp_path, {"pkg/a.py": SOURCE, "pkg/b.ts": "bar()\n", "README.md": "hi\n"})

    out = query(
        tree,
        [
            {"op": "grep", "pattern": "foo", "globs": ["*.py"], "context": 1},
            {"op": "read", "path": "pkg/a.py", "ranges": [[1, 2], [3, 4]]},
            {"op": "read", "path": "pkg/a.py", "around": "def foo", "context": 1},
            {"op": "ls", "path": "pkg"},
            {"op": "defs", "symbol": "foo", "globs": []},
            {"op": "refs", "symbol": "foo"},
        ],
    )

    results = out["results"]
    assert [r["index"] for r in results] == [0, 1, 2, 3, 4, 5]
    assert [r["op"] for r in results] == ["grep", "read", "read", "ls", "defs", "refs"]
    assert [r["error"] for r in results] == [None] * 6
    assert out["truncated"] is False

    grep = results[0]["result"]
    assert [(m["path"], m["line"]) for m in grep["matches"]] == [("pkg/a.py", 3), ("pkg/a.py", 6)]
    assert grep["matches"][0]["before"] == [""]
    assert grep["matches"][0]["after"] == ["    return 1"]

    read = results[1]["result"]
    assert read["path"] == "pkg/a.py"
    assert [(r["start"], r["end"]) for r in read["ranges"]] == [(1, 4)]  # adjacent -> merged
    assert read["ranges"][0]["content"] == "import os\n\ndef foo():\n    return 1"

    around = results[2]["result"]
    assert [(r["start"], r["end"]) for r in around["ranges"]] == [(2, 4)]

    assert {e["path"] for e in results[3]["result"]["entries"]} == {"a.py", "b.ts"}

    defs = results[4]["result"]
    assert [m["line"] for m in defs["matches"]] == [3]
    assert defs["matches"][0]["after"] == ["    return 1", ""]  # defs always carry context 2

    assert [m["line"] for m in results[5]["result"]["matches"]] == [6]


def test_an_empty_ops_list_is_an_empty_result(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "x\n"})

    assert query(tree, []) == {"results": [], "truncated": False}


def test_rev_on_an_op_is_ignored_not_rejected(tmp_path):
    """papi splits ops by rev before calling the task, so an op still
    carries its `rev` -- that must not read as a malformed op."""
    tree = make_tree(tmp_path, {"a.py": "hello\n"})

    out = query(
        tree,
        [
            {"op": "grep", "pattern": "hello", "rev": "base"},
            {"op": "ls", "rev": "head"},
            {"op": "read", "path": "a.py", "ranges": [[1, 1]], "rev": "head"},
        ],
    )

    assert [r["error"] for r in out["results"]] == [None, None, None]


# --- per-op errors -------------------------------------------------------------


def test_a_per_op_error_does_not_fail_the_other_ops(tmp_path):
    tree = make_tree(
        tmp_path, {"a.py": "hello\n", "bin.dat": b"\x00\x01binary", "dir/b.py": "hello\n"}
    )

    out = query(
        tree,
        [
            {"op": "nope"},
            {"op": "read", "path": "../outside.py", "ranges": [[1, 2]]},
            {"op": "read", "path": "missing.py", "ranges": [[1, 2]]},
            {"op": "read", "path": "bin.dat", "ranges": [[1, 1]]},
            {"op": "grep", "pattern": "(unclosed"},
            {"op": "read", "path": "a.py", "around": "(unclosed", "context": 3},
            {"op": "ls", "path": "a.py"},
            "not an object",
            {"op": "grep", "pattern": "hello"},
        ],
    )

    results = out["results"]
    codes = [r["error"]["code"] if r["error"] else None for r in results]
    assert codes == [
        "INVALID_OP",
        "PATH_ESCAPES_TREE",
        "NOT_FOUND",
        "BINARY_FILE",
        "INVALID_PATTERN",
        "INVALID_PATTERN",
        "NOT_A_DIRECTORY",
        "INVALID_OP",
        None,
    ]
    assert all(r["result"] is None for r in results[:-1])
    assert all(r["error"]["message"] for r in results[:-1])
    assert [m["path"] for m in results[-1]["result"]["matches"]] == ["a.py", "dir/b.py"]
    assert out["truncated"] is False


@pytest.mark.parametrize(
    "op",
    [
        {"op": "grep"},  # missing pattern
        {"op": "grep", "pattern": 7},
        {"op": "grep", "pattern": "x", "globs": "*.py"},
        {"op": "grep", "pattern": "x", "globs": [1]},
        {"op": "grep", "pattern": "x", "context": 21},
        {"op": "grep", "pattern": "x", "context": -1},
        {"op": "grep", "pattern": "x", "context": True},
        {"op": "grep", "pattern": "x", "maxMatches": 0},
        {"op": "grep", "pattern": "x", "maxMatches": 201},
        {"op": "grep", "pattern": "x", "ignoreCase": "yes"},
        {"op": "read", "ranges": [[1, 2]]},  # missing path
        {"op": "read", "path": "a.py"},  # neither ranges nor around
        {"op": "read", "path": "a.py", "ranges": [[1, 2]], "around": "x"},  # both
        {"op": "read", "path": "a.py", "ranges": []},
        {"op": "read", "path": "a.py", "ranges": [[1]]},
        {"op": "read", "path": "a.py", "ranges": [[0, 2]]},
        {"op": "read", "path": "a.py", "ranges": [[3, 2]]},
        {"op": "read", "path": "a.py", "ranges": [["1", "2"]]},
        {"op": "read", "path": "a.py", "around": "x", "context": 201},
        {"op": "ls", "depth": 0},
        {"op": "ls", "path": 3},
        {"op": "defs"},  # missing symbol
        {"op": "defs", "symbol": ""},
        {"op": "refs", "symbol": "x", "globs": "*.py"},
        {"pattern": "x"},  # no op at all
    ],
)
def test_a_malformed_op_is_a_per_op_invalid_op(tmp_path, op):
    tree = make_tree(tmp_path, {"a.py": "x\n"})

    out = query(tree, [op, {"op": "ls"}])

    assert out["results"][0]["result"] is None
    assert out["results"][0]["error"]["code"] == "INVALID_OP"
    assert out["results"][1]["error"] is None


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file permissions"
)
def test_an_unreadable_file_is_a_per_op_unreadable(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "hello\n", "secret.py": "x\n"})
    (tree / "secret.py").chmod(0)
    try:
        out = query(tree, [{"op": "read", "path": "secret.py", "ranges": [[1, 1]]}, {"op": "ls"}])
    finally:
        (tree / "secret.py").chmod(0o644)

    assert out["results"][0]["error"]["code"] == "UNREADABLE"
    assert out["results"][1]["error"] is None


def test_null_optional_fields_read_as_absent(tmp_path):
    """A caller serialising a model with every optional field present
    (`"globs": null`) means "not given", not a malformed op."""
    tree = make_tree(tmp_path, {"a.py": "hello\n"})

    out = query(
        tree,
        [
            {"op": "grep", "pattern": "hello", "globs": None, "context": None, "maxMatches": None},
            {"op": "read", "path": "a.py", "ranges": [[1, 1]], "around": None},
        ],
    )

    assert [r["error"] for r in out["results"]] == [None, None]


def test_ops_that_are_not_a_list_fail_the_task(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "x\n"})

    with pytest.raises(ValueError, match="ops"):
        run_query(tree, {"op": "ls"})


def test_more_than_the_op_limit_fails_the_task(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "x\n"})

    with pytest.raises(ValueError, match="ops"):
        run_query(tree, [{"op": "ls"}] * (MAX_QUERY_OPS + 1))


# --- tree not materialised fails the whole task -------------------------------


def test_tree_not_materialized_raises_out_of_run_query(tmp_path):
    with pytest.raises(TreeNotMaterializedError):
        run_query(tmp_path / "gone", [{"op": "grep", "pattern": "x"}])


def test_a_git_only_tree_raises_even_when_every_op_is_malformed(tmp_path):
    """The check is not left to whichever op happens to touch disk first:
    a batch of malformed ops against an evicted tree must still surface as
    the miss papi re-materialises on, not as a page of INVALID_OP."""
    tree = tmp_path / "tree"
    (tree / ".git").mkdir(parents=True)

    with pytest.raises(TreeNotMaterializedError):
        run_query(tree, [{"op": "nope"}])


# --- defs / refs -----------------------------------------------------------------


def test_defs_finds_the_definition_and_refs_excludes_it(tmp_path):
    tree = make_tree(
        tmp_path,
        {
            "svc.py": (
                "def _share_url(x):\n"
                "    return x\n"
                "\n"
                "url = _share_url(1)\n"
                "other = _share_url_extra(2)\n"
            ),
            "web/share.ts": "export const _share_url: Fn = build();\n_share_url();\n",
        },
    )

    out = query(
        tree,
        [{"op": "defs", "symbol": "_share_url"}, {"op": "refs", "symbol": "_share_url"}],
    )

    defs = out["results"][0]["result"]["matches"]
    assert [(m["path"], m["line"]) for m in defs] == [("svc.py", 1), ("web/share.ts", 1)]
    assert defs[0]["after"] == ["    return x", ""]

    refs = out["results"][1]["result"]["matches"]
    assert [(m["path"], m["line"]) for m in refs] == [("svc.py", 4), ("web/share.ts", 2)]


def test_refs_excludes_a_definition_line_longer_than_the_grep_text_cap(tmp_path):
    """GrepMatch.text is cut at 400 bytes, so a definition keyword past that
    point is invisible in `text`: the exclusion must look at the full line."""
    long_def = " " * 450 + "def foo():"
    long_ref = "x = " + "a" * 450 + " + foo()"
    tree = make_tree(tmp_path, {"a.py": f"{long_def}\n{long_ref}\n"})

    out = query(tree, [{"op": "refs", "symbol": "foo"}])

    assert [m["line"] for m in out["results"][0]["result"]["matches"]] == [2]


def test_defs_and_refs_respect_globs(tmp_path):
    tree = make_tree(
        tmp_path, {"a.py": "def foo():\n    foo()\n", "b.go": "func foo() {}\nfoo()\n"}
    )

    out = query(
        tree,
        [
            {"op": "defs", "symbol": "foo", "globs": ["*.go"]},
            {"op": "refs", "symbol": "foo", "globs": ["*.py"]},
        ],
    )

    assert [(m["path"], m["line"]) for m in out["results"][0]["result"]["matches"]] == [("b.go", 1)]
    assert [(m["path"], m["line"]) for m in out["results"][1]["result"]["matches"]] == [("a.py", 2)]


# --- the response budget ---------------------------------------------------------


def test_the_budget_truncates_later_ops_with_response_budget(tmp_path):
    line = "y" * 99
    tree = make_tree(tmp_path, {"big.txt": "\n".join([line] * 1500), "a.py": "hello\n"})
    read_all = {"op": "read", "path": "big.txt", "ranges": [[1, 1500]]}

    out = query(tree, [read_all, read_all, {"op": "grep", "pattern": "hello"}, {"op": "ls"}])

    results = out["results"]
    assert out["truncated"] is True
    assert results[0]["error"] is None
    assert results[0]["result"]["truncated"] is False
    assert results[0]["result"]["ranges"][0]["end"] == 1500

    # The op that straddles the cap keeps the whole lines that fit.
    assert results[1]["error"] is None
    partial = results[1]["result"]
    assert partial["truncated"] is True
    assert 1 <= partial["ranges"][0]["end"] < 1500
    assert partial["ranges"][0]["content"] == "\n".join([line] * partial["ranges"][0]["end"])

    for later in results[2:]:
        assert later["result"] is None
        assert later["error"]["code"] == "RESPONSE_BUDGET"
    assert [r["index"] for r in results] == [0, 1, 2, 3]

    assert wire_size(out) <= QUERY_BUDGET


def test_the_budget_counts_json_escaping_not_only_content_bytes(tmp_path):
    """read_ranges fills content up to its raw-byte budget; every `"` then
    doubles on the wire. The query budget measures the serialised result,
    so the response still lands under the cap (CAP-1's deferred minor)."""
    line = '"' * 99
    tree = make_tree(tmp_path, {"quotes.txt": "\n".join([line] * 2600)})

    out = query(tree, [{"op": "read", "path": "quotes.txt", "ranges": [[1, 2600]]}])

    assert out["truncated"] is True
    assert out["results"][0]["result"]["truncated"] is True
    assert wire_size(out) <= QUERY_BUDGET < MAX_READ_RESPONSE_BYTES


def test_the_budget_counts_per_op_envelope_overhead(tmp_path):
    """Many small results: the per-entry and per-match JSON structure, not
    just the matched text, is what fills the budget."""
    tree = make_tree(tmp_path, {f"f{i:03}.py": "hit\n" * 200 for i in range(60)})
    ops = [
        {"op": "grep", "pattern": "hit", "globs": [f"f{i:03}.py"], "context": 20} for i in range(60)
    ]

    out = query(tree, ops)

    assert out["truncated"] is True
    assert out["results"][-1]["error"]["code"] == "RESPONSE_BUDGET"
    assert wire_size(out) <= QUERY_BUDGET


def test_a_single_line_larger_than_the_budget_is_clipped_not_dropped(tmp_path):
    tree = make_tree(tmp_path, {"min.js": "z" * (400 * 1024)})

    out = query(tree, [{"op": "read", "path": "min.js", "ranges": [[1, 1]]}])

    result = out["results"][0]["result"]
    assert result["truncated"] is True
    assert result["ranges"][0]["start"] == 1
    assert result["ranges"][0]["end"] == 1
    assert len(result["ranges"][0]["content"]) > 200 * 1024
    assert wire_size(out) <= QUERY_BUDGET


# --- schema and manifest ---------------------------------------------------------


def test_query_schema_is_valid_json_and_matches_a_sample_output(tmp_path):
    schema = json.loads((WORKTREE_CAPABILITY / "schemas" / "query.json").read_text())
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
        "result": {"kind": "rw.repo_query.v1", "schema": "./schemas/query.json"}
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
