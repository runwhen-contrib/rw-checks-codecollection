"""Behaviour tests for the artifact-tools capability (grep, jq, sql, slice).

These run the real tasks end to end: `load_capability` on the shipped
capability directory, then `run_request`, against the real `rg`, `jq` and
DuckDB. Inputs are staged where a local (relay-less) run of the standalone
capability SDK reads them, `<scope>/.rw-artifacts/inputs/source`, and outputs
land under `<scope>/.rw-artifacts/`.

They live outside `tests/` on purpose. artifact-tools needs the standalone
`runwhen-capability` SDK (its `ctx.artifacts` API), which is the same
distribution name as the SDK vendored under `sdk/` and cannot share a
virtualenv with it. `make artifact-tools-venv` builds a venv of its own and
`make test-artifact-tools` runs this directory in it.
"""

from __future__ import annotations

import base64
import inspect
import io
import json
import logging
import os
import random
import shutil
import subprocess
import sys
import threading
import time
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

_MISSING = [name for name in ("rg", "jq") if shutil.which(name) is None]
if _MISSING:
    raise RuntimeError(
        f"{' and '.join(_MISSING)} not found on PATH: these tests run the real tools and do not "
        "skip without them. Put ripgrep and jq on PATH (the image installs both); "
        "`make artifact-tools-venv` builds the Python side."
    )
try:
    import duckdb
except ImportError as exc:  # pragma: no cover - environment problem
    raise RuntimeError(
        "duckdb is not installed: run `make artifact-tools-venv` and "
        "`make test-artifact-tools` so these tests use that venv"
    ) from exc

from jsonschema import Draft202012Validator  # noqa: E402
from runwhen_capability.host import run_request  # noqa: E402
from runwhen_capability.loader import load_capability  # noqa: E402
from runwhen_capability.models import (  # noqa: E402
    InputArtifactDecl,
    OutputDecl,
    RequestEnvelope,
)

REPO = Path(__file__).resolve().parent.parent
CAP_DIR = REPO / "capabilities" / "artifact-tools"
sys.path.insert(0, str(CAP_DIR))

from artifact_tools import deadline as deadline_mod  # noqa: E402
from artifact_tools import grep as grep_mod  # noqa: E402
from artifact_tools import jq as jq_mod  # noqa: E402
from artifact_tools import slice as slice_mod  # noqa: E402
from artifact_tools import sql as sql_mod  # noqa: E402

CAP = load_capability(CAP_DIR)

MIB = 1 << 20
SCHEMA_FILES = {"grep": "grep.v1.json", "jq": "jq.v1.json", "sql": "sql.v1.json"}


# --- helpers -------------------------------------------------------------------------------


def stage(tmp_path: Path, data: bytes | None) -> Path:
    """A scope directory with `data` as the `source` input artifact."""
    scope = tmp_path / "scope"
    inputs = scope / ".rw-artifacts" / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    if data is not None:
        (inputs / "source").write_bytes(data)
    return scope


def invoke(
    scope: Path, task: str, inputs: dict, *, outputs=(), input_artifacts=(), deadline_seconds=None
):
    request = RequestEnvelope.model_validate(
        {"version": 1, "tasks": [{"task": task, "inputs": {"source": "art_test", **inputs}}]}
    )
    result = run_request(
        CAP,
        request,
        credentials={},
        scope_dir=scope,
        outputs=outputs,
        input_artifacts=input_artifacts,
        deadline_seconds=deadline_seconds,
    )
    (task_result,) = result.tasks
    return task_result


def validate(task: str, value) -> None:
    schema = json.loads((CAP_DIR / "schemas" / SCHEMA_FILES[task]).read_text())
    Draft202012Validator(schema).validate(value)


def run_ok(tmp_path: Path, task: str, inputs: dict, data: bytes | None, **kwargs) -> dict:
    """Runs a task that must succeed; returns its outputs, with `result` already checked against
    the checked-in JSON schema (inline, or read back from the artifact it spilled to)."""
    task_result = invoke(stage(tmp_path, data), task, inputs, **kwargs)
    assert task_result.status == "ok", task_result.error
    outputs = task_result.outputs
    if task in SCHEMA_FILES:
        result = outputs["result"]
        if "$artifact" in result:
            result = json.loads((tmp_path / "scope" / ".rw-artifacts" / "result").read_bytes())
        validate(task, result)
    return outputs


def run_fails(tmp_path: Path, task: str, inputs: dict, data: bytes | None, **kwargs) -> str:
    task_result = invoke(stage(tmp_path, data), task, inputs, **kwargs)
    assert task_result.status == "failed", f"expected a failure, got {task_result.outputs}"
    assert task_result.error
    return task_result.error


def artifact_bytes(tmp_path: Path, name: str) -> bytes:
    return (tmp_path / "scope" / ".rw-artifacts" / name).read_bytes()


def write_big_line_file(path: Path, *, line_bytes: int = 16 * MIB, total: int = 24 * MIB) -> None:
    """`total` bytes: a short line, one `line_bytes` line starting with a match, then filler."""
    path.parent.mkdir(parents=True, exist_ok=True)
    filler = b"filler line without the word\n" * 1000
    with path.open("wb") as fh:
        fh.write(b"first needle line\n")
        fh.write(b"needle " + b"x" * (line_bytes - len(b"needle ")) + b"\n")
        while fh.tell() < total:
            fh.write(filler)
        fh.write(b"last needle line\n")


def stage_file(tmp_path: Path, write) -> Path:
    scope = tmp_path / "scope"
    inputs = scope / ".rw-artifacts" / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    write(inputs / "source")
    return scope


def python_peak_bytes(call) -> int:
    """Peak Python-side allocation while `call()` runs (the subprocesses' memory is not counted)."""
    tracemalloc.start()
    try:
        call()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


# --- manifest and task wiring --------------------------------------------------------------


def test_task_signatures_accept_every_manifest_input():
    manifest = yaml.safe_load((CAP_DIR / "manifest.yaml").read_text())
    for task in manifest["tasks"]:
        params = set(inspect.signature(CAP.registry.tasks[task["name"]].func).parameters) - {"ctx"}
        declared = {
            "".join(f"_{c.lower()}" if c.isupper() else c for c in name) for name in task["inputs"]
        }
        assert declared == params, f"task {task['name']}: manifest inputs vs function parameters"
        assert set(CAP.registry.tasks[task["name"]].outputs) == set(task["outputs"])


# --- grep ----------------------------------------------------------------------------------


def test_grep_caps_matches_and_counts_all(tmp_path):
    data = b"".join(b"match %d here\nnoise\n" % i for i in range(1000))
    out = run_ok(tmp_path, "grep", {"pattern": "match", "maxMatches": 50}, data)
    result = out["result"]
    assert len(result["matches"]) == 50
    assert result["totalMatches"] == 1000
    assert result["truncated"] is True
    assert "narrow" in result["hint"]
    assert "saveAll" in result["hint"]
    assert [m["lineNumber"] for m in result["matches"][:3]] == [1, 3, 5]
    assert result["matches"][0]["text"] == "match 0 here"
    assert result["longLines"] == 0
    assert result["bytesScanned"] == len(data)
    assert "matches" not in out


def test_grep_default_cap_is_fifty_matches(tmp_path):
    data = b"hit\n" * 80
    result = run_ok(tmp_path, "grep", {"pattern": "hit"}, data)["result"]
    assert len(result["matches"]) == 50
    assert result["totalMatches"] == 80


def test_grep_save_all_writes_artifact(tmp_path):
    data = b"".join(b"match %d here\nnoise\n" % i for i in range(1000))
    out = run_ok(tmp_path, "grep", {"pattern": "match", "maxMatches": 5, "saveAll": True}, data)
    assert out["matches"]["$artifact"].startswith("local_")
    saved = artifact_bytes(tmp_path, "matches").decode()
    assert saved.splitlines() == [f"{2 * i + 1}:match {i} here" for i in range(1000)]
    assert saved.endswith("\n")
    assert out["result"]["totalMatches"] == 1000
    assert "matches" in out["result"]["hint"]


def test_grep_save_all_hint_does_not_ask_for_save_all_again(tmp_path):
    data = b"hit\n" * 80
    result = run_ok(tmp_path, "grep", {"pattern": "hit", "saveAll": "true"}, data)["result"]
    assert result["truncated"] is True
    assert "saveAll=true" not in result["hint"]
    assert "'matches' artifact" in result["hint"]


def test_grep_without_save_all_creates_no_artifact(tmp_path):
    out = run_ok(tmp_path, "grep", {"pattern": "a"}, b"a\n")
    assert "matches" not in out
    assert not (tmp_path / "scope" / ".rw-artifacts" / "matches").exists()


def test_grep_save_all_keeps_raw_bytes(tmp_path):
    data = b"ok needle\n\xff\xfeneedle bad utf8\nneedle with crlf\r\n"
    run_ok(tmp_path, "grep", {"pattern": "needle", "saveAll": True}, data)
    assert artifact_bytes(tmp_path, "matches") == (
        b"1:ok needle\n2:\xff\xfeneedle bad utf8\n3:needle with crlf\n"
    )


def test_grep_context_lines(tmp_path):
    data = b"".join(b"l%d\n" % i for i in range(1, 12)).replace(b"l5\n", b"needle5\n")
    result = run_ok(tmp_path, "grep", {"pattern": "needle", "context": 2}, data)["result"]
    (match,) = result["matches"]
    assert match["lineNumber"] == 5 and match["text"] == "needle5"
    assert [(c["lineNumber"], c["text"]) for c in match["before"]] == [(3, "l3"), (4, "l4")]
    assert [(c["lineNumber"], c["text"]) for c in match["after"]] == [(6, "l6"), (7, "l7")]


def test_grep_context_at_file_edges_and_between_close_matches(tmp_path):
    data = b"needle a\nx\nneedle b\ny\nz\nw\n"
    matches = run_ok(tmp_path, "grep", {"pattern": "needle", "context": 2}, data)["result"][
        "matches"
    ]
    first, second = matches
    assert first["before"] == []
    assert [c["lineNumber"] for c in first["after"]] == [2]
    assert [c["lineNumber"] for c in second["before"]] == [2]
    assert [c["lineNumber"] for c in second["after"]] == [4, 5]


def test_grep_zero_context_has_no_context_lines(tmp_path):
    result = run_ok(tmp_path, "grep", {"pattern": "b"}, b"a\nb\nc\n")["result"]
    assert result["matches"][0]["before"] == [] and result["matches"][0]["after"] == []


def test_grep_ignore_case(tmp_path):
    data = b"Error one\nerror two\nERROR three\nfine\n"
    assert run_ok(tmp_path, "grep", {"pattern": "error"}, data)["result"]["totalMatches"] == 1
    result = run_ok(tmp_path, "grep", {"pattern": "error", "ignoreCase": True}, data)["result"]
    assert result["totalMatches"] == 3


def test_grep_invalid_regex_fails(tmp_path):
    error = run_fails(tmp_path, "grep", {"pattern": "("}, b"a\n")
    assert "regex parse error" in error or "unclosed group" in error


def test_grep_invalid_regex_with_a_large_input_reports_the_regex_error(tmp_path):
    # ripgrep exits before reading its input: the feeder must end quietly, not raise BrokenPipe.
    error = run_fails(tmp_path, "grep", {"pattern": "("}, b"some line of text\n" * 400_000)
    assert "regex parse error" in error or "unclosed group" in error
    assert "BrokenPipe" not in error and "Broken pipe" not in error


class FlakySource(io.BytesIO):
    """An input stream that goes away after its first chunk, as a relay connection can."""

    def __init__(self, first: bytes) -> None:
        super().__init__(first)
        self.reads = 0

    def read(self, size: int = -1) -> bytes:
        self.reads += 1
        if self.reads > 1:
            raise OSError("relay went away")
        return super().read(size)


def fake_ctx(source: io.BytesIO):
    artifacts = SimpleNamespace(input=lambda name: source)
    return SimpleNamespace(artifacts=artifacts, input_artifacts=[], log=logging.getLogger("test"))


def test_grep_fails_instead_of_returning_a_partial_answer_when_the_input_breaks():
    ctx = fake_ctx(FlakySource(b"needle\n" * 10))
    with pytest.raises(OSError, match="relay went away"):
        grep_mod.run_grep(
            ctx, pattern="needle", ignore_case=False, context=0, max_matches=5, save_all=False
        )


def test_jq_fails_instead_of_returning_a_partial_answer_when_the_input_breaks():
    ctx = fake_ctx(FlakySource(b'{"a": 1}\n' * 10))
    with pytest.raises(OSError, match="relay went away"):
        jq_mod.run_jq(ctx, program=".a", lines=True)


def test_grep_pattern_starting_with_dash_is_a_pattern_not_a_flag(tmp_path):
    result = run_ok(tmp_path, "grep", {"pattern": "--version"}, b"x --version y\nz\n")["result"]
    assert result["totalMatches"] == 1


def test_grep_no_match(tmp_path):
    result = run_ok(tmp_path, "grep", {"pattern": "absent"}, b"a\nb\n")["result"]
    assert result["totalMatches"] == 0
    assert result["matches"] == []
    assert result["truncated"] is False
    assert result["hint"] is None


def test_grep_empty_input(tmp_path):
    result = run_ok(tmp_path, "grep", {"pattern": "x"}, b"")["result"]
    assert result["totalMatches"] == 0 and result["bytesScanned"] == 0


def test_grep_long_line_is_cut_to_its_first_64_kib(tmp_path):
    data = b"short needle\n" + b"needle " + b"z" * 100_000 + b"\n" + b"tail needle\n"
    result = run_ok(tmp_path, "grep", {"pattern": "needle"}, data)["result"]
    assert result["longLines"] == 1
    assert result["totalMatches"] == 3
    assert result["bytesScanned"] == len(b"short needle\n") + 64 * 1024 + 1 + len(b"tail needle\n")
    assert result["matches"][2]["lineNumber"] == 3
    assert "64 KiB" in result["hint"]
    assert result["truncated"] is False


def test_grep_does_not_see_past_the_cut(tmp_path):
    data = b"y" * 70_000 + b"LATE\nLATE at the start\n"
    result = run_ok(tmp_path, "grep", {"pattern": "LATE"}, data)["result"]
    assert result["longLines"] == 1
    assert result["totalMatches"] == 1
    assert result["matches"][0]["lineNumber"] == 2


def test_grep_line_of_exactly_the_limit_is_not_cut(tmp_path):
    data = b"a" * grep_mod.MAX_LINE_BYTES + b"\n" + b"b" * (grep_mod.MAX_LINE_BYTES + 1) + b"\n"
    result = run_ok(tmp_path, "grep", {"pattern": "a|b"}, data)["result"]
    assert result["longLines"] == 1
    assert result["bytesScanned"] == 2 * grep_mod.MAX_LINE_BYTES + 2


def test_grep_text_is_capped_at_1024_characters(tmp_path):
    data = b"needle " + b"e" * 5000 + b"\nneedle short\n"
    matches = run_ok(tmp_path, "grep", {"pattern": "needle"}, data)["result"]["matches"]
    assert len(matches[0]["text"]) == 1024 and matches[0]["textTruncated"] is True
    assert matches[1]["text"] == "needle short" and matches[1]["textTruncated"] is False


def test_grep_binary_and_invalid_utf8_lines_still_match(tmp_path):
    data = b"abc\x00needle\x00def\n\xff\xfeneedle bad utf8\nplain needle\r\n"
    matches = run_ok(tmp_path, "grep", {"pattern": "needle"}, data)["result"]["matches"]
    assert [m["lineNumber"] for m in matches] == [1, 2, 3]
    assert matches[0]["text"] == "abc\x00needle\x00def"
    assert matches[1]["text"] == "��needle bad utf8"
    assert matches[2]["text"] == "plain needle"


def test_grep_worst_case_result_fits_under_one_mib(tmp_path):
    # 600 matches asking for 500 with 5 lines of context each side, every line far over the
    # 1024-character text cap (some over the 64 KiB input cut too), in multi-byte text that
    # costs 6 bytes per character once JSON-escaped.
    context = ("ctx " + "\u00e9" * 1200 + "\n").encode()
    match = ("needle " + "\u00e9" * 1200 + "\n").encode()
    huge_context = b"ctx " + b"h" * 100_000 + b"\n"
    data = (context * 6 + match + context * 6 + huge_context) * 600
    result = run_ok(tmp_path, "grep", {"pattern": "needle", "maxMatches": 500, "context": 5}, data)[
        "result"
    ]
    assert result["totalMatches"] == 600
    assert result["longLines"] == 600
    assert result["truncated"] is True
    assert 0 < len(result["matches"]) < 500
    assert len(result["matches"][5]["before"]) == 5 and len(result["matches"][5]["after"]) == 5
    assert len(json.dumps(result)) < MIB
    assert len(json.dumps(result)) <= grep_mod.RESULT_BUDGET_BYTES + 4096
    assert f"first {len(result['matches'])} of 600" in result["hint"]


def test_grep_matches_keep_file_order_when_the_budget_stops_adding(tmp_path):
    line = b"needle " + b"e" * 1000 + b"\n"
    result = run_ok(tmp_path, "grep", {"pattern": "needle", "maxMatches": 500}, line * 2000)[
        "result"
    ]
    numbers = [m["lineNumber"] for m in result["matches"]]
    assert numbers == list(range(1, len(numbers) + 1))
    assert result["totalMatches"] == 2000


def test_grep_event_larger_than_the_limit_kills_rg_and_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(grep_mod, "EVENT_MAX_BYTES", 300)
    error = run_fails(tmp_path, "grep", {"pattern": "."}, b"x" * 400 + b"\n")
    assert "larger than" in error


@pytest.mark.parametrize(
    ("task", "inputs"),
    [
        ("grep", {"pattern": "x"}),
        ("jq", {"filter": "."}),
        ("sql", {"query": "select 1"}),
        ("slice", {"fromLine": 1, "toLine": 2}),
    ],
)
def test_missing_input_artifact_fails(tmp_path, task, inputs):
    assert "source" in run_fails(tmp_path, task, inputs, None)


@pytest.mark.parametrize("limit", [1, 2, 3, 7, 16])
def test_cut_long_lines_matches_a_naive_reference(limit):
    rng = random.Random(limit)
    for _ in range(300):
        pieces = []
        for _ in range(rng.randint(0, 12)):
            n = rng.choice([0, 1, limit - 1, limit, limit + 1, 2 * limit, 5 * limit + 3])
            pieces.append(bytes(rng.choice(b"ab") for _ in range(max(n, 0))))
        data = b"\n".join(pieces) + rng.choice([b"", b"\n"])
        chunks, pos = [], 0
        while pos < len(data):
            step = rng.randint(1, 3 * limit + 5)
            chunks.append(data[pos : pos + step])
            pos += step
        stats = grep_mod.FeedStats()
        got = b"".join(grep_mod.cut_long_lines(iter(chunks), limit, stats))
        expected, long_lines = reference_cut(data, limit)
        assert got == expected, (limit, data, chunks)
        assert stats.long_lines == long_lines, (limit, data, chunks)
        assert stats.bytes_scanned == len(expected)


def reference_cut(data: bytes, limit: int) -> tuple[bytes, int]:
    out, long_lines = bytearray(), 0
    parts = data.split(b"\n")
    for index, part in enumerate(parts):
        if len(part) > limit:
            long_lines += 1
        out += part[:limit]
        if index < len(parts) - 1:
            out += b"\n"
    return bytes(out), long_lines


def test_cut_long_lines_takes_the_fast_path_for_chunks_of_short_lines():
    chunk = b"short line\n" * 50_000
    stats = grep_mod.FeedStats()
    (piece,) = list(grep_mod.cut_long_lines(iter([chunk]), grep_mod.MAX_LINE_BYTES, stats))
    assert piece is chunk
    assert stats.long_lines == 0 and stats.bytes_scanned == len(chunk)


# --- jq ------------------------------------------------------------------------------------


def jsonl(rows) -> bytes:
    return "".join(json.dumps(row) + "\n" for row in rows).encode()


def test_jq_jsonl_filter(tmp_path):
    data = jsonl({"id": i, "kind": "even" if i % 2 == 0 else "odd"} for i in range(10))
    result = run_ok(tmp_path, "jq", {"filter": 'select(.kind == "even") | .id'}, data)["result"]
    assert result["output"] == "0\n2\n4\n6\n8"
    assert result["outputLines"] == 5
    assert result["lines"] is True
    assert result["truncated"] is False
    assert result["hint"] is None


def test_jq_empty_output(tmp_path):
    result = run_ok(tmp_path, "jq", {"filter": "select(false)"}, b'{"a": 1}\n')["result"]
    assert result["output"] == "" and result["outputLines"] == 0 and result["truncated"] is False


def test_jq_detects_jsonl_and_pretty_printed_documents(tmp_path):
    rows = [{"id": 1, "v": "a"}, {"id": 2, "v": "b"}]
    compact = run_ok(tmp_path / "a", "jq", {"filter": ".id"}, jsonl(rows))["result"]
    assert compact["lines"] is True and compact["output"] == "1\n2"
    document = json.dumps({"items": rows}, indent=2).encode()
    pretty = run_ok(tmp_path / "b", "jq", {"filter": ".items | length"}, document)["result"]
    assert pretty["lines"] is False and pretty["output"] == "2"


def test_jq_single_line_document_counts_as_jsonl(tmp_path):
    result = run_ok(tmp_path, "jq", {"filter": ".a"}, b'{"a": 7}')["result"]
    assert result["lines"] is True and result["output"] == "7"


def test_jq_explicit_lines_overrides_the_sniff(tmp_path):
    data = jsonl([{"a": 1}, {"a": 2}])
    forced_off = run_ok(tmp_path / "a", "jq", {"filter": ".a", "lines": False}, data)["result"]
    assert forced_off["lines"] is False and forced_off["output"] == "1\n2"
    document = json.dumps({"a": [1, 2]}, indent=2).encode()
    forced_on = run_ok(tmp_path / "b", "jq", {"filter": ".a[]", "lines": "true"}, document)[
        "result"
    ]
    assert forced_on["lines"] is True and forced_on["output"] == "1\n2"


def test_jq_first_line_longer_than_the_sniff_window_is_a_document(tmp_path, monkeypatch):
    monkeypatch.setattr(jq_mod, "SNIFF_BYTES", 16)
    data = jsonl([{"long": "x" * 100}, {"long": "y"}])
    assert run_ok(tmp_path, "jq", {"filter": ".long | length"}, data)["result"]["lines"] is False


def test_jq_refuses_huge_single_document(tmp_path, monkeypatch):
    monkeypatch.setattr(jq_mod, "MAX_DOCUMENT_BYTES", 1000)
    document = json.dumps({"items": list(range(500))}, indent=2).encode()
    assert len(document) > 1000
    error = run_fails(tmp_path, "jq", {"filter": ".items | length"}, document)
    assert error.startswith("E_TOO_LARGE_FOR_JQ:")
    assert "use sql with format=json" in error and "lines=true" in error
    assert "limit 1000 bytes" in error


def test_jq_too_large_message_states_the_real_limit_and_size():
    message = str(jq_mod._too_large(3 * 1024**3))
    assert message.startswith("E_TOO_LARGE_FOR_JQ:")
    assert "3221225472 bytes" in message and "limit 128 MiB" in message
    # Which tool to use instead depends on the shape of the document.
    assert "array of records" in message and "use sql with format=json" in message
    assert "one big object" in message and "grep or slice" in message and "16 MiB" in message
    assert "lines=true" in message


def test_jq_document_limit_matches_what_jq_can_hold():
    # jq needs about six times a pretty-printed document, and its address space is capped at
    # 1 GiB, so a document much over 150 MiB would die inside jq.
    assert jq_mod.MAX_DOCUMENT_BYTES == 128 * 1024 * 1024
    assert jq_mod.MAX_DOCUMENT_BYTES * 6 < jq_mod.ADDRESS_SPACE_BYTES


def test_the_manifest_states_the_limit_the_code_enforces():
    manifest = (CAP_DIR / "manifest.yaml").read_text()
    limit = f"{jq_mod.MAX_DOCUMENT_BYTES // MIB} MiB"
    assert f"over {limit} is" in " ".join(manifest.split())


@pytest.mark.parametrize(
    "stderr", ["jq: error: cannot allocate memory", "jq: error: out of memory"]
)
def test_jq_running_out_of_memory_is_reported_as_too_large(tmp_path, monkeypatch, stderr):
    # What jq prints when its allocation fails (the address-space limit makes it fail rather than
    # the pod being killed), standing in for a real document too big for it.
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "jq"
    stub.write_text(f"#!/bin/sh\ncat > /dev/null\necho '{stderr}' >&2\nexit 134\n")
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{stub_dir}{os.pathsep}{os.environ['PATH']}")
    error = run_fails(tmp_path / "run", "jq", {"filter": ".", "lines": False}, b'{"a": 1}\n')
    assert error.startswith("E_TOO_LARGE_FOR_JQ:"), error
    assert "use sql with format=json" in error


def test_jq_allows_the_words_as_field_names(tmp_path):
    data = b'{"import": 5, "include": 6}\n'
    result = run_ok(tmp_path, "jq", {"filter": ".import + .include"}, data)["result"]
    assert result["output"] == "11"


def test_jq_user_errors_are_not_mistaken_for_running_out_of_memory(tmp_path):
    # `error` and `debug` write to stderr, and the filter chooses the text; only jq's own
    # allocator message, on a line of its own, counts.
    for filter_ in (".msg | error", ".msg | debug | error", '"jq: error: out of memory" | error'):
        data = b'{"msg": "out of memory"}\n'
        error = run_fails(tmp_path / str(abs(hash(filter_))), "jq", {"filter": filter_}, data)
        assert not error.startswith("E_TOO_LARGE_FOR_JQ"), (filter_, error)
        assert "out of memory" in error


def test_jq_other_failures_are_still_plain_errors(tmp_path):
    error = run_fails(tmp_path, "jq", {"filter": ".a.b"}, b'{"a": 1}\n')
    assert not error.startswith("E_TOO_LARGE_FOR_JQ")


@pytest.mark.parametrize(
    "program",
    [
        'import "a" as $x {search: "/etc"}; $x',
        'include "a"; .',
        'import @text "creds" as $c {search: "/d"}; $c',
        'import @json "creds" as $c {search: "/d"}; $c',
        'include @base64 "m" {search: "/d"}; f',
        "import $x; 1",
        'import "a" as $x; $x',
        '# a comment first\nimport "a" as $x; 1',
        'import\n  "a" as $x;\n.',
        'module {version: 1}; import "a" as $x; .',
        'import"a" as $x; .',
    ],
)
def test_jq_refuses_to_import_or_include_modules(tmp_path, program):
    error = run_fails(tmp_path, "jq", {"filter": program}, b'{"a": 1}\n')
    assert error == "jq filters may not import or include modules"


@pytest.mark.parametrize(
    ("program", "output"),
    [
        ('{"import": .a, "include": 2}', '{"import":1,"include":2}'),
        ("{import: .a}", '{"import":1}'),
        ('"import \\"x\\" as $y; 1"', '"import \\"x\\" as $y; 1"'),
        ('"include"', '"include"'),
        ('[{"name": "include"}] | map(select(.name == "include")) | length', "1"),
        ('{"a": 1} | .a as $import | $import', "1"),
        (". as $include | $include | .a", "1"),
        ("{a: 1} | .a", "1"),
        # the words inside a string's interpolation, where strings nest
        (r'"\(if .a then "include" else "x" end)"', '"include"'),
        (r'"\("import")"', '"import"'),
        (r'"\(.a) \("include") \("y")"', '"1 include y"'),
        (r'"a \("b \("import") c") d"', '"a b import c d"'),
        ("[$__loc__ | .line]", "[1]"),
        ('{"x": $__loc__} | .x.file', '"<top-level>"'),
        ("{import: 1, include: 2} | .import + .include", "3"),
        ('# import "x" as $y;\n.a', "1"),
    ],
)
def test_jq_allows_the_words_as_data(tmp_path, program, output):
    result = run_ok(tmp_path, "jq", {"filter": program}, b'{"a": 1}\n')["result"]
    assert result["output"] == output


def test_jq_large_jsonl_is_not_refused_by_the_document_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(jq_mod, "MAX_DOCUMENT_BYTES", 1000)
    data = jsonl({"id": i} for i in range(500))
    assert len(data) > 1000
    result = run_ok(tmp_path, "jq", {"filter": ".id"}, data)["result"]
    assert result["lines"] is True and result["outputLines"] == 500


def test_jq_refuses_a_declared_size_before_reading(tmp_path, monkeypatch):
    monkeypatch.setattr(jq_mod, "MAX_DOCUMENT_BYTES", 1000)
    declared = [InputArtifactDecl(input="source", sizeBytes=5000, sha256="0" * 64)]
    document = json.dumps({"a": [1, 2, 3]}, indent=2).encode()
    assert len(document) < 1000
    error = run_fails(tmp_path, "jq", {"filter": ".a"}, document, input_artifacts=declared)
    assert error.startswith("E_TOO_LARGE_FOR_JQ:") and "5000" in error
    ok = run_ok(
        tmp_path, "jq", {"filter": ".a[0]", "lines": True}, document, input_artifacts=declared
    )
    assert ok["result"]["output"] == "1"


def test_jq_output_is_cut_at_64_kib_on_a_line_boundary(tmp_path):
    data = jsonl({"id": i, "pad": "p" * 30} for i in range(5000))
    result = run_ok(tmp_path, "jq", {"filter": "."}, data)["result"]
    assert result["truncated"] is True
    assert len(result["output"].encode()) <= 64 * 1024
    assert result["hint"] == (
        "output cut at 64 KiB; narrow the filter (select fewer fields, or use first/limit)"
    )
    lines = result["output"].split("\n")
    assert result["outputLines"] == len(lines)
    assert all(json.loads(line)["pad"] == "p" * 30 for line in lines)
    assert [json.loads(line)["id"] for line in lines] == list(range(len(lines)))


def test_jq_output_without_a_newline_is_cut_at_a_character_boundary(tmp_path):
    data = jsonl(["é" * 100_000])
    result = run_ok(tmp_path, "jq", {"filter": "."}, data)["result"]
    assert result["truncated"] is True
    encoded = result["output"].encode("utf-8")
    assert 64 * 1024 - 4 <= len(encoded) <= 64 * 1024
    assert "�" not in result["output"]
    assert result["outputLines"] == 1


def test_jq_compile_error_fails(tmp_path):
    error = run_fails(tmp_path, "jq", {"filter": ".a |"}, b'{"a": 1}\n')
    assert "jq" in error and "exited" in error


def test_jq_runtime_error_fails(tmp_path):
    error = run_fails(tmp_path, "jq", {"filter": ".a.b"}, b'{"a": 1}\n')
    assert "Cannot index" in error


def test_jq_malformed_input_fails(tmp_path):
    run_fails(tmp_path, "jq", {"filter": ".", "lines": True}, b'{"a": 1}\n{oops\n')


def test_jq_filter_starting_with_a_dash_is_a_filter_not_a_flag(tmp_path):
    result = run_ok(tmp_path, "jq", {"filter": "-.a"}, b'{"a": 3}\n')["result"]
    assert result["output"] == "-3"


def test_jq_filter_cannot_read_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ARTIFACT_TOOLS_TEST_SECRET", "hunter2")
    result = run_ok(
        tmp_path, "jq", {"filter": "[env.ARTIFACT_TOOLS_TEST_SECRET, $ENV.PATH != null]"}, b"1\n"
    )["result"]
    assert "hunter2" not in result["output"]
    assert json.loads(result["output"])[0] is None


def test_jq_limits_the_address_space_where_the_platform_can(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(jq_mod.resource, "prlimit", lambda *args: calls.append(args), raising=False)
    run_ok(tmp_path, "jq", {"filter": "."}, b"1\n")
    (pid, which, limits) = calls[0]
    assert isinstance(pid, int) and pid > 0
    assert which == jq_mod.resource.RLIMIT_AS
    assert limits == (jq_mod.ADDRESS_SPACE_BYTES, jq_mod.ADDRESS_SPACE_BYTES) == (1 << 30, 1 << 30)


def test_jq_still_runs_when_the_address_space_limit_cannot_be_set(tmp_path, monkeypatch, caplog):
    def refuse(*_args):
        raise PermissionError("not allowed")

    monkeypatch.setattr(jq_mod.resource, "prlimit", refuse, raising=False)
    with caplog.at_level(logging.WARNING):
        result = run_ok(tmp_path, "jq", {"filter": ".a"}, b'{"a": 5}\n')["result"]
    assert result["output"] == "5"
    assert "address space" in caplog.text


def test_jq_python_memory_stays_bounded_for_a_huge_line(tmp_path):
    scope = stage_file(
        tmp_path,
        lambda path: path.write_bytes(
            b'{"id": 1}\n"' + b"x" * (16 * MIB) + b'"\n' + b'{"id": 2}\n' * 800_000
        ),
    )
    holder = {}
    peak = python_peak_bytes(lambda: holder.update(tr=invoke(scope, "jq", {"filter": "length"})))
    task_result = holder["tr"]
    assert task_result.status == "ok", task_result.error
    assert task_result.outputs["result"]["lines"] is True
    assert task_result.outputs["result"]["output"].split("\n")[1] == str(16 * MIB)
    assert peak < 8 * MIB, f"python peak {peak / MIB:.1f} MiB"


# --- sql -----------------------------------------------------------------------------------


def csv_rows(count: int) -> bytes:
    lines = ["id,name,score"] + [f"{i},name{i},{i * 1.5}" for i in range(count)]
    return ("\n".join(lines) + "\n").encode()


def make_parquet(path: Path, count: int) -> bytes:
    connection = duckdb.connect(":memory:")
    connection.execute(
        f"COPY (SELECT range AS id, 'n' || range AS name FROM range({count})) "
        f"TO '{path}' (FORMAT parquet)"
    )
    connection.close()
    return path.read_bytes()


def test_sql_csv_query_limited_rows(tmp_path):
    result = run_ok(
        tmp_path,
        "sql",
        {"query": "select id, name from t order by id", "maxRows": 5},
        csv_rows(100),
    )["result"]
    assert result["columns"] == [
        {"name": "id", "type": "BIGINT"},
        {"name": "name", "type": "VARCHAR"},
    ]
    assert result["rows"] == [[i, f"name{i}"] for i in range(5)]
    assert result["rowCount"] == 5
    assert result["truncated"] is True
    assert result["format"] == "csv"
    assert result["hint"] == (
        "returned the first 5 rows; filter or aggregate in the query, or raise maxRows (max 2000)"
    )


def test_sql_default_row_limit_is_200(tmp_path):
    result = run_ok(tmp_path, "sql", {"query": "select * from t"}, csv_rows(500))["result"]
    assert result["rowCount"] == 200 and result["truncated"] is True


def test_sql_complete_result_is_not_truncated(tmp_path):
    result = run_ok(
        tmp_path, "sql", {"query": "select count(*) as n, sum(score) as s from t"}, csv_rows(10)
    )["result"]
    assert result["rows"] == [[10, 67.5]]
    assert result["truncated"] is False and result["hint"] is None


def test_sql_exactly_max_rows_is_not_truncated(tmp_path):
    result = run_ok(tmp_path, "sql", {"query": "select id from t", "maxRows": 10}, csv_rows(10))[
        "result"
    ]
    assert result["rowCount"] == 10 and result["truncated"] is False


def test_sql_order_by_is_respected_under_the_row_limit(tmp_path):
    result = run_ok(
        tmp_path,
        "sql",
        {"query": "select id from t order by id desc", "maxRows": 3},
        csv_rows(5000),
    )["result"]
    assert result["rows"] == [[4999], [4998], [4997]]


@pytest.mark.parametrize(
    "query",
    [
        "select 1; -- trailing comment",
        "select 1;",
        "select 1 -- trailing comment",
        "with a as (select 1 as x) select x from a",
        "from t limit 1",
        "values (1)",
        "(select 1)",
    ],
)
def test_sql_accepts_select_shaped_statements(tmp_path, query):
    result = run_ok(tmp_path, "sql", {"query": query}, csv_rows(3))["result"]
    assert result["rows"] and result["rows"][0][0] in (1, 0)


def test_sql_describe_and_summarize_are_selects(tmp_path):
    described = run_ok(tmp_path / "d", "sql", {"query": "describe t"}, csv_rows(3))["result"]
    assert [row[0] for row in described["rows"]] == ["id", "name", "score"]
    summary = run_ok(tmp_path / "s", "sql", {"query": "summarize t"}, csv_rows(3))["result"]
    assert summary["rowCount"] == 3


def test_sql_cannot_read_other_files(tmp_path):
    error = run_fails(
        tmp_path, "sql", {"query": "select * from read_csv_auto('/etc/passwd')"}, csv_rows(3)
    )
    assert "passwd" in error


def test_sql_can_still_read_the_artifact_through_its_view_after_lockdown(tmp_path):
    result = run_ok(tmp_path, "sql", {"query": "select count(*) from t"}, csv_rows(7))["result"]
    assert result["rows"] == [[7]]


def test_the_duckdb_lockdown_holds_without_the_single_select_gate(tmp_path):
    # The task only lets one SELECT through, but the lockdown must hold on its own: drive the
    # session it builds with statements the gate would have refused.
    source = tmp_path / "data.csv"
    source.write_bytes(csv_rows(3))
    temp_dir = tmp_path / "duck-tmp"
    temp_dir.mkdir()
    con = duckdb.connect(":memory:")
    sql_mod._configure(con, temp_dir, 256 * MIB)
    con.execute(f"CREATE VIEW t AS SELECT * FROM {sql_mod._reader('csv', source)[0]}")
    sql_mod._lock_down(con, source)
    attempts = [
        (duckdb.PermissionException, f"COPY t TO '{tmp_path}/out.csv'"),
        (duckdb.PermissionException, f"ATTACH '{tmp_path}/other.db' AS other"),
        (duckdb.PermissionException, f"EXPORT DATABASE '{tmp_path}/export'"),
        (duckdb.PermissionException, "INSTALL httpfs"),
        (duckdb.PermissionException, "LOAD httpfs"),
        (duckdb.PermissionException, "SELECT * FROM read_text('/etc/passwd')"),
        (duckdb.InvalidInputException, "SET enable_external_access=true"),
        (duckdb.InvalidInputException, "SET lock_configuration=false"),
        (duckdb.InvalidInputException, f"SET allowed_paths=['{tmp_path}']"),
        (duckdb.InvalidInputException, "SET memory_limit='64GB'"),
    ]
    for error_type, statement in attempts:
        with pytest.raises(error_type, match="configuration|locked"):
            con.execute(statement)
    assert not list(tmp_path.glob("out.csv")) and not (tmp_path / "other.db").exists()
    assert con.execute("select count(*) from t").fetchall() == [(3,)]
    con.close()


@pytest.mark.parametrize(
    ("input_bytes", "expected"),
    [
        (0, 4 * 1024**3),
        (1024**2, 4 * 1024**3),
        (3 * 1024**3, 4 * 1024**3),
        (4 * 1024**3, 3 * 1024**3),
        (6 * 1024**3, 1 * 1024**3),
        (6 * 1024**3 + 512 * MIB, 512 * MIB),
        (7 * 1024**3, 256 * MIB),
        (50 * 1024**3, 256 * MIB),
    ],
)
def test_sql_spill_allowance_leaves_room_for_the_spooled_input(input_bytes, expected):
    # workSizeLimit (8 GiB) holds the spooled input, a GiB of other files, and the spill.
    assert sql_mod._max_temp_bytes(input_bytes) == expected


def test_sql_spill_allowance_is_what_the_session_gets(tmp_path):
    data = csv_rows(10)
    query = "select current_setting('max_temp_directory_size') as spill"
    result = run_ok(tmp_path, "sql", {"query": query}, data)["result"]
    assert result["rows"][0][0].startswith("4.0 GiB")


# (query, the reason it fails). A statement that is not one SELECT is stopped by the task before
# DuckDB sees it; a SELECT that reaches for a file is stopped by DuckDB's own lockdown.
ESCAPES = [
    ("SET enable_external_access=true", "single SELECT statement"),
    ("SET lock_configuration=false", "single SELECT statement"),
    ("SET allowed_paths=['/etc/passwd']", "single SELECT statement"),
    ("COPY t TO '{tmp}/exfil.csv'", "single SELECT statement"),
    ("COPY (select 1) TO '{tmp}/exfil2.csv'", "single SELECT statement"),
    ("EXPORT DATABASE '{tmp}/exfil_db'", "single SELECT statement"),
    ("ATTACH '{tmp}/other.db' AS other", "single SELECT statement"),
    ("INSTALL httpfs", "single SELECT statement"),
    ("LOAD httpfs", "single SELECT statement"),
    ("select * from read_text('/etc/passwd')", "disabled by configuration"),
    ("select * from read_blob('/etc/hosts')", "disabled by configuration"),
    ("select * from glob('/etc/*')", "disabled by configuration"),
    ("select * from '/etc/passwd'", "does not exist"),
    ("select * from read_csv('/etc/passwd')", "disabled by configuration"),
    ("select * from read_json('/etc/passwd')", "disabled by configuration"),
    ("select * from read_parquet('/etc/passwd')", "disabled by configuration"),
    ("select * from sniff_csv('/etc/passwd')", "disabled by configuration"),
    ("select 1; select 2", "single SELECT statement"),
    ("select 1; copy t to '{tmp}/exfil3.csv'", "single SELECT statement"),
    ("CREATE TABLE x AS SELECT 1", "single SELECT statement"),
    ("CREATE VIEW v AS SELECT 1", "single SELECT statement"),
    ("INSERT INTO t VALUES (1, 'a', 1.0)", "single SELECT statement"),
    ("UPDATE t SET id = 1", "single SELECT statement"),
    ("DROP VIEW t", "single SELECT statement"),
    ("DELETE FROM t", "single SELECT statement"),
    ("CALL pragma_version()", "single SELECT statement"),
    ("EXPLAIN SELECT 1", "single SELECT statement"),
    ("CREATE SECRET s (TYPE s3)", "single SELECT statement"),
]


@pytest.mark.parametrize(("query", "reason"), ESCAPES)
def test_sql_escapes_fail(tmp_path, query, reason):
    error = run_fails(tmp_path, "sql", {"query": query.format(tmp=tmp_path)}, csv_rows(3))
    assert reason in error, error
    assert not list(tmp_path.glob("exfil*")), "a query wrote outside the sandbox"
    assert not (tmp_path / "other.db").exists()


@pytest.mark.parametrize(
    "query",
    ["select 1; select 2", "CREATE TABLE x AS SELECT 1", "SET threads=1", "EXPLAIN SELECT 1"],
)
def test_sql_non_select_and_multiple_statements_are_named_as_such(tmp_path, query):
    assert "single SELECT statement" in run_fails(tmp_path, "sql", {"query": query}, csv_rows(3))


def test_sql_works_on_a_read_only_input(tmp_path):
    scope = stage(tmp_path, csv_rows(5))
    source = scope / ".rw-artifacts" / "inputs" / "source"
    source.chmod(0o444)
    before = source.read_bytes()
    task_result = invoke(scope, "sql", {"query": "select count(*) from t"})
    assert task_result.status == "ok", task_result.error
    assert task_result.outputs["result"]["rows"] == [[5]]
    assert source.read_bytes() == before


def test_sql_removes_its_temp_directory(tmp_path):
    run_ok(tmp_path, "sql", {"query": "select count(*) from t"}, csv_rows(5))
    assert not (tmp_path / "scope" / ".duckdb-tmp").exists()
    run_fails(tmp_path / "again", "sql", {"query": "select * from nope"}, csv_rows(5))
    assert not (tmp_path / "again" / "scope" / ".duckdb-tmp").exists()


def test_sql_json_jsonl_parquet_and_auto_formats(tmp_path):
    rows = [{"id": i, "name": f"n{i}"} for i in range(4)]
    # (format, data, the reader `auto` is expected to pick: any `{`/`[` start reads as json)
    cases = [
        ("json", json.dumps(rows).encode(), "json"),
        ("jsonl", jsonl(rows), "json"),
        ("parquet", make_parquet(tmp_path / "p.parquet", 4), "parquet"),
        ("csv", b"id,name\n0,n0\n1,n1\n2,n2\n3,n3\n", "csv"),
    ]
    for index, (fmt, data, auto_reader) in enumerate(cases):
        for requested, reader in ((fmt, fmt), ("auto", auto_reader)):
            result = run_ok(
                tmp_path / f"case{index}{requested}",
                "sql",
                {"query": "select id, name from t order by id", "format": requested},
                data,
            )["result"]
            assert result["rows"] == [[i, f"n{i}"] for i in range(4)], (fmt, requested)
            assert result["format"] == reader, (fmt, requested)


@pytest.mark.parametrize(
    ("body", "reader", "query", "rows"),
    [
        (b'{"a": 1}\n{"a": 2}\n', "json", "select a from t order by a", [[1], [2]]),
        (b'[{"a": 1}, {"a": 2}]', "json", "select count(*) from t", None),
        (b"id,name\n1,x\n2,y\n", "csv", "select id, name from t order by id", [[1, "x"], [2, "y"]]),
    ],
)
def test_sql_auto_sniff_ignores_a_byte_order_mark(tmp_path, body, reader, query, rows):
    result = run_ok(tmp_path, "sql", {"query": query}, b"\xef\xbb\xbf" + body)["result"]
    assert result["format"] == reader
    if rows is not None:
        assert result["rows"] == rows


def test_sql_auto_skips_leading_whitespace_when_sniffing(tmp_path):
    result = run_ok(tmp_path, "sql", {"query": "select a from t"}, b' \n\t[{"a": 1}]')["result"]
    assert result["rows"] == [[1]] and result["format"] == "json"


def test_sql_wrong_format_for_the_data_fails(tmp_path):
    run_fails(tmp_path, "sql", {"query": "select * from t", "format": "parquet"}, csv_rows(3))


def test_sql_values_are_made_json_safe(tmp_path):
    query = (
        "select date '2024-02-03' as d, time '04:05:06' as tm, "
        "timestamp '2024-02-03 04:05:06' as ts, "
        "timestamptz '2024-02-03 04:05:06+00' as tstz, 1.25::decimal(5,2) as dec, "
        "uuid '12345678-1234-5678-1234-567812345678' as u, interval 3 day as iv, "
        "'ab'::blob as bl, 'nan'::double as nan, 'inf'::double as inf, '-inf'::double as ninf, "
        "[1, 2, null] as lst, {'k': 'v', 'n': [1]} as st, null as nul, true as flag, "
        "12345678901234567890123::hugeint as huge, ['2024-02-03 04:05:06+00'::timestamptz] as tzs, "
        "['nan'::double, 'inf'::double] as lnan"
    )
    result = run_ok(tmp_path, "sql", {"query": query}, csv_rows(1))["result"]
    names = [c["name"] for c in result["columns"]]
    row = dict(zip(names, result["rows"][0], strict=True))
    assert row["d"] == "2024-02-03"
    assert row["tm"] == "04:05:06"
    assert row["ts"] == "2024-02-03T04:05:06"
    assert row["tstz"].startswith("2024-02-03 04:05:06")
    assert row["dec"] == "1.25"
    assert row["u"] == "12345678-1234-5678-1234-567812345678"
    assert row["iv"] == "3 days, 0:00:00"
    assert row["bl"] == base64.b64encode(b"ab").decode()
    assert (row["nan"], row["inf"], row["ninf"]) == ("nan", "inf", "-inf")
    assert row["lst"] == [1, 2, None]
    assert row["st"] == {"k": "v", "n": [1]}
    assert row["nul"] is None and row["flag"] is True
    assert row["huge"] == 12345678901234567890123
    assert row["tzs"] == ["2024-02-03 04:05:06+00"]
    assert row["lnan"] == ["nan", "inf"]
    types = {c["name"]: c["type"] for c in result["columns"]}
    assert types["tstz"] == "TIMESTAMP WITH TIME ZONE"
    json.dumps(result, allow_nan=False)


def test_sql_csv_timestamps_with_an_offset_do_not_need_a_timezone_package(tmp_path):
    data = b"stamp,v\n2024-02-03T04:05:06Z,1\n2024-02-03T05:05:06Z,2\n"
    result = run_ok(tmp_path, "sql", {"query": "select * from t order by stamp"}, data)["result"]
    assert result["columns"][0]["type"] == "TIMESTAMP WITH TIME ZONE"
    assert result["rows"][0][0].startswith("2024-02-03 04:05:06")


def test_sql_duplicate_column_names_are_kept(tmp_path):
    result = run_ok(
        tmp_path, "sql", {"query": "select id, id, now() as n, now() as n from t"}, csv_rows(1)
    )["result"]
    assert [c["name"] for c in result["columns"]] == ["id", "id", "n", "n"]
    assert result["rows"][0][:2] == [0, 0]


def test_sql_long_cells_are_capped_at_16_kib(tmp_path):
    query = (
        "select repeat('x', 100000) as s, repeat('y', 100000)::blob as b, "
        "['z' || repeat('z', 20000)] as l"
    )
    row = run_ok(tmp_path, "sql", {"query": query}, csv_rows(1))["result"]["rows"][0]
    cap = sql_mod._cell_cap(3)  # three cut columns share the row's 16 Ki characters
    assert cap == 16384 // 3
    assert row[0] == "x" * cap + "…"
    assert row[1].endswith("…") and len(row[1]) == len(base64.b64encode(b"y" * cap)) + 1
    # A list is bounded as its JSON text: cut, and marked like any other long cell.
    assert isinstance(row[2], str) and row[2].startswith('["zzz')
    assert len(row[2]) == cap + 1 and row[2].endswith("…")


def test_sql_a_single_text_column_keeps_the_full_cell_size(tmp_path):
    query = "select repeat('x', 100000) as s from t"
    cell = run_ok(tmp_path, "sql", {"query": query}, csv_rows(1))["result"]["rows"][0][0]
    assert cell == "x" * 16384 + "…"


# DuckDB hands a result to Python whole, so a cell is bounded where it is produced, in the
# query's projection, and the rows are fetched in batches sized by bytes.
BOUNDED_CELL_QUERIES = {
    "megabyte text on every row": (
        "select repeat('x', 1000000) || id as s from t limit 250",
        {},
        "csv",
    ),
    "one huge text cell per row": (
        "select repeat('x', 4000000) as s from t",
        {"maxRows": 5},
        "csv",
    ),
    "string_agg over the whole input": (
        "select string_agg(name || repeat('z', 100), ',') as s from t",
        {},
        "big",
    ),
    "a huge blob": (
        "select repeat('y', 4000000)::blob as b from t limit 6",
        {"maxRows": 5},
        "csv",
    ),
    "a list of the whole input": ("select list(name || repeat('z', 100)) as l from t", {}, "big"),
    "a struct holding a huge text": (
        "select {'k': repeat('x', 4000000)} as s from t limit 6",
        {"maxRows": 5},
        "csv",
    ),
    "a long text beside a time-zone cell": (
        "select repeat('x', 1000000) || id as s, now() as n from t limit 250",
        {},
        "csv",
    ),
    "thirty wide text columns": (
        "select " + ", ".join(f"repeat('a', 100000) as c{i}" for i in range(30)) + " from t",
        {"maxRows": 50},
        "csv",
    ),
}


@pytest.mark.parametrize("name", list(BOUNDED_CELL_QUERIES))
def test_sql_python_memory_stays_bounded_for_wide_cells(tmp_path, name):
    query, extra, source = BOUNDED_CELL_QUERIES[name]
    data = csv_rows(3000) if source == "csv" else csv_rows(200_000)
    scope = stage(tmp_path, data)
    holder = {}
    peak = python_peak_bytes(
        lambda: holder.update(tr=invoke(scope, "sql", {"query": query, **extra}))
    )
    task_result = holder["tr"]
    assert task_result.status == "ok", task_result.error
    result = task_result.outputs["result"]
    validate("sql", result)
    assert peak < 8 * MIB, f"python peak {peak / MIB:.1f} MiB"
    cells = [cell for row in result["rows"] for cell in row if isinstance(cell, str)]
    long_cells = [cell for cell in cells if len(cell) > 100]
    assert long_cells, "the query should have produced long cells"
    # Every long cell was cut at 16 KiB and says so.
    assert all(cell.endswith("\u2026") for cell in long_cells)
    blob_cell = len(base64.b64encode(b"y" * sql_mod.CELL_MAX_BYTES)) + 1
    assert all(len(cell) <= max(sql_mod.CELL_MAX_CHARS + 1, blob_cell) for cell in long_cells)


def test_sql_wide_table_is_cut_by_the_row_budget_not_by_memory(tmp_path):
    query = "select " + ", ".join(f"repeat('a', 100000) as c{i}" for i in range(30)) + " from t"
    result = run_ok(tmp_path, "sql", {"query": query, "maxRows": 2000}, csv_rows(300))["result"]
    assert result["truncated"] is True
    assert 1 <= result["rowCount"] < 300
    # 30 text columns share one row of 16 Ki characters.
    cap = sql_mod.ROW_MAX_CHARS // 30
    assert all(cell == "a" * cap + "\u2026" for cell in result["rows"][0])
    assert "narrower columns" in result["hint"] and "raise maxRows" not in result["hint"]


def test_sql_cell_bound_keeps_blob_and_nested_values_readable(tmp_path):
    query = "select 'abc'::blob as b, [1, 2] as l, {'k': 'v'} as s, map {'a': 1} as m, 'text' as v"
    row = run_ok(tmp_path, "sql", {"query": query}, csv_rows(1))["result"]["rows"][0]
    assert row == [base64.b64encode(b"abc").decode(), [1, 2], {"k": "v"}, {"a": 1}, "text"]


@pytest.mark.parametrize(
    ("cut_columns", "cap"),
    [(0, 16384), (1, 16384), (2, 8192), (3, 5461), (4, 4096), (5, 3276), (12, 1365), (30, 546)]
    + [(1024, 16), (4096, 16), (100_000, 16)],
)
def test_sql_cell_cap_shares_one_row_budget_between_the_cut_columns(cut_columns, cap):
    assert sql_mod._cell_cap(cut_columns) == cap
    assert cut_columns * cap <= max(sql_mod.ROW_MAX_CHARS, cut_columns * sql_mod.MIN_CELL_CHARS)


def test_sql_projection_counts_only_the_columns_it_cuts():
    connection = duckdb.connect(":memory:")
    relation = connection.sql(
        "select 1 as n, 'a' as s, 'b'::blob as b, [1] as l, now() as z, date '2020-01-01' as d"
    )
    projection = sql_mod._projection(list(relation.columns), list(relation.types))
    assert projection.nested == [False, False, False, True, False, False]
    assert projection.cut_columns == 4  # s, b, l and the time-zone cast
    assert projection.cell_cap == 4096
    wide = connection.sql("select " + ", ".join(f"'x' as c{i}" for i in range(40)))
    projection = sql_mod._projection(list(wide.columns), list(wide.types))
    assert projection.cut_columns == 40 and projection.cell_cap == 16384 // 40
    assert projection.sql.count("left(") == 40


def test_sql_fetch_batches_are_sized_by_bytes_from_the_row_width():
    worst_char = 4  # a character of a str, in Python's memory, at most
    for row_chars in (1, 100, 16_384, 65_536, 1_000_000):
        batch = sql_mod._batch_rows(row_chars)
        assert batch >= 1
        assert batch == 1 or batch * row_chars * worst_char <= 4 * MIB
    assert sql_mod._batch_rows(65_536) == 16
    assert sql_mod._batch_rows(0) == sql_mod.MAX_FETCH_ROWS  # numbers only: bounded by count
    assert sql_mod._batch_rows(10_000_000) == 1


def test_sql_query_beyond_the_memory_limit_fails_cleanly(tmp_path):
    # 201 rows of 4 MB is more than the 640 MB session limit: DuckDB refuses, the pod is safe.
    error = run_fails(
        tmp_path, "sql", {"query": "select repeat('x', 4000000) || id as s from t"}, csv_rows(3000)
    )
    assert "Out of Memory" in error


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ("select * from t order by id desc", True),
        ("SELECT id AS a FROM t ORDER\n  BY a LIMIT 3", True),
        ("select * from t union all select * from t order by 1", True),
        ("from t order by id", True),
        ("(select * from t order by id)", True),
        ("values (2), (1) order by 1", True),
        ("select * from t", False),
        ("select * from t -- order by id", False),
        ("select * from t /* order by id */", False),
        ("select 'order by' as s from t", False),
        ('select "order by" from t', False),
        ("select order_by_col from t", False),
        ("select * from t where id in (select id from t order by id desc limit 3000)", False),
        ("with s as (select * from t order by id) select * from s", False),
        ("select id, row_number() over (order by id) as n from t", False),
        ("describe t", False),
        ("summarize t", False),
        ("pivot t on id", False),  # DuckDB cannot serialise it: treated as "no ORDER BY"
        ("select * from", False),  # nor can it serialise what it cannot parse
    ],
)
def test_sql_finds_a_top_level_order_by_with_the_duckdb_parser(statement, expected):
    connection = duckdb.connect(":memory:")
    connection.execute("create table t as select range as id, 1 as order_by_col from range(3)")
    assert sql_mod._sorts_at_the_top(connection, statement) is expected


def test_sql_a_sorted_result_stays_sorted_without_insertion_order(tmp_path):
    # A query that sorts is run with DuckDB's insertion-order preservation off (it needs the
    # limit pushed down, and that is what makes the limit cheap). The sort must not suffer.
    rows = run_ok(
        tmp_path / "all",
        "sql",
        {"query": "select id from t order by id desc", "maxRows": 2000},
        csv_rows(100_000),
    )["result"]["rows"]
    assert rows == [[i] for i in range(99_999, 97_999, -1)]
    ties = run_ok(
        tmp_path / "ties",
        "sql",
        {"query": "select id % 7 as k, id from t order by k", "maxRows": 1500},
        csv_rows(50_000),
    )["result"]["rows"]
    keys = [row[0] for row in ties]
    assert keys == sorted(keys) and set(keys) == {0}  # 7143 rows have k = 0: all ties


def test_sql_a_plain_scan_keeps_insertion_order(tmp_path):
    rows = run_ok(
        tmp_path, "sql", {"query": "select id from t", "maxRows": 2000}, csv_rows(60_000)
    )["result"]["rows"]
    assert rows == [[i] for i in range(2000)]


def test_sql_rows_come_back_in_file_order_across_batches(tmp_path):
    result = run_ok(tmp_path, "sql", {"query": "select id from t", "maxRows": 2000}, csv_rows(5000))
    rows = result["result"]["rows"]
    assert rows == [[i] for i in range(2000)]
    assert result["result"]["truncated"] is True


def test_sql_sorted_query_over_many_rows_returns_the_top_rows(tmp_path):
    query = "select id from t order by score desc"
    rows = run_ok(tmp_path, "sql", {"query": query, "maxRows": 40}, csv_rows(60_000))["result"][
        "rows"
    ]
    assert rows == [[i] for i in range(59_999, 59_959, -1)]


def test_sql_hint_names_what_ended_the_result(tmp_path):
    by_rows = run_ok(
        tmp_path / "r", "sql", {"query": "select id from t", "maxRows": 5}, csv_rows(50)
    )
    assert by_rows["result"]["hint"].endswith("or raise maxRows (max 2000)")
    at_the_ceiling = run_ok(
        tmp_path / "c", "sql", {"query": "select id from t", "maxRows": 2000}, csv_rows(2100)
    )["result"]
    assert at_the_ceiling["rowCount"] == 2000 and at_the_ceiling["truncated"] is True
    assert "maxRows" not in at_the_ceiling["hint"]
    wide = "select repeat('x', 16000) as s from t"
    by_bytes = run_ok(tmp_path / "b", "sql", {"query": wide, "maxRows": 1000}, csv_rows(1000))
    hint = by_bytes["result"]["hint"]
    assert by_bytes["result"]["rowCount"] < 1000
    assert "size limit" in hint and "narrower columns" in hint and "maxRows" not in hint


def test_sql_stops_at_the_row_byte_budget(tmp_path):
    query = "select repeat('x', 16000) as s from range(1000)"
    result = run_ok(tmp_path, "sql", {"query": query, "maxRows": 1000}, csv_rows(1))["result"]
    assert result["truncated"] is True
    assert 200 < result["rowCount"] < 1000
    assert result["hint"].startswith(f"returned the first {result['rowCount']} rows;")


def test_sql_large_result_spills_to_an_artifact(tmp_path):
    query = "select id, repeat('x', 200) as pad from t"
    spill = [OutputDecl(task="sql", name="result", spill=True)]
    outputs = run_ok(
        tmp_path, "sql", {"query": query, "maxRows": 2000}, csv_rows(3000), outputs=spill
    )
    assert outputs["result"]["$artifact"].startswith("local_")
    spilled = json.loads(artifact_bytes(tmp_path, "result"))
    assert spilled["rowCount"] == 2000 and spilled["truncated"] is True


def test_sql_small_result_stays_inline_even_when_spill_is_allowed(tmp_path):
    spill = [OutputDecl(task="sql", name="result", spill=True)]
    outputs = run_ok(tmp_path, "sql", {"query": "select 1 as one"}, csv_rows(1), outputs=spill)
    assert outputs["result"]["rows"] == [[1]]


def test_sql_query_error_is_reported(tmp_path):
    assert "nonexistent" in run_fails(
        tmp_path, "sql", {"query": "select nonexistent from t"}, csv_rows(2)
    )


def test_sql_session_is_configured_and_locked(tmp_path):
    query = (
        "select current_setting('memory_limit') as mem, current_setting('threads') as threads, "
        "current_setting('enable_external_access') as external, "
        "current_setting('lock_configuration') as locked, "
        "current_setting('max_temp_directory_size') as spill, "
        "current_setting('autoload_known_extensions') as autoload, "
        "current_setting('python_enable_replacements') as replacements, "
        "current_setting('streaming_buffer_size') as stream_buffer"
    )
    result = run_ok(tmp_path, "sql", {"query": query}, csv_rows(1))["result"]
    row = dict(zip([c["name"] for c in result["columns"]], result["rows"][0], strict=True))
    assert row["mem"].startswith("610.3 MiB")
    assert row["threads"] == 2
    assert row["external"] is False and row["locked"] is True
    assert row["spill"].startswith("4.0 GiB")
    assert row["autoload"] is False and row["replacements"] is False
    # DuckDB sizes this by the vectors, not the strings in them: at its default it lets the scan
    # run thousands of wide rows ahead of the reader.
    assert row["stream_buffer"] == "8.0 KiB"


# tracemalloc cannot see DuckDB, which keeps the rows it has produced until they are fetched. So
# the wide-row cases run in a child process and are judged on its peak RSS: a 2Gi pod has no room
# for a request that reaches it.
RSS_CHILD = """
import json, resource, sys
from pathlib import Path
from runwhen_capability.host import run_request
from runwhen_capability.loader import load_capability
from runwhen_capability.models import RequestEnvelope

cap_dir, scope, query, max_rows = sys.argv[1], Path(sys.argv[2]), sys.argv[3], int(sys.argv[4])
capability = load_capability(Path(cap_dir))
request = RequestEnvelope.model_validate({"version": 1, "tasks": [{"task": "sql", "inputs": {
    "source": "art_x", "query": query, "maxRows": max_rows, "format": "parquet"}}]})
(task,) = run_request(capability, request, credentials={}, scope_dir=scope).tasks
rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
result = task.outputs.get("result") or {}
print(json.dumps({
    "status": task.status, "error": task.error, "rows": result.get("rowCount"),
    "truncated": result.get("truncated"),
    "rss_mib": rss / (2**20 if sys.platform == "darwin" else 2**10),  # bytes on macOS, KiB on Linux
}))
"""


def make_wide_parquet(path: Path, columns: int, unit: str, *, cells=17_000, rows=2_100) -> None:
    """`rows` rows of `columns` text cells, each `cells` characters of `unit`, and an `id`, in row
    groups of 50 (so reading it never needs a giant vector). Compresses to almost nothing."""
    cols = ", ".join(f"repeat('{unit}', {cells}) || id::varchar AS c{i}" for i in range(columns))
    batches = " UNION ALL ".join(
        f"SELECT {cols}, id FROM range({start}, {min(start + 50, rows)}) t(id)"
        for start in range(0, rows, 50)
    )
    connection = duckdb.connect(":memory:")
    connection.execute(
        f"COPY ({batches}) TO '{path}' (FORMAT parquet, ROW_GROUP_SIZE 50, COMPRESSION zstd)"
    )
    connection.close()


# The query shapes include two that fooled a text search for "order by": a comment, and an ORDER BY
# inside a subquery. Neither sorts at the top, so neither may reach DuckDB as a LIMIT (which made
# it hold 1.5 to 2.3 GiB). A subquery that DuckDB joins to the wide table is another matter: that
# join costs 1.4 GiB or more by itself, LIMIT or not (see the report), so the subquery here is a
# scalar one.
RSS_QUERIES = {
    "plain": "select * from t",
    "order-by-in-a-comment": "select * from t -- order by id",
    "order-by-in-a-subquery": (
        "select * from t where id >= (select id from t order by id desc limit 1 offset 1999)"
    ),
}


@pytest.mark.parametrize("query_name", list(RSS_QUERIES))
@pytest.mark.parametrize(
    ("columns", "unit"),
    [(30, "x"), (12, "\U0001f600")],
    ids=["30-ascii-columns", "12-emoji-columns"],
)
def test_sql_peak_rss_stays_well_under_the_pod_limit_for_wide_rows(
    tmp_path, columns, unit, query_name
):
    scope = stage(tmp_path, None)
    make_wide_parquet(scope / ".rw-artifacts" / "inputs" / "source", columns, unit)
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            RSS_CHILD,
            str(CAP_DIR),
            str(scope),
            RSS_QUERIES[query_name],
            "2000",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert child.returncode == 0, child.stderr[-2000:]
    report = json.loads(child.stdout.strip().splitlines()[-1])
    assert report["status"] == "ok", report["error"]
    assert report["rows"] >= 1 and report["truncated"] is True
    # One request owns the pod while it runs (the executor serves requests one at a time), and the
    # pod's memory limit is 2Gi. These inputs are deliberately extreme (816 KB rows of 4-byte text),
    # and DuckDB's scan memory follows the input's width and varies with how its two scan threads
    # interleave: Linux runs measured 0.35 to 1.2 GiB. Before rows were streamed and the ORDER BY
    # check used the parser, the same shapes took 1.5 to 2.6 GiB.
    assert report["rss_mib"] < 1536, f"peak RSS {report['rss_mib']:.0f} MiB"


# --- slice ---------------------------------------------------------------------------------


def numbered(count: int, *, terminated: bool = True) -> bytes:
    text = "\n".join(f"line {i}" for i in range(1, count + 1))
    return (text + ("\n" if terminated else "")).encode()


def test_slice_writes_lines(tmp_path):
    out = run_ok(tmp_path, "slice", {"fromLine": 3, "toLine": 6}, numbered(10))
    assert out["slice"]["$artifact"].startswith("local_")
    assert artifact_bytes(tmp_path, "slice") == b"line 3\nline 4\nline 5\n"


@pytest.mark.parametrize(
    ("data", "from_line", "to_line", "expected"),
    [
        (numbered(5), 1, 2, b"line 1\n"),
        (numbered(5), 1, 6, numbered(5)),
        (numbered(5), 5, 6, b"line 5\n"),
        (numbered(5), 4, 100, b"line 4\nline 5\n"),
        (numbered(5), 6, 9, b""),
        (numbered(5), 100, 200, b""),
        (numbered(5, terminated=False), 4, 9, b"line 4\nline 5"),
        (numbered(5, terminated=False), 5, 6, b"line 5"),
        (b"a\r\nb\r\nc\r\n", 2, 3, b"b\r\n"),
        (b"\n\n\nx\n", 2, 4, b"\n\n"),
        (b"", 1, 2, b""),
    ],
)
def test_slice_ranges(tmp_path, data, from_line, to_line, expected):
    run_ok(tmp_path, "slice", {"fromLine": from_line, "toLine": to_line}, data)
    assert artifact_bytes(tmp_path, "slice") == expected


def test_slice_across_many_chunks_matches_a_reference(tmp_path):
    rng = random.Random(7)
    sizes = [70_000 if i % 5000 == 0 else rng.choice([0, 1, 5, 300]) for i in range(60_000)]
    data = b"\n".join(b"x" * size for size in sizes) + b"\n"
    assert len(data) > 3 * MIB
    lines = data.split(b"\n")[:-1]
    ranges = [(1, 3), (30_000, 30_050), (59_990, 70_000), (1, 60_001)]
    for case, (from_line, to_line) in enumerate(ranges):
        scope_root = tmp_path / str(case)
        run_ok(scope_root, "slice", {"fromLine": from_line, "toLine": to_line}, data)
        expected = b"".join(line + b"\n" for line in lines[from_line - 1 : to_line - 1])
        assert artifact_bytes(scope_root, "slice") == expected, (from_line, to_line)


def test_slice_matches_a_reference_whatever_the_chunk_size(tmp_path, monkeypatch):
    rng = random.Random(11)
    for case in range(60):
        monkeypatch.setattr(slice_mod, "READ_BYTES", rng.choice([1, 2, 3, 5, 8, 13]))
        pieces = [b"y" * rng.randint(0, 6) for _ in range(rng.randint(0, 12))]
        data = b"\n".join(pieces) + rng.choice([b"", b"\n"])
        from_line = rng.randint(1, 15)
        to_line = from_line + rng.randint(1, 15)
        run_ok(tmp_path / str(case), "slice", {"fromLine": from_line, "toLine": to_line}, data)
        lines = data.split(b"\n")
        if data.endswith(b"\n"):
            lines = lines[:-1]
            expected = b"".join(line + b"\n" for line in lines[from_line - 1 : to_line - 1])
        else:
            kept = lines[from_line - 1 : to_line - 1]
            expected = b"\n".join(kept) + (b"\n" if kept and to_line - 1 < len(lines) else b"")
        assert artifact_bytes(tmp_path / str(case), "slice") == expected, (data, from_line, to_line)


def test_slice_accepts_numbers_as_decimal_strings(tmp_path):
    run_ok(tmp_path, "slice", {"fromLine": "2", "toLine": "4"}, numbered(5))
    assert artifact_bytes(tmp_path, "slice") == b"line 2\nline 3\n"


@pytest.mark.parametrize(
    ("from_line", "to_line", "needle"),
    [
        (0, 5, "fromLine"),
        (-3, 5, "fromLine"),
        (5, 5, "toLine"),
        (7, 3, "toLine"),
        (1, 10_000_002, "10000000"),
        ("abc", 5, "fromLine"),
        (1.5, 5, "fromLine"),
        (True, 5, "fromLine"),
    ],
)
def test_slice_rejects_invalid_ranges(tmp_path, from_line, to_line, needle):
    error = run_fails(tmp_path, "slice", {"fromLine": from_line, "toLine": to_line}, numbered(5))
    assert needle in error
    assert not (tmp_path / "scope" / ".rw-artifacts" / "slice").exists()


def test_slice_allows_the_widest_range(tmp_path):
    run_ok(tmp_path, "slice", {"fromLine": 1, "toLine": 10_000_001}, numbered(3))
    assert artifact_bytes(tmp_path, "slice") == numbered(3)


def test_slice_python_memory_stays_bounded_for_a_huge_line(tmp_path):
    scope = stage_file(tmp_path, write_big_line_file)
    peak = python_peak_bytes(lambda: invoke(scope, "slice", {"fromLine": 2, "toLine": 3}))
    assert (scope / ".rw-artifacts" / "slice").stat().st_size == 16 * MIB + 1
    assert peak < 8 * MIB, f"python peak {peak / MIB:.1f} MiB"


def test_grep_python_memory_stays_bounded_for_a_huge_line(tmp_path):
    scope = stage_file(tmp_path, write_big_line_file)
    holder = {}
    peak = python_peak_bytes(
        lambda: holder.update(tr=invoke(scope, "grep", {"pattern": "needle", "maxMatches": 10}))
    )
    task_result = holder["tr"]
    assert task_result.status == "ok", task_result.error
    result = task_result.outputs["result"]
    assert result["longLines"] == 1
    assert result["totalMatches"] == 3
    assert [m["lineNumber"] for m in result["matches"][:2]] == [1, 2]
    assert peak < 8 * MIB, f"python peak {peak / MIB:.1f} MiB"


# --- the request deadline ------------------------------------------------------------------
# `rwtask serve` takes one request at a time and does not kill the pod at the deadline, so each
# task stops itself: the SDK puts the deadline on `ctx.deadline_at`, and a task stops a few
# seconds early (MARGIN_SECONDS) so its error reaches the caller before the lease runs out.


@pytest.fixture
def no_margin(monkeypatch):
    """Stop exactly at the deadline, so a 2 s deadline in a test is a 2 s wait."""
    monkeypatch.setattr(deadline_mod, "MARGIN_SECONDS", 0.0)


def timed(call):
    started = time.monotonic()
    outcome = call()
    return outcome, time.monotonic() - started


def test_jq_stops_a_runaway_filter_at_the_deadline(tmp_path, no_margin):
    scope = stage(tmp_path, b"1\n")
    task_result, seconds = timed(
        lambda: invoke(
            scope, "jq", {"filter": "last(range(1e18))", "lines": True}, deadline_seconds=2
        )
    )
    assert task_result.status == "failed"
    assert task_result.error.startswith("E_DEADLINE:"), task_result.error
    assert "after 2 s" in task_result.error
    assert 1.5 < seconds < 6, f"{seconds:.1f} s"


def test_sql_interrupts_a_runaway_query_at_the_deadline(tmp_path, no_margin):
    data = b"id\n" + b"\n".join(b"%d" % i for i in range(200_000)) + b"\n"
    scope = stage(tmp_path, data)
    query = "select count(*) from t a, t b where a.id + b.id = -1"
    task_result, seconds = timed(lambda: invoke(scope, "sql", {"query": query}, deadline_seconds=2))
    assert task_result.status == "failed"
    assert task_result.error.startswith("E_DEADLINE:"), task_result.error
    assert 1.5 < seconds < 6, f"{seconds:.1f} s"
    assert not (scope / ".duckdb-tmp").exists()


class SlowSource(io.RawIOBase):
    """An input that trickles: a small chunk every `pause` seconds, for a long time."""

    def __init__(
        self, pause: float, chunks: int = 1000, payload: bytes = b"nothing to see here\n" * 50
    ) -> None:
        self.pause = pause
        self.left = chunks
        self.payload = payload

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if self.left <= 0:
            return b""
        self.left -= 1
        time.sleep(self.pause)
        return self.payload

    def readline(self, size: int = -1) -> bytes:
        return self.read(size)


class DiscardingOutput(io.BytesIO):
    ref = "discarded"


def slow_ctx(deadline_in: float | None, pause: float = 0.2, payload: bytes | None = None):
    source = SlowSource(pause) if payload is None else SlowSource(pause, payload=payload)
    ctx = fake_ctx(source)
    ctx.artifacts.open = lambda name, content_type=None: DiscardingOutput()
    ctx.deadline_at = None if deadline_in is None else time.monotonic() + deadline_in
    ctx.workdir = Path(".")
    return ctx


def test_grep_stops_a_slow_search_at_the_deadline(no_margin):
    ctx = slow_ctx(2)
    started = time.monotonic()
    with pytest.raises(deadline_mod.ToolError, match="^E_DEADLINE: stopped at the request"):
        grep_mod.run_grep(
            ctx, pattern="needle", ignore_case=False, context=0, max_matches=5, save_all=False
        )
    assert 1.5 < time.monotonic() - started < 6


def test_jq_stops_a_slow_input_at_the_deadline(no_margin):
    # Valid JSON lines, so jq is still waiting for more when the deadline comes (text that is
    # not JSON makes it fail at once on some platforms, before the deadline means anything).
    ctx = slow_ctx(2, payload=b'{"a": 1}\n' * 100)
    started = time.monotonic()
    with pytest.raises(deadline_mod.ToolError, match="^E_DEADLINE:"):
        jq_mod.run_jq(ctx, program=".", lines=True)
    assert 1.5 < time.monotonic() - started < 6


def test_slice_checks_the_deadline_between_chunks(no_margin):
    ctx = slow_ctx(1)
    started = time.monotonic()
    with pytest.raises(deadline_mod.ToolError, match="^E_DEADLINE:"):
        slice_mod.run_slice(ctx, from_line=10**9, to_line=10**9 + 5)
    assert 0.8 < time.monotonic() - started < 5


@pytest.mark.parametrize(
    ("task", "inputs"),
    [
        ("grep", {"pattern": "x"}),
        ("jq", {"filter": "."}),
        ("sql", {"query": "select 1"}),
        ("slice", {"fromLine": 1, "toLine": 2}),
    ],
)
def test_a_deadline_inside_the_margin_stops_the_task_at_once(tmp_path, task, inputs):
    # The default margin is 5 s: a deadline 1 s away is already too close to start.
    assert deadline_mod.MARGIN_SECONDS == 5.0
    scope = stage(tmp_path, b"x\n")
    task_result, seconds = timed(lambda: invoke(scope, task, inputs, deadline_seconds=1))
    assert task_result.status == "failed"
    assert task_result.error.startswith("E_DEADLINE:"), task_result.error
    assert seconds < 3


def test_no_deadline_means_no_timer(tmp_path):
    before = threading.active_count()
    watch = deadline_mod.Deadline(SimpleNamespace(deadline_at=None), "advice")
    watch.arm(lambda: pytest.fail("fired"))
    watch.check()
    watch.cancel()
    assert not watch.expired and threading.active_count() == before


def test_the_timer_is_cancelled_when_the_work_finishes_first(tmp_path):
    scope = stage(tmp_path, b"1\n2\n")
    task_result = invoke(scope, "jq", {"filter": "."}, deadline_seconds=3600)
    assert task_result.status == "ok", task_result.error
    assert not [t for t in threading.enumerate() if isinstance(t, threading.Timer)]


def test_a_finished_task_is_not_failed_by_a_late_deadline(tmp_path, no_margin):
    # The deadline passes just after the answer is complete: the answer stands.
    scope = stage(tmp_path, b"hit\n")
    result = invoke(scope, "grep", {"pattern": "hit"}, deadline_seconds=30)
    assert result.status == "ok"


def test_grep_cut_off_in_the_middle_of_an_event_is_a_deadline_error(
    tmp_path, monkeypatch, no_margin
):
    # ripgrep killed at the deadline can leave half an event on its output; that must not be
    # parsed. (A stand-in `rg` that writes half an event and waits to be killed.)
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "rg"
    stub.write_text('#!/bin/sh\nprintf \'{"type":"match","data":{"lin\'\nexec sleep 30\n')
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{stub_dir}{os.pathsep}{os.environ['PATH']}")
    ctx = fake_ctx(io.BytesIO(b"needle\n"))
    ctx.deadline_at = time.monotonic() + 1
    started = time.monotonic()
    with pytest.raises(deadline_mod.ToolError, match="^E_DEADLINE:"):
        grep_mod.run_grep(
            ctx, pattern="needle", ignore_case=False, context=0, max_matches=5, save_all=False
        )
    assert time.monotonic() - started < 5


def test_grep_reaps_ripgrep_when_setup_after_the_spawn_fails(monkeypatch):
    spawned = []
    real_spawn = grep_mod.spawn

    def spawn_and_note(argv):
        proc = real_spawn(argv)
        spawned.append(proc)
        return proc

    def broken(*_args, **_kwargs):
        raise RuntimeError("setup broke")

    monkeypatch.setattr(grep_mod, "spawn", spawn_and_note)
    monkeypatch.setattr(grep_mod, "StderrTail", broken)
    ctx = fake_ctx(io.BytesIO(b"needle\n"))
    with pytest.raises(RuntimeError, match="setup broke"):
        grep_mod.run_grep(
            ctx, pattern="needle", ignore_case=False, context=0, max_matches=5, save_all=False
        )
    assert spawned and spawned[0].poll() is not None, "ripgrep was left running"


def test_jq_reaps_jq_when_setup_after_the_spawn_fails(monkeypatch):
    spawned = []
    real_spawn = jq_mod.spawn

    def spawn_and_note(argv):
        proc = real_spawn(argv)
        spawned.append(proc)
        return proc

    def broken(*_args, **_kwargs):
        raise RuntimeError("setup broke")

    monkeypatch.setattr(jq_mod, "spawn", spawn_and_note)
    monkeypatch.setattr(jq_mod, "_limit_address_space", broken)
    ctx = fake_ctx(io.BytesIO(b"1\n"))
    with pytest.raises(RuntimeError, match="setup broke"):
        jq_mod.run_jq(ctx, program=".", lines=True)
    assert spawned and spawned[0].poll() is not None, "jq was left running"


# --- parameter validation ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("task", "inputs", "needle"),
    [
        ("grep", {"pattern": "x", "context": 6}, "context"),
        ("grep", {"pattern": "x", "context": -1}, "context"),
        ("grep", {"pattern": "x", "maxMatches": 0}, "maxMatches"),
        ("grep", {"pattern": "x", "maxMatches": 501}, "maxMatches"),
        ("grep", {"pattern": "x", "maxMatches": "many"}, "maxMatches"),
        ("grep", {"pattern": "x", "maxMatches": True}, "maxMatches"),
        ("grep", {"pattern": "x", "ignoreCase": "maybe"}, "ignoreCase"),
        ("grep", {"pattern": "x", "ignoreCase": 1}, "ignoreCase"),
        ("grep", {"pattern": "x", "saveAll": "yes"}, "saveAll"),
        ("grep", {"pattern": ""}, "pattern"),
        ("jq", {"filter": "   "}, "filter"),
        ("grep", {"pattern": 5}, "pattern"),
        ("jq", {"filter": ""}, "filter"),
        ("jq", {"filter": ".", "lines": "perhaps"}, "lines"),
        ("sql", {"query": ""}, "query"),
        ("sql", {"query": "   "}, "query"),
        ("sql", {"query": "select 1", "maxRows": 2001}, "maxRows"),
        ("sql", {"query": "select 1", "maxRows": 0}, "maxRows"),
        ("sql", {"query": "select 1", "format": "xml"}, "format"),
    ],
)
def test_parameter_validation_rejects_instead_of_clamping(tmp_path, task, inputs, needle):
    assert needle in run_fails(tmp_path, task, inputs, b"x\n")


def test_grep_pattern_of_one_space_is_a_valid_regex(tmp_path):
    data = b"no-space\nhas a space\nnone\n"
    result = run_ok(tmp_path, "grep", {"pattern": " "}, data)["result"]
    assert [m["text"] for m in result["matches"]] == ["has a space"]


def test_parameters_accept_strings_agents_send(tmp_path):
    data = b"hit\n" * 10
    inputs = {"pattern": "HIT", "ignoreCase": "TRUE", "context": "1", "maxMatches": "3"}
    result = run_ok(tmp_path, "grep", inputs, data)["result"]
    assert len(result["matches"]) == 3 and result["totalMatches"] == 10
    result = run_ok(
        tmp_path / "sql", "sql", {"query": "select * from t", "maxRows": "2"}, csv_rows(5)
    )["result"]
    assert result["rowCount"] == 2


def test_parameter_bounds_are_inclusive(tmp_path):
    data = b"hit\n" * 600
    assert (
        len(
            run_ok(tmp_path, "grep", {"pattern": "hit", "maxMatches": 500}, data)["result"][
                "matches"
            ]
        )
        == 500
    )
    assert run_ok(tmp_path / "c", "grep", {"pattern": "hit", "context": 5}, data)["result"]
    assert run_ok(tmp_path / "s", "sql", {"query": "select 1", "maxRows": 2000}, csv_rows(1))[
        "result"
    ]
