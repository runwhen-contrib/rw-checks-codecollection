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
import random
import shutil
import sys
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

from artifact_tools import grep as grep_mod  # noqa: E402
from artifact_tools import jq as jq_mod  # noqa: E402
from artifact_tools import slice as slice_mod  # noqa: E402

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


def invoke(scope: Path, task: str, inputs: dict, *, outputs=(), input_artifacts=()):
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
    assert "3221225472 bytes" in message and "limit 512 MiB" in message


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


@pytest.mark.parametrize(
    "query",
    [
        "SET enable_external_access=true",
        "SET lock_configuration=false",
        "SET allowed_paths=['/etc/passwd']",
        "COPY t TO '{tmp}/exfil.csv'",
        "COPY (select 1) TO '{tmp}/exfil2.csv'",
        "EXPORT DATABASE '{tmp}/exfil_db'",
        "ATTACH '{tmp}/other.db' AS other",
        "INSTALL httpfs",
        "LOAD httpfs",
        "select * from read_text('/etc/passwd')",
        "select * from read_blob('/etc/hosts')",
        "select * from glob('/etc/*')",
        "select * from '/etc/passwd'",
        "select * from read_csv('/etc/passwd')",
        "select * from read_json('/etc/passwd')",
        "select * from read_parquet('/etc/passwd')",
        "select * from sniff_csv('/etc/passwd')",
        "select 1; select 2",
        "select 1; copy t to '{tmp}/exfil3.csv'",
        "CREATE TABLE x AS SELECT 1",
        "CREATE VIEW v AS SELECT 1",
        "INSERT INTO t VALUES (1, 'a', 1.0)",
        "UPDATE t SET id = 1",
        "DROP VIEW t",
        "DELETE FROM t",
        "CALL pragma_version()",
        "EXPLAIN SELECT 1",
        "CREATE SECRET s (TYPE s3)",
    ],
)
def test_sql_escapes_fail(tmp_path, query):
    run_fails(tmp_path, "sql", {"query": query.format(tmp=tmp_path)}, csv_rows(3))
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
        "12345678901234567890123::hugeint as huge, ['2024-02-03 04:05:06+00'::timestamptz] as tzs"
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
    assert "2024-02-03 04:05:06" in row["tzs"]
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
    assert row[0] == "x" * 16384 + "…"
    assert row[1].endswith("…") and len(row[1]) == len(base64.b64encode(b"y" * 16384)) + 1
    assert row[2][0] == "z" * 16384 + "…"


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
        "current_setting('python_enable_replacements') as replacements"
    )
    result = run_ok(tmp_path, "sql", {"query": query}, csv_rows(1))["result"]
    row = dict(zip([c["name"] for c in result["columns"]], result["rows"][0], strict=True))
    assert row["mem"].startswith("953.6 MiB")
    assert row["threads"] == 2
    assert row["external"] is False and row["locked"] is True
    assert row["spill"].startswith("4.0 GiB")
    assert row["autoload"] is False and row["replacements"] is False


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
