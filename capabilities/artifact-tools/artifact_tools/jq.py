"""jq: run a jq filter over an artifact and return a bounded answer.

jq reads its input incrementally, so an input with one JSON value per line (JSONL)
is processed in constant memory however large it is. A single big document is
different: jq parses it whole, so a document over MAX_DOCUMENT_BYTES is refused
before it can take the pod down (and, on Linux, the jq process also gets an
address-space limit as a backstop). The answer is capped at MAX_OUTPUT_BYTES.
"""

from __future__ import annotations

import itertools
import json
import re
import resource
import subprocess
from collections.abc import Iterator
from typing import Any

from .deadline import Deadline
from .errors import ToolError
from .models import JqResult
from .procs import (
    Feeder,
    StderrTail,
    kill,
    read_chunks,
    shutdown,
    spawn,
)

# jq holds about six times a pretty-printed document, and its address space is capped at
# ADDRESS_SPACE_BYTES (1 GiB), so a larger document would die inside jq with a worse error.
MAX_DOCUMENT_BYTES = 128 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
SNIFF_BYTES = 1 << 20
ADDRESS_SPACE_BYTES = 1 << 30

_MIB = 1 << 20


def _looks_like_jsonl(first_line: bytes) -> bool:
    """True when the first line ended within the sniff window and is one JSON value."""
    if not first_line.endswith(b"\n") and len(first_line) >= SNIFF_BYTES:
        return False
    try:
        json.loads(first_line)
    except ValueError:
        return False
    return True


def _declared_size(ctx: Any) -> int | None:
    for declared in getattr(ctx, "input_artifacts", []) or []:
        if declared.input == "source":
            return declared.sizeBytes or None
    return None


def _too_large(size: int | None, *, out_of_memory: bool = False) -> ToolError:
    limit = (
        f"{MAX_DOCUMENT_BYTES // _MIB} MiB"
        if MAX_DOCUMENT_BYTES % _MIB == 0
        else f"{MAX_DOCUMENT_BYTES} bytes"
    )
    if out_of_memory:
        how_big = "made jq run out of memory"
    elif size is not None:
        how_big = f"is {size} bytes"
    else:
        how_big = f"is larger than {limit}"
    return ToolError(
        "E_TOO_LARGE_FOR_JQ",
        f"the input {how_big}, and jq loads a whole non-JSONL document into memory "
        f"(limit {limit}). For an array of records, use sql with format=json. For one big "
        "object, use grep or slice (DuckDB's JSON reader takes a single object of at most "
        "16 MiB). If every line is one JSON value, pass lines=true.",
    )


# What jq says on stderr, before it aborts, when an allocation fails (jq 1.6 to 1.8).
_OUT_OF_MEMORY = ("cannot allocate memory", "out of memory")

_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|#[^\n]*|[A-Za-z_][A-Za-z0-9_]*|\S', re.DOTALL)


def check_program(program: str) -> None:
    """Refuses a filter that imports or includes a module, which would read files from a
    directory the caller names. Strings, comments, object keys (`{import: 1}`) and field
    names (`.import`) are not module directives: a directive is `import` or `include` followed
    by a string. Tokenised just enough to tell those apart; anything unclear is refused."""
    tokens = [t for t in _TOKEN.findall(program) if not t.startswith("#")]
    for index, token in enumerate(tokens[:-1]):
        if token in ("import", "include") and tokens[index + 1].startswith('"'):
            if index == 0 or tokens[index - 1] not in (".", "$"):
                raise ValueError("jq filters may not import or include modules")


def _pieces(head: bytes, source: Any, *, lines: bool) -> Iterator[bytes]:
    """The sniffed bytes, then the rest of the input; stops with an error as soon as a
    non-JSONL document passes the size limit."""
    seen = 0
    for piece in itertools.chain([head] if head else [], read_chunks(source)):
        seen += len(piece)
        if not lines and seen > MAX_DOCUMENT_BYTES:
            raise _too_large(None)
        yield piece


def _limit_address_space(ctx: Any, proc: subprocess.Popen) -> None:
    """An out-of-memory backstop for jq (Linux only); the document limit is the real guard."""
    if not hasattr(resource, "prlimit"):
        return
    try:
        resource.prlimit(proc.pid, resource.RLIMIT_AS, (ADDRESS_SPACE_BYTES, ADDRESS_SPACE_BYTES))
    except (OSError, ValueError) as exc:
        ctx.log.warning("could not limit jq's address space: %s", exc)


def _cut_output(data: bytes) -> bytes:
    """`data` (more than MAX_OUTPUT_BYTES of it) cut to fit: at the last newline within the
    limit, or failing that at a UTF-8 character boundary."""
    window = data[:MAX_OUTPUT_BYTES]
    newline = window.rfind(b"\n")
    if newline > 0:
        return window[:newline]
    for end in range(len(window), max(len(window) - 4, 0), -1):
        try:
            window[:end].decode("utf-8")
        except UnicodeDecodeError:
            continue
        return window[:end]
    return window


def run_jq(ctx: Any, *, program: str, lines: bool | None) -> JqResult:
    """Runs the jq `program` over the `source` input. `lines` None means "decide from the first
    line"."""
    check_program(program)
    with ctx.artifacts.input("source") as source:
        head = b""
        if lines is None:
            head = source.readline(SNIFF_BYTES)
            lines = _looks_like_jsonl(head)
        declared = _declared_size(ctx)
        if not lines and declared is not None and declared > MAX_DOCUMENT_BYTES:
            raise _too_large(declared)

        watch = Deadline(ctx, "narrow the filter (first, limit) or use a smaller input")
        proc = spawn(["jq", "-c", "--", program])
        stderr = feeder = None
        try:
            _limit_address_space(ctx, proc)
            stderr = StderrTail(proc.stderr)
            feeder = Feeder(
                _pieces(head, source, lines=lines), proc.stdin, on_error=lambda _exc: kill(proc)
            )
            feeder.start()
            watch.arm(lambda: kill(proc))
            data = proc.stdout.read(MAX_OUTPUT_BYTES + 1)
            truncated = len(data) > MAX_OUTPUT_BYTES
            if truncated:
                kill(proc)
            returncode = proc.wait()
            if watch.expired and returncode != 0 and not truncated:
                raise watch.error()  # killed at the deadline
            if not truncated:
                feeder.join()
            if feeder.error is not None:
                raise feeder.error
            if returncode != 0 and not truncated:
                tail = stderr.text()
                if any(message in tail.lower() for message in _OUT_OF_MEMORY):
                    raise _too_large(_declared_size(ctx), out_of_memory=True)
                raise RuntimeError(f"jq exited with status {returncode}: {tail}")
        finally:
            watch.cancel()
            shutdown(proc, feeder, stderr)

    if truncated:
        data = _cut_output(data)
    output = data.decode("utf-8", errors="replace")
    if output.endswith("\n"):
        output = output[:-1]
    return JqResult(
        output=output,
        outputLines=output.count("\n") + 1 if output else 0,
        truncated=truncated,
        hint=(
            "output cut at 64 KiB; narrow the filter (select fewer fields, or use first/limit)"
            if truncated
            else None
        ),
        lines=lines,
    )
