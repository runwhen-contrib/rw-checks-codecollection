"""slice: copy a range of lines of an artifact into a new artifact.

The input is streamed in fixed-size chunks and only the bytes of the requested lines
are written, so neither the input nor the slice is ever held in memory, and a
single enormous line costs no more than any other.
"""

from __future__ import annotations

from typing import Any

from .deadline import Deadline
from .procs import read_chunks

MAX_LINES = 10_000_000
# The artifact writer already holds about seven 1 MiB buffers while an upload keeps up with the
# reads, so this side reads in quarter-MiB pieces to keep the whole under 8 MiB.
READ_BYTES = 256 * 1024


def check_range(from_line: int, to_line: int) -> None:
    """The half-open 1-based line range [from_line, to_line) must be non-empty and at most
    MAX_LINES long."""
    if from_line < 1:
        raise ValueError(f"fromLine must be at least 1, got {from_line}")
    if to_line <= from_line:
        raise ValueError(f"toLine must be greater than fromLine ({from_line}), got {to_line}")
    if to_line - from_line > MAX_LINES:
        raise ValueError(
            f"toLine - fromLine must be at most {MAX_LINES} lines, got {to_line - from_line}"
        )


def _nth_newline(chunk: bytes, count: int, start: int = 0) -> int:
    """The index of the `count`-th newline at or after `start` (`count` >= 1, and there are
    at least that many)."""
    position = start - 1
    for _ in range(count):
        position = chunk.find(b"\n", position + 1)
    return position


def _copy_lines(
    chunk: bytes, newlines: int, line: int, from_line: int, to_line: int, out: Any
) -> bool:
    """Writes the part of `chunk` (which holds `newlines` newlines and starts in line number
    `line`) that lies in the range to `out`. Returns True once the end of the range is in this
    chunk."""
    if line + newlines < from_line:  # the whole chunk is before the range
        return False
    skip = max(0, from_line - line)  # newlines to pass before the range starts
    start = _nth_newline(chunk, skip) + 1 if skip else 0
    need = to_line - line - skip  # newlines from `start` to the end of the range
    finished = newlines - skip >= need
    end = _nth_newline(chunk, need, start) + 1 if finished else len(chunk)
    if end > start:
        out.write(memoryview(chunk)[start:end])
    return finished


def run_slice(ctx: Any, *, from_line: int, to_line: int) -> Any:
    """Writes lines `from_line` .. `to_line - 1` of the `source` input, newlines included, to the
    `slice` artifact and returns its ArtifactRef. A range past the end of the input gives an
    empty artifact; an unterminated last line is written as it is."""
    check_range(from_line, to_line)
    line = 1  # the number of the line the next chunk starts in
    watch = Deadline(ctx, "slice a shorter range, or one nearer the start")
    with ctx.artifacts.input("source") as source, ctx.artifacts.open("slice", "text/plain") as out:
        for chunk in read_chunks(source, READ_BYTES):
            watch.check()
            newlines = chunk.count(b"\n")
            if _copy_lines(chunk, newlines, line, from_line, to_line, out):
                break
            line += newlines
    return out.ref
