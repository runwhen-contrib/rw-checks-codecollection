"""grep: search an artifact with ripgrep and return a bounded answer.

The artifact is streamed through ripgrep's stdin and never held in memory. Two
things are bounded here because ripgrep itself is not:

- ripgrep buffers a whole line, and its JSON event for a match carries the whole
  line, so an input with one multi-gigabyte line would exhaust the pod. The
  feeder therefore cuts every input line longer than MAX_LINE_BYTES to its first
  MAX_LINE_BYTES (the rest of that line is discarded, its newline kept) and
  counts how many it cut.
- The answer. At most `maxMatches` matching lines are kept, each text is capped,
  and the kept matches stop being added once their serialized size reaches
  RESULT_BUDGET_BYTES, so the result always fits the capability's result limit.
  Every matching line is still counted in `totalMatches`.
"""

from __future__ import annotations

import base64
import contextlib
import json
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from .deadline import Deadline
from .models import GrepMatch, GrepResult
from .procs import (
    Feeder,
    LineTooLong,
    StderrTail,
    bounded_lines,
    kill,
    read_chunks,
    shutdown,
    spawn,
)

MAX_LINE_BYTES = 64 * 1024
EVENT_MAX_BYTES = 8 * 1024 * 1024
MAX_TEXT_CHARS = 1024
RESULT_BUDGET_BYTES = 512 * 1024

_MATCH_PREFIX = b'{"type":"match"'
_EVENT_PREFIX = b'{"type":"'


@dataclass
class FeedStats:
    """What the feeder did to the input: bytes handed to ripgrep, lines it had to cut."""

    bytes_scanned: int = 0
    long_lines: int = 0


# --- feeding ripgrep -----------------------------------------------------------------------


def cut_long_lines(chunks: Iterable[bytes], limit: int, stats: FeedStats) -> Iterator[bytes]:
    """Passes `chunks` through with every line cut to its first `limit` bytes.

    The rest of a long line is dropped and its newline kept, so line numbers stay true. A line
    is long when it has more than `limit` bytes before its newline (or before the end of the
    input). `stats` counts each cut line once, however many chunks it spans, and the bytes let
    through. Memory is one chunk and the pieces cut from it.

    Most chunks have no long line, and for those the chunk is passed on untouched after a
    cheap check: a line longer than `limit` contains a whole aligned block of `limit // 2`
    bytes with no newline in it, so a chunk where every such block has a newline (and whose
    first line, joined to the unfinished line before it, is short enough) has no line to cut.
    """
    block = max(1, limit // 2)
    unfinished = 0  # bytes of the line in progress that were let through
    dropping = False  # inside a long line, past the cut
    for chunk in chunks:
        if not dropping and _all_lines_short(chunk, unfinished, limit, block):
            last = chunk.rfind(b"\n")
            unfinished = unfinished + len(chunk) if last < 0 else len(chunk) - last - 1
            stats.bytes_scanned += len(chunk)
            yield chunk
            continue
        parts, unfinished, dropping = _cut_chunk(chunk, unfinished, dropping, limit, stats)
        kept = b"".join(parts)
        if kept:
            stats.bytes_scanned += len(kept)
            yield kept


def _all_lines_short(chunk: bytes, unfinished: int, limit: int, block: int) -> bool:
    """True when no line of `chunk` can exceed `limit` (False means "look closer")."""
    first = chunk.find(b"\n")
    if unfinished + (len(chunk) if first < 0 else first) > limit:
        return False
    return all(
        chunk.find(b"\n", start, start + block) >= 0
        for start in range(0, len(chunk) - block + 1, block)
    )


def _cut_chunk(
    chunk: bytes, unfinished: int, dropping: bool, limit: int, stats: FeedStats
) -> tuple[list[bytes], int, bool]:
    """Cuts the long lines out of one chunk; returns the pieces kept and the new state."""
    parts: list[bytes] = []
    size = len(chunk)
    pos = 0  # start of the line segment being looked at
    keep_from = 0  # start of the bytes not yet kept or dropped
    while pos < size:
        newline = chunk.find(b"\n", pos)
        end = size if newline < 0 else newline
        if dropping:
            if pos > keep_from:
                parts.append(chunk[keep_from:pos])
            keep_from = end
        elif end - pos > limit - unfinished:
            cut_at = pos + limit - unfinished
            if cut_at > keep_from:
                parts.append(chunk[keep_from:cut_at])
            keep_from = end
            stats.long_lines += 1
            unfinished = limit
            dropping = True
        else:
            unfinished += end - pos
        if newline < 0:
            pos = size
        else:
            unfinished = 0
            dropping = False
            pos = newline + 1
    if keep_from < size:
        parts.append(chunk[keep_from:size])
    return parts, unfinished, dropping


# --- reading ripgrep's events --------------------------------------------------------------


def _strip_eol(text: str) -> str:
    if text.endswith("\n"):
        text = text[:-1]
        if text.endswith("\r"):
            text = text[:-1]
    return text


def _strip_eol_bytes(data: bytes) -> bytes:
    if data.endswith(b"\n"):
        data = data[:-1]
        if data.endswith(b"\r"):
            data = data[:-1]
    return data


def _line_bytes(lines: dict) -> bytes:
    """The raw bytes of a line from ripgrep's JSON: text, or base64 for what is not UTF-8."""
    if "text" in lines:
        return lines["text"].encode("utf-8", errors="surrogateescape")
    return base64.b64decode(lines["bytes"])


def _line_text(lines: dict) -> tuple[str, bool]:
    """A line as result text, without its line ending, capped at MAX_TEXT_CHARS."""
    if "text" in lines:
        text = lines["text"]
    else:
        text = base64.b64decode(lines["bytes"]).decode("utf-8", errors="replace")
    text = _strip_eol(text)
    if len(text) > MAX_TEXT_CHARS:
        return text[:MAX_TEXT_CHARS], True
    return text, False


class _Collector:
    """Turns ripgrep's events into the kept matches, the total, and the saveAll artifact.

    A match is held back until the next match (or the end) so the context lines that follow
    it can be attached before its size is measured against the budget.
    """

    def __init__(self, context: int, max_matches: int, writer: Any | None) -> None:
        self._context = context
        self._max_matches = max_matches
        self._writer = writer
        self.kept: list[dict[str, Any]] = []
        self.total = 0
        self._used = 0  # serialized size of the kept matches
        self._full = False  # the budget is spent: later matches are only counted
        self._pending: dict[str, Any] | None = None
        self._recent: deque[dict[str, Any]] = deque(maxlen=context)  # context lines, for `before`

    def feed(self, raw: bytes) -> None:
        if self._writer is None and self._pending is None and not self._wants_more():
            # Nothing more will be kept: matches only need counting, and cheaply.
            if raw.startswith(_MATCH_PREFIX):
                self.total += 1
                return
            if raw.startswith(_EVENT_PREFIX):
                return
        event = json.loads(raw)
        kind = event.get("type")
        if kind == "match":
            self._match(event["data"])
        elif kind == "context":
            self._context_line(event["data"])

    def finish(self) -> None:
        self._commit()

    def _wants_more(self) -> bool:
        return not self._full and len(self.kept) < self._max_matches

    def _match(self, data: dict[str, Any]) -> None:
        self._commit()
        self.total += 1
        number = data["line_number"]
        if self._writer is not None:
            line = _strip_eol_bytes(_line_bytes(data["lines"]))
            self._writer.write(b"%d:%s\n" % (number, line))
        if not self._wants_more():
            return
        text, truncated = _line_text(data["lines"])
        self._pending = {
            "lineNumber": number,
            "text": text,
            "textTruncated": truncated,
            "before": [
                line for line in self._recent if number - line["lineNumber"] <= self._context
            ],
            "after": [],
        }

    def _context_line(self, data: dict[str, Any]) -> None:
        number = data["line_number"]
        text, truncated = _line_text(data["lines"])
        line = {"lineNumber": number, "text": text, "textTruncated": truncated}
        pending = self._pending
        if pending is not None and 0 < number - pending["lineNumber"] <= self._context:
            pending["after"].append(line)
        self._recent.append(line)

    def _commit(self) -> None:
        pending, self._pending = self._pending, None
        if pending is None:
            return
        size = len(json.dumps(pending)) + 2  # as the platform serializes it, plus the separator
        if self._used + size > RESULT_BUDGET_BYTES:
            self._full = True
            return
        self.kept.append(pending)
        self._used += size


# --- the task ------------------------------------------------------------------------------


def run_grep(
    ctx: Any,
    *,
    pattern: str,
    ignore_case: bool,
    context: int,
    max_matches: int,
    save_all: bool,
) -> tuple[GrepResult, Any]:
    """Searches the `source` input; returns the result and, with `save_all`, the ArtifactRef of
    the `matches` artifact (else None)."""
    argv = ["rg", "--no-config", "--json", "--text", "-e", pattern]
    if ignore_case:
        argv.append("-i")
    if context:
        argv += ["-C", str(context)]
    argv.append("-")

    stats = FeedStats()
    with contextlib.ExitStack() as stack:
        source = stack.enter_context(ctx.artifacts.input("source"))
        writer = (
            stack.enter_context(ctx.artifacts.open("matches", "text/plain")) if save_all else None
        )
        collector = _Collector(context, max_matches, writer)
        watch = Deadline(ctx, "search a smaller part of the artifact (slice it first)")
        proc = spawn(argv)
        stderr = feeder = None
        try:
            stderr = StderrTail(proc.stderr)
            feeder = Feeder(
                cut_long_lines(read_chunks(source), MAX_LINE_BYTES, stats),
                proc.stdin,
                on_error=lambda _exc: kill(proc),
            )
            feeder.start()
            watch.arm(lambda: kill(proc))
            try:
                for raw in bounded_lines(proc.stdout, EVENT_MAX_BYTES):
                    if not raw.endswith(b"\n"):
                        break  # ripgrep was cut off in the middle of an event: not parseable
                    collector.feed(raw)
            except LineTooLong:
                kill(proc)
                raise RuntimeError(
                    f"ripgrep produced a result event larger than {EVENT_MAX_BYTES} bytes; "
                    "narrow the pattern"
                ) from None
            returncode = proc.wait()
            if watch.expired and returncode not in (0, 1):
                raise watch.error()  # killed at the deadline
            feeder.join()
            if feeder.error is not None:
                raise feeder.error
            if returncode not in (0, 1):
                raise RuntimeError(f"ripgrep failed (exit status {returncode}): {stderr.text()}")
            collector.finish()
        finally:
            watch.cancel()
            shutdown(proc, feeder, stderr)
    ref = writer.ref if writer is not None else None

    total, kept = collector.total, collector.kept
    parts = []
    if len(kept) < total:
        advice = (
            "every matching line is in the 'matches' artifact"
            if save_all
            else "narrow the pattern, or set saveAll=true to write every matching line to the "
            "'matches' artifact"
        )
        parts.append(f"showing the first {len(kept)} of {total} matching lines; {advice}")
    if stats.long_lines:
        parts.append(
            f"{stats.long_lines} line(s) over 64 KiB were searched only in their first 64 KiB"
        )
    hint = ". ".join(parts) or None
    if hint and stats.long_lines:
        hint += "."
    result = GrepResult(
        matches=[GrepMatch(**match) for match in kept],
        totalMatches=total,
        truncated=len(kept) < total,
        hint=hint,
        longLines=stats.long_lines,
        bytesScanned=stats.bytes_scanned,
    )
    return result, ref
