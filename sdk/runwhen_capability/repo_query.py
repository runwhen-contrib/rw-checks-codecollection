"""The rw-worktree capability's `query` task (RW-1416 cost P2, CAP-3; I3):
a batch of grep/read/ls/defs/refs ops against one checked-out tree, so a
review agent answers several questions in one round trip instead of one
task request per read.

`run_query` is pure -- a tree path and the ops in, a QueryResult out -- and
built entirely on repo_fs's building blocks, so every path still goes
through pathsafe.safe_path and every cap repo_fs already enforces still
applies per op.

Failure is per op wherever the fault is the op's: a malformed op is
INVALID_OP, and a repo_fs input error (escape, not found, binary, bad
regex, ...) carries repo_fs.error_code's code. Neither fails the others.
Two things do fail the whole task: a malformed `ops` input itself, and
TreeNotMaterializedError -- an evicted tree is not an op's fault, and
host.py must see it to flag the envelope not_materialized, which is what
makes papi re-materialise and retry once.

Response budget: the whole output is held under QUERY_BUDGET, measured as
serialised JSON rather than content bytes, so per-op, per-match and
per-range structure and string escaping all count. Room for a
RESPONSE_BUDGET entry is reserved up front for every op, so the ops past
the cap can always still be answered with one. The op that straddles the
cap keeps the leading matches/entries/whole lines that fit (and says
`truncated`); every op after it is RESPONSE_BUDGET.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .models import (
    GrepResult,
    LsResult,
    QueryError,
    QueryOpResult,
    QueryResult,
    ReadRange,
    ReadRangesResult,
)
from .repo_fs import (
    HARD_GREP_MAX_MATCHES,
    READ_BUDGET,
    _check_tree_materialized,
    error_code,
    find_around,
    grep_tree,
    ls_tree,
    read_ranges,
)
from .symbols import definition_pattern, is_definition_line, reference_pattern

# The same 256 KiB response cap, less the same 1 KiB of headroom, that
# read already works to (repo_fs.READ_BUDGET) -- here the headroom is for
# the result envelope serve.py wraps this task's output in.
QUERY_BUDGET = READ_BUDGET

# I2's limits, re-checked here so a caller other than papi gets the same
# contract rather than whatever an unbounded op would do.
MAX_QUERY_OPS = 60
MAX_GREP_CONTEXT = 20
MAX_AROUND_CONTEXT = 200
DEFAULT_AROUND_CONTEXT = 20
AROUND_MAX_WINDOWS = 5
DEFS_CONTEXT = 2

# An error message echoes caller input (a path, a pattern); keep one
# pathological input from eating the budget of every op after it.
MAX_ERROR_MESSAGE_LEN = 500

INVALID_OP = "INVALID_OP"
RESPONSE_BUDGET = "RESPONSE_BUDGET"
_RESPONSE_BUDGET_MESSAGE = (
    "response budget spent by earlier ops in this query; send this op again in a new query"
)

OpResult = GrepResult | ReadRangesResult | LsResult


class _InvalidOp(ValueError):
    """An op that is missing a required field or has a malformed one."""


# --- op validation -----------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _field(op: dict, key: str, check: Callable[[Any], bool], expected: str, required=False):
    """`op[key]`, or None when absent -- a null reads as absent, since a
    caller serialising a model may send every optional field."""
    value = op.get(key)
    if value is None:
        if required:
            raise _InvalidOp(f"missing required field {key!r}")
        return None
    if not check(value):
        raise _InvalidOp(f"{key!r} must be {expected}")
    return value


def _int_field(op: dict, key: str, low: int, high: int | None = None) -> int | None:
    def check(v):
        return _is_int(v) and v >= low and (high is None or v <= high)

    expected = f"an integer >= {low}" if high is None else f"an integer from {low} to {high}"
    return _field(op, key, check, expected)


def _globs(op: dict) -> list[str] | None:
    def check(v):
        return isinstance(v, list) and all(isinstance(g, str) for g in v)

    return _field(op, "globs", check, "an array of strings")


def _symbol(op: dict) -> str:
    return _field(
        op, "symbol", lambda v: isinstance(v, str) and v != "", "a non-empty string", True
    )


def _ranges(op: dict) -> list[tuple[int, int]]:
    def check(v):
        return (
            isinstance(v, list)
            and len(v) > 0
            and all(
                isinstance(r, list)
                and len(r) == 2
                and all(_is_int(n) for n in r)
                and 1 <= r[0] <= r[1]
                for r in v
            )
        )

    ranges = _field(op, "ranges", check, "a non-empty array of [start, end] line pairs")
    return [(start, end) for start, end in ranges]


# --- ops ---------------------------------------------------------------------


def _grep(tree: Path, op: dict) -> GrepResult:
    pattern = _field(op, "pattern", lambda v: isinstance(v, str), "a string", required=True)
    globs = _globs(op)
    context = _int_field(op, "context", 0, MAX_GREP_CONTEXT) or 0
    ignore_case = _field(op, "ignoreCase", lambda v: isinstance(v, bool), "a boolean") or False
    max_matches = _int_field(op, "maxMatches", 1, HARD_GREP_MAX_MATCHES)
    return grep_tree(
        tree,
        pattern,
        globs=globs,
        max_matches=max_matches,
        ignore_case=ignore_case,
        context=context,
    )


def _read(tree: Path, op: dict) -> ReadRangesResult:
    path = _field(op, "path", lambda v: isinstance(v, str), "a string", required=True)
    if (op.get("ranges") is None) == (op.get("around") is None):
        raise _InvalidOp("read takes exactly one of 'ranges' or 'around'")
    if op.get("ranges") is not None:
        return read_ranges(tree, path, _ranges(op))

    around = _field(op, "around", lambda v: isinstance(v, str), "a string")
    context = _int_field(op, "context", 0, MAX_AROUND_CONTEXT)
    context = DEFAULT_AROUND_CONTEXT if context is None else context
    windows = find_around(tree, path, around, context, max_windows=AROUND_MAX_WINDOWS)
    return read_ranges(tree, path, windows)


def _ls(tree: Path, op: dict) -> LsResult:
    path = _field(op, "path", lambda v: isinstance(v, str), "a string")
    depth = _int_field(op, "depth", 1)
    return ls_tree(tree, path=path, depth=depth)


def _defs(tree: Path, op: dict) -> GrepResult:
    symbol = _symbol(op)
    globs = _globs(op)
    return grep_tree(tree, definition_pattern(symbol), globs=globs, context=DEFS_CONTEXT)


def _refs(tree: Path, op: dict) -> GrepResult:
    symbol = _symbol(op)
    globs = _globs(op)
    # `exclude` sees the full line, not the 400-byte match text, so a long
    # definition line can't slip into refs past the snippet cut.
    return grep_tree(
        tree,
        reference_pattern(symbol),
        globs=globs,
        exclude=lambda line: is_definition_line(line, symbol),
    )


_OPS: dict[str, Callable[[Path, dict], OpResult]] = {
    "grep": _grep,
    "read": _read,
    "ls": _ls,
    "defs": _defs,
    "refs": _refs,
}


def _op_name(op: Any) -> str | None:
    name = op.get("op") if isinstance(op, dict) else None
    return name if isinstance(name, str) and name in _OPS else None


def _error(index: int, op: str | None, code: str, message: str) -> QueryOpResult:
    return QueryOpResult(
        index=index,
        op=op,
        error=QueryError(code=code, message=message[:MAX_ERROR_MESSAGE_LEN]),
    )


def _run_op(tree: Path, index: int, op: Any) -> QueryOpResult:
    if not isinstance(op, dict):
        return _error(index, None, INVALID_OP, "op must be a JSON object")
    name = _op_name(op)
    if name is None:
        return _error(
            index, None, INVALID_OP, f"unknown op {op.get('op')!r}; expected one of {list(_OPS)}"
        )
    try:
        return QueryOpResult(index=index, op=name, result=_OPS[name](tree, op))
    except _InvalidOp as exc:
        return _error(index, name, INVALID_OP, str(exc))
    except Exception as exc:
        code = error_code(exc)
        if code is None:
            raise  # TreeNotMaterializedError, or a bug: fails the whole task
        return _error(index, name, code, str(exc))


# --- the response budget --------------------------------------------------------


def _size(value: Any) -> int:
    """Wire bytes of `value`: json.dumps' defaults (", " and ": "
    separators, non-ASCII escaped) are exactly what serve.py's
    requests.post(json=...) sends, and with everything ASCII-escaped the
    string length is the byte count."""
    return len(json.dumps(value))


def _entry_size(entry: QueryOpResult) -> int:
    return _size(entry.model_dump(mode="json"))


def _with_result(entry: QueryOpResult, result: OpResult) -> QueryOpResult:
    return entry.model_copy(update={"result": result})


def _trim_items(entry: QueryOpResult, field: str, available: int) -> OpResult | None:
    """The longest prefix of a grep result's `matches` or an ls result's
    `entries` that fits in `available`, or None if not even one does."""
    result = entry.result
    shell = _with_result(entry, result.model_copy(update={field: [], "truncated": True}))
    used = _entry_size(shell)
    kept = []
    for item in getattr(result, field):
        add = _size(item.model_dump(mode="json")) + (2 if kept else 0)  # 2: ", "
        if used + add > available:
            break
        kept.append(item)
        used += add
    if not kept:
        return None
    return result.model_copy(update={field: kept, "truncated": True})


def _clip_content(content: str, room: int) -> str | None:
    """The longest line-aligned prefix of `content` whose JSON string takes
    at most `room` bytes -- or, when not even the first line fits, that
    line clipped, as read_lines clips a single over-budget line."""
    low, high = 0, len(content)
    while low < high:
        mid = (low + high + 1) // 2
        if _size(content[:mid]) <= room:
            low = mid
        else:
            high = mid - 1
    if low == 0:
        return None
    prefix = content[:low]
    if low < len(content) and "\n" in prefix:
        prefix = prefix[: prefix.rfind("\n")]
    return prefix


def _trim_read(entry: QueryOpResult, available: int) -> ReadRangesResult | None:
    """The whole ranges that fit, plus the line-aligned head of the first
    range that doesn't."""
    result = entry.result
    shell = _with_result(entry, result.model_copy(update={"ranges": [], "truncated": True}))
    used = _entry_size(shell)
    kept: list[ReadRange] = []
    for rng in result.ranges:
        separator = 2 if kept else 0
        add = _size(rng.model_dump(mode="json")) + separator
        if used + add <= available:
            kept.append(rng)
            used += add
            continue
        # The shell keeps rng.end, which has at least as many digits as the
        # clipped end -- an upper bound. +2: its empty content's quotes,
        # which _size(content) counts again.
        empty = ReadRange(start=rng.start, end=rng.end, content="")
        room = available - used - separator - _size(empty.model_dump(mode="json")) + 2
        clipped = _clip_content(rng.content, room)
        if clipped is not None:
            end = rng.start + clipped.count("\n")
            kept.append(ReadRange(start=rng.start, end=end, content=clipped))
        break
    if not kept:
        return None
    return result.model_copy(update={"ranges": kept, "truncated": True})


def _fit(entry: QueryOpResult, available: int) -> tuple[QueryOpResult | None, int, bool]:
    """(entry or its trimmed form, its size, whether it was trimmed) --
    (None, 0, False) when nothing useful fits in `available`."""
    size = _entry_size(entry)
    if size <= available:
        return entry, size, False

    if isinstance(entry.result, ReadRangesResult):
        trimmed = _trim_read(entry, available)
    elif isinstance(entry.result, GrepResult):
        trimmed = _trim_items(entry, "matches", available)
    elif isinstance(entry.result, LsResult):
        trimmed = _trim_items(entry, "entries", available)
    else:
        trimmed = None  # an error entry too large to fit
    if trimmed is None:
        return None, 0, False

    fitted = _with_result(entry, trimmed)
    size = _entry_size(fitted)
    if size > available:  # never exceed the cap on an arithmetic slip
        return None, 0, False
    return fitted, size, True


# --- entry point -------------------------------------------------------------


def run_query(worktree: Path, ops: list) -> QueryResult:
    """Runs `ops` against `worktree` in order (see the module docstring).
    An op's `rev` is ignored: papi splits ops by rev and sends each rev's
    ops to the tree checked out at that sha."""
    if not isinstance(ops, list):
        raise ValueError(f"ops must be a JSON array, got {type(ops).__name__}")
    if len(ops) > MAX_QUERY_OPS:
        raise ValueError(f"too many ops: {len(ops)} (at most {MAX_QUERY_OPS})")

    tree = Path(worktree)
    # Up front, not left to the first op that touches disk: a batch of
    # malformed ops against an evicted tree must still read as a miss.
    _check_tree_materialized(tree)

    budget_errors = [
        _error(index, _op_name(op), RESPONSE_BUDGET, _RESPONSE_BUDGET_MESSAGE)
        for index, op in enumerate(ops)
    ]
    # Each op's held-back room: its RESPONSE_BUDGET entry plus the ", "
    # before it. Released as that op is answered.
    held = [_entry_size(e) + (2 if index else 0) for index, e in enumerate(budget_errors)]
    reserved = sum(held)
    used = _size(QueryResult().model_dump(mode="json"))  # {"results": [], "truncated": false}

    results: list[QueryOpResult] = []
    exhausted = False
    for index, op in enumerate(ops):
        reserved -= held[index]
        separator = 2 if index else 0
        entry: QueryOpResult | None = None
        size = 0
        if not exhausted:
            available = QUERY_BUDGET - used - reserved - separator
            entry, size, trimmed = _fit(_run_op(tree, index, op), available)
            exhausted = entry is None or trimmed
        if entry is None:
            entry = budget_errors[index]
            size = held[index] - separator
        results.append(entry)
        used += separator + size

    return QueryResult(results=results, truncated=exhausted)
