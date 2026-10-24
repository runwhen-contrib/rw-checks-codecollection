"""sql: run one SELECT over an artifact, as the table `t`, with DuckDB.

The query comes from a caller, so the DuckDB session is locked down before it
runs: the artifact's file is the only file it may read, nothing can be written,
attached, installed or loaded, and the configuration cannot be changed back. The
session is also bounded (memory, threads, spill size), and so is the answer (row
count, bytes of rows, size of one cell).

A cell is bounded where it is produced, not after: DuckDB hands a result to Python
as full objects, so a text cell is cut by `left()` in the query's projection, a blob
by `array_slice`, and a list, struct or map is turned into its JSON text and cut the
same way. The columns that get cut share one row of ROW_MAX_CHARS characters, so a
row's width is bounded too however many columns there are. The result is streamed:
rows are fetched in batches from the running query (never materialised whole), sized
from the row width so one batch stays near FETCH_BYTES, and the query is stopped as
soon as the result is full.

DuckDB 1.5.6 lockdown, as found by trying it: `SET allowed_paths=['<the file>']`,
then `SET enable_external_access=false`, then `SET lock_configuration=true`, in
that order. The view over the file keeps working, every other path (reads,
`COPY ... TO`, `ATTACH`, `INSTALL`/`LOAD`) is refused, and the settings cannot be
set again. Spilling to the temp directory still works with external access off,
so the temp directory needs no allowance of its own.
"""

from __future__ import annotations

import base64
import datetime
import decimal
import json
import math
import shutil
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb

from .deadline import Deadline
from .errors import ToolError
from .models import SqlColumn, SqlResult

CELL_MAX_CHARS = 16 * 1024
CELL_MAX_BYTES = 16 * 1024
# The cut columns of a row share this many characters (so each gets at most CELL_MAX_CHARS, and
# at least MIN_CELL_CHARS however many there are). This is what bounds the memory of a request
# over wide rows, because DuckDB holds the cut rows it has produced ahead of the reader: peak RSS
# for 2000 rows of 12 columns of 4-byte characters was 840 MiB (1331 MiB on Linux) at 64 Ki, 560
# at 32 Ki and 400 at 16 Ki, with two scan threads racing (the higher figure is the unlucky run).
ROW_MAX_CHARS = 16 * 1024
MIN_CELL_CHARS = 16
ROW_BUDGET_BYTES = 4 * 1024 * 1024
FETCH_BYTES = 4 * 1024 * 1024
MAX_FETCH_ROWS = 256
SNIFF_BYTES = 4096
MAX_ROWS_LIMIT = 2000  # the manifest's cap on the maxRows input

# The work directory holds the spooled input, whatever else a request leaves there, and the
# spill. This is the manifest's `execution.workSizeLimit`; keep the two in step.
WORK_SIZE_BYTES = 8 * 1024**3
_WORK_RESERVE_BYTES = 1024**3
_SPILL_MAX_BYTES = 4 * 1024**3
_SPILL_MIN_BYTES = 256 * 1024**2

_UTF8_BOM = b"\xef\xbb\xbf"

# DuckDB sizes the buffer between a running query and the reader by the vectors, not the strings
# in them, so at its default (about 1 MiB) the scan runs thousands of wide rows ahead of the
# reader and everything it has produced sits in memory. The buffer then holds about one chunk.
_STREAMING_BUFFER = "8KiB"

# Python holds up to 4 bytes per character of a str; a batch is sized for text of that kind.
_WORST_BYTES_PER_CHAR = 4

# Column types that come back small and are passed through as they are.
_PASS_THROUGH = frozenset(
    "boolean tinyint smallint integer bigint utinyint usmallint uinteger ubigint hugeint uhugeint "
    "float double decimal date time timestamp interval uuid".split()
)
_NESTED = frozenset({"list", "array", "struct", "map", "union"})


def _sql_literal(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _sniff_format(path: Path) -> str:
    """csv, json or parquet from the first bytes of the file."""
    with path.open("rb") as fh:
        head = fh.read(SNIFF_BYTES)
    if head.startswith(b"PAR1"):
        return "parquet"
    stripped = head.removeprefix(_UTF8_BOM).lstrip(b" \t\r\n\f\v")
    if stripped[:1] in (b"{", b"["):
        return "json"
    return "csv"


def _reader(fmt: str, path: Path) -> tuple[str, str]:
    """The reader expression for the artifact, and the name of the reader used."""
    if fmt == "auto":
        fmt = _sniff_format(path)
    quoted = _sql_literal(str(path))
    expression = {
        "csv": f"read_csv_auto({quoted})",
        "json": f"read_json_auto({quoted})",
        "jsonl": f"read_json_auto({quoted}, format='newline_delimited')",
        "parquet": f"read_parquet({quoted})",
    }[fmt]
    return expression, fmt


def _select_statement(con: duckdb.DuckDBPyConnection, query: str) -> str:
    """The text of `query`, which must be exactly one SELECT (a WITH or a FROM-first query
    counts) and nothing else."""
    statements = con.extract_statements(query)
    if len(statements) != 1 or statements[0].type != duckdb.StatementType.SELECT:
        raise ValueError("query must be a single SELECT statement")
    return statements[0].query


def _max_temp_bytes(input_bytes: int) -> int:
    """How much DuckDB may spill: what is left of the work directory after the spooled input and
    a GiB of other files, but never more than 4 GiB nor less than 256 MiB."""
    room = WORK_SIZE_BYTES - input_bytes - _WORK_RESERVE_BYTES
    return max(_SPILL_MIN_BYTES, min(_SPILL_MAX_BYTES, room))


def _configure(con: duckdb.DuckDBPyConnection, temp_dir: Path, max_temp_bytes: int) -> None:
    for setting in (
        # Below the pod's share on purpose: two requests can run in one pod (2Gi) beside Python,
        # and DuckDB spills to its temp directory rather than pass this limit.
        "memory_limit='640MB'",
        "threads=2",
        f"temp_directory={_sql_literal(str(temp_dir))}",
        f"max_temp_directory_size='{max_temp_bytes}B'",
        f"streaming_buffer_size='{_STREAMING_BUFFER}'",
        "autoinstall_known_extensions=false",
        "autoload_known_extensions=false",
        "allow_community_extensions=false",
        "allow_persistent_secrets=false",
        # A query must not reach Python variables (this module's own, say) by name.
        "python_enable_replacements=false",
        # Casts to text of timestamps with a time zone read the same on every host.
        "TimeZone='UTC'",
    ):
        con.execute(f"SET {setting}")


def _lock_down(con: duckdb.DuckDBPyConnection, path: Path) -> None:
    con.execute(f"SET allowed_paths=[{_sql_literal(str(path))}]")
    con.execute("SET enable_external_access=false")
    con.execute("SET lock_configuration=true")


def _json_safe(value: Any, cap: int = CELL_MAX_CHARS) -> Any:
    """`value` as something `json.dumps` writes without error or surprise; a text or blob longer
    than `cap` (the query leaves one unit over) is cut and marked."""
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, str):
        return value if len(value) <= cap else value[:cap] + "…"
    if isinstance(value, bytes | bytearray | memoryview):
        raw = bytes(value)
        cut = len(raw) > cap
        text = base64.b64encode(raw[:cap]).decode("ascii")
        return text + "…" if cut else text
    if isinstance(value, datetime.date | datetime.time):  # datetime is a date
        return value.isoformat()
    if isinstance(value, decimal.Decimal | uuid.UUID | datetime.timedelta):
        return str(value)
    if isinstance(value, list | tuple):
        return [_json_safe(item, cap) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item, cap) for key, item in value.items()}
    return str(value)


def _nested_cell(text: Any, cap: int) -> Any:
    """A list, struct, map or union cell, which arrives as its JSON text (cut by the query): the
    value again when the text is whole, else the cut text, marked like any long cell."""
    if not isinstance(text, str):
        return _json_safe(text, cap)
    if len(text) > cap:
        return text[:cap] + "\u2026"
    try:
        return _json_safe(json.loads(text), cap)
    except ValueError:
        return text


def _cell_cap(cut_columns: int) -> int:
    """The longest a cut cell may be: the cut columns of a row share ROW_MAX_CHARS characters."""
    return min(CELL_MAX_CHARS, max(MIN_CELL_CHARS, ROW_MAX_CHARS // max(cut_columns, 1)))


@dataclass
class _Projection:
    sql: str  # the projection list, for `rel.project`
    nested: list[bool]  # per column: arrives as JSON text to read back
    cut_columns: int  # how many columns the query cuts
    cell_cap: int  # characters (or bytes) kept of each

    @property
    def row_chars(self) -> int:
        """The most text one row can hold."""
        return self.cut_columns * self.cell_cap


def _projection(columns: list[str], types: list[Any]) -> _Projection:
    """Every column by position, with its name kept (a repeated name stays repeated), and
    bounded in size by the query itself:

    - numbers, dates, times, intervals and uuids pass through;
    - VARCHAR (and JSON) becomes `left(col, cap + 1)`, so a longer cell is one character over
      and shows as cut;
    - BLOB becomes `array_slice(col, 1, cap + 1)`;
    - LIST, ARRAY, STRUCT, MAP and UNION become `left(to_json(col), cap + 1)`, the JSON text,
      which `_nested_cell` reads back into a value when it fits (`nested` says which);
    - anything else (a time zone, bit string, enum, ...) is cast to VARCHAR and cut.

    `cap` is `_cell_cap` of the number of columns that get cut. The text of a cell arrives in
    Python as a str, which DuckDB would otherwise build in full (a time zone also needs a
    timezone package this image does not ship).
    """
    kinds = [type_.id for type_ in types]
    cut_columns = sum(kind not in _PASS_THROUGH for kind in kinds)
    cap = _cell_cap(cut_columns)
    items = []
    for position, (name, kind) in enumerate(zip(columns, kinds, strict=True), start=1):
        alias = '"' + name.replace('"', '""') + '"'
        ref = f"#{position}"
        if kind in _PASS_THROUGH:
            value = ref
        elif kind == "varchar":
            value = f"left({ref}, {cap + 1})"
        elif kind == "blob":
            value = f"array_slice({ref}, 1, {cap + 1})"
        elif kind in _NESTED:
            value = f"left(CAST(to_json({ref}) AS VARCHAR), {cap + 1})"
        else:
            value = f"left(CAST({ref} AS VARCHAR), {cap + 1})"
        items.append(f"{value} AS {alias}")
    return _Projection(", ".join(items), [kind in _NESTED for kind in kinds], cut_columns, cap)


def _sorts_at_the_top(con: duckdb.DuckDBPyConnection, statement: str) -> bool:
    """Whether `statement` has an ORDER BY of its own (not in a subquery, a CTE, a window or a
    comment), by asking DuckDB's parser for its syntax tree: then it is worth telling DuckDB to
    stop at `max_rows + 1` rows, so that it keeps just the best few instead of sorting everything
    (top-N). Otherwise the rows are streamed and counted here: with rows that are wide, a LIMIT
    makes DuckDB hold far more than it returns (1.5 GiB of RSS for 2001 wide Parquet rows,
    against 315 MiB streaming without it).

    The statement is a bound parameter of a function that only parses, and it has already been
    accepted as one SELECT. If the parser cannot serialise it (a PIVOT, say) the answer is no,
    which only costs the top-N speed-up."""
    try:
        document = con.execute("SELECT json_serialize_sql(?)", [statement]).fetchone()[0]
        parsed = json.loads(document)
        if parsed.get("error"):
            return False
        modifiers = parsed["statements"][0]["node"].get("modifiers", [])
        return any(modifier.get("type") == "ORDER_MODIFIER" for modifier in modifiers)
    except (duckdb.Error, ValueError, KeyError, IndexError, TypeError):
        return False


def _row_cost(cells: list[Any]) -> int:
    """What a kept row counts against ROW_BUDGET_BYTES: the larger of its size as JSON and the
    memory its text takes in Python (a cut cell ends in a non-ASCII mark, so it is held at two
    bytes a character, twice its JSON size)."""
    held = sum(sys.getsizeof(cell) for cell in cells if isinstance(cell, str))
    return max(len(json.dumps(cells)) + 2, held)


def _batch_rows(row_chars: int) -> int:
    """How many rows to fetch at once: as many as keep a batch of worst-case text within
    FETCH_BYTES (and no more than MAX_FETCH_ROWS), but at least one."""
    if row_chars <= 0:
        return MAX_FETCH_ROWS
    return max(1, min(MAX_FETCH_ROWS, FETCH_BYTES // (row_chars * _WORST_BYTES_PER_CHAR)))


def _hint(shown: int, ended_by: str, max_rows: int) -> str:
    """What to tell a caller whose result was cut, according to what cut it."""
    if ended_by == "bytes":
        return (
            f"returned the first {shown} rows; the result reached its size limit, so select "
            "fewer or narrower columns, or filter or aggregate in the query"
        )
    advice = "filter or aggregate in the query"
    if max_rows < MAX_ROWS_LIMIT:
        advice += f", or raise maxRows (max {MAX_ROWS_LIMIT})"
    return f"returned the first {shown} rows; {advice}"


def run_sql(ctx: Any, *, query: str, fmt: str, max_rows: int) -> SqlResult:
    """Runs `query` (one SELECT over the table `t`, the `source` input) and returns at most
    `max_rows` rows."""
    con = duckdb.connect(":memory:")
    temp_dir = Path(ctx.workdir) / ".duckdb-tmp"
    watch = Deadline(ctx, "filter earlier, avoid joins that multiply rows, or query less")
    try:
        watch.arm(con.interrupt)
        statement = _select_statement(con, query)
        path = ctx.artifacts.input_path("source")
        reader, used = _reader(fmt, path)
        temp_dir.mkdir(parents=True, exist_ok=True)
        _configure(con, temp_dir, _max_temp_bytes(path.stat().st_size))
        watch.check()
        con.execute(f"CREATE VIEW t AS SELECT * FROM {reader}")
        sorts = _sorts_at_the_top(con, statement)
        if sorts:
            # The LIMIT given to DuckDB below only stays cheap when it need not keep the rows in
            # file order; the query's own ORDER BY decides the order of what comes back.
            con.execute("SET preserve_insertion_order=false")
        _lock_down(con, path)

        rel = con.sql(statement)
        names = list(rel.columns)
        types = list(rel.types)
        projection = _projection(names, types)
        # Streamed, with no `.execute()` (which holds every row the query produces). The row
        # limit is applied below as rows arrive, and closing the connection stops the query;
        # DuckDB is only told the limit when the query sorts (see `_sorts_at_the_top`).
        stream = rel.project(projection.sql)
        if sorts:
            stream = stream.limit(max_rows + 1)
        batch_rows = _batch_rows(projection.row_chars)

        rows: list[list[Any]] = []
        used_bytes = 0
        ended_by = ""
        while not ended_by:
            watch.check()  # an interrupt only reaches a query that is running
            batch = stream.fetchmany(batch_rows)
            if not batch:
                break
            for row in batch:
                if len(rows) >= max_rows:
                    ended_by = "rows"  # an extra row exists
                    break
                cells = [
                    _nested_cell(cell, projection.cell_cap)
                    if is_nested
                    else _json_safe(cell, projection.cell_cap)
                    for cell, is_nested in zip(row, projection.nested, strict=True)
                ]
                size = _row_cost(cells)
                if rows and used_bytes + size > ROW_BUDGET_BYTES:
                    ended_by = "bytes"
                    break
                rows.append(cells)
                used_bytes += size
    except ToolError:
        raise
    except Exception as exc:
        if watch.expired:
            raise watch.error() from exc  # the interrupt, or what it left behind
        raise
    finally:
        watch.cancel()
        con.close()
        shutil.rmtree(temp_dir, ignore_errors=True)

    return SqlResult(
        columns=[
            SqlColumn(name=name, type=str(type_)) for name, type_ in zip(names, types, strict=True)
        ],
        rows=rows,
        rowCount=len(rows),
        truncated=bool(ended_by),
        hint=_hint(len(rows), ended_by, max_rows) if ended_by else None,
        format=used,
    )
