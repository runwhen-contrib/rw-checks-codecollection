"""sql: run one SELECT over an artifact, as the table `t`, with DuckDB.

The query comes from a caller, so the DuckDB session is locked down before it
runs: the artifact's file is the only file it may read, nothing can be written,
attached, installed or loaded, and the configuration cannot be changed back. The
session is also bounded (memory, threads, spill size), and so is the answer (row
count, bytes of rows, size of one cell).

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
import uuid
from pathlib import Path
from typing import Any

import duckdb

from .models import SqlColumn, SqlResult

CELL_MAX_CHARS = 16 * 1024
ROW_BUDGET_BYTES = 4 * 1024 * 1024
FETCH_ROWS = 100
SNIFF_BYTES = 4096

_READERS = ("csv", "json", "jsonl", "parquet")


def _sql_literal(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _sniff_format(path: Path) -> str:
    """csv, json or parquet from the first bytes of the file."""
    with path.open("rb") as fh:
        head = fh.read(SNIFF_BYTES)
    if head.startswith(b"PAR1"):
        return "parquet"
    stripped = head.lstrip(b" \t\r\n\f\v")
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


def _configure(con: duckdb.DuckDBPyConnection, temp_dir: Path) -> None:
    for setting in (
        "memory_limit='1GB'",
        "threads=2",
        f"temp_directory={_sql_literal(str(temp_dir))}",
        "max_temp_directory_size='4GiB'",
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


def _json_safe(value: Any) -> Any:
    """`value` as something `json.dumps` writes without error or surprise."""
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, str):
        return value if len(value) <= CELL_MAX_CHARS else value[:CELL_MAX_CHARS] + "…"
    if isinstance(value, bytes | bytearray | memoryview):
        raw = bytes(value)
        cut = len(raw) > CELL_MAX_CHARS
        text = base64.b64encode(raw[:CELL_MAX_CHARS]).decode("ascii")
        return text + "…" if cut else text
    if isinstance(value, datetime.date | datetime.time):  # datetime is a date
        return value.isoformat()
    if isinstance(value, decimal.Decimal | uuid.UUID | datetime.timedelta):
        return str(value)
    if isinstance(value, list | tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return str(value)


def _projection(columns: list[str], types: list[str]) -> str:
    """Every column by position, with its name kept (a repeated name stays repeated). A
    column holding a time zone is cast to text: DuckDB hands those to Python only through a
    timezone package this image does not ship, and the text reads the same."""
    items = []
    for position, (name, type_name) in enumerate(zip(columns, types, strict=True), start=1):
        alias = '"' + name.replace('"', '""') + '"'
        value = f"CAST(#{position} AS VARCHAR)" if "TIME ZONE" in type_name else f"#{position}"
        items.append(f"{value} AS {alias}")
    return ", ".join(items)


def run_sql(ctx: Any, *, query: str, fmt: str, max_rows: int) -> SqlResult:
    """Runs `query` (one SELECT over the table `t`, the `source` input) and returns at most
    `max_rows` rows."""
    con = duckdb.connect(":memory:")
    temp_dir = Path(ctx.workdir) / ".duckdb-tmp"
    try:
        statement = _select_statement(con, query)
        path = ctx.artifacts.input_path("source")
        reader, used = _reader(fmt, path)
        temp_dir.mkdir(parents=True, exist_ok=True)
        _configure(con, temp_dir)
        con.execute(f"CREATE VIEW t AS SELECT * FROM {reader}")
        _lock_down(con, path)

        rel = con.sql(statement)
        names = list(rel.columns)
        types = [str(type_name) for type_name in rel.types]
        cursor = rel.project(_projection(names, types)).limit(max_rows + 1).execute()

        rows: list[list[Any]] = []
        used_bytes = 0
        truncated = False
        while not truncated:
            batch = cursor.fetchmany(FETCH_ROWS)
            if not batch:
                break
            for row in batch:
                if len(rows) >= max_rows:
                    truncated = True  # an extra row exists
                    break
                cells = [_json_safe(cell) for cell in row]
                size = len(json.dumps(cells)) + 2
                if rows and used_bytes + size > ROW_BUDGET_BYTES:
                    truncated = True
                    break
                rows.append(cells)
                used_bytes += size
    finally:
        con.close()
        shutil.rmtree(temp_dir, ignore_errors=True)

    return SqlResult(
        columns=[
            SqlColumn(name=name, type=type_name)
            for name, type_name in zip(names, types, strict=True)
        ],
        rows=rows,
        rowCount=len(rows),
        truncated=truncated,
        hint=(
            f"returned the first {len(rows)} rows; filter or aggregate in the query, "
            "or raise maxRows (max 2000)"
            if truncated
            else None
        ),
        format=used,
    )
