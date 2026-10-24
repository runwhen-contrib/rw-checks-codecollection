"""Result models for the tasks whose `result` output carries a JSON value.

Pydantic only, no SDK import: `scripts/export_schemas.py` imports this module to
write the JSON Schemas under `schemas/`, and it runs where the capability SDK
is the vendored one. Field names are the JSON names (camelCase), as in the
other capabilities' result models.

Bump a model's schema version constant when its shape changes in a way a
consumer must handle differently; the export then writes a new
`<name>.v<N>.json` and the manifest's schema reference moves to it.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

GREP_RESULT_SCHEMA_VERSION = 1
JQ_RESULT_SCHEMA_VERSION = 1
SQL_RESULT_SCHEMA_VERSION = 1


class GrepLine(BaseModel):
    """One line of the input, 1-based `lineNumber`, without its line ending. `text` is cut to
    1024 characters, and `textTruncated` says so."""

    lineNumber: int
    text: str
    textTruncated: bool = False


class GrepMatch(GrepLine):
    """A matching line with the `context` lines before and after it that did not match."""

    before: list[GrepLine] = Field(default_factory=list)
    after: list[GrepLine] = Field(default_factory=list)


class GrepResult(BaseModel):
    """Output of the `grep` task. `matches` holds the first matching lines in file order;
    `totalMatches` counts every matching line, kept or not. `longLines` is how many input
    lines over 64 KiB were searched only in their first 64 KiB, and `bytesScanned` the bytes
    searched."""

    matches: list[GrepMatch] = Field(default_factory=list)
    totalMatches: int
    truncated: bool = False
    hint: str | None = None
    longLines: int = 0
    bytesScanned: int = 0


class JqResult(BaseModel):
    """Output of the `jq` task: the filter's output, one compact JSON value per line, without a
    trailing newline. `lines` is the input mode used (one JSON value per line, or one whole
    document)."""

    output: str
    outputLines: int
    truncated: bool = False
    hint: str | None = None
    lines: bool


class SqlColumn(BaseModel):
    name: str
    type: str


class SqlResult(BaseModel):
    """Output of the `sql` task. `rows` are JSON-safe values in `columns` order; `format` is
    the reader that was used on the artifact (csv, json, jsonl or parquet)."""

    columns: list[SqlColumn] = Field(default_factory=list)
    rows: list[list[Any]] = Field(default_factory=list)
    rowCount: int
    truncated: bool = False
    hint: str | None = None
    format: str
