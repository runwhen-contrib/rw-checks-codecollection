"""artifact-tools capability tasks: `grep`, `jq`, `sql` and `slice`, four read-only
tools that each take one artifact (the `source` input, possibly many gigabytes) and
hand back a bounded answer or a new artifact.

The bytes are read through `ctx.artifacts` by input NAME; the `source` value itself
(the artifact's reference, as the platform passes it) is not needed and is ignored.
The work is in the `artifact_tools` package next to this file; these functions
validate the inputs and shape the outputs the manifest declares. Every task returns
a dict literal keyed by its declared outputs (tests/test_output_contract.py reads
them from the source).

This capability runs only against the standalone capability SDK, which provides
`ctx.artifacts`; the SDK vendored in this repository predates it.
"""

from __future__ import annotations

from artifact_tools.grep import run_grep
from artifact_tools.jq import run_jq
from artifact_tools.params import as_bool, as_choice, as_int, as_text
from artifact_tools.slice import run_slice
from artifact_tools.sql import run_sql
from runwhen_capability import Context, task

# Far beyond any real line count; keeps a pathological number out of the arithmetic.
_MAX_LINE_NUMBER = 2**53


@task(outputs={"result": "rw.artifact_grep.v1", "matches": "artifact"})
def grep(
    ctx: Context,
    source: str,
    pattern: str,
    ignore_case: bool | str | None = None,
    context: int | str | None = None,
    max_matches: int | str | None = None,
    save_all: bool | str | None = None,
):
    result, matches = run_grep(
        ctx,
        pattern=as_text("pattern", pattern, allow_blank=True),
        ignore_case=as_bool("ignoreCase", ignore_case),
        context=as_int("context", context, minimum=0, maximum=5, default=0),
        max_matches=as_int("maxMatches", max_matches, minimum=1, maximum=500, default=50),
        save_all=as_bool("saveAll", save_all),
    )
    result = result.model_dump(mode="json", by_alias=True)
    if matches is None:
        return {"result": result}
    return {"result": result, "matches": matches}


@task(outputs={"result": "rw.artifact_jq.v1"})
def jq(ctx: Context, source: str, filter: str, lines: bool | str | None = None):
    result = run_jq(
        ctx, program=as_text("filter", filter), lines=as_bool("lines", lines, default=None)
    )
    return {"result": result.model_dump(mode="json", by_alias=True)}


@task(outputs={"result": "rw.artifact_sql.v1"})
def sql(
    ctx: Context,
    source: str,
    query: str,
    format: str | None = None,
    max_rows: int | str | None = None,
):
    result = run_sql(
        ctx,
        query=as_text("query", query),
        fmt=as_choice(
            "format", format, ("auto", "csv", "json", "jsonl", "parquet"), default="auto"
        ),
        max_rows=as_int("maxRows", max_rows, minimum=1, maximum=2000, default=200),
    )
    return {"result": result.model_dump(mode="json", by_alias=True)}


@task(outputs={"slice": "artifact"})
def slice(ctx: Context, source: str, from_line: int | str, to_line: int | str):
    ref = run_slice(
        ctx,
        from_line=as_int("fromLine", from_line, minimum=1, maximum=_MAX_LINE_NUMBER),
        to_line=as_int("toLine", to_line, minimum=1, maximum=_MAX_LINE_NUMBER),
    )
    return {"slice": ref}
