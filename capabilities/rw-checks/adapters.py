"""Tool output -> Finding records, one adapter per tool.

Each adapter is a PURE function: raw tool stdout (str), plus the tool
module's own SEVERITY map -> list[dict]. It does no I/O and knows nothing
about the Context. The dicts it returns are the record shape
`ctx.findings.from_records()` consumes:

    {path, rule, line, severity, message, snippet}

`path` and `severity` are the two that matter:

  path      MUST be repo-relative as the tool reported it. from_records()
            normalises and drops anything resolving outside the worktree, so
            an adapter never needs to make paths safe -- only to find the
            right field.
  severity  is looked up in the `severity` map the CALLER passes in -- the
            tool module's own SEVERITY, not a copy of it kept here. Mapping
            belongs to the tool module because every tool has its own
            vocabulary and none of them mean the same thing: ruff marks
            every violation `error`, shellcheck's `style` and pylint's
            `convention` are both our `note`, and hadolint's `info` is not
            shellcheck's `info`. A shared map -- or two maps that can drift
            apart -- would flatten exactly the distinction the Check Run
            conclusion depends on.

Adapters live in the capability, not in the SDK, because which field holds a
path is tool knowledge. The SDK owns the generic half (normalisation, context
resolution) -- see sdk/runwhen_capability/findings.py.

Every adapter is tested against REAL captured output in
tests/fixtures/tools/, produced by scripts/capture_fixtures.sh. See that
directory's README before changing an adapter: several of these formats are
not what the tool's documentation describes.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

# --- helpers ----------------------------------------------------------------


def _loads(text: str) -> Any:
    """Tolerate an empty/whitespace payload: a tool that found nothing and
    printed nothing is a valid, empty result -- not a parse error. A tool
    that printed malformed JSON still raises, which is what we want."""
    text = (text or "").strip()
    return json.loads(text) if text else None


def _jsonl(text: str) -> list[dict]:
    """One JSON object per line (buf, trufflehog). Blank lines are skipped;
    a malformed line raises rather than being silently dropped."""
    return [json.loads(line) for line in (text or "").splitlines() if line.strip()]


# --- shellcheck -------------------------------------------------------------
# `shellcheck -f json1` -> {"comments": [{file,line,column,level,code,message}]}
# NOT a bare array: that is `-f json`. json1 is the stable, documented shape.
# tools/shellcheck.py's SEVERITY is `error`/`warning` real defects, `info`/
# `style` (advisory -- promoting them would fail a Check Run on a nit) both
# `note`.


def shellcheck(text: str, severity: Mapping[str, str]) -> list[dict]:
    payload = _loads(text)
    if not payload:
        return []
    return [
        {
            "path": c.get("file", ""),
            # SC codes are reported as bare ints; the SC prefix is what a
            # human (and any suppression comment) actually refers to.
            "rule": f"SC{c.get('code')}" if c.get("code") is not None else "",
            "line": c.get("line", 0),
            # shellcheck's column/endLine/endColumn are already 1-indexed.
            "column": c.get("column", 0),
            "end_line": c.get("endLine", 0),
            "end_column": c.get("endColumn", 0),
            "severity": severity.get(str(c.get("level", "")).lower(), "warning"),
            "message": c.get("message", ""),
        }
        for c in payload.get("comments", [])
    ]


# --- hadolint ---------------------------------------------------------------
# `hadolint -f json` -> a bare array of {code,file,line,column,level,message}.
# tools/hadolint.py's SEVERITY: `error`/`warning`/`info`->note/`style`->note.


def hadolint(text: str, severity: Mapping[str, str]) -> list[dict]:
    payload = _loads(text) or []
    return [
        {
            "path": d.get("file", ""),
            "rule": d.get("code", ""),
            "line": d.get("line", 0),
            # hadolint carries no end_line/end_column -- column only.
            "column": d.get("column", 0),
            "severity": severity.get(str(d.get("level", "")).lower(), "warning"),
            "message": d.get("message", ""),
        }
        for d in payload
    ]


# --- yamllint ---------------------------------------------------------------
# `yamllint -f parsable` -> "path:line:col: [level] message (rule)".
# Paths come back "./"-prefixed; from_records() strips that, so the adapter
# leaves it alone rather than half-normalising here.
_YAMLLINT_LINE = re.compile(
    r"^(?P<path>.+?):(?P<line>\d+):(?P<col>\d+):\s+\[(?P<level>\w+)\]\s+(?P<message>.*?)\s*\((?P<rule>[\w-]+)\)\s*$"
)
# tools/yamllint.py's SEVERITY: `error`/`warning` real, anything else `note`.


def yamllint(text: str, severity: Mapping[str, str]) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        m = _YAMLLINT_LINE.match(line.strip())
        if not m:
            continue
        out.append(
            {
                "path": m["path"],
                "rule": m["rule"],
                "line": int(m["line"]),
                "column": int(m["col"]),
                "severity": severity.get(m["level"].lower(), "note"),
                "message": m["message"],
            }
        )
    return out


# --- actionlint ---------------------------------------------------------
# `actionlint -format '{{json .}}'` -> a bare array of
# {message,filepath,line,column,kind,snippet,end_column}. actionlint has no
# severity vocabulary at all -- every lint it reports is an error-level
# finding. tools/actionlint.py's SEVERITY is `{"error": "error"}`, the
# whole (degenerate) vocabulary.


def actionlint(text: str, severity: Mapping[str, str]) -> list[dict]:
    payload = _loads(text) or []
    return [
        {
            "path": d.get("filepath", ""),
            # `kind` (action/expression/job-needs/...) is the closest thing
            # actionlint has to a rule id -- it has no separate code field.
            "rule": d.get("kind", ""),
            "line": d.get("line", 0),
            # actionlint reports no end_line -- every finding is single-line.
            "column": d.get("column", 0),
            "end_column": d.get("end_column", 0),
            "severity": severity.get("error", "error"),
            "message": d.get("message", ""),
            # `snippet` is two lines: the source line, then a caret-underline
            # pointing at the column. The second line is not source text, so
            # only the first line is kept.
            "snippet": d.get("snippet", "").splitlines()[0] if d.get("snippet") else "",
        }
        for d in payload
    ]


# --- pylint -------------------------------------------------------------
# `pylint --output-format=json` -> a bare array of
# {type,module,obj,line,column,path,symbol,message,message-id,...}.
# tools/pylint.py's SEVERITY: fatal/error->error, warning->warning,
# convention/refactor/info->note.


def pylint(text: str, severity: Mapping[str, str]) -> list[dict]:
    payload = _loads(text) or []
    out = []
    for d in payload:
        # pylint's column/endColumn are 0-INDEXED (straight off astroid's
        # col_offset/end_col_offset), unlike `line`/`endLine` which are
        # already 1-based -- so only the two column fields get +1. Checked
        # this against the fixture: "    if event == None:" reports
        # column=7, which is the 0-indexed position of the "e" in "event"
        # (1-indexed column 8).
        col = d.get("column")
        end_col = d.get("endColumn")
        out.append(
            {
                "path": d.get("path", ""),
                # message-id (e.g. "C0410") is what a `# pylint: disable=`
                # comment names; `symbol` is the human-readable alias for it.
                "rule": d.get("message-id", ""),
                "line": d.get("line", 0),
                "column": (col + 1) if isinstance(col, int) else 0,
                "end_line": d.get("endLine", 0) or 0,
                "end_column": (end_col + 1) if isinstance(end_col, int) else 0,
                "severity": severity.get(str(d.get("type", "")).lower(), "warning"),
                "message": d.get("message", ""),
            }
        )
    return out


# --- sqlfluff -------------------------------------------------------------
# `sqlfluff lint -f json` -> an array of FILES, each
# {filepath, violations: [{start_line_no,code,description,name,warning,...}]}.
# sqlfluff has no error/warning/info vocabulary of its own -- `warning` is a
# bool distinguishing advisory formatting rules from ones that would fail a
# build, so tools/sqlfluff.py's SEVERITY is `{True: "warning", False: "note"}`,
# the whole map, keyed by that bool rather than a string.


def sqlfluff(text: str, severity: Mapping[Any, str]) -> list[dict]:
    payload = _loads(text) or []
    return [
        {
            "path": f.get("filepath", ""),
            "rule": v.get("code", ""),
            "line": v.get("start_line_no", 0),
            # sqlfluff's *_pos fields are already 1-indexed.
            "column": v.get("start_line_pos", 0),
            "end_line": v.get("end_line_no", 0),
            "end_column": v.get("end_line_pos", 0),
            "severity": severity.get(v.get("warning"), "note"),
            "message": v.get("description", ""),
        }
        for f in payload
        for v in f.get("violations", [])
    ]


# --- biome ----------------------------------------------------------------
# `biome ci --reporter=json` -> {summary, diagnostics: [...], command}. Each
# diagnostic's `location` carries no line number at all -- only a byte
# offset (`span`) into `location.sourceCode` -- so the line is derived by
# counting newlines before the span start. `description` is the plain-string
# rendering of the structured `message` array and is what we want; `message`
# itself is a list of content/markup fragments, not text.
# tools/biome.py's SEVERITY: error/warning real, information/hint->note.


def biome(text: str, severity: Mapping[str, str]) -> list[dict]:
    payload = _loads(text) or {}
    out = []
    for d in payload.get("diagnostics", []):
        loc = d.get("location", {})
        source = loc.get("sourceCode") or ""
        start = (loc.get("span") or [0])[0]
        out.append(
            {
                "path": loc.get("path", {}).get("file", ""),
                "rule": d.get("category", ""),
                "line": source.count("\n", 0, start) + 1,
                # No column/end_line/end_column: biome's `location` carries
                # only a byte-offset span, no column number at all -- unlike
                # `line`, there is no way to derive one without re-decoding
                # the byte offset against the source text's line/column
                # grid. Left at the Finding default (0 == not reported).
                "severity": severity.get(str(d.get("severity", "")).lower(), "warning"),
                "message": d.get("description", ""),
            }
        )
    return out


# --- ast-grep ---------------------------------------------------------------
# `ast-grep scan --json` -> a bare array of
# {text,range:{start:{line,column},end:{...}},file,lines,ruleId,severity,message}.
# `range.start.line` is 0-INDEXED, unlike every line-reporting tool above.
# tools/ast_grep.py's SEVERITY: error/warning real, info/hint->note.


def ast_grep(text: str, severity: Mapping[str, str]) -> list[dict]:
    payload = _loads(text) or []
    out = []
    for d in payload:
        rng = d.get("range", {})
        start = rng.get("start", {})
        end = rng.get("end", {})
        # `range.start.column`/`range.end.line`/`range.end.column` are
        # 0-INDEXED, same as `range.start.line` above -- checked against the
        # fixture: "    return eval(event)" reports start.column=11, the
        # 0-indexed position of the "e" in "eval" (1-indexed column 12). All
        # three get the same +1 treatment as `line` above.
        col = start.get("column")
        end_line = end.get("line")
        end_col = end.get("column")
        out.append(
            {
                "path": d.get("file", ""),
                "rule": d.get("ruleId", ""),
                "line": start.get("line", 0) + 1,
                "column": (col + 1) if isinstance(col, int) else 0,
                "end_line": (end_line + 1) if isinstance(end_line, int) else 0,
                "end_column": (end_col + 1) if isinstance(end_col, int) else 0,
                "severity": severity.get(str(d.get("severity", "")).lower(), "warning"),
                "message": d.get("message", ""),
                "snippet": d.get("lines", ""),
            }
        )
    return out


# --- regal ------------------------------------------------------------------
# `regal lint --format=json` -> {violations: [{title,description,category,
# level,location:{file,row,col,text}}], summary}.
# tools/regal.py's SEVERITY: `{"error": "error", "warning": "warning"}`;
# anything else falls back to `note`.


def regal(text: str, severity: Mapping[str, str]) -> list[dict]:
    payload = _loads(text) or {}
    out = []
    for v in payload.get("violations", []):
        loc = v.get("location", {})
        end = loc.get("end", {})
        out.append(
            {
                "path": loc.get("file", ""),
                "rule": v.get("title", ""),
                "line": loc.get("row", 0),
                # regal's row/col are already 1-indexed.
                "column": loc.get("col", 0),
                "end_line": end.get("row", 0),
                "end_column": end.get("col", 0),
                "severity": severity.get(str(v.get("level", "")).lower(), "note"),
                "message": v.get("description", ""),
                "snippet": loc.get("text", ""),
            }
        )
    return out


# --- vale ---------------------------------------------------------------
# `vale --output=JSON` -> not an array: an OBJECT keyed by file path, each
# value a list of {Check,Message,Line,Severity,Match,Span,...}. The path is
# the dict key, not a field on the record.
# tools/vale.py's SEVERITY: error/warning real, suggestion->note.


def vale(text: str, severity: Mapping[str, str]) -> list[dict]:
    payload = _loads(text) or {}
    out = []
    for path, alerts in payload.items():
        for a in alerts:
            # `Span` is a 2-element [start, end] pair of 1-indexed column
            # offsets on `Line` -- there is no separate end-line field
            # because a vale alert never crosses a line.
            span = a.get("Span") or [0, 0]
            out.append(
                {
                    "path": path,
                    "rule": a.get("Check", ""),
                    "line": a.get("Line", 0),
                    "column": span[0] if len(span) > 0 else 0,
                    "end_column": span[1] if len(span) > 1 else 0,
                    "severity": severity.get(str(a.get("Severity", "")).lower(), "note"),
                    "message": a.get("Message", ""),
                    "snippet": a.get("Match", ""),
                }
            )
    return out


# --- flake8 -----------------------------------------------------------------
# flake8 has no JSON reporter, so the task pins an explicit --format:
#   "%(path)s:%(row)d:%(col)d:%(code)s:%(text)s"
# The message itself contains colons ("comparison to None should be 'if cond
# is None:'"), so the split is bounded to 4 -- an unbounded split would
# truncate the message at its first colon.
# tools/flake8.py's SEVERITY: F (pyflakes -- real defects) error, E/W
# (pycodestyle) warning, C (mccabe complexity)/N (pep8-naming) note.


def flake8(text: str, severity: Mapping[str, str]) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts = line.split(":", 4)
        if len(parts) != 5:
            continue
        path, row, col, code, message = parts
        if not row.isdigit():
            continue
        out.append(
            {
                "path": path,
                "rule": code,
                "line": int(row),
                # flake8/pycodestyle's %(col)d is already 1-indexed; no
                # end_line/end_column in this format.
                "column": int(col) if col.isdigit() else 0,
                "severity": severity.get(code[:1].upper(), "warning"),
                "message": message.strip(),
            }
        )
    return out


# --- checkmake --------------------------------------------------------------
# checkmake's default output is a whitespace-aligned TABLE whose columns can
# only be recovered by guessing at run boundaries. It accepts a Go
# text/template applied PER ITEM (`range` errors -- it is not given a list),
# so the task pins a delimited template:
#   "{{.Rule}}|{{.FileName}}|{{.LineNumber}}|{{.Violation}}\n"
# LineNumber is 0 for whole-file rules like minphony; 0 is the contract's
# "no location" value and passes through unchanged. checkmake has no
# severity vocabulary at all -- every rule is a style convention about
# Makefile structure -- so tools/checkmake.py's SEVERITY is the degenerate
# `{"": "note"}`, looked up by the empty-string key documenting that.
def checkmake(text: str, severity: Mapping[str, str]) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("|", 3)
        if len(parts) != 4:
            continue
        rule, path, line_no, message = parts
        out.append(
            {
                "path": path,
                "rule": rule,
                "line": int(line_no) if line_no.strip().isdigit() else 0,
                "severity": severity.get("", "note"),
                "message": message.strip(),
            }
        )
    return out


# --- dotenv-linter ----------------------------------------------------------
# "path:line RuleName: message", preceded by a "Checking <file>" header and
# followed by a "Found N problems" summary -- both must be skipped or they
# become findings with an empty rule.
_DOTENV_LINE = re.compile(r"^(?P<path>[^:]+):(?P<line>\d+)\s+(?P<rule>\w+):\s+(?P<message>.+)$")


# dotenv-linter emits no severity; its rules are conventions (casing,
# ordering) except DuplicatedKey, which is a real defect -- a later key
# silently wins. tools/dotenv_linter.py's SEVERITY is
# `{"DuplicatedKey": "warning", "": "note"}`, the `""` key its default for
# every other rule.
def dotenv_linter(text: str, severity: Mapping[str, str]) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        m = _DOTENV_LINE.match(line.strip())
        if not m:
            continue
        out.append(
            {
                "path": m["path"],
                "rule": m["rule"],
                "line": int(m["line"]),
                "severity": severity.get(m["rule"], severity.get("", "note")),
                "message": m["message"].strip(),
            }
        )
    return out


# --- buf --------------------------------------------------------------------
# `buf lint --error-format=json` emits JSON LINES, one object per finding --
# not a JSON array. json.loads() on the whole payload raises. buf lint
# findings are all failures of the configured rule set; there is no
# severity axis to map, so tools/buf.py's SEVERITY is the degenerate
# `{"": "warning"}`.
def buf(text: str, severity: Mapping[str, str]) -> list[dict]:
    return [
        {
            "path": d.get("path", ""),
            "rule": d.get("type", ""),
            "line": d.get("start_line", 0),
            # buf's start_column/end_line/end_column are already 1-indexed.
            "column": d.get("start_column", 0),
            "end_line": d.get("end_line", 0),
            "end_column": d.get("end_column", 0),
            "severity": severity.get("", "warning"),
            "message": d.get("message", ""),
        }
        for d in _jsonl(text)
    ]


# --- trufflehog -------------------------------------------------------------
# `trufflehog filesystem --json` emits JSON LINES. The path is nested at
# SourceMetadata.Data.Filesystem.file.
#
# TWO THINGS THIS ADAPTER MUST GET RIGHT:
#
# 1. `Raw` holds the DETECTED SECRET ITSELF. It never goes into `message` or
#    `snippet`: a finding is persisted, rendered in a Check Run and handed to
#    an LLM, so copying the credential there would leak it into all three.
#    The rule id and location are enough to act on.
# 2. trufflehog walks .git/objects, so a scan of a checkout reports paths like
#    ".git/objects/30/030dd1..." which are useless to a reviewer and cannot be
#    diff-filtered. Those are dropped here; the task also passes an exclusion,
#    but the adapter must not depend on the argv being right.
# A verified credential is known-live; an unverified one is a strong
# candidate. Both are errors -- the distinction belongs in the message, not
# in a downgrade to `warning` -- so tools/trufflehog.py's SEVERITY is the
# degenerate `{"": "error"}`.
def trufflehog(text: str, severity: Mapping[str, str]) -> list[dict]:
    out = []
    for d in _jsonl(text):
        meta = ((d.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
        path = meta.get("file", "")
        if not path or path.startswith(".git/") or "/.git/" in path:
            continue
        out.append(
            {
                "path": path,
                "rule": d.get("DetectorName", ""),
                "line": meta.get("line", 0),
                "severity": severity.get("", "error"),
                "message": (
                    f"{d.get('DetectorName', 'unknown')} credential detected"
                    f"{' (verified live)' if d.get('Verified') else ''}"
                ),
            }
        )
    return out
