"""Tool output -> Finding records, one adapter per tool.

Each adapter is a PURE function: raw tool stdout (str) -> list[dict]. It does
no I/O and knows nothing about the Context. The dicts it returns are the
record shape `ctx.findings.from_records()` consumes:

    {path, rule, line, severity, message, snippet}

`path` and `severity` are the two that matter:

  path      MUST be repo-relative as the tool reported it. from_records()
            normalises and drops anything resolving outside the worktree, so
            an adapter never needs to make paths safe -- only to find the
            right field.
  severity  is looked up in the adapter's own SEVERITY map. Mapping belongs
            HERE, per tool, because every tool has its own vocabulary and
            none of them mean the same thing: ruff marks every violation
            `error`, shellcheck's `style` and pylint's `convention` are both
            our `note`, and hadolint's `info` is not shellcheck's `info`.
            A shared map would flatten exactly the distinction the Check Run
            conclusion depends on.

Adapters live in the capability, not in the SDK, because which field holds a
path is tool knowledge. The SDK owns the generic half (normalisation, context
resolution, fingerprinting) -- see sdk/runwhen_capability/findings.py.

Every adapter is tested against REAL captured output in
tests/fixtures/tools/, produced by scripts/capture_fixtures.sh. See that
directory's README before changing an adapter: several of these formats are
not what the tool's documentation describes.
"""

from __future__ import annotations

import json
import re
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
SHELLCHECK_SEVERITY = {
    "error": "error",
    "warning": "warning",
    "info": "note",
    "style": "note",
}


def shellcheck(text: str) -> list[dict]:
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
            "severity": SHELLCHECK_SEVERITY.get(str(c.get("level", "")).lower(), "warning"),
            "message": c.get("message", ""),
        }
        for c in payload.get("comments", [])
    ]


# --- hadolint ---------------------------------------------------------------
# `hadolint -f json` -> a bare array of {code,file,line,column,level,message}.
HADOLINT_SEVERITY = {
    "error": "error",
    "warning": "warning",
    "info": "note",
    "style": "note",
}


def hadolint(text: str) -> list[dict]:
    payload = _loads(text) or []
    return [
        {
            "path": d.get("file", ""),
            "rule": d.get("code", ""),
            "line": d.get("line", 0),
            "severity": HADOLINT_SEVERITY.get(str(d.get("level", "")).lower(), "warning"),
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
YAMLLINT_SEVERITY = {"error": "error", "warning": "warning"}


def yamllint(text: str) -> list[dict]:
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
                "severity": YAMLLINT_SEVERITY.get(m["level"].lower(), "note"),
                "message": m["message"],
            }
        )
    return out


# --- actionlint ---------------------------------------------------------
# `actionlint -format '{{json .}}'` -> a bare array of
# {message,filepath,line,column,kind,snippet,end_column}. actionlint has no
# severity vocabulary at all -- every lint it reports is an error-level
# finding.
ACTIONLINT_SEVERITY = {"error": "error"}


def actionlint(text: str) -> list[dict]:
    payload = _loads(text) or []
    return [
        {
            "path": d.get("filepath", ""),
            # `kind` (action/expression/job-needs/...) is the closest thing
            # actionlint has to a rule id -- it has no separate code field.
            "rule": d.get("kind", ""),
            "line": d.get("line", 0),
            "severity": ACTIONLINT_SEVERITY["error"],
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
PYLINT_SEVERITY = {
    "fatal": "error",
    "error": "error",
    "warning": "warning",
    "convention": "note",
    "refactor": "note",
    "info": "note",
}


def pylint(text: str) -> list[dict]:
    payload = _loads(text) or []
    return [
        {
            "path": d.get("path", ""),
            # message-id (e.g. "C0410") is what a `# pylint: disable=`
            # comment names; `symbol` is the human-readable alias for it.
            "rule": d.get("message-id", ""),
            "line": d.get("line", 0),
            "severity": PYLINT_SEVERITY.get(str(d.get("type", "")).lower(), "warning"),
            "message": d.get("message", ""),
        }
        for d in payload
    ]


# --- sqlfluff -------------------------------------------------------------
# `sqlfluff lint -f json` -> an array of FILES, each
# {filepath, violations: [{start_line_no,code,description,name,warning,...}]}.
# sqlfluff has no error/warning/info vocabulary of its own -- `warning` is a
# bool distinguishing advisory formatting rules from ones that would fail a
# build, so it is the whole map.
SQLFLUFF_SEVERITY = {True: "warning", False: "note"}


def sqlfluff(text: str) -> list[dict]:
    payload = _loads(text) or []
    return [
        {
            "path": f.get("filepath", ""),
            "rule": v.get("code", ""),
            "line": v.get("start_line_no", 0),
            "severity": SQLFLUFF_SEVERITY.get(v.get("warning"), "note"),
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
BIOME_SEVERITY = {
    "error": "error",
    "warning": "warning",
    "information": "note",
    "hint": "note",
}


def biome(text: str) -> list[dict]:
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
                "severity": BIOME_SEVERITY.get(str(d.get("severity", "")).lower(), "warning"),
                "message": d.get("description", ""),
            }
        )
    return out


# --- ast-grep ---------------------------------------------------------------
# `ast-grep scan --json` -> a bare array of
# {text,range:{start:{line,column},end:{...}},file,lines,ruleId,severity,message}.
# `range.start.line` is 0-INDEXED, unlike every line-reporting tool above.
AST_GREP_SEVERITY = {
    "error": "error",
    "warning": "warning",
    "info": "note",
    "hint": "note",
}


def ast_grep(text: str) -> list[dict]:
    payload = _loads(text) or []
    return [
        {
            "path": d.get("file", ""),
            "rule": d.get("ruleId", ""),
            "line": d.get("range", {}).get("start", {}).get("line", 0) + 1,
            "severity": AST_GREP_SEVERITY.get(str(d.get("severity", "")).lower(), "warning"),
            "message": d.get("message", ""),
            "snippet": d.get("lines", ""),
        }
        for d in payload
    ]


# --- regal ------------------------------------------------------------------
# `regal lint --format=json` -> {violations: [{title,description,category,
# level,location:{file,row,col,text}}], summary}.
REGAL_SEVERITY = {"error": "error", "warning": "warning"}


def regal(text: str) -> list[dict]:
    payload = _loads(text) or {}
    out = []
    for v in payload.get("violations", []):
        loc = v.get("location", {})
        out.append(
            {
                "path": loc.get("file", ""),
                "rule": v.get("title", ""),
                "line": loc.get("row", 0),
                "severity": REGAL_SEVERITY.get(str(v.get("level", "")).lower(), "note"),
                "message": v.get("description", ""),
                "snippet": loc.get("text", ""),
            }
        )
    return out


# --- vale ---------------------------------------------------------------
# `vale --output=JSON` -> not an array: an OBJECT keyed by file path, each
# value a list of {Check,Message,Line,Severity,Match,Span,...}. The path is
# the dict key, not a field on the record.
VALE_SEVERITY = {"error": "error", "warning": "warning", "suggestion": "note"}


def vale(text: str) -> list[dict]:
    payload = _loads(text) or {}
    out = []
    for path, alerts in payload.items():
        for a in alerts:
            out.append(
                {
                    "path": path,
                    "rule": a.get("Check", ""),
                    "line": a.get("Line", 0),
                    "severity": VALE_SEVERITY.get(str(a.get("Severity", "")).lower(), "note"),
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
FLAKE8_SEVERITY = {
    "F": "error",  # pyflakes: real defects (undefined name, unused import)
    "E": "warning",  # pycodestyle errors
    "W": "warning",  # pycodestyle warnings
    "C": "note",  # mccabe complexity
    "N": "note",  # pep8-naming, if installed
}


def flake8(text: str) -> list[dict]:
    out = []
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        parts = line.split(":", 4)
        if len(parts) != 5:
            continue
        path, row, _col, code, message = parts
        if not row.isdigit():
            continue
        out.append(
            {
                "path": path,
                "rule": code,
                "line": int(row),
                "severity": FLAKE8_SEVERITY.get(code[:1].upper(), "warning"),
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
# "no location" value and passes through unchanged.
def checkmake(text: str) -> list[dict]:
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
                # checkmake has no severity vocabulary at all -- every rule is
                # a style convention about Makefile structure, so `note` is the
                # honest mapping rather than inventing a gradation.
                "severity": "note",
                "message": message.strip(),
            }
        )
    return out


# --- dotenv-linter ----------------------------------------------------------
# "path:line RuleName: message", preceded by a "Checking <file>" header and
# followed by a "Found N problems" summary -- both must be skipped or they
# become findings with an empty rule.
_DOTENV_LINE = re.compile(r"^(?P<path>[^:]+):(?P<line>\d+)\s+(?P<rule>\w+):\s+(?P<message>.+)$")


def dotenv_linter(text: str) -> list[dict]:
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
                # dotenv-linter emits no severity; its rules are conventions
                # (casing, ordering) except DuplicatedKey, which is a real
                # defect -- a later key silently wins.
                "severity": "warning" if m["rule"] == "DuplicatedKey" else "note",
                "message": m["message"].strip(),
            }
        )
    return out


# --- buf --------------------------------------------------------------------
# `buf lint --error-format=json` emits JSON LINES, one object per finding --
# not a JSON array. json.loads() on the whole payload raises.
def buf(text: str) -> list[dict]:
    return [
        {
            "path": d.get("path", ""),
            "rule": d.get("type", ""),
            "line": d.get("start_line", 0),
            # buf lint findings are all failures of the configured rule set;
            # there is no severity axis to map.
            "severity": "warning",
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
def trufflehog(text: str) -> list[dict]:
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
                # A verified credential is known-live; an unverified one is a
                # strong candidate. Both are errors -- the distinction belongs
                # in the message, not in a downgrade to `warning`.
                "severity": "error",
                "message": (
                    f"{d.get('DetectorName', 'unknown')} credential detected"
                    f"{' (verified live)' if d.get('Verified') else ''}"
                ),
            }
        )
    return out
