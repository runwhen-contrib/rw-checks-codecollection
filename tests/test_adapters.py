"""Adapter tests -- every one runs against REAL captured tool output.

tests/fixtures/tools/<tool>.<ext> is what the tool actually emitted inside the
built image (scripts/capture_fixtures.sh). Asserting against those bytes is
the point: several of these formats differ from the tool's documentation, and
a fixture written by hand would encode the documentation's version of reality
rather than the tool's.

Each tool gets the same three assertions -- it parses, it finds the defects
the sample repo deliberately contains, and every record is well-formed --
plus whatever is specific to that tool's format.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "tools"
sys.path.insert(0, str(Path(__file__).parent.parent / "capabilities" / "rw-checks"))

import adapters  # noqa: E402

VALID_SEVERITIES = {"error", "warning", "note"}


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


def assert_well_formed(records: list[dict]) -> None:
    """Every adapter's contract with ctx.findings.from_records()."""
    assert records, "adapter returned no records for a fixture that has findings"
    for r in records:
        assert r["path"], f"record has no path: {r}"
        assert not r["path"].startswith("/"), f"path must be repo-relative: {r['path']}"
        assert r["rule"], f"record has no rule id: {r}"
        assert r["severity"] in VALID_SEVERITIES, f"bad severity {r['severity']!r}: {r}"
        assert isinstance(r["line"], int) and r["line"] >= 0, f"bad line: {r}"
        for key in ("column", "end_line", "end_column"):
            val = r.get(key, 0)
            assert isinstance(val, int) and val >= 0, f"bad {key}: {r}"


# --- empty / malformed input, for every adapter -----------------------------

ALL_ADAPTERS = [
    "shellcheck",
    "hadolint",
    "yamllint",
    "actionlint",
    "pylint",
    "sqlfluff",
    "biome",
    "ast_grep",
    "regal",
    "vale",
    "flake8",
    "checkmake",
    "dotenv_linter",
    "buf",
    "trufflehog",
]


@pytest.mark.parametrize("name", ALL_ADAPTERS)
def test_empty_input_is_not_an_error(name):
    """A tool that found nothing and printed nothing yields no findings --
    never an exception. This is the common case on a clean repo."""
    fn = getattr(adapters, name)
    assert fn("") == []
    assert fn("   \n  ") == []


# --- shellcheck -------------------------------------------------------------


def test_shellcheck_parses_json1():
    records = adapters.shellcheck(fixture("shellcheck.json"))
    assert_well_formed(records)
    # `cd $1` unquoted in the fixture's deploy.sh.
    assert any(r["rule"] == "SC2164" for r in records)


def test_shellcheck_prefixes_numeric_codes():
    """shellcheck reports `code` as a bare int; SC#### is what a human and a
    `# shellcheck disable=` comment actually name."""
    records = adapters.shellcheck(fixture("shellcheck.json"))
    assert all(r["rule"].startswith("SC") for r in records)


def test_shellcheck_maps_style_to_note():
    """style/info are advisory -- promoting them to warning would fail a
    Check Run on a nit."""
    assert adapters.SHELLCHECK_SEVERITY["style"] == "note"
    assert adapters.SHELLCHECK_SEVERITY["info"] == "note"


def test_shellcheck_carries_column_and_end_line():
    """shellcheck's column/endLine/endColumn are already 1-indexed --
    SC2164 on `cd $1` (scripts/deploy.sh:2)."""
    records = adapters.shellcheck(fixture("shellcheck.json"))
    sc2164 = next(r for r in records if r["rule"] == "SC2164")
    assert sc2164["column"] == 1
    assert sc2164["end_line"] == 2
    assert sc2164["end_column"] == 6


# --- hadolint ---------------------------------------------------------------


def test_hadolint_parses_bare_array():
    records = adapters.hadolint(fixture("hadolint.json"))
    assert_well_formed(records)
    # FROM ubuntu:latest in the fixture Dockerfile.
    assert any(r["rule"] == "DL3007" for r in records)


def test_hadolint_all_rules_are_dl_or_sc():
    """hadolint embeds shellcheck for RUN lines, so both prefixes are valid
    and both must survive the adapter."""
    records = adapters.hadolint(fixture("hadolint.json"))
    assert all(r["rule"].startswith(("DL", "SC")) for r in records)


def test_hadolint_carries_column_only():
    """hadolint reports column but no end_line/end_column at all."""
    records = adapters.hadolint(fixture("hadolint.json"))
    dl3007 = next(r for r in records if r["rule"] == "DL3007")
    assert dl3007["column"] == 1
    assert dl3007.get("end_line", 0) == 0
    assert dl3007.get("end_column", 0) == 0


# --- yamllint ---------------------------------------------------------------


def test_yamllint_parses_parsable_format():
    records = adapters.yamllint(fixture("yamllint.txt"))
    assert_well_formed(records)
    assert any(r["rule"] == "document-start" for r in records)


def test_yamllint_skips_unparseable_lines():
    """The parsable format is line-oriented; a summary or banner line must be
    ignored rather than turning into a finding with an empty rule."""
    noise = "some banner line\n./a.yaml:1:1: [error] too many spaces (colons)\n\n"
    records = adapters.yamllint(noise)
    assert len(records) == 1
    assert records[0]["rule"] == "colons"


def test_yamllint_severity_mapping():
    records = adapters.yamllint(fixture("yamllint.txt"))
    assert {r["severity"] for r in records} <= VALID_SEVERITIES
    assert any(r["severity"] == "error" for r in records)


def test_yamllint_carries_column():
    """The parsable format's column was already captured by the regex and
    discarded -- ./bad.yaml:1:7 [error] too many spaces after colon."""
    records = adapters.yamllint(fixture("yamllint.txt"))
    colons = next(r for r in records if r["rule"] == "colons")
    assert colons["column"] == 7


# --- actionlint ---------------------------------------------------------


def test_actionlint_parses_bare_array():
    records = adapters.actionlint(fixture("actionlint.json"))
    assert_well_formed(records)
    # `needs: nonexistent-job` in the fixture's ci.yml.
    assert any(r["rule"] == "job-needs" for r in records)


def test_actionlint_snippet_drops_caret_line():
    """actionlint's `snippet` is source line + caret-underline; the caret
    line is not source text and would corrupt the finding's context."""
    records = adapters.actionlint(fixture("actionlint.json"))
    for r in records:
        assert "\n" not in r["snippet"]
        assert "^" not in r["snippet"]


def test_actionlint_has_no_severity_field_everything_is_error():
    records = adapters.actionlint(fixture("actionlint.json"))
    assert all(r["severity"] == "error" for r in records)


def test_actionlint_carries_column_and_end_column_but_no_end_line():
    """actionlint findings are always single-line -- `end_line` is not part
    of its output at all."""
    records = adapters.actionlint(fixture("actionlint.json"))
    job_needs = next(r for r in records if r["rule"] == "job-needs")
    assert job_needs["column"] == 3
    assert job_needs["end_column"] == 9
    assert job_needs.get("end_line", 0) == 0


# --- pylint ---------------------------------------------------------------


def test_pylint_parses_bare_array():
    records = adapters.pylint(fixture("pylint.json"))
    assert_well_formed(records)
    # `import os, sys` on one line in the fixture's app.py.
    assert any(r["rule"] == "C0410" for r in records)


def test_pylint_severity_mapping():
    records = adapters.pylint(fixture("pylint.json"))
    by_rule = {r["rule"]: r["severity"] for r in records}
    assert by_rule["C0410"] == "note"  # convention
    assert by_rule["W0123"] == "warning"  # eval-used


def test_pylint_column_is_zero_indexed_in_the_fixture():
    """pylint's column/endColumn come straight off astroid's
    col_offset/end_col_offset, which are 0-indexed -- unlike `line`/`endLine`,
    which are already 1-based. `if event == None:` (src/app.py:8) reports
    column=7, the 0-indexed position of the "e" in "event"; the adapter adds
    1 to both column fields to match GitHub's 1-based convention."""
    records = adapters.pylint(fixture("pylint.json"))
    c0121 = next(r for r in records if r["rule"] == "C0121")
    assert c0121["line"] == 8
    assert c0121["column"] == 8
    assert c0121["end_line"] == 8
    assert c0121["end_column"] == 21


# --- sqlfluff ---------------------------------------------------------------


def test_sqlfluff_flattens_files_to_violations():
    records = adapters.sqlfluff(fixture("sqlfluff.json"))
    assert_well_formed(records)
    assert all(r["path"] == "db/schema.sql" for r in records)
    assert any(r["rule"] == "CP01" for r in records)


def test_sqlfluff_warning_flag_maps_to_our_severity():
    """The fixture's violations are all formatting rules (`warning: false`),
    which map to `note`, not `error` -- sqlfluff has no error vocabulary of
    its own, and flattening these to error would fail a Check Run on a nit."""
    records = adapters.sqlfluff(fixture("sqlfluff.json"))
    assert records
    assert all(r["severity"] == "note" for r in records)


def test_sqlfluff_carries_position_fields():
    """sqlfluff's *_pos/*_no fields are already 1-indexed -- CP01 on
    db/schema.sql:2 ("select name,email ..." should be uppercase)."""
    records = adapters.sqlfluff(fixture("sqlfluff.json"))
    cp01 = next(r for r in records if r["rule"] == "CP01")
    assert cp01["line"] == 2
    assert cp01["column"] == 1
    assert cp01["end_line"] == 2
    assert cp01["end_column"] == 7


# --- biome ------------------------------------------------------------------


def test_biome_parses_diagnostics():
    records = adapters.biome(fixture("biome.json"))
    assert_well_formed(records)
    assert any(r["rule"] == "lint/suspicious/noDoubleEquals" for r in records)


def test_biome_uses_description_not_structured_message():
    """`message` is a list of markup fragments, not text; `description` is
    the plain-string rendering and is what belongs in a Finding."""
    records = adapters.biome(fixture("biome.json"))
    assert any(
        r["message"] == "Using == may be unsafe if you are relying on type coercion."
        for r in records
    )


def test_biome_derives_line_from_byte_offset():
    """biome's `location` has no line number field at all -- only a byte
    offset (`span`) into `location.sourceCode` -- so the adapter counts
    newlines to recover it."""
    records = adapters.biome(fixture("biome.json"))
    by_rule = {
        r["rule"]: r["line"] for r in records if r["rule"] == "lint/suspicious/noDoubleEquals"
    }
    assert by_rule["lint/suspicious/noDoubleEquals"] == 3


def test_biome_has_no_column_at_all():
    """biome's `location` carries only a byte-offset `span` into
    `sourceCode` -- no line/column grid at all, unlike every other adapter.
    `line` is derived by counting newlines before the span (see above);
    column/end_line/end_column have no equivalent to derive from and stay at
    the Finding default of 0."""
    records = adapters.biome(fixture("biome.json"))
    assert records
    for r in records:
        assert r.get("column", 0) == 0
        assert r.get("end_line", 0) == 0
        assert r.get("end_column", 0) == 0


# --- ast-grep -----------------------------------------------------------


def test_ast_grep_parses_bare_array():
    records = adapters.ast_grep(fixture("ast-grep.json"))
    assert_well_formed(records)
    assert any(r["rule"] == "no-eval" for r in records)


def test_ast_grep_line_is_zero_indexed_in_the_fixture():
    """`range.start.line` is 0-indexed; `return eval(event)` is line 10 in
    the fixture's app.py, reported as `range.start.line == 9`."""
    records = adapters.ast_grep(fixture("ast-grep.json"))
    assert any(r["line"] == 10 for r in records)


def test_ast_grep_column_is_also_zero_indexed_in_the_fixture():
    """`range.start.column`/`range.end.line`/`range.end.column` use the
    same 0-indexed convention as `range.start.line`: "    return
    eval(event)" reports start.column=11, the 0-indexed position of the "e"
    in "eval" -- so all three get the same +1 treatment `line` already
    gets."""
    records = adapters.ast_grep(fixture("ast-grep.json"))
    no_eval = next(r for r in records if r["rule"] == "no-eval")
    assert no_eval["column"] == 12
    assert no_eval["end_line"] == 10
    assert no_eval["end_column"] == 23


# --- regal --------------------------------------------------------------


def test_regal_parses_violations():
    records = adapters.regal(fixture("regal.json"))
    assert_well_formed(records)
    assert any(r["rule"] == "use-if" for r in records)


def test_regal_severity_mapping():
    records = adapters.regal(fixture("regal.json"))
    assert {r["severity"] for r in records} == {"error"}


def test_regal_carries_location_and_end_location():
    """regal's row/col fields (and location.end.row/col) are already
    1-indexed."""
    records = adapters.regal(fixture("regal.json"))
    mismatch = next(r for r in records if r["rule"] == "directory-package-mismatch")
    assert mismatch["column"] == 9
    assert mismatch["end_line"] == 1
    assert mismatch["end_column"] == 14


# --- vale ---------------------------------------------------------------


def test_vale_path_comes_from_the_dict_key():
    """vale's output is not an array: it's an object keyed by file path.
    There is no `path`/`file` field on the alert itself."""
    records = adapters.vale(fixture("vale.json"))
    assert_well_formed(records)
    assert any(r["path"] == "docs/readme.md" for r in records)


def test_vale_parses_alert_fields():
    records = adapters.vale(fixture("vale.json"))
    assert any(r["rule"] == "Vale.Repetition" for r in records)
    assert any(r["severity"] == "error" for r in records)


def test_vale_span_becomes_column_and_end_column():
    """`Span` is a [start, end] pair of 1-indexed column offsets on `Line` --
    "The the" (docs/readme.md:6) reports Span [1, 7], both inclusive
    positions on the line. There is no end_line: a vale alert never crosses
    a line."""
    records = adapters.vale(fixture("vale.json"))
    rep = next(r for r in records if r["rule"] == "Vale.Repetition")
    assert rep["column"] == 1
    assert rep["end_column"] == 7
    assert rep.get("end_line", 0) == 0


# --- flake8 -----------------------------------------------------------------


def test_flake8_parses_pinned_format():
    records = adapters.flake8(fixture("flake8.txt"))
    assert_well_formed(records)
    assert any(r["rule"] == "F401" for r in records)


def test_flake8_keeps_colons_in_message():
    """The pinned --format is colon-delimited and flake8 messages CONTAIN
    colons ("... should be 'if cond is None:'"). An unbounded split truncates
    the message at the first one."""
    records = adapters.flake8(fixture("flake8.txt"))
    e711 = [r for r in records if r["rule"] == "E711"]
    assert e711, "fixture should contain the None-comparison finding"
    assert e711[0]["message"].endswith("'if cond is None:'")


def test_flake8_pyflakes_codes_are_errors():
    """F-codes are real defects (undefined name, unused import); E/W are
    style. Flattening them to one severity is what makes a Check Run
    meaningless."""
    records = adapters.flake8(fixture("flake8.txt"))
    by_rule = {r["rule"]: r["severity"] for r in records}
    assert by_rule["F401"] == "error"
    assert by_rule["E401"] == "warning"


def test_flake8_carries_the_pinned_col_field():
    """The pinned --format includes %(col)d, already 1-indexed, which used
    to be parsed and discarded -- no end_line/end_column in this format."""
    records = adapters.flake8(fixture("flake8.txt"))
    e711 = next(r for r in records if r["rule"] == "E711")
    assert e711["column"] == 14
    assert e711.get("end_line", 0) == 0
    assert e711.get("end_column", 0) == 0


# --- checkmake --------------------------------------------------------------


def test_checkmake_parses_delimited_template():
    records = adapters.checkmake(fixture("checkmake.txt"))
    assert_well_formed(records)
    assert all(r["rule"] == "minphony" for r in records)


def test_checkmake_zero_line_is_preserved():
    """Whole-file rules report LineNumber 0, which is the contract's
    "no location" value -- not a missing field to be defaulted elsewhere."""
    records = adapters.checkmake(fixture("checkmake.txt"))
    assert all(r["line"] == 0 for r in records)


# --- dotenv-linter ----------------------------------------------------------


def test_dotenv_parses_and_skips_banner_and_summary():
    """Output is wrapped in a "Checking .env" header and a "Found N problems"
    footer; both must be skipped rather than becoming empty-rule findings."""
    records = adapters.dotenv_linter(fixture("dotenv.txt"))
    assert_well_formed(records)
    assert len(records) == 7
    assert all(r["rule"] and not r["rule"].startswith("Found") for r in records)


def test_dotenv_duplicated_key_outranks_style_rules():
    records = adapters.dotenv_linter(fixture("dotenv.txt"))
    sev = {r["rule"]: r["severity"] for r in records}
    assert sev["DuplicatedKey"] == "warning"
    assert sev["LowercaseKey"] == "note"


# --- buf --------------------------------------------------------------------


def test_buf_parses_jsonl_not_array():
    """buf --error-format=json emits JSON LINES; json.loads() over the whole
    payload raises."""
    import json as _json

    import pytest as _pytest

    with _pytest.raises(_json.JSONDecodeError):
        _json.loads(fixture("buf.json"))
    records = adapters.buf(fixture("buf.json"))
    assert_well_formed(records)
    assert any(r["rule"] == "PACKAGE_DIRECTORY_MATCH" for r in records)


def test_buf_carries_start_and_end_column():
    """buf's start_column/end_line/end_column are already 1-indexed."""
    records = adapters.buf(fixture("buf.json"))
    msg = next(r for r in records if r["rule"] == "MESSAGE_PASCAL_CASE")
    assert msg["column"] == 9
    assert msg["end_line"] == 3
    assert msg["end_column"] == 20


# --- trufflehog -------------------------------------------------------------


def test_trufflehog_parses_nested_path():
    records = adapters.trufflehog(fixture("trufflehog.jsonl"))
    assert_well_formed(records)
    assert records[0]["path"] == "src/config.py"
    assert records[0]["severity"] == "error"


def test_trufflehog_never_emits_the_secret():
    """`Raw` holds the detected credential. A finding is persisted, rendered
    in a Check Run and handed to an LLM -- putting the secret in the message
    leaks it into all three."""
    raw_secrets = [
        json.loads(line)["Raw"] for line in fixture("trufflehog.jsonl").splitlines() if line.strip()
    ]
    assert raw_secrets, "fixture should carry at least one raw secret"
    records = adapters.trufflehog(fixture("trufflehog.jsonl"))
    blob = json.dumps(records)
    for secret in raw_secrets:
        assert secret not in blob, "adapter leaked the detected credential"


def test_trufflehog_drops_git_internals():
    """trufflehog walks .git/objects, producing paths a reviewer cannot act
    on and the diff filter cannot match."""
    payload = fixture("trufflehog.jsonl")
    assert ".git/objects" in payload, "fixture should include a .git hit"
    records = adapters.trufflehog(payload)
    assert not any(".git/" in r["path"] for r in records)


# --- severity survives the SDK boundary -------------------------------------


@pytest.mark.parametrize(
    "name,fx",
    [
        ("shellcheck", "shellcheck.json"),
        ("hadolint", "hadolint.json"),
        ("pylint", "pylint.json"),
        ("trufflehog", "trufflehog.jsonl"),
        ("flake8", "flake8.txt"),
    ],
)
def test_adapter_severity_survives_from_records(name, fx):
    """Regression: `from_records` used to look every severity up in a
    `severity_map` no task passes, so an adapter's already-mapped value missed
    the (empty) map and silently became `default_severity`. Every tool
    flattened to `warning` -- trufflehog's committed credentials included, and
    since a check run only fails on `error`, no adapter-based tool could fail
    a build."""
    from pathlib import Path as _Path

    from runwhen_capability import Context as _Context

    records = getattr(adapters, name)(fixture(fx))
    ctx = _Context(capability="rw-checks", operation=name, workdir=_Path("."), credentials={})
    findings = ctx.findings.from_records(records, root=FIXTURES.parent / "sample-repo")

    expected = sorted(r["severity"] for r in records if r["path"])
    actual = sorted(f.severity for f in findings)
    assert actual == expected, f"{name}: severity was rewritten crossing the SDK boundary"


@pytest.mark.parametrize(
    "name,fx",
    [
        ("shellcheck", "shellcheck.json"),
        ("hadolint", "hadolint.json"),
        ("pylint", "pylint.json"),
        ("sqlfluff", "sqlfluff.json"),
        ("actionlint", "actionlint.json"),
        ("regal", "regal.json"),
        ("ast_grep", "ast-grep.json"),
        ("vale", "vale.json"),
        ("flake8", "flake8.txt"),
        ("yamllint", "yamllint.txt"),
        ("buf", "buf.json"),
    ],
)
def test_adapter_column_survives_from_records(name, fx):
    """Regression guard for the point of this change: an adapter's
    column/end_line/end_column must reach the Finding the same way `line`
    already does -- from_records() is the only place that can drop them.
    Every fixture path resolves under sample-repo, so from_records() drops
    nothing and findings line up with records positionally."""
    from pathlib import Path as _Path

    from runwhen_capability import Context as _Context

    records = getattr(adapters, name)(fixture(fx))
    ctx = _Context(capability="rw-checks", operation=name, workdir=_Path("."), credentials={})
    findings = ctx.findings.from_records(records, root=FIXTURES.parent / "sample-repo")

    assert len(findings) == len(records), f"{name}: a fixture finding was dropped"
    for r, f in zip(records, findings):
        assert f.column == r.get("column", 0), f"{name}: column dropped crossing the SDK boundary"
        assert f.end_line == r.get("end_line", 0), (
            f"{name}: end_line dropped crossing the SDK boundary"
        )
        assert f.end_column == r.get("end_column", 0), (
            f"{name}: end_column dropped crossing the SDK boundary"
        )


def test_trufflehog_secrets_are_errors_end_to_end():
    """A committed credential must reach `error`: the check-run conclusion is
    `failure` only when some finding is `error`, so a downgrade here means a
    live secret does not fail the build."""
    from pathlib import Path as _Path

    from runwhen_capability import Context as _Context

    records = adapters.trufflehog(fixture("trufflehog.jsonl"))
    ctx = _Context(
        capability="rw-checks", operation="trufflehog", workdir=_Path("."), credentials={}
    )
    findings = ctx.findings.from_records(records, root=FIXTURES.parent / "sample-repo")
    assert findings and all(f.severity == "error" for f in findings)


# --- column/end_line/end_column survive the SARIF path too ------------------


def test_sarif_parse_picks_up_start_and_end_column():
    """ctx.sarif.parse must carry region.startColumn/endColumn/endLine the
    same way it already carries startLine -- ruff's real captured SARIF
    (not the hand-written tests/fixtures/ruff.sarif in test_sarif.py). Its
    artifactLocation.uri is an absolute file:// path from the machine that
    captured it, so `root="/"` is used to resolve it rather than dropping it
    as outside-worktree -- only the region fields are under test here."""
    from pathlib import Path as _Path

    from runwhen_capability import Context as _Context

    ctx = _Context(capability="rw-checks", operation="ruff", workdir=_Path("."), credentials={})
    findings = ctx.sarif.parse(fixture("ruff.sarif"), root="/")

    assert findings
    first = findings[0]
    assert first.column > 0
    assert first.end_line > 0
    assert first.end_column > 0
