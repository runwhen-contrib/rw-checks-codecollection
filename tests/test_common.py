"""tools/_common.py unit tests: the never-empty `unsafe_config_finding`
(rw-1416 finding 3), the CI-skip regex/comment-strip (finding 4), and the
check-failed/check_exit wiring (finding 2).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "capabilities" / "rw-checks"))

from runwhen_capability import Context  # noqa: E402

from tools import _common  # noqa: E402


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class _FakeContext(Context):
    """`.run()` returns a canned CompletedProcess instead of invoking a real
    subprocess -- these tests exercise the exit-code/report wiring, not any
    particular tool's binary."""

    def __init__(self, *args, returncode: int = 0, stdout: str = "", stderr: str = "", **kwargs):
        super().__init__(*args, **kwargs)
        self._returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    def run(self, argv, cwd=None, timeout=None):
        return subprocess.CompletedProcess(
            argv, self._returncode, stdout=self._stdout, stderr=self._stderr
        )


def _ctx(tmp_path: Path, **kwargs) -> _FakeContext:
    return _FakeContext(capability="rw-checks", operation="x", workdir=tmp_path, **kwargs)


# --- unsafe_config_finding never returns empty -------------------------------


def test_unsafe_config_finding_normal_path_survives(tmp_path):
    findings = _common.unsafe_config_finding(
        _ctx(tmp_path), tmp_path, ".pylintrc: sets init-hook, which executes arbitrary Python"
    )
    assert len(findings) == 1
    assert findings[0].path == ".pylintrc"


def test_unsafe_config_finding_absolute_path_falls_back(tmp_path):
    """Verified bug: an absolute path used to be dropped entirely by
    `from_records`' own normalisation, silently turning a security refusal
    into zero findings."""
    findings = _common.unsafe_config_finding(
        _ctx(tmp_path), tmp_path, "/etc/passwd: sets something"
    )
    assert len(findings) == 1
    assert findings[0].path == _common.WHOLE_REPO_PATH
    assert "/etc/passwd" in findings[0].message


def test_unsafe_config_finding_no_colon_falls_back(tmp_path):
    findings = _common.unsafe_config_finding(_ctx(tmp_path), tmp_path, "something bad happened")
    assert len(findings) == 1


def test_unsafe_config_finding_empty_reason_falls_back(tmp_path):
    findings = _common.unsafe_config_finding(_ctx(tmp_path), tmp_path, "")
    assert len(findings) == 1
    assert findings[0].path == _common.WHOLE_REPO_PATH


# --- ci_already_runs regex ---------------------------------------------------


@pytest.mark.parametrize(
    "line,binary,should_match",
    [
        # The most common way a repo runs ruff in CI -- a hyphenated action
        # name. The old trailing boundary `(?![\w-])` missed this.
        ("- uses: astral-sh/ruff-action@v1", "ruff", True),
        ("- run: ruff check .", "ruff", True),
        # A comment describing the ABSENCE of a check must never satisfy it.
        ("# we dropped ruff last year", "ruff", False),
        ("- run: npx @biomejs/biome ci .", "biome", True),
    ],
)
def test_ci_already_runs_matches_exactly_these_cases(tmp_path, line, binary, should_match):
    write(tmp_path, ".github/workflows/ci.yml", line + "\n")
    result = _common.ci_already_runs(tmp_path, binary)
    assert (result is not None) == should_match


def test_ci_already_runs_leading_boundary_still_excludes_substring_names(tmp_path):
    write(tmp_path, ".github/workflows/ci.yml", "- run: myruff check .\n")
    assert _common.ci_already_runs(tmp_path, "ruff") is None


def test_ci_already_runs_comment_after_real_code_is_stripped(tmp_path):
    write(
        tmp_path,
        ".github/workflows/ci.yml",
        "- run: echo hi  # ruff replaced by something else\n",
    )
    assert _common.ci_already_runs(tmp_path, "ruff") is None


# --- check_exit / check_failed_finding ---------------------------------------


def test_check_failed_finding_is_never_empty_and_well_formed(tmp_path):
    findings = _common.check_failed_finding(_ctx(tmp_path), tmp_path, "pylint", 137, "killed")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "rw-checks/check-failed"
    assert f.severity == "warning"
    assert f.path == _common.WHOLE_REPO_PATH
    assert f.line == 0
    assert "pylint" in f.message
    assert "137" in f.message
    assert "killed" in f.message


def test_check_exit_within_expect_exit_is_none(tmp_path):
    class Mod:
        EXPECT_EXIT = (0, 1)

    ctx = _ctx(tmp_path, returncode=1)
    proc = ctx.run(["tool"])
    assert _common.check_exit(ctx, tmp_path, "tool", proc, Mod) is None


def test_check_exit_outside_expect_exit_returns_a_finding(tmp_path):
    class Mod:
        EXPECT_EXIT = (0, 1)

    ctx = _ctx(tmp_path, returncode=137, stderr="killed")
    proc = ctx.run(["tool"])
    findings = _common.check_exit(ctx, tmp_path, "tool", proc, Mod)
    assert len(findings) == 1
    assert findings[0].rule == "rw-checks/check-failed"


# --- toml_table never raises (H6) --------------------------------------------


def test_toml_table_recursion_error_returns_none_not_raise(tmp_path):
    """`toml_table` is called during ELIGIBILITY (`_plan._counts`), before any
    guard runs -- a config that blows tomllib's own parser recursion must
    come back as "not a config" (None), not escape as a RecursionError and
    crash the whole task."""
    n = 5000
    path = write(tmp_path, "pyproject.toml", "x = " + "[" * n + "1" + "]" * n + "\n")
    assert _common.toml_table(path, "tool", "sqlfluff") is None


def test_toml_table_missing_file_returns_none(tmp_path):
    assert _common.toml_table(tmp_path / "nope.toml", "tool") is None


def test_toml_table_malformed_returns_none(tmp_path):
    path = write(tmp_path, "pyproject.toml", "not [[[ valid toml\n===\n")
    assert _common.toml_table(path, "tool") is None
