"""tools/_common.py unit tests: the `Skip`/`gate()`/`gated()` contract
(rw-1416 finding 1), the never-empty `unsafe_config_finding` (finding 3),
the CI-skip regex/comment-strip (finding 4), the check-failed wiring
(finding 2), and the single-walk-per-tree cache (finding 6).
"""

from __future__ import annotations

import pathlib
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


# --- Skip / gate() / gated() -------------------------------------------------


class _Mod:
    """A minimal stand-in for a tool module -- only the attributes gate()
    reads."""

    FILES: tuple[str, ...] = ()
    CONFIG = "optional"
    CI_BINARY: str | None = None
    GUARD = None

    @staticmethod
    def detect(tree: Path) -> list[Path]:
        return []


def test_gate_returns_none_when_nothing_skips(tmp_path):
    assert _common.gate(tmp_path, _Mod) is None


def test_gate_skips_on_missing_files(tmp_path):
    class Mod(_Mod):
        FILES = ("*.py",)

    skip = _common.gate(tmp_path, Mod)
    assert skip == _common.Skip("no matching files")
    assert skip.unsafe is False


def test_gate_skips_when_config_required_and_absent(tmp_path):
    class Mod(_Mod):
        CONFIG = "required"

    skip = _common.gate(tmp_path, Mod)
    assert skip is not None
    assert skip.reason == "not configured in this repository"
    assert skip.unsafe is False


def test_gate_skips_when_ci_already_runs(tmp_path):
    write(tmp_path, ".github/workflows/ci.yml", "- run: ruff check .\n")

    class Mod(_Mod):
        CI_BINARY = "ruff"

    skip = _common.gate(tmp_path, Mod)
    assert skip is not None
    assert "ruff" in skip.reason
    assert skip.unsafe is False


def test_gate_guard_refusal_is_unsafe_and_checked_first(tmp_path):
    """The guard runs BEFORE the files gate -- a refusal must win even when
    FILES would also have skipped the tool."""

    class Mod(_Mod):
        FILES = ("*.py",)  # would also skip -- no .py files in tmp_path
        GUARD = staticmethod(lambda tree: "config.yaml: sets something dangerous")

    skip = _common.gate(tmp_path, Mod)
    assert skip == _common.Skip("config.yaml: sets something dangerous", unsafe=True)


def test_gated_runs_when_gate_is_none(tmp_path):
    findings, stop = _common.gated(_ctx(tmp_path), tmp_path, _Mod)
    assert findings == []
    assert stop is False


def test_gated_stops_silently_on_an_ordinary_skip(tmp_path):
    class Mod(_Mod):
        FILES = ("*.py",)

    findings, stop = _common.gated(_ctx(tmp_path), tmp_path, Mod)
    assert findings == []
    assert stop is True


def test_gated_surfaces_a_finding_on_a_guard_refusal(tmp_path):
    class Mod(_Mod):
        GUARD = staticmethod(
            lambda tree: ".pylintrc: sets init-hook, which executes arbitrary Python"
        )

    findings, stop = _common.gated(_ctx(tmp_path), tmp_path, Mod)
    assert stop is True
    assert len(findings) == 1
    assert findings[0].rule == "rw-checks/unsafe-config"
    assert findings[0].severity == "warning"


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


# --- check_exit / run_to_file / check_failed_finding -------------------------


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


def test_run_to_file_raises_on_unexpected_exit_code(tmp_path):
    class Mod:
        EXPECT_EXIT = (0,)

    report = tmp_path / "out.sarif"
    report.write_text('{"runs": []}')
    ctx = _ctx(tmp_path, returncode=1, stderr="boom")

    with pytest.raises(_common.ToolFailed) as excinfo:
        _common.run_to_file(ctx, ["tool"], tmp_path, report, Mod)
    assert excinfo.value.exit_code == 1


def test_run_to_file_raises_on_missing_report(tmp_path):
    class Mod:
        EXPECT_EXIT = (0,)

    report = tmp_path / "never-written.sarif"
    ctx = _ctx(tmp_path, returncode=0)

    with pytest.raises(_common.ToolFailed):
        _common.run_to_file(ctx, ["tool"], tmp_path, report, Mod)


def test_run_to_file_raises_on_empty_report(tmp_path):
    """An empty report used to be silently read as 'the tool found nothing'
    -- exactly as wrong when the tool never ran at all."""

    class Mod:
        EXPECT_EXIT = (0,)

    report = tmp_path / "empty.sarif"
    report.write_text("   \n")
    ctx = _ctx(tmp_path, returncode=0)

    with pytest.raises(_common.ToolFailed):
        _common.run_to_file(ctx, ["tool"], tmp_path, report, Mod)


def test_run_to_file_succeeds_and_returns_the_report_text(tmp_path):
    class Mod:
        EXPECT_EXIT = (0,)

    report = tmp_path / "ok.sarif"
    report.write_text('{"runs": []}')
    ctx = _ctx(tmp_path, returncode=0)

    assert _common.run_to_file(ctx, ["tool"], tmp_path, report, Mod) == '{"runs": []}'


# --- the tree is walked once, not once per glob per tool ---------------------


def test_the_tree_is_walked_once_across_many_gate_calls(tmp_path, monkeypatch):
    write(tmp_path, "a.py", "x = 1\n")
    write(tmp_path, "conf.yaml", "key: value\n")

    calls = {"n": 0}
    original_rglob = pathlib.Path.rglob

    def counting_rglob(self, pattern):
        calls["n"] += 1
        return original_rglob(self, pattern)

    monkeypatch.setattr(pathlib.Path, "rglob", counting_rglob)

    class ModA(_Mod):
        FILES = ("*.py",)

    class ModB(_Mod):
        FILES = ("*.md",)
        CONFIG = "required"

        @staticmethod
        def detect(tree):
            return _common.config_files(tree, "conf.yaml")

    # 22 tools' worth of gate() calls against the SAME tree, mixing
    # find_files (FILES) and config_files (detect()) callers.
    for mod in (ModA, ModB, ModA, ModB, ModA):
        _common.gate(tmp_path, mod)

    assert calls["n"] == 1, f"expected exactly one walk of {tmp_path}, got {calls['n']}"
