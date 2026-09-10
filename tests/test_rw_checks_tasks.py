"""capabilities/rw-checks/tasks.py's ruff/gitleaks tool-failure handling.

PROD-1416 review: ctx.run()'s returncode was never checked, so a tool that
crashed but still emitted well-formed empty SARIF on stdout read as a clean,
0-findings scan -- FAILURE-POLICY.md's flagship row, reproduced here before
the fix (see the PR description) and pinned by
test_*_crash_with_empty_sarif_stdout_is_not_reported_as_clean below.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from runwhen_capability import Context
from runwhen_capability.loader import load_capability

FIXTURES = Path(__file__).parent / "fixtures"
CAPABILITY_DIR = Path(__file__).parent.parent / "capabilities" / "rw-checks"

EMPTY_SARIF = '{"version": "2.1.0", "runs": []}'


class FakeProc:
    def __init__(self, returncode: int, stdout: str, stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _load_task(name: str):
    capability = load_capability(CAPABILITY_DIR)
    return capability.registry.tasks[name].func


def _make_ctx(operation: str) -> Context:
    return Context(capability="rw-checks", operation=operation, workdir=FIXTURES / "repo")


# --- ruff --------------------------------------------------------------


def test_ruff_crash_with_empty_sarif_stdout_is_not_reported_as_clean():
    """The exact bug: returncode >= 2 (a ruff crash) with well-formed empty
    SARIF on stdout must raise, not return findings=[]/truncated=False."""
    ruff = _load_task("ruff")
    ctx = _make_ctx("ruff")
    ctx.run = lambda argv, cwd=None: FakeProc(2, EMPTY_SARIF, "ruff: internal error: crash\n")

    with pytest.raises(RuntimeError) as exc_info:
        ruff(ctx, tree=FIXTURES / "repo", changed=None)
    assert "2" in str(exc_info.value)
    assert "internal error: crash" in str(exc_info.value)


def test_ruff_exit_1_with_findings_is_the_normal_case_not_a_failure():
    """ruff's exit code 1 means "findings were found" -- the ordinary case
    on a real PR -- and must not be raised as a tool failure."""
    ruff = _load_task("ruff")
    ctx = _make_ctx("ruff")
    text = (FIXTURES / "ruff.sarif").read_text()
    ctx.run = lambda argv, cwd=None: FakeProc(1, text, "")

    result = ruff(ctx, tree=FIXTURES / "repo", changed=None)

    assert len(result["findings"].findings) == 2


def test_ruff_exit_0_clean_scan_is_unaffected():
    ruff = _load_task("ruff")
    ctx = _make_ctx("ruff")
    ctx.run = lambda argv, cwd=None: FakeProc(0, EMPTY_SARIF, "")

    result = ruff(ctx, tree=FIXTURES / "repo", changed=None)

    assert result["findings"].findings == []
    assert result["findings"].truncated is False


def test_ruff_stderr_is_truncated_in_the_raised_error():
    ruff = _load_task("ruff")
    ctx = _make_ctx("ruff")
    huge_stderr = "x" * 10_000
    ctx.run = lambda argv, cwd=None: FakeProc(2, EMPTY_SARIF, huge_stderr)

    with pytest.raises(RuntimeError) as exc_info:
        ruff(ctx, tree=FIXTURES / "repo", changed=None)
    assert len(str(exc_info.value)) < 10_000


# --- gitleaks ------------------------------------------------------------


def test_gitleaks_crash_with_empty_sarif_stdout_is_not_reported_as_clean():
    """gitleaks is invoked with --exit-code 0 specifically so findings never
    set a nonzero code -- any nonzero code here is the tool itself failing."""
    gitleaks = _load_task("gitleaks")
    ctx = _make_ctx("gitleaks")
    ctx.run = lambda argv, cwd=None: FakeProc(1, EMPTY_SARIF, "gitleaks: fatal: crash\n")

    with pytest.raises(RuntimeError) as exc_info:
        gitleaks(ctx, tree=FIXTURES / "repo")
    assert "1" in str(exc_info.value)
    assert "fatal: crash" in str(exc_info.value)


def test_gitleaks_exit_0_with_findings_is_the_normal_case():
    gitleaks = _load_task("gitleaks")
    ctx = _make_ctx("gitleaks")
    text = (FIXTURES / "gitleaks.sarif").read_text()
    ctx.run = lambda argv, cwd=None: FakeProc(0, text, "")

    result = gitleaks(ctx, tree=FIXTURES / "repo")

    assert len(result["findings"].findings) == 1
