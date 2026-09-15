"""End-to-end: an oversized tool output, through the REAL rw-checks
capability's `ruff` (stdout path) and `gitleaks` (report-file path) tasks,
all the way to host.run_request's TaskResult -- not a synthetic fixture
capability, so this proves the actual wiring a pod hits: OutputTooLargeError
(ctx.run's stdout cap, tools/_common.py's run_to_file stat guard) surfaces
as a disclosed `TaskResult(status="failed")`, per FAILURE-POLICY.md, and a
sibling task in the same request is unaffected.

Both tasks are chosen because their gate() never skips regardless of
`tree`'s contents (ruff needs one *.py file present; gitleaks needs
nothing at all -- FILES=(), CONFIG="optional", CI_BINARY=None, GUARD=None),
so a bare tmp_path tree plus a stubbed binary on PATH is enough to reach
ctx.run without any real git checkout.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from runwhen_capability.host import run_request
from runwhen_capability.loader import load_capability
from runwhen_capability.models import RequestEnvelope
from runwhen_capability.sarif import SARIF_BYTE_BUDGET

CAPABILITY_DIR = Path(__file__).parent.parent / "capabilities" / "rw-checks"


def _stub(tmp_path: Path, name: str, script: str) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    path = bin_dir / name
    path.write_text(f"#!{sys.executable}\n{script}")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return bin_dir


def _prepend_path(monkeypatch, bin_dir: Path) -> None:
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")


def test_ruff_stdout_overflow_fails_only_that_task(tmp_path, monkeypatch):
    """ruff writes its SARIF straight to stdout (tools/ruff.py: `ctx.sarif.
    parse(proc.stdout, ...)`) -- ctx.run's own stdout cap is what has to
    catch this. actionlint runs in the same request, against the same bare
    tree (no .github/workflows/*.yml -- its FILES gate skips it cleanly,
    `status: ok`, empty findings), proving one task's refusal does not cost
    the rest of the request."""
    (tmp_path / "a.py").write_text("import os\n")  # satisfies ruff's FILES=("*.py",) gate
    over_budget = SARIF_BYTE_BUDGET + (5 * 1024 * 1024)
    bin_dir = _stub(
        tmp_path,
        "ruff",
        f"import sys\nsys.stdout.write('a' * {over_budget})\nsys.exit(0)\n",
    )
    _prepend_path(monkeypatch, bin_dir)

    capability = load_capability(CAPABILITY_DIR)
    request = RequestEnvelope.model_validate(
        {
            "version": 1,
            "tasks": [
                {"task": "ruff", "inputs": {"tree": tmp_path, "changed": None}},
                {"task": "actionlint", "inputs": {"tree": tmp_path, "changed": None}},
            ],
        }
    )

    result = run_request(capability, request, credentials={}, scope_dir=tmp_path)

    by_task = {t.task: t for t in result.tasks}
    assert by_task["ruff"].status == "failed"
    assert "check output too large to process" in by_task["ruff"].error

    assert by_task["actionlint"].status == "ok"


def test_gitleaks_report_file_overflow_fails_only_that_task(tmp_path, monkeypatch):
    """gitleaks writes its SARIF to a report FILE, read back by
    tools/_common.py's run_to_file() -- the stat-before-read guard is what
    has to catch this, not ctx.run's stdout cap (the stub writes almost
    nothing to stdout). The stub locates the report path the same way the
    real gitleaks argv does: the argument right after `--report-path`."""
    over_budget = SARIF_BYTE_BUDGET + (5 * 1024 * 1024)
    bin_dir = _stub(
        tmp_path,
        "gitleaks",
        "import sys\n"
        "argv = sys.argv\n"
        "report = argv[argv.index('--report-path') + 1]\n"
        f"open(report, 'w').write('a' * {over_budget})\n"
        "sys.exit(0)\n",
    )
    _prepend_path(monkeypatch, bin_dir)

    capability = load_capability(CAPABILITY_DIR)
    request = RequestEnvelope.model_validate(
        {
            "version": 1,
            "tasks": [
                {"task": "gitleaks", "inputs": {"tree": tmp_path, "changed": None}},
                {"task": "actionlint", "inputs": {"tree": tmp_path, "changed": None}},
            ],
        }
    )

    result = run_request(capability, request, credentials={}, scope_dir=tmp_path)

    by_task = {t.task: t for t in result.tasks}
    assert by_task["gitleaks"].status == "failed"
    assert "check output too large to process" in by_task["gitleaks"].error

    assert by_task["actionlint"].status == "ok"
