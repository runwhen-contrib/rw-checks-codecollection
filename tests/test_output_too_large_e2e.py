"""End-to-end: an oversized tool output, through the REAL rw-checks
capability's `ruff` (stdout path) and `gitleaks` (report-file path) tasks,
all the way to host.run_request's TaskResult -- not a synthetic fixture
capability, so this proves the actual wiring a pod hits: OutputTooLargeError
(ctx.run's stdout cap, tools/_runner.py's run_to_file stat guard) surfaces
as a disclosed `TaskResult(status="failed")`, per FAILURE-POLICY.md, and a
sibling task in the same request is unaffected.

Both tasks are reached with an explicit `changed` list, because checks are
diff-scoped: `changed: None` means no diff and every check skips without
running. ruff additionally needs a config present (CONFIG="required"), so
the tree carries a ruff.toml; gitleaks takes every changed file
(FILES=(), CONFIG="optional", CI_BINARY=None, GUARD=None). A tmp_path tree
plus a stubbed binary on PATH is then enough to reach ctx.run without any
real git checkout.
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
    (tmp_path / "ruff.toml").write_text("line-length = 100\n")  # ruff's CONFIG is "required"
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
                {"task": "ruff", "inputs": {"tree": tmp_path, "changed": ["a.py"]}},
                {"task": "actionlint", "inputs": {"tree": tmp_path, "changed": ["a.py"]}},
            ],
        }
    )

    result = run_request(capability, request, credentials={}, scope_dir=tmp_path)

    by_task = {t.task: t for t in result.tasks}
    assert by_task["ruff"].status == "failed"
    assert "check output too large to process" in by_task["ruff"].error
    # B3: ">N bytes" (a lower bound) is the shape ONLY ctx.run's incremental
    # stdout cap produces (context.py:318) -- sarif.py's own post-
    # materialisation guard reports an exact count instead, with no ">",
    # so this line alone tells the two apart. Deleting ctx.run's cap would
    # still leave this task "failed" with the same message PREFIX (ruff's
    # full stdout would reach ctx.sarif.parse, which raises on it too) --
    # only this ">" proves it was caught while still streaming in.
    assert ">" in by_task["ruff"].error

    assert by_task["actionlint"].status == "ok"


def test_gitleaks_report_file_overflow_fails_only_that_task(tmp_path, monkeypatch):
    """gitleaks writes its SARIF to a report FILE, read back by
    tools/_runner.py's run_to_file() -- the stat-before-read guard is what
    has to catch this, not ctx.run's stdout cap (the stub writes almost
    nothing to stdout). The stub locates the report path the same way the
    real gitleaks argv does: the argument right after `--report-path`."""
    (tmp_path / "a.txt").write_text("hello\n")
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

    # B3: the message text alone does not tell this guard apart from
    # sarif.py's own post-materialisation size check (SarifClient.parse
    # raises the SAME "check output too large to process: N bytes" once a
    # fully-read, over-budget report reaches it) -- deleting _runner.py's
    # `report.stat()` guard left the suite green for exactly that reason.
    # Tracking Path.read_text on the report file specifically proves the
    # stat guard refused BEFORE the file was ever read into memory, which
    # is the property that guard exists for.
    report_reads: list[Path] = []
    real_read_text = Path.read_text

    def tracking_read_text(self, *args, **kwargs):
        if self.name == "gitleaks.sarif":
            report_reads.append(self)
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", tracking_read_text)

    capability = load_capability(CAPABILITY_DIR)
    request = RequestEnvelope.model_validate(
        {
            "version": 1,
            "tasks": [
                {"task": "gitleaks", "inputs": {"tree": tmp_path, "changed": ["a.txt"]}},
                {"task": "actionlint", "inputs": {"tree": tmp_path, "changed": ["a.txt"]}},
            ],
        }
    )

    result = run_request(capability, request, credentials={}, scope_dir=tmp_path)

    by_task = {t.task: t for t in result.tasks}
    assert by_task["gitleaks"].status == "failed"
    assert "check output too large to process" in by_task["gitleaks"].error
    assert report_reads == [], "the oversized report was read into memory before being refused"

    assert by_task["actionlint"].status == "ok"
