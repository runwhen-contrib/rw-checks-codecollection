"""Context.run(): the real subprocess path (context.py), exercised against
stub binaries rather than mocked -- this is exactly the boundary
OutputTooLargeError guards, so it needs a real Popen/pipe/thread stack under
test, not a canned CompletedProcess (see tests/test_common.py's
_FakeContext, which deliberately bypasses all of this).
"""

from __future__ import annotations

import logging
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from runwhen_capability import Context
from runwhen_capability.errors import OutputTooLargeError
from runwhen_capability.sarif import SARIF_BYTE_BUDGET


def _stub(tmp_path: Path, name: str, script: str) -> Path:
    """Write an executable Python stub named `name` into its own directory
    (never tmp_path itself, which is also `ctx.workdir`/`cwd` for these
    tests) and return that directory, so a test can prepend it to PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    path = bin_dir / name
    path.write_text(f"#!{sys.executable}\n{script}")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return bin_dir


def _ctx(tmp_path: Path) -> Context:
    return Context(capability="rw-checks", operation="x", workdir=tmp_path)


def _prepend_path(monkeypatch: pytest.MonkeyPatch, bin_dir: Path) -> None:
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")


def test_normal_small_output_round_trips_exactly(tmp_path, monkeypatch, caplog):
    """The existing contract, unchanged for the common case: returncode,
    stdout, and stderr (forwarded line-by-line to ctx.log at INFO, per the
    docstring) all come back exactly as the old subprocess.run(capture_
    output=True) implementation would have produced them."""
    bin_dir = _stub(
        tmp_path,
        "tool",
        "import sys\nsys.stdout.write('hello\\n')\nsys.stderr.write('world\\n')\nsys.exit(3)\n",
    )
    _prepend_path(monkeypatch, bin_dir)
    caplog.set_level(logging.INFO)

    ctx = _ctx(tmp_path)
    proc = ctx.run(["tool"])

    assert proc.returncode == 3
    assert proc.stdout == "hello\n"
    assert proc.stderr == "world\n"
    assert "tool: world" in caplog.text


def test_oversized_stdout_is_refused_and_the_process_is_killed(tmp_path, monkeypatch):
    """The core fix: a tool that emits more than SARIF_BYTE_BUDGET of
    stdout must be killed WHILE it is still writing, not read to
    completion and rejected afterward -- proven here by a marker file the
    stub only writes AFTER its (oversized) stdout write returns. If the
    process were allowed to run to completion, the marker would exist;
    OutputTooLargeError proves it does not."""
    marker = tmp_path / "completed"
    over_budget = SARIF_BYTE_BUDGET + (10 * 1024 * 1024)  # 10 MiB past budget
    bin_dir = _stub(
        tmp_path,
        "tool",
        "import sys\n"
        f"sys.stdout.write('a' * {over_budget})\n"
        "sys.stdout.flush()\n"
        f"open({str(marker)!r}, 'w').write('done')\n"
        "sys.exit(0)\n",
    )
    _prepend_path(monkeypatch, bin_dir)

    ctx = _ctx(tmp_path)
    with pytest.raises(OutputTooLargeError) as exc_info:
        ctx.run(["tool"])

    assert "check output too large to process: >" in str(exc_info.value)
    assert "bytes" in str(exc_info.value)
    assert not marker.exists(), "the tool ran to completion instead of being killed early"


def test_oversized_stderr_is_truncated_not_fatal(tmp_path, monkeypatch):
    """stderr gets its own, much smaller budget (_STDERR_BYTE_BUDGET) --
    exceeding it truncates and annotates .stderr, but does not raise or
    kill the process: stdout (the actual findings payload) is unaffected
    and the tool's real exit code still comes back."""
    over_stderr_budget = 2 * 1024 * 1024  # over the 1 MiB stderr cap, under SARIF_BYTE_BUDGET
    bin_dir = _stub(
        tmp_path,
        "tool",
        "import sys\n"
        "sys.stdout.write('ok\\n')\n"
        f"sys.stderr.write('e' * {over_stderr_budget})\n"
        "sys.exit(0)\n",
    )
    _prepend_path(monkeypatch, bin_dir)

    ctx = _ctx(tmp_path)
    proc = ctx.run(["tool"])

    assert proc.returncode == 0
    assert proc.stdout == "ok\n"
    assert proc.stderr.startswith("e" * 100)
    assert "truncated" in proc.stderr
    # Capped well under what was written -- the exact bound isn't load-bearing,
    # just that it is nowhere near the full 2 MiB the stub emitted.
    assert len(proc.stderr) < over_stderr_budget


def test_both_pipes_full_at_once_does_not_deadlock(tmp_path, monkeypatch):
    """Writes enough to BOTH stdout and stderr to exceed a typical single
    pipe buffer (~64 KiB) on each -- neither over its own budget, so this
    must complete normally. A version that only drained one stream while
    blocking on `wait()` would hang here: the child blocks writing to
    the full, undrained pipe, and the parent blocks waiting for a process
    that is blocked on it. The `timeout` below is the regression signal --
    it must not fire."""
    chunk = "x" * (256 * 1024)  # 256 KiB, several pipe-buffers' worth
    bin_dir = _stub(
        tmp_path,
        "tool",
        f"import sys\nsys.stdout.write({chunk!r})\nsys.stderr.write({chunk!r})\nsys.exit(0)\n",
    )
    _prepend_path(monkeypatch, bin_dir)

    ctx = _ctx(tmp_path)
    proc = ctx.run(["tool"], timeout=15)

    assert proc.returncode == 0
    assert len(proc.stdout) == len(chunk)


def test_timeout_still_raises_timeout_expired(tmp_path, monkeypatch):
    """Unchanged behaviour: DEFAULT_RUN_TIMEOUT (or an explicit `timeout`)
    still raises subprocess.TimeoutExpired, not OutputTooLargeError or
    anything else -- a genuine hang must stay distinguishable from an
    oversized-output refusal."""
    bin_dir = _stub(tmp_path, "tool", "import time\ntime.sleep(5)\n")
    _prepend_path(monkeypatch, bin_dir)

    ctx = _ctx(tmp_path)
    with pytest.raises(subprocess.TimeoutExpired):
        ctx.run(["tool"], timeout=0.3)
