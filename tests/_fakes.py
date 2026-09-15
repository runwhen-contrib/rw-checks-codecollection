"""A Context whose `run` records argv instead of executing tools."""

from __future__ import annotations

import subprocess
from pathlib import Path

from runwhen_capability import Context


class RecordingContext(Context):
    def __init__(
        self, tmp_path: Path, outputs: dict[str, str] | None = None, returncode: int = 0
    ) -> None:
        super().__init__(capability="rw-checks", operation="test", workdir=tmp_path / "work")
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.outputs = outputs or {}
        self.returncode = returncode
        self.calls: list[dict] = []

    def run(self, argv, cwd=None, timeout=None, env=None):  # noqa: ARG002
        self.calls.append(
            {"argv": list(argv), "cwd": Path(cwd) if cwd else None, "env": dict(env or {})}
        )
        stdout = self.outputs.get(argv[0], "")
        if "--report-path" in argv:
            Path(argv[argv.index("--report-path") + 1]).write_text(stdout)
            stdout = ""
        if "--output-file-path" in argv:
            out = Path(argv[argv.index("--output-file-path") + 1])
            out.mkdir(parents=True, exist_ok=True)
            (out / "results_sarif.sarif").write_text(self.outputs.get(argv[0], ""))
            stdout = "banner"
        return subprocess.CompletedProcess(argv, self.returncode, stdout, "")
