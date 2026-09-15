"""The `check` phase plumbing: run a planned invocation on exactly its files and
turn tool output into repo-relative findings. DIFF-SCOPED-CHECKS.md §4 and §6."""

from __future__ import annotations

import os
import shutil
import urllib.error
import urllib.request
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from . import _common
from ._plan import Invocation

MAX_BATCH_FILES = 200
MAX_BATCH_ARGV_BYTES = 64 * 1024


def batches(files: Sequence[str]) -> list[tuple[str, ...]]:
    out: list[tuple[str, ...]] = []
    current: list[str] = []
    size = 0
    for f in files:
        n = len(f.encode())
        if current and (len(current) >= MAX_BATCH_FILES or size + n > MAX_BATCH_ARGV_BYTES):
            out.append(tuple(current))
            current, size = [], 0
        current.append(f)
        size += n
    if current:
        out.append(tuple(current))
    return out


def tool_env(ctx: Any) -> dict[str, str]:
    """The root filesystem is read-only: buf (`mkdir /.cache`), tflint (plugin
    init needs a writable HOME) and pylint (no usable temp dir) all fail without this."""
    base = Path(ctx.workdir) / ".tool-home"
    env = {}
    for key, sub in (("HOME", "home"), ("XDG_CACHE_HOME", "cache"), ("TMPDIR", "tmp")):
        (base / sub).mkdir(parents=True, exist_ok=True)
        env[key] = str(base / sub)
    return env


def cwd_path(tree: Path, inv: Invocation) -> Path:
    return tree / inv.cwd if inv.cwd else tree


def _relative(path: str, cwd: str) -> str:
    return PurePosixPath(path).relative_to(cwd).as_posix() if cwd else path


def files_arg(inv: Invocation) -> list[str]:
    return [_relative(f, inv.cwd) for f in inv.files]


def config_arg(inv: Invocation) -> str | None:
    return _relative(inv.config, inv.cwd) if inv.config else None


def run(ctx: Any, argv: list[str], *, cwd: Path, env: dict[str, str] | None = None):
    return ctx.run(argv, cwd=cwd, env={**tool_env(ctx), **(env or {})})


def run_to_file(ctx: Any, argv: list[str], *, cwd: Path, report: Path, module: Any) -> str:
    """`_common.run_to_file` with a run directory and the writable env."""
    report.parent.mkdir(parents=True, exist_ok=True)
    proc = run(ctx, argv, cwd=cwd)
    try:
        text = report.read_text()
    except OSError:
        text = ""
    if proc.returncode not in getattr(module, "EXPECT_EXIT", (0,)):
        raise _common.ToolFailed(proc.returncode, proc.stderr)
    if not text.strip():
        raise _common.ToolFailed(proc.returncode, "produced no report")
    return text


def _prefix(inv: Invocation, path: str) -> str:
    return (PurePosixPath(inv.cwd) / path).as_posix() if inv.cwd else path


def records_to_findings(ctx: Any, tree: Path, inv: Invocation, records: list[dict]) -> list[Any]:
    remapped = [{**rec, "path": _prefix(inv, rec["path"])} for rec in records]
    return ctx.findings.from_records(remapped, root=tree)


def sarif_to_findings(ctx: Any, tree: Path, inv: Invocation, text: str, policy: Any) -> list[Any]:
    parsed = ctx.sarif.parse(text, root=cwd_path(tree, inv), severity=policy)
    return [f.model_copy(update={"path": _prefix(inv, f.path)}) for f in parsed]


def realign_paths(findings: list[Any], inv: Invocation) -> list[Any]:
    """Some tools report a path relative to their input rather than the run
    directory (zizmor reported `ci.yml` for `.github/workflows/ci.yml`, which
    dropped every PR finding). Map such a path to the one invocation file it
    unambiguously names."""
    files = set(inv.files)
    out = []
    for f in findings:
        if f.path in files or f.path == _common.WHOLE_REPO_PATH:
            out.append(f)
            continue
        candidates = [
            x for x in inv.files if x.endswith("/" + f.path) or PurePosixPath(x).name == f.path
        ]
        out.append(f.model_copy(update={"path": candidates[0]}) if len(candidates) == 1 else f)
    return out


def scratch_view(ctx: Any, tree: Path, inv: Invocation, name: str) -> Path:
    """A directory holding only the invocation's files (and its config) at their
    repo-relative paths, for tools that accept a single target."""
    view = Path(ctx.workdir) / f"view-{name}"
    if view.exists():
        shutil.rmtree(view)
    for rel in (*inv.files, *((inv.config,) if inv.config else ())):
        dst = view / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(tree / rel, dst)
        except OSError:
            shutil.copy2(tree / rel, dst)
    return view


def endpoint_reachable(ctx: Any, url: str, timeout: float = 3.0) -> bool:
    cache: dict[str, bool] = ctx.__dict__.setdefault("_rw_checks_reachable", {})
    if url in cache:
        return cache[url]
    try:
        urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=timeout)  # noqa: S310
        ok = True
    except urllib.error.HTTPError:
        ok = True
    except (urllib.error.URLError, OSError, TimeoutError):
        ok = False
    cache[url] = ok
    return ok


def run_check(ctx: Any, tree: Path, changed: list[str] | None, module: Any):
    applicability = module.applicable(ctx, tree, changed)
    findings = list(applicability.refusals)
    checked = 0
    for inv in applicability.invocations:
        for chunk in batches(inv.files):
            sub = Invocation(files=chunk, config=inv.config, cwd=inv.cwd)
            got = module.check(ctx, tree, sub)
            allowed = set(chunk)
            kept = [f for f in got if f.path in allowed or f.path == _common.WHOLE_REPO_PATH]
            if len(kept) != len(got):
                ctx.log.warning(
                    "%s: dropped %d findings outside its invocation files",
                    module.NAME,
                    len(got) - len(kept),
                )
            findings.extend(kept)
            checked += len(chunk)
    return ctx.findings.cap(findings, skipped=applicability.skipped, files_checked=checked)
