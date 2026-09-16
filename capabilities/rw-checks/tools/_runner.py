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

from runwhen_capability.errors import OutputTooLargeError
from runwhen_capability.sarif import SARIF_BYTE_BUDGET

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


#: rw-checks G7: a tool subprocess's ENTIRE environment, not a few extras
#: merged over the executor pod's own -- `ctx.run(..., inherit_env=False)`
#: below makes this the whole child env. A probe's payload read `GPG_KEY`
#: straight out of a tool's inherited environment; combined with any config
#: -driven exec/network vector (guards.py), that is credential exfiltration.
#: Kept to what a linter/scanner actually needs: PATH and locale so it can
#: run at all, HOME/XDG_CACHE_HOME/TMPDIR so it has a writable home on the
#: read-only root filesystem, and the handful of TLS-trust/proxy variables
#: osv-scanner and a self-hosted proxy setup legitimately need -- none of
#: which are secrets. Everything else in the pod's environment -- tokens,
#: credentials, anything else an operator or the platform set -- is simply
#: never in this dict, so a tool can never see it.
_PASSTHROUGH_ENV = (
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)


def tool_env(ctx: Any) -> dict[str, str]:
    """The complete allow-listed environment for a tool subprocess -- see
    `_PASSTHROUGH_ENV` above. The root filesystem is read-only: buf (`mkdir
    /.cache`), tflint (plugin init needs a writable HOME) and pylint (no
    usable temp dir) all fail without HOME/XDG_CACHE_HOME/TMPDIR."""
    base = Path(ctx.workdir) / ".tool-home"
    env = {
        "PATH": os.environ.get(
            "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        ),
        "LANG": "C.UTF-8",
    }
    for key, sub in (("HOME", "home"), ("XDG_CACHE_HOME", "cache"), ("TMPDIR", "tmp")):
        (base / sub).mkdir(parents=True, exist_ok=True)
        env[key] = str(base / sub)
    for key in _PASSTHROUGH_ENV:
        if key in os.environ:
            env[key] = os.environ[key]
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
    # inherit_env=False: `tool_env` is the tool's WHOLE environment, not a
    # few extras merged over the executor pod's own -- see _PASSTHROUGH_ENV
    # above. A caller's own `env` (e.g. tflint.py's TFLINT_PLUGIN_DIR) still
    # merges on TOP of the allow-list, same as before.
    return ctx.run(argv, cwd=cwd, env={**tool_env(ctx), **(env or {})}, inherit_env=False)


def run_to_file(ctx: Any, argv: list[str], *, cwd: Path, report: Path, module: Any) -> str:
    """Run a tool that writes its report to a FILE and read it back, using
    this module's `run` (the writable env) and `cwd` (the run/scratch
    directory an invocation runs from). Raises `_common.ToolFailed` -- never
    returns silently -- when the process exited outside `module.EXPECT_EXIT`,
    or when the report is missing/empty.

    Also raises `OutputTooLargeError` -- checked via `report.stat()`, BEFORE
    `report.read_text()` -- when the report file itself exceeds
    SARIF_BYTE_BUDGET. `ctx.run`'s own stdout cap does not cover this path:
    gitleaks and checkov write their report to a FILE, not stdout, which is
    the whole reason this function exists. A file-sized runaway would
    otherwise be read into memory whole -- and could OOM the pod -- before
    `ctx.sarif.parse` ever got a chance to apply its own guard."""
    report.parent.mkdir(parents=True, exist_ok=True)
    proc = run(ctx, argv, cwd=cwd)
    try:
        size = report.stat().st_size
    except OSError:
        size = 0
    if size > SARIF_BYTE_BUDGET:
        raise OutputTooLargeError(f"check output too large to process: {size} bytes")
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
