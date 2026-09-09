"""Context -- the SDK's runtime boundary. A task has no config: the task host
builds a Context from the request envelope, the resolved credentials, and the
request scope path, then calls the setup/task function. There is no config
file a task reads, no environment it inspects, no path it constructs. See
docs/static-checks/CAPABILITY-CONTRACT.md Part 2.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .errors import CredentialNotFoundError
from .findings import FindingsClient
from .git import GitClient
from .sarif import SarifClient

DEFAULT_RUN_TIMEOUT = 600  # seconds


class StorageClient:
    """`ctx.storage` -- object storage. Deferred for the POC; see
    CAPABILITY-CONTRACT.md Part 2/3 [A: deferred for POC]."""

    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx

    def put(self, name: str, data: bytes):
        raise NotImplementedError(
            "ctx.storage.put() is not implemented: object storage is deferred "
            "for the POC (CAPABILITY-CONTRACT.md Part 2/3)"
        )


class Context:
    """Built once per setup/task invocation by the task host. `capability`
    and `operation` are the task host's own knowledge (from the manifest and
    the request), never read by the task function itself -- they exist on
    Context so ctx.sarif and ctx.findings can tag/fingerprint findings
    without the task passing them explicitly."""

    def __init__(
        self,
        capability: str,
        operation: str,
        workdir: Path,
        credentials: dict[str, str] | None = None,
        log: logging.Logger | None = None,
    ) -> None:
        self.capability = capability
        self.operation = operation
        self.workdir = Path(workdir)
        self.log = log or logging.getLogger(f"runwhen_capability.{capability}.{operation}")
        self._credentials = dict(credentials or {})

        self.git = GitClient(self)
        self.sarif = SarifClient(self)
        self.findings = FindingsClient(self)
        self.storage = StorageClient(self)

    def credential(self, name: str) -> str:
        """The resolved value for a declared credential -- in memory, never
        in os.environ. Raises CredentialNotFoundError if `name` was not
        resolved for this request."""
        try:
            return self._credentials[name]
        except KeyError:
            raise CredentialNotFoundError(f"no credential resolved for {name!r}") from None

    def run(
        self,
        argv: list[str],
        cwd: Path | str | None = None,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess:
        """Runs argv as a subprocess. stdout is captured (returned on
        `.stdout`); stderr is captured and forwarded line-by-line to
        ctx.log; the timeout (default DEFAULT_RUN_TIMEOUT) is enforced by
        subprocess itself -- a timeout raises subprocess.TimeoutExpired,
        which the task host treats like any other task exception."""
        run_cwd = Path(cwd) if cwd is not None else self.workdir
        proc = subprocess.run(  # noqa: S603 -- argv is capability-controlled, by design
            argv,
            cwd=str(run_cwd),
            capture_output=True,
            text=True,
            timeout=timeout or DEFAULT_RUN_TIMEOUT,
        )
        if proc.stderr:
            prog = argv[0] if argv else "?"
            for line in proc.stderr.splitlines():
                self.log.info("%s: %s", prog, line)
        return proc
