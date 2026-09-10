"""Context -- the SDK's runtime boundary. A task has no config: the task host
builds a Context from the request envelope, the resolved credentials, and the
request scope path, then calls the setup/task function. There is no config
file a task reads, no environment it inspects, no path it constructs. See
docs/static-checks/CAPABILITY-CONTRACT.md Part 2.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

from .errors import CredentialNotFoundError
from .findings import FindingsClient
from .git import GitClient
from .repo_fs import RepoFsClient
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
    Context so ctx.sarif and ctx.findings can tag findings with them without
    the task passing them explicitly."""

    def __init__(
        self,
        capability: str,
        operation: str,
        workdir: Path,
        credentials: dict[str, str] | None = None,
        log: logging.Logger | None = None,
        allow_anonymous_credentials: bool = False,
    ) -> None:
        self.capability = capability
        self.operation = operation
        self.workdir = Path(workdir)
        self.log = log or logging.getLogger(f"runwhen_capability.{capability}.{operation}")
        self._credentials = dict(credentials or {})
        # `rwtask run --allow-anonymous` only -- see cli.py/run_local.py.
        # Never set by `rwtask serve`: an operator degrading a REQUIRED
        # credential to anonymous must be a deliberate local-dev act, not
        # something reachable from a running pod.
        self._allow_anonymous_credentials = allow_anonymous_credentials

        self.git = GitClient(self)
        self.sarif = SarifClient(self)
        self.findings = FindingsClient(self)
        self.storage = StorageClient(self)
        self.repo_fs = RepoFsClient(self)

    def credential(self, name: str, optional: bool = False) -> str | None:
        """The resolved value for a declared credential -- in memory, never
        in os.environ. When `name` was not resolved for this request:
        `optional=True` (the caller's own deliberate opt-in, mirroring the
        manifest's `needs.credentials[].optional: true`) returns None;
        otherwise raises CredentialNotFoundError naming `name` -- a
        declared credential that cannot be resolved is a hard failure, not
        a silent degrade. `--allow-anonymous` (`rwtask run` only) also
        returns None instead of raising, as a blanket local-dev override --
        see `_allow_anonymous_credentials` above."""
        try:
            return self._credentials[name]
        except KeyError:
            if optional:
                return None
            if self._allow_anonymous_credentials:
                self.log.warning(
                    "credential %r not resolved; --allow-anonymous is degrading this "
                    "request to anonymous -- a deliberate local-dev override, never "
                    "the platform default",
                    name,
                )
                return None
            raise CredentialNotFoundError(f"no credential resolved for {name!r}") from None

    def run(
        self,
        argv: list[str],
        cwd: Path | str | None = None,
        timeout: float | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        """Runs argv as a subprocess. stdout is captured (returned on
        `.stdout`); stderr is captured and forwarded line-by-line to
        ctx.log; the timeout (default DEFAULT_RUN_TIMEOUT) is enforced by
        subprocess itself -- a timeout raises subprocess.TimeoutExpired,
        which the task host treats like any other task exception.

        `env` is MERGED OVER the parent environment, never a replacement:
        a tool needs PATH and the rest of its runtime, and a caller that
        only wants to add one variable must not have to reconstruct
        everything else. Merged into a fresh dict per call rather than
        mutating `os.environ`, because tools run concurrently in one
        process -- a global mutation would leak into whatever else is
        running alongside.

        The case this exists for: the capability's root filesystem is
        READ-ONLY, so a tool that writes to the default `/tmp` fails
        outright. Only `workdir` (`/work`) is writable, so such a tool
        must be pointed at it -- see `tools/trivy.py`, whose vulnerability
        DB download died on `mkdir /tmp/trivy-...: read-only file system`.
        """
        run_cwd = Path(cwd) if cwd is not None else self.workdir
        proc = subprocess.run(  # noqa: S603 -- argv is capability-controlled, by design
            argv,
            cwd=str(run_cwd),
            capture_output=True,
            text=True,
            timeout=timeout or DEFAULT_RUN_TIMEOUT,
            env={**os.environ, **env} if env else None,
        )
        if proc.stderr:
            prog = argv[0] if argv else "?"
            for line in proc.stderr.splitlines():
                self.log.info("%s: %s", prog, line)
        return proc
