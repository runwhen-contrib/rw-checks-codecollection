"""Plumbing for the tools that run as subprocesses fed from an artifact stream.

Everything here is bounded: input is moved in 1 MiB chunks, a tool's line of
output is read with a byte limit, and a tool's stderr is reduced to a short
tail while it is drained.
"""

from __future__ import annotations

import os
import subprocess
import threading
from collections.abc import Callable, Iterable, Iterator
from typing import BinaryIO

CHUNK_BYTES = 1 << 20
STDERR_TAIL_BYTES = 4096
# How long to wait for a helper thread to notice its pipe is gone, once the process was killed.
_JOIN_TIMEOUT_SECONDS = 3


class LineTooLong(Exception):
    """A line of a tool's output did not fit in the limit."""


def read_chunks(stream: BinaryIO, size: int = CHUNK_BYTES) -> Iterator[bytes]:
    """The stream's bytes in chunks of at most `size`, until it ends."""
    while True:
        data = stream.read(size)
        if not data:
            return
        yield data


def bounded_lines(stream: BinaryIO, limit: int) -> Iterator[bytes]:
    """The stream's lines, each with its newline. A line longer than `limit` bytes raises
    LineTooLong; the stream is never read past `limit + 1` bytes into a line."""
    while True:
        line = stream.readline(limit + 1)
        if not line:
            return
        if len(line) > limit:
            raise LineTooLong(f"a line of output is longer than {limit} bytes")
        yield line


def tool_env() -> dict[str, str]:
    """The environment a tool runs in: PATH and nothing else. The tools take instructions from
    the caller (a jq filter can read `env`), so the pod's own variables must not reach them."""
    return {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")}


def spawn(argv: list[str]) -> subprocess.Popen:
    """Starts `argv` with all three pipes open, in a minimal environment. No shell."""
    return subprocess.Popen(  # noqa: S603 -- argv is fixed apart from caller data passed as arguments
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=tool_env(),
    )


def kill(proc: subprocess.Popen) -> None:
    """Kills `proc` if it is still running."""
    try:
        proc.kill()
    except ProcessLookupError:
        pass


def shutdown(
    proc: subprocess.Popen, feeder: Feeder | None = None, stderr: StderrTail | None = None
) -> None:
    """Leaves nothing running: kills the process if it is still alive, reaps it, stops and
    joins the feeder and the stderr drain (they end once the process is gone; either may be
    None if setup failed before it was made), and closes the pipes. Safe to call after a
    normal finish."""
    kill(proc)
    proc.wait()
    if feeder is not None:
        feeder.stop()
        feeder.join(timeout=_JOIN_TIMEOUT_SECONDS)
    if stderr is not None:
        stderr.text()
    for pipe in (proc.stdin, proc.stdout, proc.stderr):
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass


class StderrTail:
    """Drains a pipe on a thread, keeping only the last `limit` bytes, so the tool can never
    block on a full stderr and its message can still be reported."""

    def __init__(self, stream: BinaryIO, limit: int = STDERR_TAIL_BYTES) -> None:
        self._stream = stream
        self._limit = limit
        self._tail = b""
        self._thread = threading.Thread(target=self._drain, name="tool-stderr", daemon=True)
        self._thread.start()

    def _drain(self) -> None:
        try:
            while True:
                data = self._stream.read1(65536)
                if not data:
                    return
                self._tail = (self._tail + data)[-self._limit :]
        except (OSError, ValueError):
            return

    def text(self) -> str:
        """The tail, once the pipe has closed."""
        self._thread.join(timeout=_JOIN_TIMEOUT_SECONDS)
        return self._tail.decode("utf-8", errors="replace").strip()


class Feeder:
    """Copies pieces of bytes into a process's stdin on a thread and then closes it.

    A process that stops reading early (rg on a bad pattern, a killed jq) is not an error
    here: the write just ends. Any other failure is kept in `error`, `on_error` is called with
    it (so the caller can kill the process rather than wait for it), and the caller raises it
    after the process is done: a tool that was fed half of its input must not have its
    partial answer returned.
    """

    def __init__(
        self,
        pieces: Iterable[bytes],
        stdin: BinaryIO,
        on_error: Callable[[BaseException], None] | None = None,
    ) -> None:
        self._pieces = pieces
        self._stdin = stdin
        self._on_error = on_error
        self._stopped = threading.Event()
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, name="tool-feeder", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        """Asks the thread to end after the piece it is on."""
        self._stopped.set()

    def join(self, *, timeout: float | None = None) -> None:
        self._thread.join(timeout=timeout)

    def _run(self) -> None:
        try:
            for piece in self._pieces:
                if self._stopped.is_set():
                    break
                self._stdin.write(piece)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except BaseException as exc:  # noqa: BLE001 -- handed to the caller, see the class docstring
            self.error = exc
            if self._on_error is not None:
                self._on_error(exc)
        finally:
            try:
                self._stdin.close()
            except OSError:
                pass
