"""Stopping at the request deadline.

`rwtask serve` takes one request at a time and the runner does not kill the pod at the
deadline, so a task that never ends (a jq `last(range(1e18))`, a SQL cross join) would keep
the pod busy for hours. The SDK puts the deadline on `ctx.deadline_at` as a `time.monotonic()`
value, or None when there is none (`rwtask run`); a task watches it here and stops itself,
MARGIN_SECONDS early so that its error reaches the caller before the lease expires.

Two ways to watch: `arm` a timer that does something to the running work (kill a child,
interrupt a query) at that time, or `check` between the steps of work that is Python all the
way through.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

from .errors import ToolError

MARGIN_SECONDS = 5.0


class Deadline:
    """Watches one request's deadline for one task. `advice` finishes the error message:
    "stopped at the request deadline after N s; <advice>"."""

    def __init__(self, ctx: Any, advice: str) -> None:
        self._at: float | None = getattr(ctx, "deadline_at", None)
        self._advice = advice
        self._started = time.monotonic()
        self._timer: threading.Timer | None = None
        self.expired = False

    def arm(self, action: Callable[[], None]) -> None:
        """Runs `action` (on a timer thread) when the deadline minus the margin comes; at once,
        on the caller's thread, if that has passed. No deadline, no timer. `expired` is set
        before `action` runs."""
        if self._at is None:
            return
        delay = self._at - MARGIN_SECONDS - time.monotonic()
        if delay <= 0:
            self._fire(action)  # already too late to start: no race with the work beginning
            return
        self._timer = threading.Timer(delay, self._fire, args=(action,))
        self._timer.daemon = True
        self._timer.start()

    def _fire(self, action: Callable[[], None]) -> None:
        self.expired = True
        try:
            action()
        except Exception:  # noqa: BLE001 -- the work being stopped may already be gone
            pass

    def cancel(self) -> None:
        """Stops the timer, and waits for its action if that is running, so nothing it touches
        is closed under it."""
        timer = self._timer
        if timer is None:
            return
        timer.cancel()
        if timer.is_alive() and timer is not threading.current_thread():
            timer.join(timeout=5)

    def check(self) -> None:
        """Raises the deadline error if the time has come (or the timer already fired)."""
        if self.expired or (self._at is not None and time.monotonic() >= self._at - MARGIN_SECONDS):
            self.expired = True
            raise self.error()

    def error(self) -> ToolError:
        seconds = round(time.monotonic() - self._started)
        return ToolError(
            "E_DEADLINE", f"stopped at the request deadline after {seconds} s; {self._advice}"
        )
