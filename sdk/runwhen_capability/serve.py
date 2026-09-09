"""`rwtask serve` -- long-polls the runner over plain HTTP/JSON (not Connect).

Relay HTTP contract (this is the wire the runner must implement to match):

    POST {relay}/v1/tasks/next
        body: {"poolId": "<poolId>"}
        -> 200 {"requestId", "request", "credentials": {name: value}, "scopeId", "deadlineMs"}
           (the "request" field is a Wire-3 RequestEnvelope; see models.py)
        -> 204 when idle (the server may hold the connection up to ~30s)

    POST {relay}/v1/tasks/{requestId}/result
        body: {"status": "ok"|"failed"|"timeout", "result": {...}, "error": "..."}
           ("result" is a Wire-3 ResultEnvelope, present only on status "ok")

Both relay calls carry `Authorization: Bearer <token>`, where <token> is read
fresh from the executor token file on every poll (not cached at startup) --
polls are ~30s apart so the cost is nil, and it lets a rotated or
late-mounted token recover on its own instead of wedging the pod. The token
file path comes from --token-file, else the EXECUTOR_TOKEN_FILE env var,
else DEFAULT_TOKEN_FILE. A missing/unreadable token file is logged and the
loop keeps polling -- it never falls back to an unauthenticated request.

Per request: create <workdir>/<scopeId>/, chdir there, run setup then each
task in request.tasks order (host.run_request), aggregate into the result
envelope, POST it, then delete the scope dir. Never raises out of the loop --
a poll or post failure is logged and retried; a request that fails to
execute becomes a "failed" PutResult, not a crash.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path

import requests

from .host import run_request
from .loader import discover_capability_dir, load_capability
from .models import TaskHostRequest

POLL_TIMEOUT = 35  # seconds; a little over the relay's ~30s long-poll hold
RESULT_TIMEOUT = 30  # seconds
RETRY_DELAY = 5  # seconds, on a poll/post transport failure

DEFAULT_TOKEN_FILE = "/var/run/executor/token"


def serve(
    relay: str,
    pool_id: str,
    workdir: Path,
    capability_dir: Path | None = None,
    token_file: Path | None = None,
    max_iterations: int | None = None,
    session: requests.Session | None = None,
    log: logging.Logger | None = None,
) -> None:
    """Runs the long-poll loop. `max_iterations` (None = forever) and
    `session` exist so tests can drive this deterministically without a real
    relay or an infinite loop."""
    log = log or logging.getLogger("runwhen_capability.serve")
    session = session or requests.Session()
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    token_file = (
        Path(token_file)
        if token_file
        else Path(os.environ.get("EXECUTOR_TOKEN_FILE", DEFAULT_TOKEN_FILE))
    )

    cap_dir = Path(capability_dir) if capability_dir else discover_capability_dir()
    capability = load_capability(cap_dir)
    log.info("serving capability %r from %s", capability.capability_id, cap_dir)

    iterations = 0
    while max_iterations is None or iterations < max_iterations:
        iterations += 1
        _poll_once(session, relay, pool_id, workdir, capability, token_file, log)


def _read_token(token_file: Path, log) -> str | None:
    try:
        return token_file.read_text().strip()
    except OSError as exc:
        log.error("could not read executor token from %s: %s", token_file, exc)
        return None


def _poll_once(
    session, relay: str, pool_id: str, workdir: Path, capability, token_file: Path, log
) -> None:
    token = _read_token(token_file, log)
    if token is None:
        time.sleep(RETRY_DELAY)
        return
    headers = {"Authorization": f"Bearer {token}"}

    try:
        resp = session.post(
            f"{relay}/v1/tasks/next",
            json={"poolId": pool_id},
            timeout=POLL_TIMEOUT,
            headers=headers,
        )
    except requests.RequestException as exc:
        log.error("poll %s/v1/tasks/next failed: %s", relay, exc)
        time.sleep(RETRY_DELAY)
        return

    if resp.status_code == 204:
        return
    if resp.status_code != 200:
        log.error("poll %s/v1/tasks/next: unexpected status %s", relay, resp.status_code)
        time.sleep(RETRY_DELAY)
        return

    try:
        task_request = TaskHostRequest.model_validate(resp.json())
    except Exception as exc:  # noqa: BLE001 -- a malformed relay response must not crash the loop
        log.error("poll %s/v1/tasks/next: malformed response: %s", relay, exc)
        return

    scope_dir = workdir / task_request.scopeId
    scope_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = run_request(
            capability,
            task_request.request,
            task_request.credentials,
            scope_dir,
            log=log.getChild(task_request.requestId),
        )
        payload = {"status": "ok", "result": result.model_dump(mode="json")}
    except Exception as exc:  # noqa: BLE001 -- one request must never take down the loop
        log.exception("request %s failed", task_request.requestId)
        payload = {"status": "failed", "error": str(exc)}
    finally:
        shutil.rmtree(scope_dir, ignore_errors=True)

    try:
        session.post(
            f"{relay}/v1/tasks/{task_request.requestId}/result",
            json=payload,
            timeout=RESULT_TIMEOUT,
            headers=headers,
        )
    except requests.RequestException as exc:
        log.error("post %s/v1/tasks/%s/result failed: %s", relay, task_request.requestId, exc)
