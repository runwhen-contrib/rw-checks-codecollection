#!/usr/bin/env python3
"""Run EVERY registered task against a real checkout, inside the built image.

The adapter tests parse captured bytes; they never invoke a tool. This does
the other half: it proves each task's argv actually runs and that the
tool's live output still matches what the adapter expects. A task can pass
every unit test and still be broken by a wrong flag -- that is exactly how
the gitleaks /dev/stdout bug survived.

Run inside the image:

    docker run --rm --platform linux/amd64 --user root \
      -v "$PWD:/src" -w /src rw-checks:pinned \
      python3 scripts/smoke_tasks.py

Exit code is the number of tasks that ERRORED. A task legitimately finding
nothing is not a failure; a task raising is.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk"))

from runwhen_capability import Context  # noqa: E402
from runwhen_capability.loader import load_capability  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "tests" / "fixtures" / "sample-repo"


def make_checkout() -> Path:
    """A real git checkout -- semgrep, actionlint and gitleaks all behave
    differently in a plain directory (see tests/fixtures/tools/README.md)."""
    tmp = Path(tempfile.mkdtemp(prefix="smoke-")) / "tree"
    shutil.copytree(SAMPLE, tmp)
    subprocess.run(["git", "init", "-q", "."], cwd=tmp, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
    subprocess.run(
        ["git", "-c", "user.email=s@r.local", "-c", "user.name=smoke", "commit", "-qm", "smoke"],
        cwd=tmp,
        check=True,
    )
    return tmp


def main() -> int:
    logging.basicConfig(level=logging.ERROR)
    cap = load_capability(ROOT / "capabilities" / "rw-checks")
    tree = make_checkout()

    names = sorted(cap.registry.tasks)
    print(f"{len(names)} tasks against {tree}\n")
    print(f"{'task':16s} {'status':8s} {'findings':>9s}  detail")

    errors = 0
    empty = []
    for name in names:
        taskdef = cap.registry.tasks[name]
        ctx = Context(
            capability=cap.capability_id,
            operation=name,
            workdir=tree.parent,
            credentials={},
            allow_anonymous_credentials=True,
        )
        kwargs = {"tree": tree}
        params = taskdef.func.__code__.co_varnames[: taskdef.func.__code__.co_argcount]
        if "changed" in params:
            # None = no diff filter, so we see everything the tool reports.
            kwargs["changed"] = None
        try:
            out = taskdef.func(ctx, **kwargs)
            findings = out.get("findings", [])
            detail = ""
            if findings:
                detail = f"{findings[0].rule} {findings[0].path}:{findings[0].line}"
            else:
                empty.append(name)
            print(f"{name:16s} {'ok':8s} {len(findings):9d}  {detail}")
        except Exception as exc:  # noqa: BLE001 -- report every task, not just the first
            errors += 1
            msg = f"{type(exc).__name__}: {exc}"
            print(f"{name:16s} {'ERROR':8s} {'-':>9s}  {msg[:110]}")

    print(f"\n{len(names) - errors}/{len(names)} ran clean; {errors} errored")
    if empty:
        print(f"found nothing (check argv): {', '.join(empty)}")
    return errors


if __name__ == "__main__":
    raise SystemExit(main())
