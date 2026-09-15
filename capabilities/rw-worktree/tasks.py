"""rw-worktree capability tasks: `open` (setup) checks out (repoUrl, sha)
into the scope exactly like rw-checks's `checkout`; `read`, `grep`, `ls`
are read-only operations against that tree, ported from
internal/rwcheck/serve/{read,grep,ls}.go in runwhen-runner (the v1
worktree host) via sdk/runwhen_capability/repo_fs.py -- see that module's
docstring for the containment and glob-depth-fix details. `query` batches
grep/read/ls/defs/refs ops over the same tree in one request, via
sdk/runwhen_capability/repo_query.py.

Per docs/static-checks/EXECUTOR-CONTRACT.md "Addressing and caching": the
tree is a cache entry keyed by (repoUrl, sha), not a leased handle.
Eviction is normal -- a request against an evicted tree simply
re-materialises via `open`; there is no release, and nothing here may
surface a "handle expired" condition to a caller.
"""

from __future__ import annotations

from pathlib import Path

from runwhen_capability import Context, setup, task
from runwhen_capability.repo_query import run_query


# `setup.task: open` (manifest.yaml) requires this function be named
# "open" -- the registry keys setups by func.__name__ (decorators.py).
# That shadows the `open` builtin for the rest of THIS module, which is
# deliberate and safe: nothing below (or in the SDK modules this file
# imports -- ctx.git, ctx.repo_fs, repo_query) reads a file through the
# bare builtin; every read goes through ctx.repo_fs (directly, or via
# repo_query for the `query` task), never `open()`.
@setup(outputs=["tree"])
def open(ctx: Context, repo_url: str, sha: str):
    tree = ctx.git.checkout(repo_url, sha, credential="repo")
    return {"tree": tree}


@task(outputs={"result": "rw.repo_read.v1"})
def read(
    ctx: Context,
    tree: Path,
    path: str,
    start_line: int | None = None,
    end_line: int | None = None,
):
    result = ctx.repo_fs.read(tree, path, start_line=start_line, end_line=end_line)
    return {"result": result}


@task(outputs={"result": "rw.repo_grep.v1"})
def grep(
    ctx: Context,
    tree: Path,
    pattern: str,
    glob: str | None = None,
    max_matches: int | None = None,
    ignore_case: bool = False,
):
    result = ctx.repo_fs.grep(
        tree, pattern, glob=glob, max_matches=max_matches, ignore_case=ignore_case
    )
    return {"result": result}


@task(outputs={"result": "rw.repo_ls.v1"})
def ls(ctx: Context, tree: Path, path: str | None = None, depth: int | None = None):
    result = ctx.repo_fs.ls(tree, path=path, depth=depth)
    return {"result": result}


@task(outputs={"result": "rw.repo_query.v1"})
def query(ctx: Context, tree: Path, ops: list):
    result = run_query(tree, ops)
    return {"result": result}
