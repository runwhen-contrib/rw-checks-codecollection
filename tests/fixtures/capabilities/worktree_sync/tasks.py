"""Fixture capability: mimics rw-worktree's open(setup)+read(task) shape,
for exercising host.run_request's setup-output caching -- the mcp.v1 sync
read path is a request carrying `setup` but no credentials, against a
scope whose setup already materialised in an earlier (leased) request.

`open` requires a declared credential named "repo", exactly like
rw-worktree's real `open` (capabilities/rw-worktree/tasks.py) -- a request
with no credentials can only succeed here via a cache hit. It writes a
real file under the scope so `read` has real content to return, without
needing an actual git checkout."""

from __future__ import annotations

from pathlib import Path

from runwhen_capability import Context, setup, task


@setup(outputs=["tree"])
def open(ctx: Context, repo_url: str, sha: str):
    ctx.credential("repo")  # hard failure if unresolved -- see Context.credential()
    tree = ctx.workdir / "tree"
    tree.mkdir(parents=True, exist_ok=True)
    (tree / "hello.txt").write_text(f"hello from {repo_url}@{sha}")
    return {"tree": tree}


@task(outputs={"content": "text"})
def read(ctx: Context, tree: Path):
    return {"content": (tree / "hello.txt").read_text()}
