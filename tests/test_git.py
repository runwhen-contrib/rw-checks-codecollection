"""ctx.git.checkout / .changed_files against a real local git repository
(file-path remote, no network) -- ported behaviour from
internal/rwcheck/fetch in runwhen-runner.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from runwhen_capability import Context


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def _rev_parse(cwd: Path, ref: str) -> str:
    return subprocess.run(
        ["git", "rev-parse", ref], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def _make_origin(tmp_path: Path) -> tuple[Path, str, str]:
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q")
    _git(origin, "config", "user.email", "t@example.com")
    _git(origin, "config", "user.name", "t")

    (origin / "a.py").write_text("print('a')\n")
    (origin / "b.py").write_text("print('b')\n")
    _git(origin, "add", "-A")
    _git(origin, "commit", "-q", "-m", "base")
    base_sha = _rev_parse(origin, "HEAD")

    (origin / "a.py").write_text("print('a modified')\n")
    (origin / "c.py").write_text("print('c new')\n")
    (origin / "b.py").unlink()
    _git(origin, "add", "-A")
    _git(origin, "commit", "-q", "-m", "head")
    head_sha = _rev_parse(origin, "HEAD")

    return origin, base_sha, head_sha


def test_checkout_materialises_the_head_tree(tmp_path):
    origin, _base_sha, head_sha = _make_origin(tmp_path)
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    ctx = Context(capability="rw-checks", operation="checkout", workdir=scope_dir)

    tree = ctx.git.checkout(str(origin), head_sha)

    assert tree.is_dir()
    assert (tree / "a.py").read_text() == "print('a modified')\n"
    assert (tree / "c.py").exists()
    assert not (tree / "b.py").exists()


def test_changed_files_excludes_removed_and_uses_current_path_for_renames(tmp_path):
    origin, base_sha, head_sha = _make_origin(tmp_path)
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    ctx = Context(capability="rw-checks", operation="checkout", workdir=scope_dir)
    tree = ctx.git.checkout(str(origin), head_sha)

    changed = ctx.git.changed_files(tree, base_sha)

    assert changed is not None
    # b.py was removed -- excluded per CONTRACT.md's changed_files.json rule.
    assert set(changed) == {"a.py", "c.py"}


def test_changed_files_returns_none_when_base_is_unreachable(tmp_path):
    origin, _base_sha, head_sha = _make_origin(tmp_path)
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    ctx = Context(capability="rw-checks", operation="checkout", workdir=scope_dir)
    tree = ctx.git.checkout(str(origin), head_sha)

    changed = ctx.git.changed_files(tree, "0" * 40)

    assert changed is None


def test_changed_files_raises_for_a_tree_not_from_this_context(tmp_path):
    ctx = Context(capability="rw-checks", operation="checkout", workdir=tmp_path)
    try:
        ctx.git.changed_files(tmp_path / "nope", "deadbeef")
    except RuntimeError as exc:
        assert "was not produced by this Context" in str(exc)
    else:
        raise AssertionError("expected RuntimeError")
