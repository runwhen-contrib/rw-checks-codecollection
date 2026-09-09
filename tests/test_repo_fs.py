"""ctx.repo_fs -- read/grep/ls against a real tree on disk, ported from
internal/rwcheck/serve/{read,grep,ls}.go in runwhen-runner (the v1
worktree host). Exercises the exact regression e0c9f16 fixed (glob depth)
and the containment rules read/grep/ls all share.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from runwhen_capability.repo_fs import (
    BinaryFileError,
    PathEscapesTreeError,
    grep_tree,
    ls_tree,
    read_lines,
)


def make_tree(tmp_path: Path, files: dict[str, str | bytes]) -> Path:
    tree = tmp_path / "tree"
    tree.mkdir()
    for rel, content in files.items():
        full = tree / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            full.write_bytes(content)
        else:
            full.write_text(content)
    return tree


# --- read ----------------------------------------------------------------


def test_read_whole_file_when_no_range_given(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "one\ntwo\nthree\n"})

    got = read_lines(tree, "a.py")

    assert got.path == "a.py"
    assert got.content == "one\ntwo\nthree\n"
    assert got.startLine == 1
    assert got.totalLines == 4  # split("\n") on a trailing-newline file yields a final ""
    assert got.truncated is False


def test_read_line_range(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "one\ntwo\nthree\nfour\n"})

    got = read_lines(tree, "a.py", start_line=2, end_line=3)

    assert got.content == "two\nthree"
    assert got.startLine == 2
    assert got.endLine == 3


def test_read_missing_file_raises(tmp_path):
    tree = make_tree(tmp_path, {})

    with pytest.raises(FileNotFoundError):
        read_lines(tree, "nope.py")


def test_read_binary_file_raises(tmp_path):
    tree = make_tree(tmp_path, {"bin": b"\x00\x01\x02binary"})

    with pytest.raises(BinaryFileError):
        read_lines(tree, "bin")


def test_read_rejects_path_escaping_the_tree_with_dotdot(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "x\n"})

    with pytest.raises(PathEscapesTreeError):
        read_lines(tree, "../outside.py")


def test_read_rejects_absolute_path(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "x\n"})

    with pytest.raises(PathEscapesTreeError):
        read_lines(tree, "/etc/passwd")


def test_read_rejects_symlink_escaping_the_tree(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text("secret\n")
    tree = make_tree(tmp_path, {})
    (tree / "link.py").symlink_to(outside)

    with pytest.raises(PathEscapesTreeError):
        read_lines(tree, "link.py")


# --- grep ------------------------------------------------------------------


def test_grep_matches_across_files_and_skips_binary(tmp_path):
    tree = make_tree(
        tmp_path,
        {
            "src/a.py": "import os\nprint('hello')\n",
            "src/b.py": "import sys\nIMPORT OS\n",
            "docs/c.md": "import os is mentioned here too\n",
            "binary": b"\x00\x01\x02import-not-really-text",
        },
    )

    got = grep_tree(tree, r"^import os$")

    assert len(got.matches) == 1
    assert got.matches[0].path == "src/a.py"
    assert got.matches[0].line == 1
    assert got.truncated is False


def test_grep_ignore_case_widens_the_match(tmp_path):
    tree = make_tree(tmp_path, {"src/a.py": "import os\n", "src/b.py": "IMPORT OS\n"})

    got = grep_tree(tree, r"^import os$", ignore_case=True)

    assert {m.path for m in got.matches} == {"src/a.py", "src/b.py"}


def test_grep_glob_narrows_the_file_set(tmp_path):
    tree = make_tree(tmp_path, {"src/a.py": "needle\n", "docs/c.md": "needle\n"})

    got = grep_tree(tree, "needle", glob="docs/*")

    assert len(got.matches) == 1
    assert got.matches[0].path == "docs/c.md"


def test_grep_zero_matches_is_an_empty_list_not_none(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "nothing here\n"})

    got = grep_tree(tree, "no-such-pattern-anywhere")

    assert got.matches == []
    assert isinstance(got.matches, list)


def test_grep_max_matches_caps_and_reports_truncated(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "import a\n", "b.py": "import b\n", "c.py": "import c\n"})

    got = grep_tree(tree, "import", max_matches=1)

    assert len(got.matches) == 1
    assert got.truncated is True


def test_grep_skips_dot_git_entirely(tmp_path):
    tree = make_tree(tmp_path, {".git/config": "import os\n", "a.py": "import os\n"})

    got = grep_tree(tree, "import")

    assert all(not m.path.startswith(".git") for m in got.matches)
    assert len(got.matches) == 1


def test_grep_text_truncated_at_400_chars(tmp_path):
    long_line = "needle" + ("x" * 1000)
    tree = make_tree(tmp_path, {"long.txt": long_line})

    got = grep_tree(tree, "needle")

    assert len(got.matches) == 1
    assert len(got.matches[0].text) == 400


def test_grep_rejects_invalid_pattern(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "x\n"})

    with pytest.raises(ValueError):
        grep_tree(tree, "(unclosed")


# --- glob-at-any-depth regression (runwhen-runner e0c9f16) ------------------


def test_grep_glob_matches_at_any_depth_not_only_root(tmp_path):
    """FIELD FAILURE regression: a no-slash glob like "*.py" previously
    matched only at the repo root (path.Match-equivalent never crosses
    "/"). It must match a NESTED file too -- a root-only implementation
    would find only tools/a.py, missing tools/utils/b.py."""
    tree = make_tree(
        tmp_path,
        {
            "tools/a.py": "needle\n",
            "tools/utils/b.py": "needle\n",  # nested -- this is the regression case
            "docs/c.md": "needle\n",
        },
    )

    bare = grep_tree(tree, "needle", glob="*.py")
    assert {m.path for m in bare.matches} == {"tools/a.py", "tools/utils/b.py"}

    scoped = grep_tree(tree, "needle", glob="tools/*.py")
    assert {m.path for m in scoped.matches} == {"tools/a.py"}

    double_star = grep_tree(tree, "needle", glob="**/*.py")
    assert {m.path for m in double_star.matches} == {"tools/a.py", "tools/utils/b.py"}


# --- ls ----------------------------------------------------------------


def test_ls_default_depth_is_immediate_children_only(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "x", "sub/b.py": "y"})

    got = ls_tree(tree)

    paths = {e.path for e in got.entries}
    assert paths == {"a.py", "sub"}
    dir_entry = next(e for e in got.entries if e.path == "sub")
    assert dir_entry.type == "dir"


def test_ls_depth_recurses(tmp_path):
    tree = make_tree(tmp_path, {"sub/b.py": "y", "sub/deeper/c.py": "z"})

    got = ls_tree(tree, depth=3)

    paths = {e.path for e in got.entries}
    assert "sub/b.py" in paths
    assert "sub/deeper" in paths
    assert "sub/deeper/c.py" in paths


def test_ls_empty_directory_is_an_empty_list_not_none(tmp_path):
    tree = make_tree(tmp_path, {})

    got = ls_tree(tree)

    assert got.entries == []
    assert isinstance(got.entries, list)


def test_ls_skips_dot_git(tmp_path):
    tree = make_tree(tmp_path, {".git/config": "x", "a.py": "y"})

    got = ls_tree(tree)

    assert {e.path for e in got.entries} == {"a.py"}


def test_ls_reports_file_size(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "12345"})

    got = ls_tree(tree)

    entry = next(e for e in got.entries if e.path == "a.py")
    assert entry.type == "file"
    assert entry.size == 5


def test_ls_rejects_path_escaping_the_tree(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "x"})

    with pytest.raises(PathEscapesTreeError):
        ls_tree(tree, path="../")


def test_ls_not_a_directory_raises(tmp_path):
    tree = make_tree(tmp_path, {"a.py": "x"})

    with pytest.raises(NotADirectoryError):
        ls_tree(tree, path="a.py")


def test_ls_symlinked_entry_is_type_other_and_not_recursed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("s")
    tree = make_tree(tmp_path, {})
    (tree / "link").symlink_to(outside)

    # depth=5 -- proves the symlink is skipped BECAUSE it is a symlink, not
    # merely because the default depth=1 wouldn't have recursed anyway.
    got = ls_tree(tree, depth=5)

    entry = next(e for e in got.entries if e.path == "link")
    assert entry.type == "other"
    assert not any(e.path.startswith("link/") for e in got.entries)
