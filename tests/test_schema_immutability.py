"""Tests scripts/check_schema_immutability.py: a published schema file
(capabilities/*/schemas/<name>.v<N>.json) must never change or disappear
once it exists on a base ref -- see README.md's "Schemas label". Every case
here builds its own throwaway git repo under tmp_path so it never touches
this repo's own history.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from check_schema_immutability import check_immutability  # noqa: E402

CHECK_SCRIPT = REPO_ROOT / "scripts" / "check_schema_immutability.py"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "test")
    return repo


def _commit(repo: Path, relpath: str, content: str, message: str) -> str:
    path = repo / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    _git(repo, "add", relpath)
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD").strip()


def test_unchanged_passes(tmp_path):
    repo = _init_repo(tmp_path)
    base = _commit(repo, "capabilities/fake/schemas/a.v1.json", '{"a": 1}', "add a.v1.json")
    assert check_immutability(base, repo) == []


def test_changed_fails(tmp_path):
    repo = _init_repo(tmp_path)
    base = _commit(repo, "capabilities/fake/schemas/a.v1.json", '{"a": 1}', "add a.v1.json")
    (repo / "capabilities/fake/schemas/a.v1.json").write_text('{"a": 2}')
    failures = check_immutability(base, repo)
    assert any("a.v1.json" in f for f in failures)


def test_whitespace_only_reformat_passes(tmp_path):
    repo = _init_repo(tmp_path)
    base = _commit(repo, "capabilities/fake/schemas/a.v1.json", '{"a": 1}', "add a.v1.json")
    (repo / "capabilities/fake/schemas/a.v1.json").write_text('{\n  "a": 1\n}\n')
    assert check_immutability(base, repo) == []


def test_deleted_fails(tmp_path):
    repo = _init_repo(tmp_path)
    base = _commit(repo, "capabilities/fake/schemas/a.v1.json", '{"a": 1}', "add a.v1.json")
    (repo / "capabilities/fake/schemas/a.v1.json").unlink()
    failures = check_immutability(base, repo)
    assert any("a.v1.json" in f and "deleted" in f for f in failures)


def test_v2_added_passes(tmp_path):
    repo = _init_repo(tmp_path)
    base = _commit(repo, "capabilities/fake/schemas/a.v1.json", '{"a": 1}', "add a.v1.json")
    (repo / "capabilities/fake/schemas/a.v2.json").write_text('{"a": 2}')
    assert check_immutability(base, repo) == []


def test_unversioned_base_file_deleted_passes(tmp_path):
    repo = _init_repo(tmp_path)
    base = _commit(repo, "capabilities/fake/schemas/a.json", '{"a": 1}', "add unversioned a.json")
    (repo / "capabilities/fake/schemas/a.json").unlink()
    assert check_immutability(base, repo) == []


def test_new_unversioned_file_fails_naming(tmp_path):
    repo = _init_repo(tmp_path)
    base = _commit(repo, "capabilities/fake/schemas/a.v1.json", '{"a": 1}', "add a.v1.json")
    (repo / "capabilities/fake/schemas/b.json").write_text('{"b": 1}')
    failures = check_immutability(base, repo)
    assert any("b.json" in f for f in failures)


def test_zero_base_passes(tmp_path):
    repo = _init_repo(tmp_path)
    _commit(repo, "capabilities/fake/schemas/a.v1.json", '{"a": 1}', "add a.v1.json")
    assert check_immutability("0" * 40, repo) == []


def test_empty_base_passes(tmp_path):
    repo = _init_repo(tmp_path)
    _commit(repo, "capabilities/fake/schemas/a.v1.json", '{"a": 1}', "add a.v1.json")
    assert check_immutability("", repo) == []


def test_unresolvable_base_passes(tmp_path):
    repo = _init_repo(tmp_path)
    _commit(repo, "capabilities/fake/schemas/a.v1.json", '{"a": 1}', "add a.v1.json")
    assert check_immutability("origin/does-not-exist", repo) == []


def test_cli_reports_pass(tmp_path):
    repo = _init_repo(tmp_path)
    base = _commit(repo, "capabilities/fake/schemas/a.v1.json", '{"a": 1}', "add a.v1.json")
    result = subprocess.run(
        [sys.executable, str(CHECK_SCRIPT), "--base", base, "--repo-root", str(repo)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_cli_reports_failure(tmp_path):
    repo = _init_repo(tmp_path)
    base = _commit(repo, "capabilities/fake/schemas/a.v1.json", '{"a": 1}', "add a.v1.json")
    (repo / "capabilities/fake/schemas/a.v1.json").write_text('{"a": 2}')
    result = subprocess.run(
        [sys.executable, str(CHECK_SCRIPT), "--base", base, "--repo-root", str(repo)],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "a.v1.json" in result.stderr
