from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

CAPABILITY = Path(__file__).parent.parent / "capabilities" / "rw-checks"
FIXTURES = Path(__file__).parent / "fixtures" / "tools"
sys.path.insert(0, str(CAPABILITY))
sys.path.insert(0, str(Path(__file__).parent))

from _fakes import RecordingContext  # noqa: E402

from tools import _runner  # noqa: E402


def load(name):
    return importlib.import_module(f"tools.{name}")


def write(tree: Path, rel: str, text: str = "x\n") -> None:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def run(tmp_path, name, changed, outputs=None):
    tree = tmp_path / "tree"
    ctx = RecordingContext(tmp_path, outputs=outputs or {})
    result = _runner.run_check(ctx, tree, changed, load(name))
    return ctx, result


def test_shellcheck_runs_only_changed_scripts(tmp_path):
    tree = tmp_path / "tree"
    write(tree, "a/x.sh")
    write(tree, "b/y.sh")
    write(tree, "c/untouched.sh")
    ctx, result = run(tmp_path, "shellcheck", ["a/x.sh", "b/y.sh"], {"shellcheck": "[]"})
    assert [c["argv"] for c in ctx.calls] == [["shellcheck", "-f", "json1", "a/x.sh", "b/y.sh"]]
    assert result.files_checked == 2 and result.skipped is None


def test_zizmor_file_args_and_realigned_paths(tmp_path):
    tree = tmp_path / "tree"
    write(tree, ".github/workflows/ci.yml")
    sarif = (FIXTURES / "zizmor.sarif").read_text()
    ctx, result = run(tmp_path, "zizmor", [".github/workflows/ci.yml"], {"zizmor": sarif})
    assert ctx.calls[0]["argv"] == [
        "zizmor",
        "--format",
        "sarif",
        "--no-progress",
        ".github/workflows/ci.yml",
    ]
    assert all(
        f.path == ".github/workflows/ci.yml" for f in result.findings if f.path != "<repository>"
    )


def test_actionlint_passes_root_config_when_present(tmp_path):
    tree = tmp_path / "tree"
    write(tree, ".github/workflows/ci.yml")
    write(tree, ".github/actionlint.yaml", "self-hosted-runner: {labels: []}\n")
    ctx, _ = run(tmp_path, "actionlint", [".github/workflows/ci.yml"], {"actionlint": "[]"})
    assert ctx.calls[0]["argv"] == [
        "actionlint",
        "-format",
        "{{json .}}",
        "-no-color",
        "-config-file",
        ".github/actionlint.yaml",
        ".github/workflows/ci.yml",
    ]


def test_dotenv_linter_only_changed_env_files(tmp_path):
    tree = tmp_path / "tree"
    write(tree, "svc/.env", "A=1\n")
    ctx, result = run(tmp_path, "dotenv_linter", ["svc/.env"], {"dotenv-linter": ""})
    assert ctx.calls[0]["argv"] == ["dotenv-linter", "svc/.env"]
    assert result.files_checked == 1


def test_osv_scanner_skips_when_unreachable(tmp_path, monkeypatch):
    tree = tmp_path / "tree"
    write(tree, "requirements.txt", "requests==2.19.0\n")
    monkeypatch.setattr(_runner, "endpoint_reachable", lambda ctx, url, timeout=3.0: False)
    ctx, result = run(tmp_path, "osv_scanner", ["requirements.txt"])
    assert ctx.calls == []
    assert result.skipped == "dependency scan unavailable: api.osv.dev unreachable"


def test_osv_scanner_lockfile_args_when_reachable(tmp_path, monkeypatch):
    tree = tmp_path / "tree"
    write(tree, "requirements.txt")
    write(tree, "web/package-lock.json", "{}")
    monkeypatch.setattr(_runner, "endpoint_reachable", lambda ctx, url, timeout=3.0: True)
    sarif = (FIXTURES / "osv-scanner.sarif").read_text()
    ctx, _ = run(
        tmp_path,
        "osv_scanner",
        ["requirements.txt", "web/package-lock.json"],
        {"osv-scanner": sarif},
    )
    assert ctx.calls[0]["argv"] == [
        "osv-scanner",
        "--format",
        "sarif",
        "-L",
        "requirements.txt",
        "-L",
        "web/package-lock.json",
    ]


#: Real captured tool output per binary, so adapters/SARIF parsing never see an
#: invalid empty string.
FIXTURE_OUTPUTS = {
    "actionlint": "actionlint.json",
    "ast-grep": "ast-grep.json",
    "biome": "biome.json",
    "buf": "buf.json",
    "checkov": "checkov.sarif",
    "dotenv-linter": "dotenv.txt",
    "flake8": "flake8.txt",
    "gitleaks": "gitleaks.sarif",
    "hadolint": "hadolint.json",
    "osv-scanner": "osv-scanner.sarif",
    "pylint": "pylint.json",
    "regal": "regal.json",
    "ruff": "ruff.sarif",
    "shellcheck": "shellcheck.json",
    "sqlfluff": "sqlfluff.json",
    "tflint": "tflint.sarif",
    "vale": "vale.json",
    "yamllint": "yamllint.txt",
    "zizmor": "zizmor.sarif",
}


def fixture_outputs():
    return {binary: (FIXTURES / fname).read_text() for binary, fname in FIXTURE_OUTPUTS.items()}


@pytest.mark.parametrize(
    "name", ["shellcheck", "zizmor", "actionlint", "dotenv_linter", "osv_scanner"]
)
def test_lane_a_checks_set_writable_env(tmp_path, monkeypatch, name):
    monkeypatch.setattr(_runner, "endpoint_reachable", lambda ctx, url, timeout=3.0: True)
    mod = load(name)
    tree = tmp_path / "tree"
    target = {
        "shellcheck": "x.sh",
        "zizmor": ".github/workflows/ci.yml",
        "actionlint": ".github/workflows/ci.yml",
        "dotenv_linter": ".env",
        "osv_scanner": "requirements.txt",
    }[name]
    write(tree, target)
    ctx = RecordingContext(tmp_path, outputs=fixture_outputs())
    _runner.run_check(ctx, tree, [target], mod)
    assert ctx.calls and "HOME" in ctx.calls[0]["env"]
