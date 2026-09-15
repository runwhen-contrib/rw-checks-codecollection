"""Every check, given a realistic tree, only ever targets changed files
(DIFF-SCOPED-CHECKS.md G1)."""

from __future__ import annotations

import importlib
import pkgutil
import sys
from pathlib import Path

import pytest

CAPABILITY = Path(__file__).parent.parent / "capabilities" / "rw-checks"
sys.path.insert(0, str(CAPABILITY))
sys.path.insert(0, str(Path(__file__).parent))

from _fakes import RecordingContext  # noqa: E402
from test_tool_checks import fixture_outputs  # noqa: E402

from tools import _runner  # noqa: E402

TOOLS = sorted(
    m.name for m in pkgutil.iter_modules([str(CAPABILITY / "tools")]) if not m.name.startswith("_")
)
CONFIG_FLAGS = {"--rcfile", "--config", "-c", "--config-file", "-config-file"}

# For each tool: files to create (path -> content), and which of them are in the diff.
TREES = {
    "actionlint": (
        {".github/workflows/a.yml": "on: push\n", ".github/workflows/b.yml": "on: push\n"},
        [".github/workflows/a.yml"],
    ),
    "ast_grep": (
        {"svc/sgconfig.yml": "ruleDirs: [r]\n", "svc/a.py": "", "svc/b.py": ""},
        ["svc/a.py"],
    ),
    "biome": ({"web/biome.json": "{}", "web/a.ts": "", "web/b.ts": ""}, ["web/a.ts"]),
    "buf": ({"p/buf.yaml": "version: v1\n", "p/a.proto": "", "p/b.proto": ""}, ["p/a.proto"]),
    "checkov": ({"infra/a.tf": "", "infra/b.tf": ""}, ["infra/a.tf"]),
    "dotenv_linter": ({"s/.env": "A=1\n", "t/.env": "B=1\n"}, ["s/.env"]),
    "flake8": ({"tools/.flake8": "[flake8]\n", "tools/a.py": "", "tools/b.py": ""}, ["tools/a.py"]),
    "gitleaks": ({"a.txt": "", "b.txt": ""}, ["a.txt"]),
    "hadolint": ({"svc/Dockerfile": "FROM a\n", "api/Dockerfile": "FROM a\n"}, ["svc/Dockerfile"]),
    "osv_scanner": ({"requirements.txt": "", "web/package-lock.json": "{}"}, ["requirements.txt"]),
    "pylint": ({"svc/.pylintrc": "[MAIN]\n", "svc/a.py": "", "svc/b.py": ""}, ["svc/a.py"]),
    "regal": ({"pol/.regal/config.yaml": "", "pol/a.rego": "", "pol/b.rego": ""}, ["pol/a.rego"]),
    "ruff": ({"ruff.toml": "", "a.py": "", "b.py": ""}, ["a.py"]),
    "shellcheck": ({"a.sh": "", "b.sh": ""}, ["a.sh"]),
    "sqlfluff": ({"db/.sqlfluff": "[sqlfluff]\n", "db/a.sql": "", "db/b.sql": ""}, ["db/a.sql"]),
    "tflint": ({"m/.tflint.hcl": "", "m/a.tf": "", "m/b.tf": ""}, ["m/a.tf"]),
    "vale": ({"docs/.vale.ini": "[*.md]\n", "docs/a.md": "", "docs/b.md": ""}, ["docs/a.md"]),
    "yamllint": (
        {"k/.yamllint": "extends: default\n", "k/a.yaml": "", "k/b.yaml": ""},
        ["k/a.yaml"],
    ),
    "zizmor": (
        {".github/workflows/a.yml": "", ".github/workflows/b.yml": ""},
        [".github/workflows/a.yml"],
    ),
}


def test_every_tool_has_a_golden_tree():
    assert sorted(TREES) == TOOLS


@pytest.mark.parametrize("name", TOOLS)
def test_argv_targets_only_changed_files(tmp_path, monkeypatch, name):
    monkeypatch.setattr(_runner, "endpoint_reachable", lambda ctx, url, timeout=3.0: True)
    files, changed = TREES[name]
    tree = tmp_path / "tree"
    for rel, text in files.items():
        p = tree / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    ctx = RecordingContext(tmp_path, outputs=fixture_outputs())
    mod = importlib.import_module(f"tools.{name}")
    result = _runner.run_check(ctx, tree, changed, mod)
    assert ctx.calls, f"{name} did not run on its golden tree: {result.skipped}"
    unchanged = {rel for rel in files if rel not in changed}
    for call in ctx.calls:
        argv, cwd = call["argv"], call["cwd"]
        assert "." not in [a for i, a in enumerate(argv) if i == 0 or argv[i - 1] != "--chdir"], (
            argv
        )
        for i, arg in enumerate(argv[1:], start=1):
            candidate = (cwd / arg) if not Path(arg).is_absolute() else Path(arg)
            if not candidate.exists():
                continue
            if candidate.is_dir():
                assert argv[i - 1] == "--chdir" or candidate.is_relative_to(ctx.workdir), (
                    name,
                    argv,
                )
                continue
            try:
                rel = candidate.resolve().relative_to(tree.resolve()).as_posix()
            except ValueError:
                continue
            # An unchanged file may only appear as the value of a config flag.
            assert rel not in unchanged or argv[i - 1] in CONFIG_FLAGS, (name, rel, argv)
