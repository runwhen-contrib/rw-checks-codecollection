"""Every check, given a realistic tree, only ever targets changed files
(DIFF-SCOPED-CHECKS.md G1)."""

from __future__ import annotations

import importlib
import pkgutil
import re
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

# Literal non-path values a few tools pass as format/subcommand arguments -- they
# contain a "." or "/" (or, for `{{json .}}`, look like they might) but never name a
# file. Kept tight and explicit: growing it should mean a real tool argument was
# found, not a shortcut to silence a failure.
NON_PATH_VALUES = {"sarif", "json", "json1", "parsable", "{{json .}}"}
_NUMBER_RE = re.compile(r"-?\d+(\.\d+)?$")


def _looks_like_a_file(arg: str) -> bool:
    """True for an argv value the test must be able to resolve to a real path."""
    if arg in NON_PATH_VALUES or _NUMBER_RE.match(arg):
        return False
    return "." in arg or "/" in arg


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
        # Values passed to a config flag (e.g. gitleaks' `-c <path under the
        # view>`) are allowed to name an unchanged file, including one that
        # also shows up inside a scratch view walked below.
        config_paths = set()
        for j in range(1, len(argv)):
            if argv[j - 1] in CONFIG_FLAGS:
                v = argv[j]
                p = Path(v) if Path(v).is_absolute() else (cwd / v)
                config_paths.add(p.resolve())
        chdir_base: Path | None = None
        for i, arg in enumerate(argv[1:], start=1):
            is_abs = Path(arg).is_absolute()
            candidate = Path(arg) if is_abs else (cwd / arg)
            # tflint's `--filter <basename>` is relative to the *module*
            # directory named by the preceding `--chdir`, not to `cwd` --
            # fall back to resolving it there before giving up.
            if not is_abs and not candidate.exists() and chdir_base is not None:
                candidate = chdir_base / arg
            if not is_abs and argv[i - 1] == "--chdir":
                chdir_base = cwd / arg
            if not candidate.exists():
                # A relative argument that still looks like a file after both
                # resolution attempts is a bug in the module or the test's
                # TREES/lane modelling, not something to shrug off silently.
                assert is_abs or not _looks_like_a_file(arg), (
                    name,
                    "unresolved argv value",
                    arg,
                    "cwd",
                    cwd,
                    "chdir_base",
                    chdir_base,
                    argv,
                )
                continue
            if candidate.is_dir():
                assert argv[i - 1] == "--chdir" or candidate.is_relative_to(ctx.workdir), (
                    name,
                    argv,
                )
                # A scratch view (gitleaks' `dir <view>`) must hold only
                # changed files plus, optionally, a config passed via a
                # config flag elsewhere in argv -- walk it and prove no
                # unchanged file leaked in. (`--chdir` module directories
                # such as tflint's are the one sanctioned exception, DIFF-
                # SCOPED-CHECKS.md G1, and live under `tree`, not workdir.)
                if candidate.is_relative_to(ctx.workdir):
                    for sub in candidate.rglob("*"):
                        if sub.is_dir() or sub.resolve() in config_paths:
                            continue
                        subrel = sub.relative_to(candidate).as_posix()
                        assert subrel not in unchanged, (name, subrel, argv)
                continue
            try:
                rel = candidate.resolve().relative_to(tree.resolve()).as_posix()
            except ValueError:
                continue
            # An unchanged file may only appear as the value of a config flag.
            assert rel not in unchanged or argv[i - 1] in CONFIG_FLAGS, (name, rel, argv)
