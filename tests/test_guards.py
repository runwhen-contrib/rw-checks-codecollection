"""guards.py tests, and the wiring from a guard refusal to a task's single
`rw-checks/unsafe-config` finding (Part A of rw-1416).

Each of the four guarded tools gets a config that trips its guard (asserting
the reason names the file and the offending key), a clean config (asserting
None), and -- because "we couldn't parse it" must never be read as "it's
safe" -- a malformed config asserting a refusal too. pylint additionally
gets a NESTED config case: a tool run with a subdirectory as its cwd reads
that subdirectory's own config file, not just the repo root's.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "capabilities" / "rw-checks"))

import guards  # noqa: E402
import tasks  # noqa: E402
from runwhen_capability import Context  # noqa: E402


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


# --- pylint -----------------------------------------------------------------


def test_pylint_init_hook_trips_the_guard(tmp_path):
    write(tmp_path, ".pylintrc", "[MASTER]\ninit-hook=import subprocess\n")
    reason = guards.pylint(tmp_path)
    assert reason is not None
    assert ".pylintrc" in reason
    assert "init-hook" in reason


def test_pylint_load_plugins_trips_the_guard(tmp_path):
    write(tmp_path, "pylintrc", "[MASTER]\nload-plugins=evil_plugin\n")
    reason = guards.pylint(tmp_path)
    assert reason is not None
    assert "load-plugins" in reason


def test_pylint_clean_config_is_safe(tmp_path):
    write(tmp_path, ".pylintrc", "[MASTER]\nmax-line-length=100\n")
    assert guards.pylint(tmp_path) is None


def test_pylint_no_config_is_safe(tmp_path):
    assert guards.pylint(tmp_path) is None


def test_pylint_nested_config_trips_the_guard(tmp_path):
    """A tool run with a subdirectory as its cwd reads THAT directory's own
    .pylintrc -- not just the repo root's -- so the guard must search the
    whole tree, not only the root."""
    write(tmp_path, "services/api/pylintrc", "[MASTER]\nload-plugins=evil_plugin\n")
    reason = guards.pylint(tmp_path)
    assert reason is not None
    assert "services/api/pylintrc" in reason
    assert "load-plugins" in reason


def test_pylint_toml_load_plugins_trips_the_guard(tmp_path):
    write(tmp_path, ".pylintrc.toml", '[MASTER]\nload_plugins = ["evil_plugin"]\n')
    reason = guards.pylint(tmp_path)
    assert reason is not None
    assert "load_plugins" in reason


def test_pylint_pyproject_toml_scoped_to_tool_pylint(tmp_path):
    write(
        tmp_path,
        "pyproject.toml",
        '[tool.pylint.MASTER]\ninit-hook = "import subprocess"\n',
    )
    reason = guards.pylint(tmp_path)
    assert reason is not None
    assert "pyproject.toml" in reason
    assert "init-hook" in reason


def test_pylint_setup_cfg_scoped_to_pylint_section(tmp_path):
    write(tmp_path, "setup.cfg", "[pylint]\ninit-hook=import os\n")
    reason = guards.pylint(tmp_path)
    assert reason is not None
    assert "setup.cfg" in reason


def test_pylint_malformed_config_is_unsafe(tmp_path):
    """A config we cannot parse is not assumed benign."""
    write(tmp_path, ".pylintrc", "this is not [[[ valid ini\n===\n")
    reason = guards.pylint(tmp_path)
    assert reason is not None
    assert ".pylintrc" in reason
    assert "unsafe" in reason.lower() or "could not be parsed" in reason.lower()


# --- checkov ------------------------------------------------------------


def test_checkov_external_checks_dir_trips_the_guard(tmp_path):
    write(tmp_path, ".checkov.yaml", "external-checks-dir:\n  - ../evil-checks\n")
    reason = guards.checkov(tmp_path)
    assert reason is not None
    assert ".checkov.yaml" in reason
    assert "external-checks-dir" in reason


def test_checkov_external_checks_git_underscore_variant_trips_the_guard(tmp_path):
    write(tmp_path, ".checkov.yml", "external_checks_git:\n  - https://example.com/evil.git\n")
    reason = guards.checkov(tmp_path)
    assert reason is not None
    assert "external_checks_git" in reason


def test_checkov_clean_config_is_safe(tmp_path):
    write(tmp_path, ".checkov.yaml", "skip-check:\n  - CKV_AWS_1\nframework:\n  - terraform\n")
    assert guards.checkov(tmp_path) is None


def test_checkov_empty_external_checks_dir_is_safe(tmp_path):
    write(tmp_path, ".checkov.yaml", "external-checks-dir:\n")
    assert guards.checkov(tmp_path) is None


def test_checkov_no_config_is_safe(tmp_path):
    assert guards.checkov(tmp_path) is None


def test_checkov_malformed_config_is_unsafe(tmp_path):
    write(tmp_path, ".checkov.yaml", "external-checks-dir: [unterminated\n")
    reason = guards.checkov(tmp_path)
    assert reason is not None
    assert ".checkov.yaml" in reason


# --- sqlfluff -----------------------------------------------------------


def test_sqlfluff_dot_sqlfluff_library_path_trips_the_guard(tmp_path):
    write(
        tmp_path,
        ".sqlfluff",
        "[sqlfluff]\ndialect=ansi\n\n[sqlfluff:templater:jinja]\nlibrary_path=evil_libs\n",
    )
    reason = guards.sqlfluff(tmp_path)
    assert reason is not None
    assert ".sqlfluff" in reason
    assert "library_path" in reason


def test_sqlfluff_pyproject_toml_trips_the_guard(tmp_path):
    write(
        tmp_path,
        "pyproject.toml",
        '[tool.sqlfluff.templater.jinja]\nlibrary_path = "evil_libs"\n',
    )
    reason = guards.sqlfluff(tmp_path)
    assert reason is not None
    assert "pyproject.toml" in reason
    assert "library_path" in reason


def test_sqlfluff_clean_config_is_safe(tmp_path):
    write(tmp_path, ".sqlfluff", "[sqlfluff]\ndialect=ansi\n")
    assert guards.sqlfluff(tmp_path) is None


def test_sqlfluff_no_config_is_safe(tmp_path):
    assert guards.sqlfluff(tmp_path) is None


def test_sqlfluff_malformed_config_is_unsafe(tmp_path):
    write(tmp_path, "tox.ini", "not [[[ valid\n===\n")
    reason = guards.sqlfluff(tmp_path)
    assert reason is not None
    assert "tox.ini" in reason


# --- vale ---------------------------------------------------------------


def test_vale_packages_trips_the_guard(tmp_path):
    # vale's own files routinely have global keys before any [section]
    # header -- the guard must still find Packages there.
    write(
        tmp_path,
        ".vale.ini",
        "StylesPath = styles\nPackages = Google, write-good\n\n[*.md]\nBasedOnStyles = Vale\n",
    )
    reason = guards.vale(tmp_path)
    assert reason is not None
    assert ".vale.ini" in reason
    assert "Packages" in reason


def test_vale_clean_config_is_safe(tmp_path):
    write(tmp_path, ".vale.ini", "StylesPath = styles\nMinAlertLevel = suggestion\n")
    assert guards.vale(tmp_path) is None


def test_vale_empty_packages_is_safe(tmp_path):
    write(tmp_path, "vale.ini", "Packages =\n")
    assert guards.vale(tmp_path) is None


def test_vale_no_config_is_safe(tmp_path):
    assert guards.vale(tmp_path) is None


def test_vale_malformed_config_is_unsafe(tmp_path):
    write(tmp_path, "_vale.ini", "[unterminated section\nPackages = evil\n")
    reason = guards.vale(tmp_path)
    assert reason is not None
    assert "_vale.ini" in reason


# --- guard -> task wiring -----------------------------------------------


class _NoRunContext(Context):
    """Proves a guarded task never invokes the tool once its guard refuses:
    .run() fails the test outright if a task reaches it."""

    def run(self, argv, cwd=None, timeout=None):
        raise AssertionError(f"tool was invoked despite an unsafe config: {argv}")


@pytest.mark.parametrize("task_name", ["pylint", "checkov", "sqlfluff", "vale"])
def test_guarded_task_skips_the_tool_and_reports_one_finding(tmp_path, monkeypatch, task_name):
    # Patch the tool MODULE's GUARD, not guards.<name>: each module binds its
    # guard at import time (`GUARD = guards.pylint`), so rebinding the guards
    # module afterwards would not reach the reference the module already
    # holds. GUARD is the contract surface -- see tools/_common.py.
    import importlib

    reason = ".pylintrc: sets init-hook, which executes arbitrary Python"
    monkeypatch.setattr(importlib.import_module(task_name), "GUARD", lambda tree: reason)

    ctx = _NoRunContext(capability="rw-checks", operation=task_name, workdir=tmp_path)
    result = getattr(tasks, task_name)(ctx, tree=tmp_path, changed=None)

    findings = result["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "rw-checks/unsafe-config"
    assert finding.severity == "warning"
    assert finding.path == ".pylintrc"
    assert finding.line == 0
    assert "init-hook" in finding.message
    assert "check skipped" in finding.message


def test_unguarded_config_runs_the_tool_and_reaches_ctx_run(tmp_path, monkeypatch):
    """Sanity check the guard is actually load-bearing: a clean config must
    NOT stop the task from invoking the tool."""
    import importlib

    monkeypatch.setattr(importlib.import_module("pylint"), "GUARD", lambda tree: None)
    # pylint is CONFIG=required: without the repository's own config it is
    # skipped before the tool is ever invoked, so a bare tmp_path would prove
    # nothing here. Give it a config AND a Python file to satisfy the file
    # gate, so reaching ctx.run really is the guard's doing.
    (tmp_path / ".pylintrc").write_text("[MASTER]\n")
    (tmp_path / "a.py").write_text("import os\n")
    ran = {}

    class _RecordingContext(Context):
        def run(self, argv, cwd=None, timeout=None):
            ran["argv"] = argv
            raise SystemExit  # stop the test right after the tool would run

    ctx = _RecordingContext(capability="rw-checks", operation="pylint", workdir=tmp_path)
    with pytest.raises(SystemExit):
        tasks.pylint(ctx, tree=tmp_path, changed=None)
    assert ran["argv"][0] == "pylint"
