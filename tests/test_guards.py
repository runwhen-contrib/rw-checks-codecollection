"""guards.py tests: each guard's refusal/safe/malformed-config contract, and
the per-config-group `paths` filtering `_plan.plan` calls them with (Part A
of rw-1416).

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

sys.path.insert(0, str(Path(__file__).parent.parent / "capabilities" / "rw-checks"))

import guards  # noqa: E402


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


# --- pylint -----------------------------------------------------------------


def test_pylint_init_hook_trips_the_guard(tmp_path):
    path = write(tmp_path, ".pylintrc", "[MASTER]\ninit-hook=import subprocess\n")
    reason = guards.pylint(tmp_path, [path])
    assert reason is not None
    assert ".pylintrc" in reason
    assert "init-hook" in reason


def test_pylint_load_plugins_trips_the_guard(tmp_path):
    path = write(tmp_path, "pylintrc", "[MASTER]\nload-plugins=evil_plugin\n")
    reason = guards.pylint(tmp_path, [path])
    assert reason is not None
    assert "load-plugins" in reason


def test_pylint_clean_config_is_safe(tmp_path):
    path = write(tmp_path, ".pylintrc", "[MASTER]\nmax-line-length=100\n")
    assert guards.pylint(tmp_path, [path]) is None


def test_pylint_no_config_is_safe(tmp_path):
    assert guards.pylint(tmp_path, []) is None


def test_pylint_nested_config_trips_the_guard(tmp_path):
    """A tool run with a subdirectory as its cwd reads THAT directory's own
    .pylintrc -- not just the repo root's -- so the guard must search the
    whole tree, not only the root."""
    path = write(tmp_path, "services/api/pylintrc", "[MASTER]\nload-plugins=evil_plugin\n")
    reason = guards.pylint(tmp_path, [path])
    assert reason is not None
    assert "services/api/pylintrc" in reason
    assert "load-plugins" in reason


def test_pylint_toml_load_plugins_trips_the_guard(tmp_path):
    path = write(tmp_path, ".pylintrc.toml", '[MASTER]\nload_plugins = ["evil_plugin"]\n')
    reason = guards.pylint(tmp_path, [path])
    assert reason is not None
    assert "load_plugins" in reason


def test_pylint_pyproject_toml_scoped_to_tool_pylint(tmp_path):
    path = write(
        tmp_path,
        "pyproject.toml",
        '[tool.pylint.MASTER]\ninit-hook = "import subprocess"\n',
    )
    reason = guards.pylint(tmp_path, [path])
    assert reason is not None
    assert "pyproject.toml" in reason
    assert "init-hook" in reason


def test_pylint_setup_cfg_scoped_to_pylint_section(tmp_path):
    path = write(tmp_path, "setup.cfg", "[pylint]\ninit-hook=import os\n")
    reason = guards.pylint(tmp_path, [path])
    assert reason is not None
    assert "setup.cfg" in reason


def test_pylint_malformed_config_is_unsafe(tmp_path):
    """A config we cannot parse is not assumed benign."""
    path = write(tmp_path, ".pylintrc", "this is not [[[ valid ini\n===\n")
    reason = guards.pylint(tmp_path, [path])
    assert reason is not None
    assert ".pylintrc" in reason
    assert "unsafe" in reason.lower() or "could not be parsed" in reason.lower()


# --- checkov ------------------------------------------------------------


def test_checkov_external_checks_dir_trips_the_guard(tmp_path):
    path = write(tmp_path, ".checkov.yaml", "external-checks-dir:\n  - ../evil-checks\n")
    reason = guards.checkov(tmp_path, [path])
    assert reason is not None
    assert ".checkov.yaml" in reason
    assert "external-checks-dir" in reason


def test_checkov_external_checks_git_underscore_variant_trips_the_guard(tmp_path):
    path = write(
        tmp_path, ".checkov.yml", "external_checks_git:\n  - https://example.com/evil.git\n"
    )
    reason = guards.checkov(tmp_path, [path])
    assert reason is not None
    assert "external_checks_git" in reason


def test_checkov_clean_config_is_safe(tmp_path):
    path = write(
        tmp_path, ".checkov.yaml", "skip-check:\n  - CKV_AWS_1\nframework:\n  - terraform\n"
    )
    assert guards.checkov(tmp_path, [path]) is None


def test_checkov_empty_external_checks_dir_is_safe(tmp_path):
    path = write(tmp_path, ".checkov.yaml", "external-checks-dir:\n")
    assert guards.checkov(tmp_path, [path]) is None


def test_checkov_no_config_is_safe(tmp_path):
    assert guards.checkov(tmp_path, []) is None


def test_checkov_malformed_config_is_unsafe(tmp_path):
    path = write(tmp_path, ".checkov.yaml", "external-checks-dir: [unterminated\n")
    reason = guards.checkov(tmp_path, [path])
    assert reason is not None
    assert ".checkov.yaml" in reason


# --- sqlfluff -----------------------------------------------------------


def test_sqlfluff_dot_sqlfluff_library_path_trips_the_guard(tmp_path):
    path = write(
        tmp_path,
        ".sqlfluff",
        "[sqlfluff]\ndialect=ansi\n\n[sqlfluff:templater:jinja]\nlibrary_path=evil_libs\n",
    )
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert ".sqlfluff" in reason
    assert "library_path" in reason


def test_sqlfluff_pyproject_toml_trips_the_guard(tmp_path):
    path = write(
        tmp_path,
        "pyproject.toml",
        '[tool.sqlfluff.templater.jinja]\nlibrary_path = "evil_libs"\n',
    )
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert "pyproject.toml" in reason
    assert "library_path" in reason


def test_sqlfluff_clean_config_is_safe(tmp_path):
    path = write(tmp_path, ".sqlfluff", "[sqlfluff]\ndialect=ansi\n")
    assert guards.sqlfluff(tmp_path, [path]) is None


def test_sqlfluff_no_config_is_safe(tmp_path):
    assert guards.sqlfluff(tmp_path, []) is None


def test_sqlfluff_malformed_config_is_unsafe(tmp_path):
    path = write(tmp_path, "tox.ini", "not [[[ valid\n===\n")
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert "tox.ini" in reason


# --- vale ---------------------------------------------------------------


def test_vale_packages_trips_the_guard(tmp_path):
    # vale's own files routinely have global keys before any [section]
    # header -- the guard must still find Packages there.
    path = write(
        tmp_path,
        ".vale.ini",
        "StylesPath = styles\nPackages = Google, write-good\n\n[*.md]\nBasedOnStyles = Vale\n",
    )
    reason = guards.vale(tmp_path, [path])
    assert reason is not None
    assert ".vale.ini" in reason
    assert "Packages" in reason


def test_vale_clean_config_is_safe(tmp_path):
    path = write(tmp_path, ".vale.ini", "StylesPath = styles\nMinAlertLevel = suggestion\n")
    assert guards.vale(tmp_path, [path]) is None


def test_vale_empty_packages_is_safe(tmp_path):
    path = write(tmp_path, "vale.ini", "Packages =\n")
    assert guards.vale(tmp_path, [path]) is None


def test_vale_no_config_is_safe(tmp_path):
    assert guards.vale(tmp_path, []) is None


def test_vale_malformed_config_is_unsafe(tmp_path):
    path = write(tmp_path, "_vale.ini", "[unterminated section\nPackages = evil\n")
    reason = guards.vale(tmp_path, [path])
    assert reason is not None
    assert "_vale.ini" in reason


# --- explicit `paths`, the per-config-group form -------------------------


def test_pylint_guard_with_paths_ignores_other_configs(tmp_path):
    (tmp_path / "bad").mkdir()
    (tmp_path / "good").mkdir()
    (tmp_path / "bad" / ".pylintrc").write_text("[MAIN]\ninit-hook=import os\n")
    (tmp_path / "good" / ".pylintrc").write_text("[MAIN]\njobs=1\n")
    assert guards.pylint(tmp_path, [tmp_path / "good" / ".pylintrc"]) is None
    assert guards.pylint(tmp_path, [tmp_path / "bad" / ".pylintrc"]).startswith(
        "bad/.pylintrc: sets init-hook"
    )


def test_sqlfluff_guard_with_paths_sees_an_ancestor_in_the_chain(tmp_path):
    (tmp_path / "db").mkdir()
    (tmp_path / ".sqlfluff").write_text("[sqlfluff:templater:jinja]\nlibrary_path = ./macros\n")
    (tmp_path / "db" / ".sqlfluff").write_text("[sqlfluff]\ndialect = postgres\n")
    assert guards.sqlfluff(tmp_path, [tmp_path / "db" / ".sqlfluff"]) is None
    reason = guards.sqlfluff(tmp_path, [tmp_path / ".sqlfluff", tmp_path / "db" / ".sqlfluff"])
    assert reason and reason.startswith(".sqlfluff: sets library_path")


def test_vale_and_checkov_guards_accept_paths(tmp_path):
    (tmp_path / ".vale.ini").write_text("Packages = Google\n")
    (tmp_path / ".checkov.yaml").write_text("external-checks-dir: [./x]\n")
    assert guards.vale(tmp_path, [tmp_path / ".vale.ini"])
    assert guards.checkov(tmp_path, [tmp_path / ".checkov.yaml"])
    assert guards.vale(tmp_path, []) is None
    assert guards.checkov(tmp_path, []) is None
