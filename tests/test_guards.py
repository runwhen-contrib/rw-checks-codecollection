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

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "capabilities" / "rw-checks"))

import guards  # noqa: E402

# An unreadable file is unreadable only for a non-root user; root ignores the
# mode bits and the test would assert the opposite of reality.
skip_if_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file permissions"
)


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


def test_pylint_deeply_nested_toml_config_is_refused_not_raised(tmp_path):
    """`_walk`'s own depth bound, one of 7 call sites -- table headers nest
    the parsed document past `_WALK_MAX_DEPTH` (64) without ever tripping
    tomllib's own parser recursion, so this exercises `_walk` itself."""
    header = "a" + "".join(f".n{i}" for i in range(100))
    path = write(tmp_path, ".pylintrc.toml", f"[{header}]\nx = 1\n")
    reason = guards.pylint(tmp_path, [path])
    assert reason is not None
    assert "nested more than" in reason


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


def test_pylint_percent_value_in_unrelated_key_is_safe(tmp_path):
    """F3: a `%` in an unrelated value must not raise InterpolationSyntaxError."""
    path = write(
        tmp_path,
        ".pylintrc",
        "[MESSAGES CONTROL]\ndisable = C0114\n[FORMAT]\nlogging-format-style = 100%\n",
    )
    assert guards.pylint(tmp_path, [path]) is None


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


def test_checkov_deeply_nested_config_is_refused_not_raised(tmp_path):
    n = 100
    path = write(tmp_path, ".checkov.yaml", "[" * n + "1" + "]" * n + "\n")
    reason = guards.checkov(tmp_path, [path])
    assert reason is not None
    assert "nested more than" in reason


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


def test_sqlfluff_percent_value_in_library_path_does_not_raise(tmp_path):
    """F3: a `%` in library_path itself must not raise InterpolationSyntaxError."""
    path = write(tmp_path, ".sqlfluff", "[sqlfluff:templater:jinja]\nlibrary_path = ./lib%\n")
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert reason.startswith(".sqlfluff: sets library_path")


def test_sqlfluff_pep8_ini_library_path_trips_the_guard(tmp_path):
    path = write(tmp_path, "pep8.ini", "[sqlfluff:templater:jinja]\nlibrary_path = ./lib\n")
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert reason.startswith("pep8.ini: sets library_path")


def test_sqlfluff_section_name_case_insensitive_trips_the_guard(tmp_path):
    path = write(tmp_path, ".sqlfluff", "[SQLFluff:Templater:Jinja]\nlibrary_path = ./lib\n")
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert reason.startswith(".sqlfluff: sets library_path")


# F2's actual bug was in `_plan.guard_paths` -- whether a jinja-only tox.ini
# gets INCLUDED in the guard's chain at all -- not in this function's own
# per-file section matching, which was already correct. A test that calls
# guards.sqlfluff() directly with the file handed to it (bypassing chain
# construction entirely) still passes with F2 reverted; the real regression
# test is test_tool_checks.py's
# test_sqlfluff_guard_chain_reaches_root_tox_ini_jinja_only_section, which
# exercises the planner and therefore the chain.


# --- sqlfluff: B1, inline `-- sqlfluff:`/`--sqlfluff:` directives in the
# linted .sql file itself (the file, not a config file, is the attacker's
# only necessary input) --------------------------------------------------


def test_sqlfluff_sql_inline_library_path_trips_the_guard(tmp_path):
    path = write(tmp_path, "db/new.sql", "-- sqlfluff:library_path:lib\nselect 1\n")
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert "db/new.sql" in reason
    assert "library_path" in reason


def test_sqlfluff_sql_inline_no_space_variant_trips_the_guard(tmp_path):
    path = write(tmp_path, "db/new.sql", "--sqlfluff:templater:jinja:library_path:lib\nselect 1\n")
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert "db/new.sql" in reason
    assert "library_path" in reason


def test_sqlfluff_sql_inline_ordinary_directive_is_safe(tmp_path):
    path = write(tmp_path, "db/new.sql", "-- sqlfluff:dialect:postgres\nselect 1\n")
    assert guards.sqlfluff(tmp_path, [path]) is None


# --- sqlfluff: B2, the jinja loader's other file-disclosure keys --------


def test_sqlfluff_loader_search_path_trips_the_guard(tmp_path):
    path = write(tmp_path, ".sqlfluff", "[sqlfluff:templater:jinja]\nloader_search_path = /etc\n")
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert "loader_search_path" in reason


def test_sqlfluff_load_macros_from_path_trips_the_guard(tmp_path):
    path = write(
        tmp_path, ".sqlfluff", "[sqlfluff:templater:jinja]\nload_macros_from_path = /etc\n"
    )
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert "load_macros_from_path" in reason


def test_sqlfluff_exclude_macros_from_path_trips_the_guard(tmp_path):
    path = write(
        tmp_path, ".sqlfluff", "[sqlfluff:templater:jinja]\nexclude_macros_from_path = /etc\n"
    )
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert "exclude_macros_from_path" in reason


# --- sqlfluff: CONFIRMED #2, the inline directive scan must not be UTF-8-only
# -- sqlfluff itself reads with `encoding=autodetect`, so a UTF-16 file's
# inline `-- sqlfluff:` directive decodes to garbage under naive UTF-8 and is
# missed here while sqlfluff's own reader honours it. --------------------


def test_sqlfluff_sql_inline_utf16_le_bom_trips_the_guard(tmp_path):
    # BOM + UTF-16-LE body, matching the confirmed repro exactly.
    path = tmp_path / "db" / "new.sql"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        b"\xff\xfe" + "-- sqlfluff:library_path:lib\nSELECT {{1}} FROM t;\n".encode("utf-16-le")
    )
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert "db/new.sql" in reason
    assert "library_path" in reason


def test_sqlfluff_sql_inline_utf16_be_bom_trips_the_guard(tmp_path):
    path = tmp_path / "db" / "new.sql"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        b"\xfe\xff" + "-- sqlfluff:library_path:lib\nSELECT {{1}} FROM t;\n".encode("utf-16-be")
    )
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert "db/new.sql" in reason
    assert "library_path" in reason


def test_sqlfluff_sql_inline_utf8_ordinary_directive_is_still_safe(tmp_path):
    path = write(tmp_path, "db/new.sql", "-- sqlfluff:dialect:postgres\nselect 1\n")
    assert guards.sqlfluff(tmp_path, [path]) is None


def test_sqlfluff_sql_inline_latin1ish_no_directive_is_safe(tmp_path):
    """No false positive: decoding noise under any of the attempted
    encodings must never manufacture a directive that was never there."""
    path = tmp_path / "db" / "new.sql"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"-- description: caf\xe9 na\xefve\nselect 1;\n")
    assert guards.sqlfluff(tmp_path, [path]) is None


# --- sqlfluff: B3, unbounded `_walk` recursion ---------------------------


def test_sqlfluff_pyproject_deeply_nested_config_is_refused_not_raised(tmp_path):
    """A pyproject.toml with [tool.sqlfluff] nested 5000 levels deep used to
    blow `_walk`'s recursion; it must come back as a refusal string."""
    header = "tool.sqlfluff" + "".join(f".n{i}" for i in range(5000))
    path = write(tmp_path, "pyproject.toml", f"[{header}]\nx = 1\n")
    reason = guards.sqlfluff(tmp_path, [path])
    assert reason is not None
    assert "pyproject.toml" in reason


def test_sqlfluff_pyproject_shallow_nested_config_is_safe(tmp_path):
    header = "tool.sqlfluff" + "".join(f".n{i}" for i in range(40))
    path = write(tmp_path, "pyproject.toml", f"[{header}]\ndialect = 'ansi'\n")
    assert guards.sqlfluff(tmp_path, [path]) is None


# --- flake8 ---------------------------------------------------------------


def test_flake8_local_plugins_extension_trips_the_guard(tmp_path):
    path = write(
        tmp_path,
        ".flake8",
        "[flake8:local-plugins]\nextension =\n  XX = evilmod.pwn:Checker\npaths = .\n",
    )
    reason = guards.flake8(tmp_path, [path])
    assert reason is not None
    assert reason.startswith(".flake8: sets extension in [flake8:local-plugins]")


def test_flake8_local_plugins_report_in_setup_cfg_trips_the_guard(tmp_path):
    path = write(tmp_path, "setup.cfg", "[flake8:local-plugins]\nreport = X = m:R\n")
    reason = guards.flake8(tmp_path, [path])
    assert reason is not None
    assert "report in [flake8:local-plugins]" in reason


def test_flake8_clean_config_is_safe(tmp_path):
    path = write(tmp_path, "tox.ini", "[flake8]\nmax-line-length = 100\n")
    assert guards.flake8(tmp_path, [path]) is None


def test_flake8_malformed_config_is_unsafe(tmp_path):
    path = write(tmp_path, ".flake8", "[flake8\nbroken")
    reason = guards.flake8(tmp_path, [path])
    assert reason is not None
    assert "could not be parsed" in reason


def test_flake8_percent_value_in_extension_does_not_raise(tmp_path):
    """F3: the confirmed crash -- a `%` in [flake8:local-plugins] extension
    used to raise InterpolationSyntaxError out of the guard entirely."""
    path = write(tmp_path, ".flake8", "[flake8:local-plugins]\nextension = X100% = evil:C\n")
    reason = guards.flake8(tmp_path, [path])
    assert reason is not None
    assert reason.startswith(".flake8: sets extension in [flake8:local-plugins]")


def test_flake8_empty_paths_is_safe(tmp_path):
    path = write(tmp_path, ".flake8", "[flake8:local-plugins]\npaths =\n")
    assert guards.flake8(tmp_path, [path]) is None


def test_flake8_no_config_is_safe(tmp_path):
    assert guards.flake8(tmp_path, []) is None


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


def test_vale_percent_value_is_safe(tmp_path):
    """F3: a `%` in an unrelated value must not raise InterpolationSyntaxError."""
    path = write(
        tmp_path,
        ".vale.ini",
        "StylesPath = styles\nMinAlertLevel = suggestion\n[*.md]\nTokenIgnores = 100%\n",
    )
    assert guards.vale(tmp_path, [path]) is None


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


# --- tflint (final-fix-4 G1) ----------------------------------------------


def test_tflint_plugin_block_names_a_binary_trips_the_guard(tmp_path):
    path = write(tmp_path, ".tflint.hcl", 'plugin "aws" {\n  enabled = true\n}\n')
    reason = guards.tflint(tmp_path, [path])
    assert reason is not None
    assert ".tflint.hcl" in reason
    assert 'plugin "aws"' in reason


def test_tflint_terraform_plugin_alone_is_safe(tmp_path):
    path = write(tmp_path, ".tflint.hcl", 'plugin "terraform" {\n  enabled = true\n}\n')
    assert guards.tflint(tmp_path, [path]) is None


def test_tflint_plugin_dir_trips_the_guard(tmp_path):
    path = write(tmp_path, ".tflint.hcl", 'config {\n  plugin_dir = "./p"\n}\n')
    reason = guards.tflint(tmp_path, [path])
    assert reason is not None
    assert ".tflint.hcl" in reason
    assert "plugin_dir" in reason


def test_tflint_terraform_plugin_with_source_and_version_trips_the_guard(tmp_path):
    path = write(
        tmp_path,
        ".tflint.hcl",
        'plugin "terraform" {\n  version = "0.1"\n  source = "github.com/x/y"\n}\n',
    )
    reason = guards.tflint(tmp_path, [path])
    assert reason is not None
    assert ".tflint.hcl" in reason
    # the ATTR_WHY path specifically, not just any refusal -- a plugin named
    # "terraform" but naming a source/version is a plugin tflint does not
    # bundle under that name, a distinct reason from a non-terraform plugin.
    assert "does not bundle" in reason


def test_tflint_hash_comment_strips_unsafe_key(tmp_path):
    path = write(tmp_path, ".tflint.hcl", '# plugin "aws" { enabled = true }\n')
    assert guards.tflint(tmp_path, [path]) is None


def test_tflint_slash_comment_strips_unsafe_key(tmp_path):
    path = write(tmp_path, ".tflint.hcl", '// plugin "aws" { enabled = true }\n')
    assert guards.tflint(tmp_path, [path]) is None


def test_tflint_block_comment_strips_unsafe_key(tmp_path):
    path = write(tmp_path, ".tflint.hcl", '/* plugin "aws" { enabled = true } */\n')
    assert guards.tflint(tmp_path, [path]) is None


def test_tflint_star_slash_in_string_is_not_a_comment(tmp_path):
    """A naive, string-unaware stripper would treat this `/*` inside a
    quoted string value as a real (and, since there is no later `*/`,
    UNTERMINATED) block comment and delete everything after it -- including
    the real plugin "aws" block -- wrongly returning None. `label` isn't a
    key any guard cares about, so only string-awareness is on trial here,
    not the source/version attribute check. `#`/`//` only ever truncate to
    end of THEIR OWN line even when string-unaware, so they cannot swallow
    a later line the way an unterminated `/*` can -- this is the marker
    that actually needs string-awareness proven."""
    path = write(
        tmp_path,
        ".tflint.hcl",
        'plugin "terraform" {\n  label = "abc /* def"\n}\nplugin "aws" {\n  enabled = true\n}\n',
    )
    reason = guards.tflint(tmp_path, [path])
    assert reason is not None
    assert 'plugin "aws"' in reason


def test_tflint_no_config_is_safe(tmp_path):
    assert guards.tflint(tmp_path, []) is None


@skip_if_root
def test_tflint_unreadable_config_is_unsafe(tmp_path):
    path = write(tmp_path, ".tflint.hcl", 'plugin "terraform" {}\n')
    os.chmod(path, 0o000)
    try:
        reason = guards.tflint(tmp_path, [path])
    finally:
        os.chmod(path, 0o644)
    assert reason is not None
    assert "could not be parsed" in reason


# --- tflint: CONFIRMED #1, HCL heredocs -----------------------------------
# `_strip_hcl_comments` tracked quoted strings but not heredocs (`<<EOT ...
# EOT` / `<<-EOT ... EOT`); a `/*` inside a heredoc's literal body is not a
# comment to tflint, but the old scanner treated it as an unterminated block
# comment and stripped everything from there to EOF -- deleting a real
# `plugin "pwn"` block that followed. rr3/repro/tflint-heredoc/ is the
# confirmed reproduction.


def test_tflint_heredoc_body_hides_plugin_pwn_trips_the_guard(tmp_path):
    """The exact rr3/repro/tflint-heredoc/infra/.tflint.hcl shape."""
    path = write(
        tmp_path,
        ".tflint.hcl",
        'plugin "terraform" {\n'
        "  enabled = true\n"
        "  x = <<EOT\n"
        "/*\n"
        "EOT\n"
        "}\n"
        'plugin "pwn" {\n'
        "  enabled = true\n"
        "}\n"
        "config {\n"
        '  plugin_dir = "./p"\n'
        "}\n",
    )
    reason = guards.tflint(tmp_path, [path])
    assert reason is not None
    assert ".tflint.hcl" in reason
    assert 'plugin "pwn"' in reason


def test_tflint_indented_heredoc_body_hides_plugin_trips_the_guard(tmp_path):
    """The `<<-EOT` indented form, with the real unsafe block after the
    terminator, and the body's `/*` never actually closed anywhere -- an
    unterminated real block comment would (correctly) also refuse, so the
    body must contain a would-be-unterminated marker to prove it is opaque,
    not merely skipped because it happens to balance."""
    path = write(
        tmp_path,
        ".tflint.hcl",
        'plugin "terraform" {\n'
        "  x = <<-EOT\n"
        "    /* never closed\n"
        "    EOT\n"
        "}\n"
        'plugin "pwn" {\n'
        "  enabled = true\n"
        "}\n",
    )
    reason = guards.tflint(tmp_path, [path])
    assert reason is not None
    assert 'plugin "pwn"' in reason


def test_tflint_heredoc_data_containing_plugin_name_is_safe(tmp_path):
    """A heredoc body containing the literal text `plugin "aws"` is opaque
    DATA to tflint, not a real block -- it must not itself trip the guard
    when nothing outside the heredoc is unsafe."""
    path = write(
        tmp_path,
        ".tflint.hcl",
        'plugin "terraform" {\n'
        "  enabled = true\n"
        "  x = <<EOT\n"
        'plugin "aws" {\n'
        "  enabled = true\n"
        "}\n"
        "EOT\n"
        "}\n",
    )
    assert guards.tflint(tmp_path, [path]) is None


def test_tflint_unterminated_heredoc_is_unsafe(tmp_path):
    path = write(
        tmp_path,
        ".tflint.hcl",
        'plugin "terraform" {\n  x = <<EOT\nno terminator ever appears\n}\n',
    )
    reason = guards.tflint(tmp_path, [path])
    assert reason is not None
    assert ".tflint.hcl" in reason
    assert "could not be parsed" in reason


# --- buf (final-fix-4 G2) --------------------------------------------------


def test_buf_plugins_trips_the_guard(tmp_path):
    path = write(tmp_path, "buf.yaml", "version: v2\nplugins:\n  - plugin: ./buf-plugin-x\n")
    reason = guards.buf(tmp_path, [path])
    assert reason is not None
    assert "buf.yaml" in reason
    assert "plugins" in reason


def test_buf_deps_trips_the_guard(tmp_path):
    path = write(tmp_path, "buf.yml", "version: v2\ndeps:\n  - buf.build/acme/weather\n")
    reason = guards.buf(tmp_path, [path])
    assert reason is not None
    assert "deps" in reason


def test_buf_clean_config_is_safe(tmp_path):
    path = write(tmp_path, "buf.yaml", "version: v2\nlint:\n  use:\n    - STANDARD\n")
    assert guards.buf(tmp_path, [path]) is None


def test_buf_no_config_is_safe(tmp_path):
    assert guards.buf(tmp_path, []) is None


def test_buf_malformed_config_is_unsafe(tmp_path):
    path = write(tmp_path, "buf.yaml", "plugins: [unterminated\n")
    reason = guards.buf(tmp_path, [path])
    assert reason is not None
    assert "buf.yaml" in reason


def test_buf_deeply_nested_config_is_refused_not_raised(tmp_path):
    """`_walk`'s own depth bound, one of 7 call sites -- a YAML document
    nested well past `_WALK_MAX_DEPTH` (64) must come back as a refusal."""
    n = 100
    path = write(tmp_path, "buf.yaml", "[" * n + "1" + "]" * n + "\n")
    reason = guards.buf(tmp_path, [path])
    assert reason is not None
    assert "nested more than" in reason


# --- ast-grep (final-fix-4 G3) ---------------------------------------------


def test_ast_grep_custom_languages_library_path_trips_the_guard(tmp_path):
    path = write(
        tmp_path,
        "sgconfig.yml",
        "customLanguages:\n  mylang:\n    libraryPath: ./pwn.so\n",
    )
    reason = guards.ast_grep(tmp_path, [path])
    assert reason is not None
    assert "sgconfig.yml" in reason
    assert "customlanguages" in reason.lower()


def test_ast_grep_clean_config_is_safe(tmp_path):
    path = write(tmp_path, "sgconfig.yml", "ruleDirs:\n  - rules\n")
    assert guards.ast_grep(tmp_path, [path]) is None


def test_ast_grep_no_config_is_safe(tmp_path):
    assert guards.ast_grep(tmp_path, []) is None


def test_ast_grep_deeply_nested_config_is_refused_not_raised(tmp_path):
    n = 100
    path = write(tmp_path, "sgconfig.yml", "[" * n + "1" + "]" * n + "\n")
    reason = guards.ast_grep(tmp_path, [path])
    assert reason is not None
    assert "nested more than" in reason


# --- regal (final-fix-4 G4) -------------------------------------------------


def test_regal_custom_rule_trips_the_guard(tmp_path):
    config = write(tmp_path, "pol/.regal/config.yaml", "rules: {}\n")
    write(tmp_path, "pol/.regal/rules/pwn.rego", "package custom.regal.rules.pwn\n")
    reason = guards.regal(tmp_path, [config])
    assert reason is not None
    assert "pol/.regal/rules/pwn.rego" in reason
    assert "custom rules" in reason


def test_regal_nested_custom_rule_trips_the_guard(tmp_path):
    config = write(tmp_path, "pol/.regal/config.yaml", "rules: {}\n")
    write(tmp_path, "pol/.regal/rules/a/b.rego", "package custom.regal.rules.b\n")
    reason = guards.regal(tmp_path, [config])
    assert reason is not None
    assert "pol/.regal/rules/a/b.rego" in reason


def test_regal_no_rules_dir_is_safe(tmp_path):
    config = write(tmp_path, "pol/.regal/config.yaml", "rules: {}\n")
    assert guards.regal(tmp_path, [config]) is None


def test_regal_empty_rules_dir_is_safe(tmp_path):
    config = write(tmp_path, "pol/.regal/config.yaml", "rules: {}\n")
    (tmp_path / "pol" / ".regal" / "rules").mkdir()
    assert guards.regal(tmp_path, [config]) is None


# --- ruff (final-fix-5 G5) --------------------------------------------------


def test_ruff_toml_absolute_extend_trips_the_guard(tmp_path):
    path = write(tmp_path, "ruff.toml", 'extend = "/var/run/secrets/kubernetes.io/token"\n')
    reason = guards.ruff(tmp_path, [path])
    assert reason is not None
    assert "ruff.toml" in reason
    assert "extend" in reason


def test_dot_ruff_toml_dotdot_extend_trips_the_guard(tmp_path):
    path = write(tmp_path, ".ruff.toml", 'extend = "../../etc/x"\n')
    reason = guards.ruff(tmp_path, [path])
    assert reason is not None
    assert ".ruff.toml" in reason
    assert "extend" in reason


def test_ruff_toml_relative_extend_is_safe(tmp_path):
    path = write(tmp_path, "ruff.toml", 'extend = "base.toml"\n')
    assert guards.ruff(tmp_path, [path]) is None


def test_ruff_pyproject_toml_scoped_to_tool_ruff_trips_the_guard(tmp_path):
    path = write(tmp_path, "pyproject.toml", '[tool.ruff]\nextend = "/etc/x"\n')
    reason = guards.ruff(tmp_path, [path])
    assert reason is not None
    assert "pyproject.toml" in reason
    assert "extend" in reason


def test_ruff_no_config_is_safe(tmp_path):
    assert guards.ruff(tmp_path, []) is None


def test_ruff_malformed_config_is_unsafe(tmp_path):
    path = write(tmp_path, "ruff.toml", "this is not [[[ valid toml\n===\n")
    reason = guards.ruff(tmp_path, [path])
    assert reason is not None
    assert "ruff.toml" in reason


def test_ruff_tilde_extend_trips_the_guard(tmp_path):
    path = write(tmp_path, "ruff.toml", 'extend = "~/x"\n')
    reason = guards.ruff(tmp_path, [path])
    assert reason is not None
    assert "extend" in reason


def test_ruff_deeply_nested_config_is_refused_not_raised(tmp_path):
    header = "a" + "".join(f".n{i}" for i in range(100))
    path = write(tmp_path, "pyproject.toml", f"[tool.ruff.{header}]\nx = 1\n")
    reason = guards.ruff(tmp_path, [path])
    assert reason is not None
    assert "nested more than" in reason


# --- ruff: CONFIRMED #3, `extend` escapes via a committed symlink ----------


def test_ruff_symlink_escape_trips_the_guard(tmp_path):
    """rr3/repro/ruff-symlink/: a plain relative `extend` value, through a
    repo-committed symlinked directory, reads a host file -- absolute/`..`
    checks alone never see it."""
    (tmp_path / "hostdir").symlink_to("/etc")
    path = write(tmp_path, "ruff.toml", 'extend = "hostdir/hostname"\n')
    reason = guards.ruff(tmp_path, [path])
    assert reason is not None
    assert "ruff.toml" in reason
    assert "extend" in reason


def test_ruff_symlink_pointing_inside_the_repo_is_allowed(tmp_path):
    write(tmp_path, "base.toml", "")
    (tmp_path / "linkdir").symlink_to(tmp_path)
    path = write(tmp_path, "ruff.toml", 'extend = "linkdir/base.toml"\n')
    assert guards.ruff(tmp_path, [path]) is None


def test_ruff_dangling_symlink_pointing_outside_is_unsafe(tmp_path):
    (tmp_path / "hostdir").symlink_to("/definitely/does/not/exist-xyz123")
    path = write(tmp_path, "ruff.toml", 'extend = "hostdir/x"\n')
    reason = guards.ruff(tmp_path, [path])
    assert reason is not None
    assert "extend" in reason


# --- ruff: CONFIRMED #5, a decoy key defeats the first-match walk ----------


def test_ruff_decoy_per_file_ignores_key_does_not_hide_the_real_extend(tmp_path):
    """rr3/repro/ruff-decoy/: `lint.per-file-ignores."extend"` is a valid
    ruff glob list that sorts before the real top-level `extend` and used to
    be the ONLY occurrence `_walk_kv` ever returned."""
    path = write(
        tmp_path,
        "ruff.toml",
        'lint.per-file-ignores."extend" = ["E402"]\nextend = "/etc/hostname"\n',
    )
    reason = guards.ruff(tmp_path, [path])
    assert reason is not None
    assert "ruff.toml" in reason
    assert "extend" in reason


def test_ruff_two_extend_keys_second_one_unsafe_trips_the_guard(tmp_path):
    path = write(
        tmp_path,
        "ruff.toml",
        'lint.per-file-ignores."extend" = ["E999"]\nextend = "../../etc/passwd"\n',
    )
    reason = guards.ruff(tmp_path, [path])
    assert reason is not None
    assert "extend" in reason


# --- biome (final-fix-5 G6) --------------------------------------------------


def test_biome_json_absolute_extends_trips_the_guard(tmp_path):
    path = write(tmp_path, "biome.json", '{"extends": ["/etc/passwd"]}\n')
    reason = guards.biome(tmp_path, [path])
    assert reason is not None
    assert "biome.json" in reason
    assert "extends" in reason


def test_biome_jsonc_relative_extends_is_safe(tmp_path):
    path = write(tmp_path, "biome.jsonc", '{\n  // a comment\n  "extends": ["./base.json"]\n}\n')
    assert guards.biome(tmp_path, [path]) is None


def test_biome_jsonc_block_comment_parses(tmp_path):
    path = write(
        tmp_path,
        "biome.jsonc",
        '/* header */\n{\n  "extends": ["../../etc/passwd"]\n}\n',
    )
    reason = guards.biome(tmp_path, [path])
    assert reason is not None
    assert "biome.jsonc" in reason


def test_biome_no_config_is_safe(tmp_path):
    assert guards.biome(tmp_path, []) is None


def test_biome_malformed_config_is_unsafe(tmp_path):
    path = write(tmp_path, "biome.json", "{not valid json\n")
    reason = guards.biome(tmp_path, [path])
    assert reason is not None
    assert "biome.json" in reason


def test_biome_no_extends_key_is_safe(tmp_path):
    path = write(tmp_path, "biome.json", '{"formatter": {"enabled": true}}\n')
    assert guards.biome(tmp_path, [path]) is None


def test_biome_deeply_nested_config_is_refused_not_raised(tmp_path):
    n = 100
    path = write(tmp_path, "biome.json", "[" * n + "1" + "]" * n + "\n")
    reason = guards.biome(tmp_path, [path])
    assert reason is not None
    assert "nested more than" in reason


def test_biome_string_with_slash_star_is_not_a_comment(tmp_path):
    """A naive, string-unaware `_strip_jsonc_comments` would treat the `//`
    inside this JSON string value as a real comment marker and delete the
    real `extends` key that follows it."""
    path = write(
        tmp_path,
        "biome.jsonc",
        '{\n  "ignore": ["http://example.com/x /* not a comment */"],\n'
        '  "extends": ["/etc/passwd"]\n}\n',
    )
    reason = guards.biome(tmp_path, [path])
    assert reason is not None
    assert "extends" in reason


# --- biome: CONFIRMED #4, `extends` escapes via a committed symlink -------


def test_biome_symlink_escape_trips_the_guard(tmp_path):
    """rr3/repro/biome-symlink/."""
    (tmp_path / "hostdir").symlink_to("/etc")
    path = write(tmp_path, "biome.json", '{"extends": ["./hostdir/hostname"]}\n')
    reason = guards.biome(tmp_path, [path])
    assert reason is not None
    assert "biome.json" in reason
    assert "extends" in reason


def test_biome_dangling_symlink_pointing_outside_is_unsafe(tmp_path):
    (tmp_path / "hostdir").symlink_to("/definitely/does/not/exist-xyz123")
    path = write(tmp_path, "biome.json", '{"extends": ["./hostdir/x"]}\n')
    reason = guards.biome(tmp_path, [path])
    assert reason is not None
    assert "extends" in reason


def test_biome_symlink_pointing_inside_the_repo_is_allowed(tmp_path):
    write(tmp_path, "base.json", "{}\n")
    (tmp_path / "linkdir").symlink_to(tmp_path)
    path = write(tmp_path, "biome.json", '{"extends": ["./linkdir/base.json"]}\n')
    assert guards.biome(tmp_path, [path]) is None


# --- biome: CONFIRMED #5-shaped decoy (latent, not yet exploitable against
# real biome -- see rr3/EVIDENCE.md -- but `_walk_kv` must still find every
# occurrence, matching the same fix applied to ruff) ------------------------


def test_biome_decoy_nested_extends_does_not_hide_the_real_extends(tmp_path):
    """rr3/repro/biome-decoy/: a nested `extends` under an unrelated key
    sorts before the real top-level one."""
    path = write(
        tmp_path,
        "biome.json",
        '{ "x": { "extends": ["./ok.json"] }, "extends": ["/etc/hostname"] }\n',
    )
    write(tmp_path, "ok.json", "{}\n")
    reason = guards.biome(tmp_path, [path])
    assert reason is not None
    assert "biome.json" in reason
    assert "extends" in reason
