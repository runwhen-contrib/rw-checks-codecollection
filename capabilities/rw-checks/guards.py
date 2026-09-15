"""Guards against config-driven code execution: tools whose OWN config file
can make THEM do something dangerous when we run them against a PR's repo,
as opposed to dangerous code in the repo that the tool merely reports as a
finding.

CONFIRMED VULNERABILITY: we run `pylint --recursive=y .` with the repo as
cwd (tasks.py's `pylint` task), so pylint reads the repo's own `.pylintrc`.
A PR adding `init-hook=import subprocess; subprocess.run(...)` to that file
executes arbitrary code in our pod -- verified against the built image. The
same shape -- a repo-controlled config the tool acts on before or instead of
scanning code -- exists for checkov (`external-checks-dir`/
`external-checks-git` import and run a directory or git repo of Python check
plugins), flake8 (a non-empty `paths`, `extension` or `report` under
`[flake8:local-plugins]` adds `paths` to `sys.path` and imports the named
entry points), sqlfluff (a jinja templater `library_path` is a directory
sqlfluff imports Python modules from) and vale (a non-empty `Packages`
fetches and installs a style package from a URL). None of these are
findings a scan should report; the tool must never be invoked at all.

One guard function per affected tool, called by `_plan.plan` per config group
BEFORE the tool runs. A guard returns a short human reason when the repo's config is unsafe,
or None when it is safe to run the tool. The reason always begins
"<repo-relative config path>: " -- `_common.unsafe_config_finding` splits on
the first ": " to recover the offending path for the `rw-checks/unsafe-config`
finding's `path` field, so a guard never needs a second return value for it.

A config file matching one of the searched names that fails to parse is
treated as UNSAFE, not benign: we cannot rule out that it sets one of these
keys, and "we couldn't tell" is not the same as "it's clean". Guards never
raise -- an unreadable or malformed file yields a refusal reason, not an
exception, so one bad config file cannot crash the whole task. That
includes a config nested deeper than `_WALK_MAX_DEPTH`: `_walk` bails out
with a distinct refusal rather than recursing further, and every guard that
parses TOML/YAML also catches `RecursionError` as belt and braces against
the parser's own recursive descent.
"""

from __future__ import annotations

import configparser
import tomllib
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

# --- shared plumbing ---------------------------------------------------------


def _selected(paths: Sequence[Path], *names: str) -> list[Path]:
    """Exactly those `paths` whose basename is one of `names` -- the
    per-config-group guard, DIFF-SCOPED-CHECKS.md §5.5."""
    wanted = set(names)
    return sorted(p for p in paths if p.name in wanted and p.is_file())


def _reason(tree: Path, path: Path, key: str, why: str) -> str:
    rel = path.relative_to(tree).as_posix()
    return f"{rel}: sets {key}, {why}"


def _unparseable(tree: Path, path: Path, err: Exception) -> str:
    rel = path.relative_to(tree).as_posix()
    return f"{rel}: could not be parsed ({err}); treating as unsafe"


def _parse_ini(text: str) -> configparser.ConfigParser:
    """Tolerates a shape more than one of these tools' own files use: bare
    `key = value` lines before any `[section]` header (vale's global
    options are never nested in a section at all). configparser otherwise
    rejects that with MissingSectionHeaderError -- parking the preamble in
    a synthetic section keeps those keys visible to the search instead of
    turning a perfectly ordinary vale.ini into a parse failure.

    `interpolation=None` -- matches `_common.parse_ini`, flake8's own
    RawConfigParser and sqlfluff's own parser. Without it, the default
    BasicInterpolation raises InterpolationSyntaxError on a bare `%` in any
    value (e.g. `extension = X100% = evil:C`), which would otherwise crash
    the guard on a value we do not even care about."""
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read_string("[__preamble__]\n" + text)
    return parser


def _ini_items(parser: configparser.ConfigParser, sections: set[str] | None = None):
    """(key, value) for every option in `parser`, optionally restricted to
    `sections` -- keys already lowercased by configparser's own
    optionxform, matching how the target key names are written below."""
    for section in parser.sections():
        if sections is not None and section not in sections:
            continue
        for key in parser.options(section):
            yield key, parser.get(section, key, fallback="")


_WALK_MAX_DEPTH = 64
#: `_walk`'s signal that recursion passed `_WALK_MAX_DEPTH` -- an identity
#: sentinel, not a string, so it can never collide with a real (lowercased)
#: key name the way a string marker like "too-deep" could.
_TOO_DEEP = object()


def _walk(obj: Any, keys: set[str], depth: int = 0) -> Any:
    """Recursively search a parsed TOML/YAML document for any of `keys` as
    a dict key with a truthy value, at ANY nesting depth. Whoever writes a
    malicious config controls which section it lives under, not just the
    key name -- a guard that only checks one fixed path is trivially
    dodged by nesting the same key one level differently. Returns the
    matched key (lowercased), `_TOO_DEEP` once `depth` passes
    `_WALK_MAX_DEPTH` -- a config nested that deep is hiding something, and
    the caller must treat "we gave up looking" as unsafe, not as None -- or
    None when nothing was found within the bound."""
    if depth > _WALK_MAX_DEPTH:
        return _TOO_DEEP
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k).lower()
            if key in keys and v:
                return key
            found = _walk(v, keys, depth + 1)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _walk(item, keys, depth + 1)
            if found:
                return found
    return None


def _too_deep(tree: Path, path: Path) -> str:
    rel = path.relative_to(tree).as_posix()
    return f"{rel}: nested more than {_WALK_MAX_DEPTH} levels deep; treating as unsafe"


def _toml_table(doc: Any, *path: str) -> Any:
    """Dotted-path descent into a parsed TOML document (e.g. "tool",
    "pylint"), stopping and returning None as soon as a step is missing or
    the value at that step isn't itself a table."""
    cur = doc
    for step in path:
        if not isinstance(cur, dict) or step not in cur:
            return None
        cur = cur[step]
    return cur


# --- pylint -------------------------------------------------------------
# init-hook runs arbitrary Python before pylint does anything else with the
# target repo; load-plugins/load_plugins imports an arbitrary module by
# dotted path. Either runs code with no cooperation from the repo's actual
# source files at all.
_PYLINT_KEYS = {"init-hook", "load-plugins", "load_plugins"}
_PYLINT_WHY = "which executes arbitrary Python"


def pylint(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _selected(paths, ".pylintrc", "pylintrc"):
        try:
            parser = _parse_ini(path.read_text())
            for key, value in _ini_items(parser):
                if key in _PYLINT_KEYS and value:
                    return _reason(tree, path, key, _PYLINT_WHY)
        except (OSError, UnicodeDecodeError, configparser.Error, RecursionError) as e:
            return _unparseable(tree, path, e)

    for path in _selected(paths, ".pylintrc.toml", "pylintrc.toml"):
        try:
            doc = tomllib.loads(path.read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError) as e:
            return _unparseable(tree, path, e)
        found = _walk(doc, _PYLINT_KEYS)
        if found is _TOO_DEEP:
            return _too_deep(tree, path)
        if found:
            return _reason(tree, path, found, _PYLINT_WHY)

    for path in _selected(paths, "pyproject.toml"):
        try:
            doc = tomllib.loads(path.read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError) as e:
            return _unparseable(tree, path, e)
        section = _toml_table(doc, "tool", "pylint")
        found = _walk(section, _PYLINT_KEYS) if section is not None else None
        if found is _TOO_DEEP:
            return _too_deep(tree, path)
        if found:
            return _reason(tree, path, found, _PYLINT_WHY)

    for path in _selected(paths, "setup.cfg"):
        try:
            parser = _parse_ini(path.read_text())
            for key, value in _ini_items(parser, sections={"pylint"}):
                if key in _PYLINT_KEYS and value:
                    return _reason(tree, path, key, _PYLINT_WHY)
        except (OSError, UnicodeDecodeError, configparser.Error, RecursionError) as e:
            return _unparseable(tree, path, e)

    return None


# --- flake8 ---------------------------------------------------------------
# [flake8:local-plugins] paths/extension/report add `paths` to sys.path and
# import the named `module:attr` entry points -- flake8 executing arbitrary
# Python from the repo before it lints anything, same shape as pylint's
# init-hook/load-plugins.
_FLAKE8_LOCAL_PLUGINS_KEYS = {"paths", "extension", "report"}
_FLAKE8_WHY = "which imports and runs Python from the repository"


def flake8(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _selected(paths, ".flake8", "setup.cfg", "tox.ini"):
        try:
            parser = _parse_ini(path.read_text())
            local_plugins = {s for s in parser.sections() if s.lower() == "flake8:local-plugins"}
            for key, value in _ini_items(parser, sections=local_plugins):
                if key in _FLAKE8_LOCAL_PLUGINS_KEYS and value:
                    return _reason(tree, path, f"{key} in [flake8:local-plugins]", _FLAKE8_WHY)
        except (OSError, UnicodeDecodeError, configparser.Error, RecursionError) as e:
            return _unparseable(tree, path, e)
    return None


# --- checkov ------------------------------------------------------------
# external-checks-dir/external-checks-git point checkov at a directory or
# git repo of custom check PLUGINS -- Python modules checkov imports and
# runs, not policy data it merely evaluates.
_CHECKOV_KEYS = {
    "external-checks-dir",
    "external-checks-git",
    "external_checks_dir",
    "external_checks_git",
}
_CHECKOV_WHY = "which checkov imports and runs as a Python check plugin"


def checkov(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _selected(paths, ".checkov.yaml", ".checkov.yml"):
        try:
            doc = yaml.safe_load(path.read_text())
        except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError) as e:
            return _unparseable(tree, path, e)
        found = _walk(doc or {}, _CHECKOV_KEYS)
        if found is _TOO_DEEP:
            return _too_deep(tree, path)
        if found:
            return _reason(tree, path, found, _CHECKOV_WHY)
    return None


# --- sqlfluff -----------------------------------------------------------
# The jinja templater's library_path is a directory sqlfluff imports Python
# modules FROM (custom Jinja filters/macros) -- same "attacker-controlled
# path becomes a module import" shape as pylint's load-plugins.
# loader_search_path/load_macros_from_path/exclude_macros_from_path are the
# same templater's other file-reading knobs: not a Python import (jinja runs
# sandboxed), but `{% include %}` renders an arbitrary host file into the SQL
# we then read as tool output -- file disclosure, not RCE, same family.
# sqlfluff's loader also merges pep8.ini into the same config, so it is
# searched here even though it configures nothing else sqlfluff cares about.
# sqlfluff merges every section whose name starts with `sqlfluff` (not only
# the exact `sqlfluff:templater:jinja`), so any section prefixed that way
# with one of these keys counts -- strictly more refusals than an exact
# match, which is the point of a guard.
_SQLFLUFF_KEYS = {
    "library_path",
    "loader_search_path",
    "load_macros_from_path",
    "exclude_macros_from_path",
}
_SQLFLUFF_WHY = "which sqlfluff imports Python modules from"
_SQLFLUFF_LOADER_WHY = "which sqlfluff reads files from"


def _sqlfluff_why(key: str) -> str:
    return _SQLFLUFF_WHY if key == "library_path" else _SQLFLUFF_LOADER_WHY


def _sql_files(paths: Sequence[Path]) -> list[Path]:
    return sorted(p for p in paths if p.suffix == ".sql" and p.is_file())


def sqlfluff(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _selected(paths, ".sqlfluff", "setup.cfg", "tox.ini", "pep8.ini"):
        try:
            parser = _parse_ini(path.read_text())
            sections = {s for s in parser.sections() if s.lower().startswith("sqlfluff")}
            for key, value in _ini_items(parser, sections=sections):
                if key in _SQLFLUFF_KEYS and value:
                    return _reason(tree, path, key, _sqlfluff_why(key))
        except (OSError, UnicodeDecodeError, configparser.Error, RecursionError) as e:
            return _unparseable(tree, path, e)

    for path in _selected(paths, "pyproject.toml"):
        try:
            doc = tomllib.loads(path.read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError) as e:
            return _unparseable(tree, path, e)
        section = _toml_table(doc, "tool", "sqlfluff")
        found = _walk(section, _SQLFLUFF_KEYS) if section is not None else None
        if found is _TOO_DEEP:
            return _too_deep(tree, path)
        if found:
            return _reason(tree, path, found, _sqlfluff_why(found))

    # B1: sqlfluff's own loader scans the LINTED FILE for inline
    # `-- sqlfluff:<key>:...:<value>` / `--sqlfluff:...` directives
    # (FluffConfig.process_raw_file_for_config) and treats them as config --
    # so a changed .sql file is a config source in its own right, not just
    # the files above. `GUARD_FILES` on the sqlfluff module is what puts
    # .sql files into `paths` at all; every other guard here never sees the
    # files it is guarding, only their config.
    for path in _sql_files(paths):
        try:
            text = path.read_text(errors="replace")
        except (OSError, RecursionError) as e:
            return _unparseable(tree, path, e)
        for line in text.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("-- sqlfluff"):
                marker = "-- sqlfluff"
            elif stripped.startswith("--sqlfluff"):
                marker = "--sqlfluff"
            else:
                continue
            key_path = stripped[len(marker) :].split(":")[:-1]
            for segment in key_path:
                key = segment.strip().lower()
                if key in _SQLFLUFF_KEYS:
                    return _reason(tree, path, f"{key} inline", _sqlfluff_why(key))

    return None


# --- vale -----------------------------------------------------------------
# A non-empty Packages key makes vale DOWNLOAD AND INSTALL a style package
# from a URL before it lints anything. Arbitrary code never runs, but an
# arbitrary network fetch and unpack into our pod does.
_VALE_WHY = "which vale fetches and installs from a URL"


def vale(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _selected(paths, ".vale.ini", "_vale.ini", "vale.ini"):
        try:
            parser = _parse_ini(path.read_text())
            for key, value in _ini_items(parser):
                if key == "packages" and value:
                    return _reason(tree, path, "Packages", _VALE_WHY)
        except (OSError, UnicodeDecodeError, configparser.Error, RecursionError) as e:
            return _unparseable(tree, path, e)
    return None
