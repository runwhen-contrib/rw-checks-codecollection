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
plugins), sqlfluff (a jinja templater `library_path` is a directory sqlfluff
imports Python modules from) and vale (a non-empty `Packages` fetches and
installs a style package from a URL). None of these are findings a scan
should report; the tool must never be invoked at all.

One guard function per affected tool, called by tasks.py BEFORE the tool
runs. A guard returns a short human reason when the repo's config is unsafe,
or None when it is safe to run the tool. The reason always begins
"<repo-relative config path>: " -- tasks.py splits on the first ": " to
recover the offending path for the `rw-checks/unsafe-config` finding's
`path` field, so a guard never needs a second return value for it.

A config file matching one of the searched names that fails to parse is
treated as UNSAFE, not benign: we cannot rule out that it sets one of these
keys, and "we couldn't tell" is not the same as "it's clean". Guards never
raise -- an unreadable or malformed file yields a refusal reason, not an
exception, so one bad config file cannot crash the whole task.
"""

from __future__ import annotations

import configparser
import tomllib
from pathlib import Path
from typing import Any

import yaml

# --- shared plumbing ---------------------------------------------------------


def _config_files(tree: Path, *names: str) -> list[Path]:
    """Every file under `tree` (recursively, `.git/` excluded) whose
    basename is one of `names`. A NESTED config is included, not just a
    root one -- a tool run with that subdirectory as its cwd (or handed it
    as a --chdir/-d/-r target) reads its own local config exactly the way
    the root one is read when the tool runs at the repo root."""
    found: list[Path] = []
    for name in names:
        for p in tree.rglob(name):
            if p.is_file() and ".git" not in p.relative_to(tree).parts:
                found.append(p)
    return sorted(found)


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
    turning a perfectly ordinary vale.ini into a parse failure."""
    parser = configparser.ConfigParser(strict=False)
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


def _walk(obj: Any, keys: set[str]) -> str | None:
    """Recursively search a parsed TOML/YAML document for any of `keys` as
    a dict key with a truthy value, at ANY nesting depth. Whoever writes a
    malicious config controls which section it lives under, not just the
    key name -- a guard that only checks one fixed path is trivially
    dodged by nesting the same key one level differently. Returns the
    matched key (lowercased) or None."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k).lower()
            if key in keys and v:
                return key
            found = _walk(v, keys)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _walk(item, keys)
            if found:
                return found
    return None


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


def pylint(tree: Path) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _config_files(tree, ".pylintrc", "pylintrc"):
        try:
            parser = _parse_ini(path.read_text())
        except (OSError, UnicodeDecodeError, configparser.Error) as e:
            return _unparseable(tree, path, e)
        for key, value in _ini_items(parser):
            if key in _PYLINT_KEYS and value:
                return _reason(tree, path, key, _PYLINT_WHY)

    for path in _config_files(tree, ".pylintrc.toml", "pylintrc.toml"):
        try:
            doc = tomllib.loads(path.read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            return _unparseable(tree, path, e)
        found = _walk(doc, _PYLINT_KEYS)
        if found:
            return _reason(tree, path, found, _PYLINT_WHY)

    for path in _config_files(tree, "pyproject.toml"):
        try:
            doc = tomllib.loads(path.read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            return _unparseable(tree, path, e)
        section = _toml_table(doc, "tool", "pylint")
        found = _walk(section, _PYLINT_KEYS) if section is not None else None
        if found:
            return _reason(tree, path, found, _PYLINT_WHY)

    for path in _config_files(tree, "setup.cfg"):
        try:
            parser = _parse_ini(path.read_text())
        except (OSError, UnicodeDecodeError, configparser.Error) as e:
            return _unparseable(tree, path, e)
        for key, value in _ini_items(parser, sections={"pylint"}):
            if key in _PYLINT_KEYS and value:
                return _reason(tree, path, key, _PYLINT_WHY)

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


def checkov(tree: Path) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _config_files(tree, ".checkov.yaml", ".checkov.yml"):
        try:
            doc = yaml.safe_load(path.read_text())
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
            return _unparseable(tree, path, e)
        found = _walk(doc or {}, _CHECKOV_KEYS)
        if found:
            return _reason(tree, path, found, _CHECKOV_WHY)
    return None


# --- sqlfluff -----------------------------------------------------------
# The jinja templater's library_path is a directory sqlfluff imports Python
# modules FROM (custom Jinja filters/macros) -- same "attacker-controlled
# path becomes a module import" shape as pylint's load-plugins.
_SQLFLUFF_WHY = "which sqlfluff imports Python modules from"


def sqlfluff(tree: Path) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _config_files(tree, ".sqlfluff", "setup.cfg", "tox.ini"):
        try:
            parser = _parse_ini(path.read_text())
        except (OSError, UnicodeDecodeError, configparser.Error) as e:
            return _unparseable(tree, path, e)
        for key, value in _ini_items(parser, sections={"sqlfluff:templater:jinja"}):
            if key == "library_path" and value:
                return _reason(tree, path, "library_path", _SQLFLUFF_WHY)

    for path in _config_files(tree, "pyproject.toml"):
        try:
            doc = tomllib.loads(path.read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            return _unparseable(tree, path, e)
        section = _toml_table(doc, "tool", "sqlfluff", "templater", "jinja")
        if isinstance(section, dict) and section.get("library_path"):
            return _reason(tree, path, "library_path", _SQLFLUFF_WHY)

    return None


# --- vale -----------------------------------------------------------------
# A non-empty Packages key makes vale DOWNLOAD AND INSTALL a style package
# from a URL before it lints anything. Arbitrary code never runs, but an
# arbitrary network fetch and unpack into our pod does.
_VALE_WHY = "which vale fetches and installs from a URL"


def vale(tree: Path) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _config_files(tree, ".vale.ini", "_vale.ini", "vale.ini"):
        try:
            parser = _parse_ini(path.read_text())
        except (OSError, UnicodeDecodeError, configparser.Error) as e:
            return _unparseable(tree, path, e)
        for key, value in _ini_items(parser):
            if key == "packages" and value:
                return _reason(tree, path, "Packages", _VALE_WHY)
    return None
