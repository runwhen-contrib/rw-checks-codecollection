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

A later security probe ran every remaining `GUARD = None` tool's real argv
inside the built image, under the executor pod's own constraints, and found
four more: tflint (a `.tflint.hcl` `plugin` block naming anything but
`terraform`, a `plugin_dir` key, or a plugin's `source`/`version` all make
tflint install or load a plugin BINARY from the repo's own tree), buf (a v2
`buf.yaml`'s `plugins` key makes `buf lint` exec a local check-plugin
binary; its `deps` key fetches modules from the network), ast-grep
(`sgconfig.yml`'s `customLanguages.<lang>.libraryPath` is a native library
ast-grep `dlopen`s -- the library's constructor ran before ast-grep's own
symbol lookup failed) and regal (`.regal/rules/**/*.rego` are auto-loaded
and evaluated as Rego; a rule calling `http.send` reached an external
listener, and the response was surfaced in the finding -- an outbound
network channel and an exfiltration path, even though Rego has no
file-read builtin and is not itself RCE).

A third probe pass covered the two tools still left at `GUARD = None` and
found a file-read vector in each, not exec: ruff (`ruff.toml`/`.ruff.toml`/
`pyproject.toml`'s `[tool.ruff]`'s `extend` names another config file ruff
reads and merges in -- an absolute or `..`-escaping target makes ruff read
an arbitrary host file and echo its content into the TOML parse error it
raises, which then lands verbatim in the PR finding: confirmed
deterministic against the built image) and biome (`biome.json`/
`biome.jsonc`'s `extends` resolves the same way, from disk rather than
fetched -- an absolute or `..`-escaping entry made biome read `/etc/passwd`
and echo it to stderr, which every run forwards to `ctx.log`, and into a
finding whenever biome then exits outside `EXPECT_EXIT`: confirmed, though
not deterministically outside `(0, 1)`). GritQL `plugins` in a biome config
are declarative -- no exec, no fetch -- and are not guarded.

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
import json
import re
import tomllib
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
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


def _walk_kv(obj: Any, keys: set[str], depth: int = 0) -> Any:
    """Like `_walk`, but returns the matching `(key, value)` PAIR instead of
    only the key -- for a guard that must inspect the value itself (ruff's
    `extend` path, biome's `extends` entries), not merely detect that the
    key is present. Same depth bound and `_TOO_DEEP` sentinel as `_walk`,
    which is defined in terms of this rather than duplicating the walk."""
    if depth > _WALK_MAX_DEPTH:
        return _TOO_DEEP
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k).lower()
            if key in keys and v:
                return key, v
            found = _walk_kv(v, keys, depth + 1)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _walk_kv(item, keys, depth + 1)
            if found:
                return found
    return None


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
    found = _walk_kv(obj, keys, depth)
    if found is None or found is _TOO_DEEP:
        return found
    return found[0]


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


def _unsafe_path(value: str) -> bool:
    """True when `value` -- a path a tool config points somewhere else on
    disk -- would resolve outside the repository: absolute, `~`-relative (a
    tool's own path handling may expand that to the user's home, which is
    outside the repo too), or containing a `..` segment. A plain relative
    path that stays inside the repo is ordinary config reuse and is safe."""
    if value.startswith("~"):
        return True
    if PurePosixPath(value).is_absolute():
        return True
    return ".." in PurePosixPath(value).parts


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


# --- tflint -----------------------------------------------------------------
# tflint bundles only the `terraform` ruleset; anything else named by a
# `plugin "<name>"` block is a plugin BINARY tflint installs and executes.
# `plugin_dir` (default `./.tflint.d/plugins`, or set explicitly) resolves
# INSIDE the PR's tree, and a plugin block's own `source`/`version` names a
# plugin we never installed, which tflint then tries to install/load from
# that same repo-controlled directory -- confirmed against the built image:
# both a `plugin "x"` block plus a committed `./.tflint.d/plugins/
# tflint-ruleset-x` and a `plugin_dir = "./p"` plus `./p/tflint-ruleset-x`
# ran the repo binary as the pod's own uid. No HCL parser is available, so
# `.tflint.hcl` is scanned textually, after stripping `#`/`//` line comments
# and `/* ... */` block comments -- never inside a quoted string, so a `#`
# or `//` in e.g. a URL value cannot truncate a live line.
_TFLINT_PLUGIN_WHY = "which tflint loads as a binary from the repository"
_TFLINT_PLUGIN_ATTR_WHY = (
    "which names a plugin tflint does not bundle, so tflint installs and loads it "
    "as a binary from the repository's plugin dir"
)
_TFLINT_PLUGIN_DIR_WHY = "which tflint loads plugin binaries from"
_TFLINT_PLUGIN_BLOCK = re.compile(r'plugin\s+"([^"]*)"\s*\{')
_TFLINT_PLUGIN_DIR_KEY = re.compile(r"\bplugin_dir\b\s*=")
_TFLINT_PLUGIN_ATTR_KEY = re.compile(r"\b(?:source|version)\b\s*=")


def _strip_hcl_comments(text: str) -> str:
    """`#`/`//` to end of line and `/* ... */` blocks, never stripped inside
    a quoted string."""
    out: list[str] = []
    in_string = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "#" or text[i : i + 2] == "//":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if text[i : i + 2] == "/*":
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _hcl_block(text: str, open_brace: int) -> str:
    """The content between the `{` at `open_brace` and its matching `}`,
    tracking quoted strings so a brace inside a string value is not
    counted. An unterminated block returns everything to end of text
    rather than raising, matching guards' "never raise" contract."""
    depth = 0
    in_string = False
    start = open_brace + 1
    i, n = open_brace, len(text)
    while i < n:
        ch = text[i]
        if in_string:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i]
        i += 1
    return text[start:]


def tflint(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _selected(paths, ".tflint.hcl"):
        try:
            text = path.read_text()
        except (OSError, UnicodeDecodeError) as e:
            return _unparseable(tree, path, e)
        stripped = _strip_hcl_comments(text)
        for m in _TFLINT_PLUGIN_BLOCK.finditer(stripped):
            name = m.group(1)
            block = _hcl_block(stripped, m.end() - 1)
            if name != "terraform":
                return _reason(tree, path, f'plugin "{name}"', _TFLINT_PLUGIN_WHY)
            if _TFLINT_PLUGIN_ATTR_KEY.search(block):
                return _reason(tree, path, f'plugin "{name}"', _TFLINT_PLUGIN_ATTR_WHY)
        if _TFLINT_PLUGIN_DIR_KEY.search(stripped):
            return _reason(tree, path, "plugin_dir", _TFLINT_PLUGIN_DIR_WHY)
    return None


# --- buf ----------------------------------------------------------------
# A v2 buf.yaml's top-level `plugins` key makes `buf lint` exec a check
# plugin -- a local path or a name resolved off PATH -- BEFORE buf reports
# anything: confirmed against the built image, the plugin binary ran even
# though the go-plugin handshake then failed. `deps` makes buf fetch
# modules from the BSR over the network. Both are refused at any nesting
# depth (`_walk`, same as checkov/pylint's TOML/YAML guards above).
_BUF_PLUGINS_WHY = "which buf executes as a binary"
_BUF_DEPS_WHY = "which buf fetches from the network"
_BUF_KEYS = {"plugins", "deps"}
_BUF_WHY = {"plugins": _BUF_PLUGINS_WHY, "deps": _BUF_DEPS_WHY}


def buf(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _selected(paths, "buf.yaml", "buf.yml"):
        try:
            doc = yaml.safe_load(path.read_text())
        except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError) as e:
            return _unparseable(tree, path, e)
        found = _walk(doc or {}, _BUF_KEYS)
        if found is _TOO_DEEP:
            return _too_deep(tree, path)
        if found:
            return _reason(tree, path, found, _BUF_WHY[found])
    return None


# --- ast-grep -------------------------------------------------------------
# `sgconfig.yml`'s `customLanguages.<lang>.libraryPath` makes ast-grep
# `dlopen` a repo-committed shared library -- confirmed against the built
# image: the library's ELF constructor ran (a marker file was written) as
# the pod's own uid, before ast-grep's own symbol lookup then failed.
# Refusing a non-empty `customLanguages` outright is simpler and safer than
# trying to validate individual libraryPath values.
_AST_GREP_WHY = "which ast-grep loads as a native library from the repository"
_AST_GREP_KEYS = {"customlanguages"}


def ast_grep(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _selected(paths, "sgconfig.yml", "sgconfig.yaml"):
        try:
            doc = yaml.safe_load(path.read_text())
        except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError) as e:
            return _unparseable(tree, path, e)
        found = _walk(doc or {}, _AST_GREP_KEYS)
        if found is _TOO_DEEP:
            return _too_deep(tree, path)
        if found:
            return _reason(tree, path, found, _AST_GREP_WHY)
    return None


# --- regal ------------------------------------------------------------------
# regal auto-loads every `.regal/rules/**/*.rego` next to a `.regal/
# config.yaml` and evaluates it as OPA Rego -- confirmed against the built
# image: a repo-committed rule calling `http.send` reached an external
# listener, and the response status was surfaced in the finding regal
# produced. Rego has no file-read builtin and `opa.runtime().env` is empty
# in this build, so this is not RCE -- but findings are posted onto the PR,
# so it is still an outbound network channel AND an exfiltration path (the
# response body ends up in a finding). Any `*.rego` under the config's own
# sibling `rules/` directory trips it, at any depth; the config's own
# content is never even parsed, since regal auto-loads every rule file
# there regardless of what `config.yaml` says.
_REGAL_WHY = "which regal executes, and which can make network requests"


def regal(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in sorted(
        p for p in paths if p.name == "config.yaml" and p.parent.name == ".regal" and p.is_file()
    ):
        try:
            rule_files = sorted((path.parent / "rules").rglob("*.rego"))
        except OSError as e:
            return _unparseable(tree, path, e)
        if rule_files:
            return _reason(tree, rule_files[0], "custom rules", _REGAL_WHY)
    return None


# --- ruff (final-fix-5 G5) ---------------------------------------------------
# `extend` in ruff.toml/.ruff.toml, or under `[tool.ruff]` in pyproject.toml,
# names another ruff config file that ruff reads and merges in. An absolute
# or `..`-escaping target makes ruff read an arbitrary host file and echo its
# content into the TOML parse error it then raises -- confirmed against the
# built image: ruff exits 2 EVERY time on such a target, outside
# EXPECT_EXIT, so `_common.check_failed_finding` embeds `proc.stderr` --
# which is that file's content -- straight into the PR finding. Searched at
# any nesting depth via `_walk_kv`, same defense-in-depth as every other
# guard here, even though ruff's own schema only ever reads `extend` from
# the top level (of the file, or of `[tool.ruff]`).
_RUFF_KEYS = {"extend"}
_RUFF_WHY = "which ruff reads from outside the repository"


def ruff(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _selected(paths, "ruff.toml", ".ruff.toml"):
        try:
            doc = tomllib.loads(path.read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError) as e:
            return _unparseable(tree, path, e)
        found = _walk_kv(doc, _RUFF_KEYS)
        if found is _TOO_DEEP:
            return _too_deep(tree, path)
        if found:
            key, value = found
            if isinstance(value, str) and _unsafe_path(value):
                return _reason(tree, path, key, _RUFF_WHY)

    for path in _selected(paths, "pyproject.toml"):
        try:
            doc = tomllib.loads(path.read_text())
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError) as e:
            return _unparseable(tree, path, e)
        section = _toml_table(doc, "tool", "ruff")
        found = _walk_kv(section, _RUFF_KEYS) if section is not None else None
        if found is _TOO_DEEP:
            return _too_deep(tree, path)
        if found:
            key, value = found
            if isinstance(value, str) and _unsafe_path(value):
                return _reason(tree, path, key, _RUFF_WHY)

    return None


# --- biome (final-fix-5 G6) --------------------------------------------------
# biome.json/.jsonc's `extends` resolves entries from DISK, npm-style -- not
# fetched, so no network vector -- but an absolute or `..`-escaping entry
# makes biome READ an arbitrary host file and echo its content to stderr:
# confirmed against the built image (an absolute `extends` target surfaced
# /etc/passwd's own content). `ctx.run` forwards every run's stderr to
# `ctx.log`, so that alone is a log-exfil channel; when biome then exits
# outside EXPECT_EXIT the same content lands in the PR finding (observed,
# though not made deterministic). GritQL `plugins` are declarative -- no
# exec, no fetch -- and are not guarded. No YAML/HCL parser needed: JSONC is
# JSON with `//` and `/* ... */` comments stripped first, same shape as
# tflint's HCL comment strip.
_BIOME_WHY = "which biome reads from outside the repository"


def _strip_jsonc_comments(text: str) -> str:
    """`//` to end of line and `/* ... */` blocks, never stripped inside a
    quoted JSON string -- same approach as `_strip_hcl_comments` above."""
    out: list[str] = []
    in_string = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if text[i : i + 2] == "//":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if text[i : i + 2] == "/*":
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _unsafe_extends(value: Any) -> bool:
    """`extends` is a string or a list of strings; any entry that resolves
    outside the repo trips the guard. A non-string entry (or a differently
    shaped `extends`) names no path at all, so it is left alone."""
    if isinstance(value, str):
        return _unsafe_path(value)
    if isinstance(value, list):
        return any(isinstance(v, str) and _unsafe_path(v) for v in value)
    return False


def biome(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _selected(paths, "biome.json", "biome.jsonc"):
        try:
            doc = json.loads(_strip_jsonc_comments(path.read_text()))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as e:
            return _unparseable(tree, path, e)
        found = _walk_kv(doc, {"extends"})
        if found is _TOO_DEEP:
            return _too_deep(tree, path)
        if found:
            _, value = found
            if _unsafe_extends(value):
                return _reason(tree, path, "extends", _BIOME_WHY)
    return None
