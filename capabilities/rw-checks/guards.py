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

An adversarial re-review ran the real tools in the built image against the
guards above and found five more bypasses, not new vectors: tflint's HCL
comment stripper tracked quoted strings but not heredocs (`<<EOT ... EOT`),
so a `/*` inside a heredoc's literal body -- not a comment to tflint at all
-- was treated as an unterminated block comment and deleted a real
`plugin "pwn"` block that followed it; sqlfluff's inline `-- sqlfluff:`
directive scan read a linted `.sql` file as UTF-8 only, so a UTF-16-BOM
file's directive decoded to replacement-character noise and was missed,
while sqlfluff's own `encoding=autodetect` honoured it; ruff's and biome's
`extend`/`extends` guard rejected only absolute, `~`-relative, and literal
`..` values -- a repo-committed SYMLINKED directory turns a plain relative
value into one that still escapes the tree, which none of those textual
checks can see; and `_walk_kv` returned only the FIRST occurrence of a
matching key, so a decoy (e.g. ruff's `lint.per-file-ignores."extend"`, a
valid glob list that sorts before a real top-level `extend` string) hid the
real, dangerous occurrence from a guard that inspects the value, not merely
the key's presence.

A second adversarial re-review, against the fixes above, found that three
of those FIXED CLASSES still admitted a bypass, one fix introduced a crash,
and two were fresh RCEs: tflint's heredoc terminator match required the
plain `<<` form's terminator flush-left and unpadded (`line.rstrip("\r") ==
marker`), while real HCL/tflint accepts leading and trailing whitespace on
it -- an indented `  EOT` closed the heredoc for tflint but not for this
scanner, which kept consuming a real `plugin "pwn"` block that followed as
opaque heredoc body and never saw it; sqlfluff's `_sql_texts` scanned
utf-8/utf-16-le/utf-16-be only, while sqlfluff itself decodes with
`chardet.detect`, which returns UTF-32 at confidence 1.0 for a UTF-32
`.sql` file -- confirmed with an inline `-- sqlfluff:library_path:`
directive invisible to the guard and honoured by sqlfluff; ruff's and
biome's `extend`/`extends` guard inspected only the ONE config file `_plan`
resolved, never the file THAT file's own `extend`/`extends` pointed to in
turn -- a safe first hop (`ruff.toml`'s `extend = "base.toml"`) hid an
unsafe second one (`base.toml`'s own `extend = "/etc/hostname"`), confirmed
leaking `/etc/hostname` into a PR finding; and the previous round's own
`_unsafe_path` fix (`Path.resolve()`, to catch the symlink-escape case
above) introduced a crash of its own -- `Path.resolve()` raises
`ValueError` on a value with an embedded NUL byte (reachable via a TOML/
JSON escape sequence), which the guard's `except (OSError, RuntimeError)`
did not catch, so the exception escaped `run_check` and crashed the whole
task, confirmed for both ruff and biome.

A third adversarial re-review, against the fixes above, found that BOTH of
that round's own fixes produced ANOTHER same-class bypass, both fresh
RCEs: tflint's heredoc introducer regex captured only the identifier
portion of a hyphenated or non-ASCII marker (`<<EO-T` matched marker `EO`,
not the real `EO-T`; `<<café` the same way) -- tflint itself closes the
heredoc at the marker it actually wrote, but the guard kept hunting for
its own truncated one and swallowed a real `plugin "pwn"` block, plus its
enabling `config { plugin_dir = "./p" }`, as opaque heredoc body; and
sqlfluff's `.sql` decoder still decoded every candidate STRICTLY (a single
malformed unit -- a stray trailing byte making a UTF-16 file odd-length, a
lone surrogate, an invalid multibyte sequence -- raised `UnicodeDecodeError`
and discarded that candidate's ENTIRE text), while sqlfluff itself opens a
linted file with `errors="backslashreplace"` and recovers everything
around the bad unit, honouring an intact directive elsewhere in the same
file. Three rounds running into the same failure mode -- a hand-rolled
parser has to agree with the real tool's parser exactly, and it keeps
diverging at a new edge -- is why both are fixed structurally instead this
time, accepting the false-negative/false-positive cost instead of trying
to match the parser again: `tflint` now refuses ANY `.tflint.hcl`
containing a heredoc outright, without attempting to parse it at all (the
heredoc-tracking code this made dead was deleted, not kept around unused);
and every sqlfluff `.sql` candidate decode now uses `errors=
"backslashreplace"`, matching sqlfluff's own reader exactly, backed by a
byte-level scan for the directive marker under five encodings that does
not depend on any candidate decode succeeding, recognising the directive,
or even running at all. Separately (latent, not itself exploitable in the
built image, where `/work/tree` has no symlink component): `_reason` and
`_too_deep` compare a `_walk_extend_chain` hop -- always `Path.resolve()`d
-- against an unresolved `tree`, which can raise `ValueError` when the
repo root itself sits behind a symlink hop the OS quietly follows (macOS's
`/var` -> `/private/var`, or a repo-committed symlinked tree root); `ruff`
and `biome` now resolve both `tree` and the starting config path once,
together, before entering the chain, so every hop compares against the
same resolved root from the start.

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
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

try:
    import chardet
except ImportError:  # sqlfluff itself depends on chardet, but a guard must
    chardet = None  # not assume every environment importing this module does.

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


def _walk_kv(obj: Any, keys: set[str], depth: int = 0):
    """Recursively search a parsed TOML/YAML/JSON document for EVERY dict key
    in `keys` with a truthy value, at ANY nesting depth, yielding each
    matching `(key, value)` PAIR as it is found -- not only the first.
    CONFIRMED #5: a decoy key that sorts earlier in the document (or nests
    one level differently, e.g. ruff's `lint.per-file-ignores."extend"`, a
    valid glob list) must never hide a later, dangerous occurrence of the
    same key from a caller that inspects the VALUE, not merely the key's
    presence -- a caller that stopped at the first match saw only the decoy.
    Also yields the `_TOO_DEEP` sentinel and stops, once `depth` passes
    `_WALK_MAX_DEPTH` -- a config nested that deep is hiding something, and
    the caller must treat "we gave up looking" as unsafe on its own, the
    same as a real match, without waiting for more of the document."""
    if depth > _WALK_MAX_DEPTH:
        yield _TOO_DEEP
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k).lower()
            if key in keys and v:
                yield key, v
            yield from _walk_kv(v, keys, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_kv(item, keys, depth + 1)


def _walk(obj: Any, keys: set[str], depth: int = 0) -> Any:
    """Whether ANY of `keys` is present (as a dict key with a truthy value,
    at any nesting depth) -- for a caller that only needs to know THAT a key
    is there, not its value, so the first `_walk_kv` match already refuses
    and nothing is gained by seeing the rest. Returns the matched key
    (lowercased), `_TOO_DEEP` if the walk bailed out before finding one, or
    None when nothing was found within the bound."""
    for found in _walk_kv(obj, keys, depth):
        return _TOO_DEEP if found is _TOO_DEEP else found[0]
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


def _resolve_in_tree(tree: Path, config_dir: Path, value: str) -> Path | None:
    """Resolve `value` -- a path a tool config at `config_dir` points
    somewhere else on disk -- to the Path it names when that stays inside
    the repository, or None when it does not. Absolute and `~`-relative
    values (a tool's own path handling may expand the latter to the user's
    home, which is outside the repo too) and any value containing a NUL
    byte are refused outright, without touching the filesystem, so nothing
    here depends on resolution alone -- W4: a NUL byte is reachable through
    a TOML/JSON escape sequence even though the file on disk has none, and
    `Path.resolve()` raises `ValueError` on one, which callers must never
    see either. A plain relative value must also actually RESOLVE
    (`Path.resolve()`, non-strict, so a dangling symlink still resolves to
    its lexical target) inside `tree` -- CONFIRMED #3/#4: a repo-committed
    symlinked directory on the way turns an ordinary-looking relative value
    into one that walks straight out of the tree, which a purely textual
    `..`/absolute check never sees. A path we cannot even resolve (e.g. a
    symlink loop, or -- W4, belt and braces -- a `ValueError` `.resolve()`
    itself still manages to raise) is exactly the "we couldn't tell" case
    guards.py's own docstring treats as unsafe."""
    if "\0" in value:
        return None
    if value.startswith("~"):
        return None
    if PurePosixPath(value).is_absolute():
        return None
    try:
        resolved = (config_dir / value).resolve()
        root = tree.resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    return resolved if resolved.is_relative_to(root) else None


def _unsafe_path(tree: Path, config_dir: Path, value: str) -> bool:
    """True when `value` would resolve outside the repository -- see
    `_resolve_in_tree`."""
    return _resolve_in_tree(tree, config_dir, value) is None


_CHAIN_MAX_DEPTH = 10


def _try_resolve(path: Path) -> Path:
    """`path.resolve()`, defensively -- guards must never raise, and
    `Path.resolve()` can (a genuine symlink loop), the same "we couldn't
    tell" shape `_resolve_in_tree` above already guards against. Falls back
    to `path` unresolved rather than crash."""
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        return path


def _chain_start(tree: Path, path: Path) -> tuple[Path, Path]:
    """V3 (latent): every hop `_walk_extend_chain` follows is a
    `Path.resolve()`d value (`_resolve_in_tree`'s return), but `_reason` /
    `_unparseable` / `_too_deep` compare it against `tree` AS GIVEN --
    unresolved. When the repo root itself sits behind a symlink hop the OS
    quietly follows (macOS's `/var` -> `/private/var`; a repo-committed
    symlinked tree root), that comparison raises `ValueError` out of the
    guard entirely. It does not reproduce in the image, where `/work/tree`
    has no symlink component, but nothing here should depend on that.
    Resolving `tree` ALONE would only move the mismatch: every OTHER guard
    (and the very first, non-hop config file here) builds `path` directly
    from the UNRESOLVED `tree` argument and never resolves it independently,
    so comparing that against a freshly resolved `tree` breaks exactly as
    often as the bug it would fix. Resolving both together, ONCE, right
    before the chain starts -- and passing that same pair all the way down,
    since every hop after it is already resolved the same way -- means
    `tree` and `path` can never drift apart again for the rest of the
    walk."""
    return _try_resolve(tree), _try_resolve(path)


def _walk_extend_chain(
    tree: Path,
    path: Path,
    section: Any,
    keys: set[str],
    why: str,
    load: Callable[[Path], Any],
    load_errors: tuple[type[Exception], ...],
    visited: set[Path],
    depth: int,
) -> str | None:
    """W3: ruff's and biome's `extend`/`extends` name another OF THEIR OWN
    config files that the tool reads and merges in -- and that file's own
    `extend`/`extends`, if it has one, is followed exactly the same way by
    the real tool. The guard used to inspect only the ONE config file
    `_plan` resolved, so a safe FIRST hop hid an unsafe SECOND one from it
    entirely -- CONFIRMED: `ruff.toml`'s `extend = "base.toml"` is safe on
    its own (relative, inside the tree), but `base.toml`'s own `extend =
    "/etc/hostname"` was never even parsed, and its content leaked into a
    PR finding. `visited` (resolved hop paths) and `_CHAIN_MAX_DEPTH` bound
    the walk, the same shape as `_walk`'s own depth bound above --
    exceeding the bound or revisiting an already-resolved path (a cycle) is
    refused, not silently treated as safe just because it terminates."""
    for found in _walk_kv(section, keys):
        if found is _TOO_DEEP:
            return _too_deep(tree, path)
        key, value = found
        values = value if isinstance(value, list) else [value]
        for v in values:
            if not isinstance(v, str):
                continue
            hop = _resolve_in_tree(tree, path.parent, v)
            if hop is None:
                return _reason(tree, path, key, why)
            if depth >= _CHAIN_MAX_DEPTH or hop in visited:
                return _reason(tree, path, key, why)
            if not hop.is_file():
                continue
            visited.add(hop)
            try:
                hop_doc = load(hop)
            except load_errors as e:
                return _unparseable(tree, hop, e)
            reason = _walk_extend_chain(
                tree, hop, hop_doc, keys, why, load, load_errors, visited, depth + 1
            )
            if reason:
                return reason
    return None


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


#: CONFIRMED #2 (UTF-16) and W2 (UTF-32): sqlfluff's own loader reads a
#: linted file with `encoding=autodetect` -- `chardet.detect` -- so a
#: UTF-16 OR UTF-32 file's inline `-- sqlfluff:` directive is honoured by
#: the real tool while a naive UTF-8-only read here never sees it. Each BOM
#: is stripped before decoding under its matching encoding, the same way
#: sqlfluff's own reader would. The 4-byte UTF-32-LE BOM (`ff fe 00 00`)
#: starts with the 2-byte UTF-16-LE BOM (`ff fe`) -- listed and matched
#: FIRST (longest first, and at most one BOM per file), so a UTF-32-LE file
#: is never mistaken for a UTF-16-LE one with only the first two of its
#: four BOM bytes stripped.
_SQL_BOMS = (
    (b"\xff\xfe\x00\x00", "utf-32-le"),
    (b"\x00\x00\xfe\xff", "utf-32-be"),
    (b"\xff\xfe", "utf-16-le"),
    (b"\xfe\xff", "utf-16-be"),
)


def _sql_texts(data: bytes) -> list[str]:
    """Every decoding this guard scans a linted `.sql` file's bytes under --
    not the single naive UTF-8 read it used to be. V2 (CONFIRMED,
    sqlfluff-u16-odd): NEVER decode strictly -- the BOM-matched and
    chardet-guessed candidates below now both use `errors="backslashreplace"`,
    matching how sqlfluff's own loader opens a linted file exactly. A single
    malformed unit ANYWHERE (a stray trailing byte making a UTF-16 file
    odd-length, a lone surrogate, an invalid multibyte sequence) used to
    raise `UnicodeDecodeError` under a strict decode and discard that
    candidate's text WHOLESALE, while sqlfluff recovers everything around
    the bad unit and honours an intact directive elsewhere in the same
    file -- confirmed with an odd-length, BOM-less UTF-16LE `.sql` file
    whose `-- sqlfluff:library_path:` directive was invisible here and
    honoured by sqlfluff. `errors="replace"` (not `"backslashreplace"`) is
    still used for the plain UTF-8 attempt only -- a genuinely UTF-16/
    UTF-32 file decoded as UTF-8 is mostly noise either way and will not
    spell out a directive, so nothing here depends on which noise it
    produces. `_sql_marker_present` below is an independent backstop for
    when NONE of these candidates recognise a directive at all -- no
    BOM, chardet unavailable, or chardet's guess wrong -- so a decode
    failing to run, or to guess right, is no longer itself enough to miss
    one."""
    texts = [data.decode("utf-8", errors="replace")]
    for bom, encoding in _SQL_BOMS:
        if not data.startswith(bom):
            continue
        texts.append(data[len(bom) :].decode(encoding, errors="backslashreplace"))
        break  # a file has exactly one BOM; the longest match wins
    if chardet is not None:
        guessed = chardet.detect(data).get("encoding")
        if guessed:
            try:
                texts.append(data.decode(guessed, errors="backslashreplace"))
            except LookupError:
                pass  # chardet's guessed name is not a codec Python knows.
    return texts


def _sql_inline_directive(text: str) -> tuple[bool, str | None]:
    """Scans `text`'s lines for a `-- sqlfluff:`/`--sqlfluff:` inline
    directive. Returns `(True, key)` for the first `_SQLFLUFF_KEYS` key such
    a directive sets, `(True, None)` when a directive line is present but
    sets none of them (e.g. `-- sqlfluff:dialect:postgres`), and `(False,
    None)` when `text` has no such line at all. V2: the `bool` lets
    `sqlfluff()`'s byte-level marker backstop below tell "this decode DID
    read a directive here, it just was not a dangerous key" apart from
    "this decode never recognised one at all" -- only the latter, alongside
    a raw marker match under some OTHER encoding entirely, means this
    guard's own reading of the file cannot be trusted."""
    found = False
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("-- sqlfluff"):
            marker = "-- sqlfluff"
        elif stripped.startswith("--sqlfluff"):
            marker = "--sqlfluff"
        else:
            continue
        found = True
        key_path = stripped[len(marker) :].split(":")[:-1]
        for segment in key_path:
            key = segment.strip().lower()
            if key in _SQLFLUFF_KEYS:
                return True, key
    return found, None


#: V2: the inline directive's own marker text, searched for directly in the
#: linted file's RAW BYTES -- independent of any candidate decode above
#: succeeding, recognising a directive, or even running at all (chardet may
#: be unavailable, or simply guess an encoding neither the BOM list nor its
#: own detection covers). Each of the five encodings sqlfluff's own loader
#: might be reading the file as is tried; a file with no BOM is exactly the
#: shape this backstop exists for, since `_SQL_BOMS` above never even
#: attempts one.
_SQL_DIRECTIVE_MARKERS = ("-- sqlfluff", "--sqlfluff")
_SQL_MARKER_ENCODINGS = ("utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")


def _sql_marker_present(data: bytes) -> bool:
    """Whether the sqlfluff inline-directive marker (case-insensitive)
    appears anywhere in `data`'s raw bytes, encoded under any of
    `_SQL_MARKER_ENCODINGS`. `bytes.lower()` only ever folds the ASCII
    range (0x41-0x5A), so it safely case-folds a marker's letters wherever
    they sit inside a multi-byte encoding too -- the padding/null bytes
    around them under UTF-16/UTF-32 are untouched -- without needing a
    per-encoding case fold of its own."""
    lowered = data.lower()
    return any(
        marker.encode(encoding) in lowered
        for marker in _SQL_DIRECTIVE_MARKERS
        for encoding in _SQL_MARKER_ENCODINGS
    )


def _sql_marker_unreadable(tree: Path, path: Path) -> str:
    rel = path.relative_to(tree).as_posix()
    return (
        f"{rel}: may contain an inline sqlfluff directive this guard could not "
        "decode; treating as unsafe"
    )


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
            data = path.read_bytes()
        except (OSError, RecursionError) as e:
            return _unparseable(tree, path, e)
        directive_seen = False
        for text in _sql_texts(data):
            found, key = _sql_inline_directive(text)
            if key:
                return _reason(tree, path, f"{key} inline", _sqlfluff_why(key))
            directive_seen = directive_seen or found
        # V2: none of the candidate decodes above recognised a directive at
        # all -- if the marker's bytes are in the file anyway, under any
        # encoding, we know a directive is present and could not read it.
        if not directive_seen and _sql_marker_present(data):
            return _sql_marker_unreadable(tree, path)

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
#: V1: a THIRD attempt at matching a heredoc's own terminator -- CONFIRMED
#: #1 (a `/*` inside the body wrongly read as an unterminated block
#: comment) and W1 (an indented terminator wrongly left unclosed) were each
#: a real bug in a real HCL feature this scanner had to re-implement, fixed
#: in turn, and each fix still diverged from real HCL/tflint at a new edge:
#: a hyphenated or non-ASCII marker (`<<EO-T`, `<<café`) matched only the
#: identifier PORTION of the old introducer regex (`EO`, not the real
#: `EO-T`), so tflint closed the heredoc where the guard did not, and a
#: real `plugin "pwn"` block past it was swallowed as opaque body. No
#: amount of matching the real parser more closely has held for three
#: rounds running -- so a `.tflint.hcl` containing ANY heredoc introducer
#: is refused outright, below, before any of this module's own HCL
#: scanning ever runs on it. The false negative this accepts (a heredoc
#: that sets nothing unsafe is refused all the same) is the deliberate
#: point: a refusal is cheap, a fourth divergence is not.
_HCL_HEREDOC_WHY = "which this guard cannot analyse safely"


def _strip_hcl_comments(text: str) -> str | None:
    """`#`/`//` to end of line and `/* ... */` blocks, never stripped
    inside a quoted string: a `/*`, `#` or `//` that only LOOKS like a
    comment marker because it happens to sit inside a string value is not
    one. `tflint` above refuses any `.tflint.hcl` containing a heredoc
    outright before this ever runs, so this no longer needs (or has) any
    heredoc awareness of its own -- the heredoc-tracking this scanner used
    to do is exactly the dead code three rounds of diverging from tflint's
    own parser argue against keeping around. An unterminated string or
    block comment cannot be told apart from one hiding the rest of the
    file, so it is UNSAFE, signalled by returning None rather than
    guessing where it would have ended."""
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
            if j == -1:
                return None
            i = j + 2
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
        # V1: before any other analysis -- a heredoc is refused outright,
        # not parsed, see `_HCL_HEREDOC_WHY` above.
        if "<<" in text:
            return _reason(tree, path, "a heredoc", _HCL_HEREDOC_WHY)
        stripped = _strip_hcl_comments(text)
        if stripped is None:
            return _unparseable(tree, path, ValueError("unterminated string or comment"))
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


# --- ruff (final-fix-5 G5, final-fix-7 W3) ------------------------------------
# `extend` in ruff.toml/.ruff.toml, or under `[tool.ruff]` in pyproject.toml,
# names another ruff config file that ruff reads and merges in. An absolute
# or `..`-escaping target makes ruff read an arbitrary host file and echo its
# content into the TOML parse error it then raises -- confirmed against the
# built image: ruff exits 2 EVERY time on such a target, outside
# EXPECT_EXIT, so `_common.check_failed_finding` embeds `proc.stderr` --
# which is that file's content -- straight into the PR finding. Searched at
# any nesting depth via `_walk_kv`, same defense-in-depth as every other
# guard here, even though ruff's own schema only ever reads `extend` from
# the top level (of the file, or of `[tool.ruff]`). CONFIRMED #5: every
# occurrence is checked, not just the first -- `lint.per-file-ignores.
# "extend"` is a valid ruff glob list that sorts before a real top-level
# `extend` string and used to hide it from a first-match walk entirely. W3:
# the target file's OWN `extend` is followed too, transitively -- see
# `_walk_extend_chain` above.
_RUFF_KEYS = {"extend"}
_RUFF_WHY = "which ruff reads from outside the repository"
_RUFF_LOAD_ERRORS = (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError)


def _load_ruff_hop(path: Path) -> Any:
    """A file named by `extend` is itself a full ruff config, top-level
    schema -- never nested under `[tool.ruff]`, even when the file doing
    the naming was a pyproject.toml."""
    return tomllib.loads(path.read_text())


def ruff(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _selected(paths, "ruff.toml", ".ruff.toml"):
        try:
            doc = tomllib.loads(path.read_text())
        except _RUFF_LOAD_ERRORS as e:
            return _unparseable(tree, path, e)
        root, start = _chain_start(tree, path)
        reason = _walk_extend_chain(
            root,
            start,
            doc,
            _RUFF_KEYS,
            _RUFF_WHY,
            _load_ruff_hop,
            _RUFF_LOAD_ERRORS,
            {start},
            0,
        )
        if reason:
            return reason

    for path in _selected(paths, "pyproject.toml"):
        try:
            doc = tomllib.loads(path.read_text())
        except _RUFF_LOAD_ERRORS as e:
            return _unparseable(tree, path, e)
        section = _toml_table(doc, "tool", "ruff")
        if section is not None:
            root, start = _chain_start(tree, path)
            reason = _walk_extend_chain(
                root,
                start,
                section,
                _RUFF_KEYS,
                _RUFF_WHY,
                _load_ruff_hop,
                _RUFF_LOAD_ERRORS,
                {start},
                0,
            )
            if reason:
                return reason

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
# tflint's HCL comment strip. W3: the target file's OWN `extends` is
# followed too, transitively, even though biome's transitive case did not
# reproduce against the real tool -- see `_walk_extend_chain` above.
_BIOME_WHY = "which biome reads from outside the repository"
_BIOME_LOAD_ERRORS = (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError)


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


def _load_biome_hop(path: Path) -> Any:
    return json.loads(_strip_jsonc_comments(path.read_text()))


def biome(tree: Path, paths: Sequence[Path]) -> str | None:
    """Reason to refuse, or None when safe."""
    for path in _selected(paths, "biome.json", "biome.jsonc"):
        try:
            doc = json.loads(_strip_jsonc_comments(path.read_text()))
        except _BIOME_LOAD_ERRORS as e:
            return _unparseable(tree, path, e)
        # CONFIRMED #5-shaped: every `extends` occurrence is checked, not
        # just the first -- see the same fix on ruff above.
        root, start = _chain_start(tree, path)
        reason = _walk_extend_chain(
            root,
            start,
            doc,
            {"extends"},
            _BIOME_WHY,
            _load_biome_hop,
            _BIOME_LOAD_ERRORS,
            {start},
            0,
        )
        if reason:
            return reason
    return None
