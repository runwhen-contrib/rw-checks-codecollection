"""The `applicable` phase: decide, without running any tool, which changed files a
check runs on and how. DIFF-SCOPED-CHECKS.md §5 is the binding rule order."""

from __future__ import annotations

import fnmatch
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from . import _common

NO_DIFF = "base commit unavailable; nothing to scope to"


@dataclass(frozen=True)
class ConfigName:
    """One file that can configure a check. `name` may contain a directory
    (".regal/config.yaml", ".github/actionlint.yaml"). `section` names the TOML
    table path (pyproject) or INI section (setup.cfg/tox.ini) that must exist
    for the file to count as this check's config."""

    name: str
    section: tuple[str, ...] = ()


@dataclass(frozen=True)
class Resolved:
    """A config that applies to a file: its repo-relative path and the
    directory the walk found it from (the directory a lane-B run uses)."""

    path: str
    base: str


@dataclass(frozen=True)
class Invocation:
    files: tuple[str, ...]
    config: str | None = None
    cwd: str = ""


@dataclass(frozen=True)
class Applicability:
    invocations: tuple[Invocation, ...] = ()
    skipped: str | None = None
    refusals: tuple[Any, ...] = ()


def matches(rel: str, patterns: Sequence[str]) -> bool:
    """Empty `patterns` matches every file. A pattern without "/" matches the
    basename; one with "/" must match the whole repo-relative path part by part."""
    if not patterns:
        return True
    parts = PurePosixPath(rel).parts
    for pattern in patterns:
        if "/" not in pattern:
            if fnmatch.fnmatchcase(parts[-1], pattern):
                return True
            continue
        pat_parts = PurePosixPath(pattern).parts
        if len(pat_parts) == len(parts) and all(
            fnmatch.fnmatchcase(p, q) for p, q in zip(parts, pat_parts, strict=True)
        ):
            return True
    return False


def eligible_files(tree: Path, changed: Sequence[str], patterns: Sequence[str]) -> list[str]:
    """Changed files matching `patterns` that exist under `tree` and resolve inside it."""
    root = tree.resolve()
    out: set[str] = set()
    for rel in changed:
        if not matches(rel, patterns):
            continue
        path = tree / rel
        if not path.is_file():
            continue
        try:
            path.resolve().relative_to(root)
        except ValueError:
            continue
        out.add(rel)
    return sorted(out)


def _counts(path: Path, cfg: ConfigName) -> bool:
    if not path.is_file():
        return False
    if not cfg.section:
        return True
    if path.name.endswith(".toml"):
        return _common.toml_table(path, *cfg.section) is not None
    return _common.ini_section(path, cfg.section[0]) is not None


def nearest_config(
    tree: Path, rel_file: str, names: Sequence[ConfigName], *, scope: str = "nearest"
) -> Resolved | None:
    """Walk from the file's directory to the tree root; the first directory holding
    a counting config wins, names tried in declaration order within a directory.
    `scope="root"` only looks at the tree root."""
    directory = PurePosixPath(rel_file).parent
    dirs: list[PurePosixPath] = []
    if scope == "root":
        dirs = [PurePosixPath(".")]
    else:
        current = directory
        while True:
            dirs.append(current)
            if current == PurePosixPath("."):
                break
            current = current.parent
    for d in dirs:
        for cfg in names:
            rel = (d / cfg.name).as_posix()
            if _counts(tree / rel, cfg):
                base = "" if d == PurePosixPath(".") else d.as_posix()
                return Resolved(path=rel, base=base)
    return None


def guard_paths(tree: Path, resolved: Resolved, module: Any, files: Sequence[str]) -> list[Path]:
    """Every config file the tool will load for this group. Only sqlfluff merges
    ancestor configs (GUARD_CHAIN); every other guarded tool loads exactly one.

    sqlfluff loads config from its cwd (the tree root -- sqlfluff is lane A)
    down to EACH LINTED FILE'S OWN DIRECTORY, so in chain mode the lineage is
    the union, root-first, of every directory from the root down to and
    including each `f` in `files`'s parent directory -- not just the
    resolved config's own directory (which is always one of those ancestors,
    so the union already covers it).

    Every name in `CONFIG_NAMES` plus `GUARD_EXTRA_NAMES` (default `()`) is a
    candidate in each of those directories; any that exists as a file is
    included, ignoring `ConfigName.section` -- sqlfluff merges any
    `sqlfluff:*` section, not only the ones `_counts`/`nearest_config` treat
    as "configured" for eligibility. `GUARD_EXTRA_NAMES` adds config names
    that the guard must see but that play no part in eligibility -- sqlfluff
    merges `pep8.ini` into its config even though nothing here treats a
    `pep8.ini`-only repo as configured for sqlfluff at all (that stays
    `module.CONFIG_NAMES`, used by `nearest_config`/`eligible_files`). The
    guard itself decides what inside a candidate file matters."""
    if not getattr(module, "GUARD_CHAIN", False):
        return [tree / resolved.path]
    names = tuple(module.CONFIG_NAMES) + tuple(getattr(module, "GUARD_EXTRA_NAMES", ()))
    dirs: set[PurePosixPath] = set()
    for f in files:
        current = PurePosixPath(f).parent
        while True:
            dirs.add(current)
            if current == PurePosixPath("."):
                break
            current = current.parent
    ordered = sorted(dirs, key=lambda d: (len(d.parts), d.as_posix()))
    chain: list[Path] = []
    for d in ordered:
        for cfg in names:
            candidate = tree / (d / cfg.name).as_posix()
            if candidate.is_file():
                chain.append(candidate)
    return chain


def _lane_invocations(
    module: Any, groups: dict[Resolved | None, list[str]]
) -> tuple[Invocation, ...]:
    lane = module.LANE
    ordered = sorted(groups.items(), key=lambda kv: kv[0].path if kv[0] else "")
    if lane in ("A", "C"):
        files = tuple(sorted(f for _, fs in ordered for f in fs))
        configs = {r.path for r, _ in ordered if r is not None}
        config = next(iter(configs)) if len(configs) == 1 and None not in groups else None
        return (Invocation(files=files, config=config, cwd=""),)
    if lane == "B":
        return tuple(
            Invocation(
                files=tuple(sorted(fs)), config=r.path if r else None, cwd=r.base if r else ""
            )
            for r, fs in ordered
        )
    raise ValueError(f"{module.NAME}: lane {lane} needs a group() hook")


def plan(ctx: Any, tree: Path, changed: list[str] | None, module: Any) -> Applicability:
    if changed is None:
        return Applicability(skipped=NO_DIFF)
    files = eligible_files(tree, changed, module.FILES)
    if not files:
        return Applicability(skipped=f"no changed {module.KIND} files")
    if module.CI_BINARY:
        ci = _common.ci_already_runs(tree, module.CI_BINARY)
        if ci:
            return Applicability(skipped=ci)

    scope = getattr(module, "CONFIG_SCOPE", "nearest")
    groups: dict[Resolved | None, list[str]] = {}
    unconfigured = 0
    for rel in files:
        resolved = (
            nearest_config(tree, rel, module.CONFIG_NAMES, scope=scope)
            if module.CONFIG_NAMES
            else None
        )
        if resolved is None and module.CONFIG == "required":
            unconfigured += 1
            continue
        groups.setdefault(resolved, []).append(rel)
    notes: list[str] = []
    if unconfigured:
        if not groups:
            return Applicability(skipped=f"no {module.NAME} config applies to the changed files")
        notes.append(
            f"{unconfigured} of {len(files)} changed {module.KIND} "
            f"files have no {module.NAME} config"
        )

    refusals: list[Any] = []
    guard: Callable[[Path, Sequence[Path]], str | None] | None = getattr(module, "GUARD", None)
    if guard is not None:
        # GUARD_FILES: bool = False (default) -- for a tool whose OWN linted
        # file can set its config (sqlfluff scans a changed .sql file for
        # inline `-- sqlfluff:` directives, see guards.sqlfluff), the guard
        # must see the group's own files too, not only its config files.
        # This is the one place a module opts a tool's changed files into
        # the guard's input; every other guarded tool never sees them.
        guard_files = getattr(module, "GUARD_FILES", False)
        for resolved in sorted((r for r in groups if r is not None), key=lambda r: r.path):
            paths = guard_paths(tree, resolved, module, groups[resolved])
            if guard_files:
                paths = paths + [tree / f for f in groups[resolved]]
            reason = guard(tree, paths)
            if reason:
                refusals.extend(_common.unsafe_config_finding(ctx, tree, reason))
                count = len(groups.pop(resolved))
                notes.append(
                    f"{count} of {len(files)} changed {module.KIND} files use an unsafe "
                    f"{module.NAME} config ({resolved.path})"
                )
        if not groups:
            return Applicability(
                skipped=f"every applicable {module.NAME} config is unsafe", refusals=tuple(refusals)
            )

    narrow = getattr(module, "narrow", None)
    if narrow is not None:
        groups, note = narrow(ctx, tree, changed, groups)
        if note:
            notes.append(note)
        if not groups:
            return Applicability(skipped="; ".join(notes) or None, refusals=tuple(refusals))

    group = getattr(module, "group", None)
    invocations = group(tree, groups) if group is not None else _lane_invocations(module, groups)
    return Applicability(
        invocations=invocations, skipped="; ".join(notes) or None, refusals=tuple(refusals)
    )
