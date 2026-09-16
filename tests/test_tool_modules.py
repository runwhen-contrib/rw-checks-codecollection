"""The tool-module contract, enforced by a test rather than a schema.

An earlier design made tools declarative data, which would have validated
these at load time. Tools are Python modules instead -- config discovery is
open-ended and recursive, and a schema cannot express it -- so the contract
is enforced here. Every module under capabilities/rw-checks/tools/ must
satisfy this or the suite fails.
"""

from __future__ import annotations

import dis
import importlib
import pkgutil
import sys
from pathlib import Path, PurePosixPath

import pytest

CAPABILITY = Path(__file__).parent.parent / "capabilities" / "rw-checks"
TOOLS = CAPABILITY / "tools"
sys.path.insert(0, str(CAPABILITY))

VALID_SEVERITIES = {"error", "warning", "note"}
VALID_CONFIG = {"required", "optional"}


def tool_modules():
    """Every tool module, by name. `_common` is plumbing, not a tool."""
    return sorted(m.name for m in pkgutil.iter_modules([str(TOOLS)]) if not m.name.startswith("_"))


def load(name):
    """Always under the package name. Importing the same file as both
    `pylint` and `tools.pylint` would create two module objects, so a test
    patching one would silently not affect the other."""
    return importlib.import_module(f"tools.{name}")


@pytest.mark.parametrize("name", tool_modules())
def test_declares_a_severity_map(name):
    """Severity is the only signal GitHub acts on: it sets the annotation
    level and decides pass/fail. Every tool has its own vocabulary and none
    of them mean the same thing, so a shared default is never right."""
    mod = load(name)
    severity = getattr(mod, "SEVERITY", None)
    assert severity, f"{name} declares no SEVERITY map"
    assert set(severity.values()) <= VALID_SEVERITIES, (
        f"{name}.SEVERITY maps outside error|warning|note: {set(severity.values())}"
    )


@pytest.mark.parametrize("name", tool_modules())
def test_severity_map_is_actually_read_by_check(name):
    """A map nothing reads at run time is decoration, not policy -- exactly
    the bug this guards against: a module could once declare a SEVERITY map
    that disagreed with what actually got applied (adapters.<TOOL>_SEVERITY
    or a hardcoded severity.py policy) and every test still passed. Every
    `check()` must reference its own module's SEVERITY (adapter-based tools
    pass it straight through) or a `_POLICY` built from it (the 7 SARIF
    tools) -- proven statically via the compiled function's own name table,
    so this holds even for tools whose gate a bare tmp_path never clears."""
    mod = load(name)
    referenced = mod.check.__code__.co_names
    assert "SEVERITY" in referenced or "_POLICY" in referenced, (
        f"{name}.check() never references SEVERITY or a _POLICY built from it"
    )


@pytest.mark.parametrize("name", tool_modules())
def test_policy_closes_over_the_declared_severity_map(name):
    """For the SARIF tools, `_POLICY` must wrap the EXACT SEVERITY object
    the module declares -- not a copy, not a different tool's map -- or the
    declared map and the one actually applied can drift apart silently."""
    mod = load(name)
    policy = getattr(mod, "_POLICY", None)
    if policy is None:
        pytest.skip(f"{name} passes SEVERITY directly to its adapter; no _POLICY built")
    cell_values = [c.cell_contents for c in (policy.__closure__ or ())]
    # `severity.constant()` extracts its map's one value up front rather
    # than keeping the whole (single-entry) dict alive -- there is nothing
    # left to look up. Accept either shape: the map itself in the closure
    # (from_level/by_rule_prefix), or the map's own single value
    # (constant).
    closes_over_map = any(v is mod.SEVERITY for v in cell_values)
    closes_over_constant = len(mod.SEVERITY) == 1 and any(
        v in mod.SEVERITY.values() for v in cell_values
    )
    assert closes_over_map or closes_over_constant, (
        f"{name}._POLICY does not close over {name}.SEVERITY"
    )


# --- the inventory must agree in three places -------------------------------


def _manifest_task_names():
    import yaml

    manifest = yaml.safe_load((CAPABILITY / "manifest.yaml").read_text())
    return sorted(t["name"] for t in manifest["tasks"])


def _registered_task_names():
    from runwhen_capability.loader import load_capability

    return sorted(load_capability(CAPABILITY).registry.tasks)


def test_tool_modules_manifest_and_registry_all_agree():
    """Three inventories, one truth: a module under tools/, an entry in the
    manifest, and a registered task.

    Dispatch is `registry.tasks.get(name)` keyed on `func.__name__` with no
    alias layer, so a manifest name that does not match a function name
    silently 404s at run time rather than failing at load. That is why this
    is asserted in both directions instead of one.
    """
    modules = tool_modules()
    manifest = _manifest_task_names()
    registered = _registered_task_names()

    assert modules == manifest, (
        f"tools/ and manifest disagree — only in tools/: {set(modules) - set(manifest)}; "
        f"only in manifest: {set(manifest) - set(modules)}"
    )
    assert manifest == registered, (
        f"manifest and registry disagree — only in manifest: {set(manifest) - set(registered)}; "
        f"only registered: {set(registered) - set(manifest)}"
    )


def test_every_task_declares_both_inputs():
    """Every task takes both `tree` and `changed`: `_plan.plan` scopes every
    invocation to the diff, so every module needs `changed` to scope to.
    """
    import yaml

    manifest = yaml.safe_load((CAPABILITY / "manifest.yaml").read_text())
    for entry in manifest["tasks"]:
        assert sorted(entry.get("inputs") or {}) == ["changed", "tree"], (
            f"{entry['name']} does not declare both tree and changed"
        )


@pytest.mark.parametrize("name", tool_modules())
def test_diff_scoped_contract(name):
    mod = load(name)
    for attr in (
        "NAME",
        "KIND",
        "FILES",
        "CONFIG",
        "CONFIG_NAMES",
        "CI_BINARY",
        "LANE",
        "EXPECT_EXIT",
        "GUARD",
        "applicable",
        "check",
    ):
        assert hasattr(mod, attr), f"{name} lacks {attr}"
    assert mod.CONFIG in VALID_CONFIG
    assert mod.LANE in {"A", "B", "C", "D"}
    assert mod.LANE != "D" or hasattr(mod, "group"), f"{name}: lane D needs group()"
    import inspect

    assert list(inspect.signature(mod.check).parameters) == ["ctx", "tree", "inv"]


# --- CONFIG_NAMES and the guard must agree on which files matter ------------

# Every guarded tool names its config files twice: once as `CONFIG_NAMES` on
# the module, and again as the literal basenames passed to
# `guards._selected(paths, ...)` inside its own guard function. Nothing
# enforces that these agree -- add a name to CONFIG_NAMES and forget the
# guard, and the guard silently stops covering that file. `regal` is excluded:
# its guard never calls `_selected` at all (it globs a `.regal/rules/`
# directory instead), so there is nothing here to extract.
_NOT_BASENAME_DRIVEN = {"regal"}


def _selected_literal_names(guard) -> set[str]:
    """The string literals passed as `*names` to every `guards._selected(...)`
    call inside `guard`'s own code object -- found by walking its
    instructions and collecting the `LOAD_CONST` strings between each
    `_selected` load and the `CALL` that follows it. Light introspection, not
    a general-purpose call-argument extractor: it only has to hold for the
    one call shape every guard here actually uses."""
    names: set[str] = set()
    instructions = list(dis.get_instructions(guard))
    for i, instr in enumerate(instructions):
        if instr.argval != "_selected" or not instr.opname.startswith("LOAD_"):
            continue
        for later in instructions[i + 1 :]:
            if later.opname.startswith("CALL"):
                break
            if later.opname == "LOAD_CONST" and isinstance(later.argval, str):
                names.add(later.argval)
    return names


@pytest.mark.parametrize("name", [n for n in tool_modules() if n not in _NOT_BASENAME_DRIVEN])
def test_config_names_covered_by_the_guard(name):
    mod = load(name)
    guard = mod.GUARD
    if guard is None:
        pytest.skip(f"{name} has no guard")
    selected = _selected_literal_names(guard)
    for config_name in mod.CONFIG_NAMES:
        basename = PurePosixPath(config_name.name).name
        assert basename in selected, (
            f"{name}.CONFIG_NAMES names {config_name.name!r}, but guards.{name}'s own "
            f"_selected(...) calls never filter on {basename!r}: {sorted(selected)}"
        )
