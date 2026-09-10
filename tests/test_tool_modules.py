"""The tool-module contract, enforced by a test rather than a schema.

An earlier design made tools declarative data, which would have validated
these at load time. Tools are Python modules instead -- config discovery is
open-ended and recursive, and a schema cannot express it -- so the contract
is enforced here. Every module under capabilities/rw-checks/tools/ must
satisfy this or the suite fails.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys
from pathlib import Path

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
    # (from_level/by_rule_prefix/by_cvss), or the map's own single value
    # (constant).
    closes_over_map = any(v is mod.SEVERITY for v in cell_values)
    closes_over_constant = len(mod.SEVERITY) == 1 and any(
        v in mod.SEVERITY.values() for v in cell_values
    )
    assert closes_over_map or closes_over_constant, (
        f"{name}._POLICY does not close over {name}.SEVERITY"
    )


@pytest.mark.parametrize("name", tool_modules())
def test_declares_the_applicability_contract(name):
    mod = load(name)
    assert isinstance(getattr(mod, "FILES", None), tuple), f"{name}.FILES must be a tuple"
    assert getattr(mod, "CONFIG", None) in VALID_CONFIG, (
        f"{name}.CONFIG must be one of {VALID_CONFIG}"
    )
    ci = getattr(mod, "CI_BINARY", "<missing>")
    assert ci is None or isinstance(ci, str), f"{name}.CI_BINARY must be a str or None"
    guard = getattr(mod, "GUARD", "<missing>")
    assert guard is None or callable(guard), f"{name}.GUARD must be callable or None"


@pytest.mark.parametrize("name", tool_modules())
def test_defines_detect_and_check(name):
    mod = load(name)
    assert callable(getattr(mod, "detect", None)), f"{name} defines no detect()"
    assert callable(getattr(mod, "check", None)), f"{name} defines no check()"


@pytest.mark.parametrize("name", tool_modules())
def test_detect_returns_paths_on_an_empty_tree(tmp_path, name):
    """detect() runs during applicability, before any tool is invoked, so it
    must never raise on a repository that does not use the tool."""
    result = load(name).detect(tmp_path)
    assert isinstance(result, list)
    assert all(isinstance(p, Path) for p in result)


def test_config_required_tools_skip_an_unconfigured_repo(tmp_path):
    """A `required` tool must not run without the repo's own config -- an
    opinionated linter run on defaults reports findings nobody asked for."""
    from tools import _common

    (tmp_path / "a.py").write_text("import os\n")
    for name in tool_modules():
        mod = load(name)
        if getattr(mod, "CONFIG", "optional") != "required":
            continue
        assert _common.gate(tmp_path, mod), f"{name} is CONFIG=required but did not skip"


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
    """Every task takes both `tree` and `changed`: findings are scoped to
    the diff (`_common.scoped`), so every module needs the diff to scope to.
    """
    import yaml

    manifest = yaml.safe_load((CAPABILITY / "manifest.yaml").read_text())
    for entry in manifest["tasks"]:
        assert sorted(entry.get("inputs") or {}) == ["changed", "tree"], (
            f"{entry['name']} does not declare both tree and changed"
        )


def test_every_module_scopes_its_findings_to_the_diff():
    """Every check reports on the CHANGE, security scanners included.

    A tool that returns `ctx.sarif.parse(...)` or `ctx.findings.from_records(...)`
    straight out of `check()` reports the whole repository, which on a
    three-line pull request buries the review under a backlog the author did
    not create. `_common.scoped` (and `_common.emit`, which wraps it) is the
    single place that policy lives; this asserts nothing bypasses it.

    Source-level on purpose: the behavioural version needs the real tool
    binaries, which only exist inside the built image.
    """
    import re

    offenders = {}
    for name in tool_modules():
        src = (TOOLS / f"{name}.py").read_text()
        body = src[src.index("def check(") :]
        returns = [
            ln.strip()
            for ln in body.splitlines()
            if re.match(r"\s*return (ctx\.sarif\.parse|ctx\.findings\.from_records)", ln)
        ]
        if returns:
            offenders[name] = returns
    assert not offenders, (
        "these modules return unscoped findings instead of routing through "
        f"_common.scoped/_common.emit: {offenders}"
    )
