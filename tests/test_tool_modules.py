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
sys.path.insert(0, str(TOOLS))

VALID_SEVERITIES = {"error", "warning", "note"}
VALID_CONFIG = {"required", "optional"}


def tool_modules():
    """Every tool module, by name. `_common` is plumbing, not a tool."""
    return sorted(m.name for m in pkgutil.iter_modules([str(TOOLS)]) if not m.name.startswith("_"))


def load(name):
    return importlib.import_module(name)


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
    import _common

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
    """Whether a tool's findings are reduced to the diff is the MODULE's
    decision (`_common.emit`'s `diff_filter`). The manifest passes both
    inputs uniformly — expressing the policy in both places lets them drift.
    """
    import yaml

    manifest = yaml.safe_load((CAPABILITY / "manifest.yaml").read_text())
    for entry in manifest["tasks"]:
        assert sorted(entry.get("inputs") or {}) == ["changed", "tree"], (
            f"{entry['name']} does not declare both tree and changed"
        )
