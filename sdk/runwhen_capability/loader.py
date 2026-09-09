"""Loads a capability directory: its manifest.yaml (for the capability id)
and its tasks.py (for the registered setup/task functions).
"""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path

import yaml

from .decorators import Registry, _current_registry
from .errors import CapabilityLoadError


class LoadedCapability:
    def __init__(self, capability_dir: Path, capability_id: str, registry: Registry) -> None:
        self.dir = capability_dir
        self.capability_id = capability_id
        self.registry = registry


def load_manifest(capability_dir: Path) -> dict:
    manifest_path = capability_dir / "manifest.yaml"
    if not manifest_path.is_file():
        raise CapabilityLoadError(f"no manifest.yaml in {capability_dir}")
    with manifest_path.open() as f:
        manifest = yaml.safe_load(f)
    if not isinstance(manifest, dict) or "capability" not in manifest:
        raise CapabilityLoadError(f"{manifest_path}: missing required 'capability' key")
    return manifest


def load_capability(capability_dir: Path) -> LoadedCapability:
    capability_dir = Path(capability_dir)
    manifest = load_manifest(capability_dir)

    tasks_path = capability_dir / "tasks.py"
    if not tasks_path.is_file():
        raise CapabilityLoadError(f"no tasks.py in {capability_dir}")

    registry = Registry()
    token = _current_registry.set(registry)
    try:
        module_name = f"runwhen_capability_tasks_{uuid.uuid4().hex}"
        spec = importlib.util.spec_from_file_location(module_name, tasks_path)
        if spec is None or spec.loader is None:
            raise CapabilityLoadError(f"could not load {tasks_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        _current_registry.reset(token)

    return LoadedCapability(capability_dir, manifest["capability"], registry)


def discover_capability_dir(base: Path = Path("capabilities")) -> Path:
    """Auto-discovers the single capability a capability image ships (image
    == capability, 1:1). Used by `rwtask serve`, which is not told a
    capability directory on the command line -- the image already is one."""
    base = Path(base)
    candidates = sorted(base.glob("*/manifest.yaml"))
    if len(candidates) != 1:
        raise CapabilityLoadError(
            f"expected exactly one capability under {base}/*/manifest.yaml, found {len(candidates)}"
        )
    return candidates[0].parent
