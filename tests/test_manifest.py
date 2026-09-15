"""Sanity-check the shipped capability manifests: an absent `egress` key
must parse cleanly through the repo's own loader. See the `needs:` comment
in each manifest for why `egress` isn't declared -- it's not
capability-static; a literal here would be wrong by construction for GHE.

Also covers Contract 1 (docs/ccv-capability-catalog PLAN.md in
runwhen-auto): neither manifest has an `image` key any more -- an image
cannot know its own digest -- and scripts/manifest_label.py, the thing that
turns a manifest into the com.runwhen.capability.manifest.v1 label CI sets
at build time, round-trips a manifest's bytes exactly and refuses one that
still has `image:`.
"""

from __future__ import annotations

import base64
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from runwhen_capability.loader import load_manifest

REPO_ROOT = Path(__file__).parent.parent
CAPABILITIES = REPO_ROOT / "capabilities"
MANIFEST_LABEL_SCRIPT = REPO_ROOT / "scripts" / "manifest_label.py"


@pytest.mark.parametrize("capability_dir", ["rw-checks", "rw-worktree"])
def test_shipped_manifest_loads_without_egress(capability_dir):
    manifest = load_manifest(CAPABILITIES / capability_dir)
    assert "egress" not in manifest["needs"]


@pytest.mark.parametrize("capability_dir", ["rw-checks", "rw-worktree"])
def test_shipped_manifest_has_no_image_key(capability_dir):
    manifest = load_manifest(CAPABILITIES / capability_dir)
    assert "image" not in manifest


@pytest.mark.parametrize("capability_dir", ["rw-checks", "rw-worktree"])
def test_shipped_manifest_resources_and_work_size_limit(capability_dir):
    manifest = load_manifest(CAPABILITIES / capability_dir)
    resources = manifest["execution"]["resources"]
    assert resources.keys() == {"cpuRequest", "cpuLimit", "memoryRequest", "memoryLimit"}
    assert all(isinstance(v, str) for v in resources.values())
    assert isinstance(manifest["execution"]["workSizeLimit"], str)


def run_manifest_label(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(MANIFEST_LABEL_SCRIPT), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("capability_dir", ["rw-checks", "rw-worktree"])
def test_manifest_label_script_round_trips_manifest_bytes(capability_dir):
    result = run_manifest_label(f"capabilities/{capability_dir}")
    assert result.returncode == 0, result.stderr
    assert "\n" not in result.stdout, "output must be base64 with no line breaks"
    decoded = base64.b64decode(result.stdout)
    assert decoded == (CAPABILITIES / capability_dir / "manifest.yaml").read_bytes()


def test_manifest_label_script_fails_on_missing_manifest():
    result = run_manifest_label("capabilities/does-not-exist")
    assert result.returncode != 0
    assert "no such file" in result.stderr


@pytest.mark.parametrize(
    "image_line",
    [
        "image: ghcr.io/example/fake@sha256:deadbeef\n",
        "image:\n  repository: ghcr.io/example/fake\n",
        '"image": ghcr.io/example/fake@sha256:deadbeef\n',
    ],
)
def test_manifest_label_script_fails_on_top_level_image_key(image_line):
    with tempfile.TemporaryDirectory() as tmp:
        capability_dir = Path(tmp) / "capabilities" / "fake"
        capability_dir.mkdir(parents=True)
        (capability_dir / "manifest.yaml").write_text(f"{image_line}capability: fake\n")
        result = run_manifest_label(str(capability_dir))
    assert result.returncode != 0
    assert "image" in result.stderr


def test_manifest_label_script_ignores_nested_image_key():
    with tempfile.TemporaryDirectory() as tmp:
        capability_dir = Path(tmp) / "capabilities" / "fake"
        capability_dir.mkdir(parents=True)
        (capability_dir / "manifest.yaml").write_text(
            "capability: fake\nsetup:\n  image: x\nimages: []\n"
        )
        result = run_manifest_label(str(capability_dir))
    assert result.returncode == 0, result.stderr
