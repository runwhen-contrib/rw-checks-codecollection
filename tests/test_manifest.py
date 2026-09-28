"""Sanity-check the shipped capability manifests: an absent `egress` key
must parse cleanly through the SDK's own loader. See the `needs:` comment
in each manifest for why `egress` isn't declared -- it's not
capability-static; a literal here would be wrong by construction for GHE.

Also covers the image labels: neither manifest has an `image` key -- an
image cannot know its own digest -- and `rwtask label`, which turns a
manifest into the com.runwhen.capability.manifest.v1 label CI sets at
build time, round-trips each shipped manifest's bytes exactly. The
`--schemas` tests further down cover the com.runwhen.capability.schemas.v1
label: the base64 of every file under a capability's schemas/ directory,
keyed "schemas/<filename>" -- see README.md's "Schemas label". The label
rules themselves are tested in the runwhen-capability SDK.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from runwhen_capability.label import encode_manifest, schemas_label
from runwhen_capability.loader import load_manifest

REPO_ROOT = Path(__file__).parent.parent
CAPABILITIES = REPO_ROOT / "capabilities"


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


@pytest.mark.parametrize("capability_dir", ["rw-checks", "rw-worktree"])
def test_manifest_label_round_trips_manifest_bytes(capability_dir):
    value = encode_manifest(CAPABILITIES / capability_dir)
    assert "\n" not in value, "the label must be base64 with no line breaks"
    decoded = base64.b64decode(value)
    assert decoded == (CAPABILITIES / capability_dir / "manifest.yaml").read_bytes()


# --- --schemas: com.runwhen.capability.schemas.v1 ---------------------------


@pytest.mark.parametrize(
    ("capability_dir", "expected_keys"),
    [
        ("rw-checks", {"schemas/findings.v1.json"}),
        (
            "rw-worktree",
            {
                "schemas/grep.v1.json",
                "schemas/ls.v1.json",
                "schemas/query.v1.json",
                "schemas/read.v1.json",
            },
        ),
    ],
)
def test_schemas_label_real_manifests_produce_expected_keys(capability_dir, expected_keys):
    decoded = json.loads(base64.b64decode(schemas_label(CAPABILITIES / capability_dir)))
    assert decoded.keys() == expected_keys


@pytest.mark.parametrize(
    ("dockerfile", "capability_dir"),
    [
        ("Dockerfile.rw-checks", "rw-checks"),
        ("Dockerfile.rw-worktree", "rw-worktree"),
    ],
)
def test_dockerfile_carries_schemas_label(dockerfile, capability_dir):
    text = (REPO_ROOT / dockerfile).read_text()
    assert "ARG CAPABILITY_SCHEMAS_B64=" in text
    assert 'com.runwhen.capability.schemas.v1="${CAPABILITY_SCHEMAS_B64}"' in text
