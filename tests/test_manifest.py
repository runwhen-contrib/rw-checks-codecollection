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

The `--schemas` tests further down cover the com.runwhen.capability.schemas.v1
label the same script produces: the base64 of every file under a
capability's schemas/ directory, keyed "schemas/<filename>" -- see
README.md's "Schemas label".
"""

from __future__ import annotations

import base64
import json
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


# --- --schemas: com.runwhen.capability.schemas.v1 ---------------------------


def _make_fake_capability(root: Path, schema_ref: str | None) -> Path:
    """A throwaway capabilities/fake/ with a manifest that references
    schema_ref (verbatim, unquoted) in flow style, or no schema output at
    all when schema_ref is None."""
    capability_dir = root / "capabilities" / "fake"
    capability_dir.mkdir(parents=True)
    if schema_ref is None:
        manifest = "capability: fake\n"
    else:
        manifest = (
            "capability: fake\n"
            "tasks:\n"
            "  - name: t\n"
            "    outputs:\n"
            f"      result: {{ kind: rw.fake.v1, schema: {schema_ref} }}\n"
        )
    (capability_dir / "manifest.yaml").write_text(manifest)
    return capability_dir


def test_manifest_label_script_schemas_includes_every_file_including_unreferenced():
    with tempfile.TemporaryDirectory() as tmp:
        capability_dir = _make_fake_capability(Path(tmp), "./schemas/a.v1.json")
        schemas_dir = capability_dir / "schemas"
        schemas_dir.mkdir()
        (schemas_dir / "a.v1.json").write_text('{"type": "object"}')
        (schemas_dir / "b.v1.json").write_text('{"type": "object", "unreferenced": true}')
        result = run_manifest_label("--schemas", str(capability_dir))
    assert result.returncode == 0, result.stderr
    decoded = json.loads(base64.b64decode(result.stdout))
    assert decoded == {
        "schemas/a.v1.json": {"type": "object"},
        "schemas/b.v1.json": {"type": "object", "unreferenced": True},
    }


def test_manifest_label_script_schemas_fails_on_referenced_but_missing_file():
    with tempfile.TemporaryDirectory() as tmp:
        capability_dir = _make_fake_capability(Path(tmp), "./schemas/missing.v1.json")
        (capability_dir / "schemas").mkdir()
        result = run_manifest_label("--schemas", str(capability_dir))
    assert result.returncode != 0
    assert "missing.v1.json" in result.stderr


@pytest.mark.parametrize("bad_ref", ["/etc/passwd", "../escape.json", "../../etc/passwd"])
def test_manifest_label_script_schemas_rejects_absolute_or_dotdot_refs(bad_ref):
    with tempfile.TemporaryDirectory() as tmp:
        capability_dir = _make_fake_capability(Path(tmp), bad_ref)
        (capability_dir / "schemas").mkdir()
        result = run_manifest_label("--schemas", str(capability_dir))
    assert result.returncode != 0
    assert "relative" in result.stderr


def test_manifest_label_script_schemas_fails_on_non_object_json():
    with tempfile.TemporaryDirectory() as tmp:
        capability_dir = _make_fake_capability(Path(tmp), None)
        schemas_dir = capability_dir / "schemas"
        schemas_dir.mkdir()
        (schemas_dir / "a.v1.json").write_text("[1, 2, 3]")
        result = run_manifest_label("--schemas", str(capability_dir))
    assert result.returncode != 0
    assert "a.v1.json" in result.stderr


def test_manifest_label_script_schemas_empty_dir_is_empty_value():
    with tempfile.TemporaryDirectory() as tmp:
        capability_dir = _make_fake_capability(Path(tmp), None)
        result = run_manifest_label("--schemas", str(capability_dir))
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_manifest_label_script_schemas_deterministic():
    with tempfile.TemporaryDirectory() as tmp:
        capability_dir = _make_fake_capability(Path(tmp), None)
        schemas_dir = capability_dir / "schemas"
        schemas_dir.mkdir()
        (schemas_dir / "b.v1.json").write_text('{"b": 1}')
        (schemas_dir / "a.v1.json").write_text('{"a": 2}')
        first = run_manifest_label("--schemas", str(capability_dir))
        second = run_manifest_label("--schemas", str(capability_dir))
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert first.stdout == second.stdout


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
def test_manifest_label_script_schemas_real_manifests_produce_expected_keys(
    capability_dir, expected_keys
):
    result = run_manifest_label("--schemas", f"capabilities/{capability_dir}")
    assert result.returncode == 0, result.stderr
    decoded = json.loads(base64.b64decode(result.stdout))
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
