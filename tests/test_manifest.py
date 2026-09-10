"""Sanity-check the shipped capability manifests: an absent `egress` key
must parse cleanly through the repo's own loader. See the `needs:` comment
in each manifest for why `egress` isn't declared -- it's not
capability-static; a literal here would be wrong by construction for GHE.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from runwhen_capability.loader import load_manifest

CAPABILITIES = Path(__file__).parent.parent / "capabilities"


@pytest.mark.parametrize("capability_dir", ["rw-checks", "rw-worktree"])
def test_shipped_manifest_loads_without_egress(capability_dir):
    manifest = load_manifest(CAPABILITIES / capability_dir)
    assert "egress" not in manifest["needs"]
