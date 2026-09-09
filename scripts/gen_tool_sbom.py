#!/usr/bin/env python3
"""Regenerate sbom/tools.cdx.json from tools/tools.yaml.

Downloads every declared artifact, for every declared architecture, and
records its sha256. Emits a CycloneDX 1.6 SBOM (ECMA-424) -- the format
Trivy, Grype, osv-scanner and Dependency-Track all consume natively.

Run this whenever tools/tools.yaml changes:

    python3 scripts/gen_tool_sbom.py

Why a real SBOM instead of a bespoke lock file: a statically linked binary
installed into /usr/local/bin is invisible to any scanner that works off a
package database, because there is no dpkg or pip record of it. A scan of
this image would report clean while ~15 unmanaged binaries sit in it. A
CycloneDX component with a PURL is what lets CVE matching see them.

The sha256 recorded here is ALSO the build-time integrity check:
scripts/install_tools.sh installs from this file, verifying each download
against the hash below. tools.yaml is never read at image build time, so a
version bumped there but not re-hashed here cannot reach an image.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
TOOLS_YAML = ROOT / "tools" / "tools.yaml"
SBOM_PATH = ROOT / "sbom" / "tools.cdx.json"
CHUNK = 1 << 20


def fetch_sha256(url: str) -> tuple[str, int]:
    """sha256 and byte length of `url`, streamed (artifacts reach ~90 MB)."""
    digest = hashlib.sha256()
    size = 0
    req = urllib.request.Request(url, headers={"User-Agent": "rw-checks-sbom/1.0"})
    with urllib.request.urlopen(req, timeout=180) as resp:  # noqa: S310 -- https URLs from a reviewed, checked-in file
        while chunk := resp.read(CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def build_component(tool: dict, known: dict[str, str] | None = None) -> dict:
    """One CycloneDX component, with a `distribution` externalReference per
    architecture carrying that artifact's own hash.

    Per-arch artifacts are external references rather than separate
    components on purpose: CVE matching keys off the component's `purl`
    (one tool, one version, regardless of arch), so splitting a tool into
    two components would double-report every finding against it.
    """
    refs = []
    for arch in sorted(tool["urls"]):
        url = tool["urls"][arch]
        print(f"  {tool['name']:16s} {arch:6s} ", end="", flush=True)
        if known and url in known:
            sha = known[url]
            print(f"{sha[:16]}... (reused)")
        else:
            sha, size = fetch_sha256(url)
            print(f"{sha[:16]}... ({size / 1048576:.1f} MB)")
        refs.append(
            {
                "type": "distribution",
                "url": url,
                "comment": f"linux/{arch}",
                "hashes": [{"alg": "SHA-256", "content": sha}],
            }
        )
    return {
        "type": "application",
        "name": tool["name"],
        "version": str(tool["version"]),
        "purl": tool["purl"],
        "scope": "required",
        "externalReferences": refs,
        "properties": [
            {"name": "rw:archive-kind", "value": tool["kind"]},
            {"name": "rw:binary-name", "value": tool["binary"]},
        ],
    }


def load_known_hashes() -> dict[str, tuple[str, int]]:
    """url -> sha256 from the existing SBOM, for --reuse-hashes."""
    if not SBOM_PATH.exists():
        return {}
    sbom = json.loads(SBOM_PATH.read_text())
    known = {}
    for comp in sbom.get("components", []):
        for ref in comp.get("externalReferences", []):
            for h in ref.get("hashes", []):
                if h.get("alg") == "SHA-256":
                    known[ref["url"]] = h["content"]
    return known


def main() -> int:
    reuse = "--reuse-hashes" in sys.argv
    known = load_known_hashes() if reuse else {}
    if reuse:
        print(
            "--reuse-hashes: reusing recorded hashes for unchanged URLs.\n"
            "  For metadata-only edits. A release asset CAN be replaced in place,\n"
            "  and only a full re-run would catch that -- do one before shipping.\n"
        )
    spec = yaml.safe_load(TOOLS_YAML.read_text())
    print(f"hashing {len(spec['tools'])} tools from {TOOLS_YAML.relative_to(ROOT)}")

    components = []
    failures = []
    for tool in spec["tools"]:
        try:
            components.append(build_component(tool, known))
        except Exception as exc:  # noqa: BLE001 -- report every failure, not just the first
            print(f"  {tool['name']:16s} FAILED: {exc}", file=sys.stderr)
            failures.append(tool["name"])

    if failures:
        print(f"\n{len(failures)} tool(s) failed: {', '.join(failures)}", file=sys.stderr)
        print("SBOM NOT written -- a partial SBOM would silently drop tools.", file=sys.stderr)
        return 1

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            # No serialNumber/timestamp: this file is committed, and a value
            # that changes on every regeneration turns every re-hash into a
            # spurious diff. Provenance for a specific build belongs on the
            # build's own attestation, not in the checked-in source SBOM.
            "component": {
                "type": "container",
                "name": "rw-checks-codecollection",
                "description": "Static-check tools bundled into the rw-checks capability image",
            },
            "tools": {
                "components": [
                    {"type": "application", "name": "gen_tool_sbom.py", "version": "1.0"}
                ]
            },
        },
        "components": sorted(components, key=lambda c: c["name"]),
    }

    SBOM_PATH.parent.mkdir(parents=True, exist_ok=True)
    SBOM_PATH.write_text(json.dumps(sbom, indent=2, sort_keys=False) + "\n")
    print(f"\nwrote {SBOM_PATH.relative_to(ROOT)} ({len(components)} components)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
