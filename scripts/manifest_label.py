#!/usr/bin/env python3
"""Prints, for a given capability directory, the base64 encoding of either:

  - that capability's manifest.yaml, for use as the
    com.runwhen.capability.manifest.v1 OCI label; or
  - (--schemas) a compact, sorted-key JSON object holding EVERY file under
    that capability's schemas/ directory -- not only the ones the current
    manifest references -- keyed "schemas/<filename>", for use as the
    com.runwhen.capability.schemas.v1 OCI label. This is how the catalog
    (cc-catalog-svc) gets every schema version an image has ever published
    straight off the pushed image, without a platform release.

Neither travels on the image as a separate build artifact: CI runs this at
build time and passes each output straight in as a build-arg
(CAPABILITY_MANIFEST_B64 / CAPABILITY_SCHEMAS_B64).

stdlib only -- no PyYAML dependency here, so this stays runnable in a bare
`python3` step before any `pip install`. The `image:` check below, and the
`schema:` refs --schemas cross-checks against the schemas/ directory, are
therefore both line/text scans, not a YAML parse.

Usage: python3 scripts/manifest_label.py capabilities/<name>
       python3 scripts/manifest_label.py --schemas capabilities/<name>
"""

from __future__ import annotations

import base64
import json
import posixpath
import re
import sys
from pathlib import Path

# Matches a top-level `image:` key only -- not `resources:` or anything
# indented under `execution:`. A manifest that still has one is a leftover
# from the pre-label placeholder (see manifest.yaml's own header comment)
# and must not ship as a label. Also matches a bare `image:` line (a block
# value on the following lines) and a quoted key.
TOP_LEVEL_IMAGE_KEY = re.compile(r"^(image|\"image\"|'image')\s*:(\s|$)")

# Every `schema:` value in a manifest, block or flow style alike (both
# appear in this repo's manifests -- see capabilities/rw-checks/manifest.yaml
# for the flow style: `findings: { kind: ..., schema: ./schemas/x.json }`).
# The negative lookbehind keeps this from matching an identifier that merely
# ends in "schema" (there are none today, but the manifest is hand-written).
SCHEMA_REF = re.compile(r"(?<![\w])schema\s*:\s*([^\s,}]+)")


class ManifestLabelError(RuntimeError):
    """A schemas/ file or a manifest `schema:` ref can't be resolved into
    the com.runwhen.capability.schemas.v1 label."""


def find_schema_refs(manifest_text: str) -> list[str]:
    """Every raw `schema:` value in a manifest's text, in appearance order."""
    return [match.group(1).strip("\"'") for match in SCHEMA_REF.finditer(manifest_text)]


def normalize_schema_ref(ref: str) -> str:
    """posixpath.normpath's a manifest `schema:` ref (e.g.
    "./schemas/findings.v1.json" -> "schemas/findings.v1.json"). Raises
    ManifestLabelError if the ref is absolute or escapes the capability
    directory via a '..' segment."""
    key = posixpath.normpath(ref)
    if posixpath.isabs(key) or key == ".." or key.startswith("../"):
        raise ManifestLabelError(
            f"schema ref {ref!r} must be relative and stay under the capability directory"
        )
    return key


def build_schemas_map(capability_dir: Path) -> dict[str, dict]:
    """Every file in capability_dir/schemas/, keyed
    posixpath.normpath("schemas/<filename>"), parsed as JSON -- each must be
    a JSON object. Every `schema:` ref the capability's manifest.yaml
    contains (normalised) must be among these keys. Raises
    ManifestLabelError naming the offending file/ref otherwise. No
    schemas/ dir and no manifest ref -> {}."""
    schemas: dict[str, dict] = {}
    schemas_dir = capability_dir / "schemas"
    if schemas_dir.is_dir():
        for path in sorted(schemas_dir.iterdir()):
            if not path.is_file():
                continue
            key = normalize_schema_ref(f"schemas/{path.name}")
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ManifestLabelError(f"{path}: not valid JSON: {exc}") from exc
            if not isinstance(parsed, dict):
                raise ManifestLabelError(
                    f"{path}: must be a JSON object, got {type(parsed).__name__}"
                )
            schemas[key] = parsed

    manifest_path = capability_dir / "manifest.yaml"
    if manifest_path.is_file():
        for ref in find_schema_refs(manifest_path.read_text(encoding="utf-8")):
            key = normalize_schema_ref(ref)
            if key not in schemas:
                raise ManifestLabelError(
                    f"{manifest_path}: references schema {ref!r} ({key!r}), which is not "
                    f"a file under {schemas_dir} -- every manifest schema: ref must exist on disk"
                )
    return schemas


def encode_schemas(schemas: dict[str, dict]) -> str:
    """Base64 (standard alphabet, padded) of the schemas map, compactly
    serialised with sorted keys so the same schemas/ directory always
    produces the same value. Empty schemas/ dir (and no manifest ref) ->
    empty string, i.e. no label content."""
    if not schemas:
        return ""
    payload = json.dumps(schemas, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(payload).decode("ascii")


def main() -> int:
    args = sys.argv[1:]
    schemas_mode = False
    if args[:1] == ["--schemas"]:
        schemas_mode = True
        args = args[1:]

    if len(args) != 1:
        print(f"usage: {sys.argv[0]} [--schemas] capabilities/<name>", file=sys.stderr)
        return 2

    capability_dir = Path(args[0])
    manifest_path = capability_dir / "manifest.yaml"
    if not manifest_path.is_file():
        print(f"{manifest_path}: no such file", file=sys.stderr)
        return 1

    if schemas_mode:
        try:
            schemas = build_schemas_map(capability_dir)
        except ManifestLabelError as exc:
            print(f"manifest_label --schemas: {exc}", file=sys.stderr)
            return 1
        print(encode_schemas(schemas), end="")
        return 0

    raw = manifest_path.read_bytes()
    text = raw.decode("utf-8")
    if any(TOP_LEVEL_IMAGE_KEY.match(line) for line in text.splitlines()):
        print(
            f"{manifest_path}: still has a top-level 'image:' key -- an image "
            "cannot know its own digest; remove it (see the manifest's own "
            "header comment)",
            file=sys.stderr,
        )
        return 1

    print(base64.b64encode(raw).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
