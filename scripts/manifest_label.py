#!/usr/bin/env python3
"""Prints the base64 encoding of a capability's manifest.yaml, for use as
the com.runwhen.capability.manifest.v1 OCI label (Contract 1 --
docs/ccv-capability-catalog PLAN.md in runwhen-auto). The manifest travels
on the image, not as a separate build artifact: CI runs this at build time
and passes the output straight in as CAPABILITY_MANIFEST_B64.

stdlib only -- no PyYAML dependency here, so this stays runnable in a bare
`python3` step before any `pip install`. The `image:` check below is
therefore a line check, not a YAML parse.

Usage: python3 scripts/manifest_label.py capabilities/<name>
"""

from __future__ import annotations

import base64
import re
import sys
from pathlib import Path

# Matches a top-level `image:` key only -- not `resources:` or anything
# indented under `execution:`. A manifest that still has one is a leftover
# from the pre-label placeholder (see manifest.yaml's own header comment)
# and must not ship as a label. Also matches a bare `image:` line (a block
# value on the following lines) and a quoted key.
TOP_LEVEL_IMAGE_KEY = re.compile(r"^(image|\"image\"|'image')\s*:(\s|$)")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} capabilities/<name>", file=sys.stderr)
        return 2

    manifest_path = Path(sys.argv[1]) / "manifest.yaml"
    if not manifest_path.is_file():
        print(f"{manifest_path}: no such file", file=sys.stderr)
        return 1

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
