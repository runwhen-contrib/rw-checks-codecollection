"""trufflehog -- committed-credential scanning.

Always applicable, like gitleaks: a secret does not stop being a secret
because the repo has no config for this tool, and CI_BINARY is None because
secret scanning is wanted regardless of what the repo's own CI does. NOT
diff-filtered: a secret committed before this diff is still a leaked secret
today.
"""

from __future__ import annotations

import sys
from pathlib import Path

import _common
import adapters
from runwhen_capability import Context

# A verified credential is known-live; an unverified one is a strong
# candidate. adapters.trufflehog() maps both to `error` -- the distinction
# belongs in the message, not in a downgrade to `warning`. Declared here
# only to satisfy the package-wide contract; adapters.py is the actual
# source of truth.
SEVERITY = {"": "error"}
FILES = ()
CONFIG = "optional"
CI_BINARY = None
GUARD = None


def detect(tree: Path) -> list[Path]:
    return []


def check(ctx: Context, tree: Path, changed: list[str] | None):
    if _common.gate(tree, sys.modules[__name__]):
        return []
    # --no-verification is required: verification means calling each
    # provider with the credential trufflehog just found, which this check
    # must never do. --exclude-paths (a file of newline-separated regexes,
    # written under ctx.workdir -- the per-request scope dir, wiped every
    # request, NOT /tmp) keeps trufflehog from walking .git/objects at all;
    # the adapter also drops any ".git/" path defensively, but the argv
    # should not rely on that backstop alone.
    exclude_file = ctx.workdir / "trufflehog-exclude.txt"
    exclude_file.write_text(r"\.git/" + "\n")
    proc = ctx.run(
        [
            "trufflehog",
            "filesystem",
            ".",
            "--json",
            "--no-update",
            "--no-verification",
            "--exclude-paths",
            str(exclude_file),
        ],
        cwd=tree,
    )
    # Secret scan, not a lint -- not diff-filtered, same reasoning as
    # gitleaks/trivy/osv-scanner/checkov/zizmor.
    return _common.emit(ctx, adapters.trufflehog(proc.stdout), tree, None, diff_filter=False)
