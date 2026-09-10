"""trufflehog -- committed-credential scanning.

Always applicable, like gitleaks: a secret does not stop being a secret
because the repo has no config for this tool, and CI_BINARY is None because
secret scanning is wanted regardless of what the repo's own CI does.
Diff-scoped like every other check (see _common.scoped): a secret already
on the base branch belongs to a scheduled full scan, not to whoever opened
the next unrelated pull request. `changed` is the PR's cumulative diff, so
a secret added anywhere in the branch is still caught.
"""

from __future__ import annotations

import sys
from pathlib import Path

import adapters
from runwhen_capability import Context

from . import _common

# A verified credential is known-live; an unverified one is a strong
# candidate. Both are errors -- the distinction belongs in the message, not
# in a downgrade to `warning` -- so this is the whole (degenerate)
# vocabulary.
SEVERITY = {"": "error"}
FILES = ()
CONFIG = "optional"
CI_BINARY = None
GUARD = None
# trufflehog's differentiator over gitleaks is credential VERIFICATION, and
# this check must never verify (it would call the provider with the secret it
# just found -- see --no-verification below). Without it the two find the same
# things: both flagged the identical PAT at src/config.py:8 on the fixture.
SUPERSEDED_BY = "gitleaks"
# No --fail flag below, so trufflehog's "183 = verified secret found"
# convention never fires; --no-verification also means nothing gets marked
# verified in the first place. Exit stays 0 regardless of findings.
EXPECT_EXIT = (0,)


def detect(tree: Path) -> list[Path]:
    return []


def check(ctx: Context, tree: Path, changed: list[str] | None):
    findings, stop = _common.gated(ctx, tree, sys.modules[__name__])
    if stop:
        return findings
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
    fail = _common.check_exit(ctx, tree, "trufflehog", proc, sys.modules[__name__])
    if fail is not None:
        return fail
    return _common.emit(ctx, adapters.trufflehog(proc.stdout, SEVERITY), tree, changed)
