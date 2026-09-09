"""rw-checks task registrations.

Thin by design. Everything about a tool -- its argv, severity map, config
discovery, applicability and diff-filtering -- lives in its own module under
`tools/`. This file only names the tools and wires each one to the SDK's task
registry.

The 22 registrations are generated from `_TOOLS` rather than hand-written,
because the bodies were identical 22 times over and that duplication is what
this split exists to remove. `_TOOLS` is still the explicit, greppable
inventory: a test asserts it matches the manifest's `tasks[]` in both
directions, and the SDK registers by `func.__name__`, so a name here must
equal a name there or dispatch silently 404s.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

# tasks.py is loaded by importlib.util.spec_from_file_location under a
# generated module name (see sdk/runwhen_capability/loader.py), so it is never
# part of a package and a plain `import tools.ruff` has nothing to resolve
# against. Put this directory and tools/ on the path first.
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent / "tools"))

from runwhen_capability import Context, setup, task  # noqa: E402

#: Every tool this capability ships, one module each under tools/.
#: MUST match the manifest's tasks[] exactly -- see tests/test_manifest_tasks.py.
_TOOLS = (
    "actionlint",
    "ast_grep",
    "biome",
    "buf",
    "checkmake",
    "checkov",
    "dotenv_linter",
    "flake8",
    "gitleaks",
    "hadolint",
    "osv_scanner",
    "pylint",
    "regal",
    "ruff",
    "shellcheck",
    "sqlfluff",
    "tflint",
    "trivy",
    "trufflehog",
    "vale",
    "yamllint",
    "zizmor",
)


@setup(outputs=["tree", "changed"])
def checkout(ctx: Context, repo_url: str, sha: str, base_sha: str | None = None):
    tree = ctx.git.checkout(repo_url, sha, credential="repo")
    changed = ctx.git.changed_files(tree, base_sha) if base_sha else None
    return {"tree": tree, "changed": changed}


def _register(name: str) -> None:
    """Register one tool module as a task of the same name.

    `changed` defaults to None so a task whose manifest entry omits it still
    binds -- but every entry declares it now: whether a tool's findings are
    reduced to the diff is the MODULE's decision (`_common.emit`'s
    `diff_filter`), not the manifest's. Declaring it in both places is two
    expressions of one policy, and they drift.
    """
    module = importlib.import_module(name)

    def run(ctx: Context, tree: Path, changed: list[str] | None = None):
        return {"findings": module.check(ctx, tree, changed)}

    run.__name__ = name
    run.__qualname__ = name
    run.__doc__ = (module.__doc__ or "").strip().splitlines()[0] if module.__doc__ else name
    task(outputs={"findings": "rw.findings.v1"})(run)
    # Also bind as a module attribute, so `tasks.pylint(...)` works exactly as
    # a hand-written function would. The decorator alone only populates the
    # registry; tests and anything else importing this module reach the tasks
    # by name.
    globals()[name] = run


for _name in _TOOLS:
    _register(_name)
