"""rw-checks task registrations.

One `@task` per tool, each a real named function you can jump to and grep for.
The body is one line because everything else about a tool -- its argv, severity
map, config discovery, applicability and diff-filter decision -- lives in its
own module under `tools/`, beside the `detect()` the discovery task will call.

An earlier version generated these in a loop with `importlib.import_module`
and `globals()[name] = ...`. Shorter, and worse: `tasks.ruff` existed at run
time but nowhere in the source, so nothing could jump to it and nothing could
grep it. The duplication the tools/ split removed was the three-line
run/parse/filter TAIL repeated 22 times -- a list of what this capability
offers is worth writing out.

No sys.path juggling here: `load_capability` puts the capability directory and
`tools/` on the path before this file is exec'd, because a tasks.py loaded by
path belongs to no package.
"""

from __future__ import annotations

from pathlib import Path

import tools.actionlint
import tools.ast_grep
import tools.biome
import tools.buf
import tools.checkmake
import tools.checkov
import tools.dotenv_linter
import tools.flake8
import tools.gitleaks
import tools.hadolint
import tools.osv_scanner
import tools.pylint
import tools.regal
import tools.ruff
import tools.shellcheck
import tools.sqlfluff
import tools.tflint
import tools.trivy
import tools.trufflehog
import tools.vale
import tools.yamllint
import tools.zizmor
from runwhen_capability import Context, setup, task


@setup(outputs=["tree", "changed"])
def checkout(ctx: Context, repo_url: str, sha: str, base_sha: str | None = None):
    tree = ctx.git.checkout(repo_url, sha, credential="repo")
    changed = ctx.git.changed_files(tree, base_sha) if base_sha else None
    return {"tree": tree, "changed": changed}


@task(outputs={"findings": "rw.findings.v1"})
def actionlint(ctx: Context, tree: Path, changed: list[str] | None = None):
    """actionlint -- GitHub Actions workflow lint."""
    return {"findings": tools.actionlint.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def ast_grep(ctx: Context, tree: Path, changed: list[str] | None = None):
    """ast-grep -- structural code search/lint against the repo's OWN rules."""
    return {"findings": tools.ast_grep.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def biome(ctx: Context, tree: Path, changed: list[str] | None = None):
    """biome -- JS/TS/JSON/CSS lint."""
    return {"findings": tools.biome.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def buf(ctx: Context, tree: Path, changed: list[str] | None = None):
    """buf -- protobuf lint."""
    return {"findings": tools.buf.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def checkmake(ctx: Context, tree: Path, changed: list[str] | None = None):
    """checkmake -- Makefile lint."""
    return {"findings": tools.checkmake.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def checkov(ctx: Context, tree: Path, changed: list[str] | None = None):
    """checkov -- IaC misconfiguration scanning."""
    return {"findings": tools.checkov.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def dotenv_linter(ctx: Context, tree: Path, changed: list[str] | None = None):
    """dotenv-linter -- .env file lint."""
    return {"findings": tools.dotenv_linter.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def flake8(ctx: Context, tree: Path, changed: list[str] | None = None):
    """flake8 -- fast Python lint, ahead of pylint's deeper (slower) pass."""
    return {"findings": tools.flake8.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def gitleaks(ctx: Context, tree: Path, changed: list[str] | None = None):
    """gitleaks -- committed-credential scanning."""
    return {"findings": tools.gitleaks.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def hadolint(ctx: Context, tree: Path, changed: list[str] | None = None):
    """hadolint -- Dockerfile defects."""
    return {"findings": tools.hadolint.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def osv_scanner(ctx: Context, tree: Path, changed: list[str] | None = None):
    """osv-scanner -- dependency (lockfile) vulnerability scanning."""
    return {"findings": tools.osv_scanner.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def pylint(ctx: Context, tree: Path, changed: list[str] | None = None):
    """pylint -- deeper Python analysis than ruff, and slower."""
    return {"findings": tools.pylint.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def regal(ctx: Context, tree: Path, changed: list[str] | None = None):
    """regal -- Rego (OPA policy) lint."""
    return {"findings": tools.regal.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def ruff(ctx: Context, tree: Path, changed: list[str] | None = None):
    """ruff -- fast Python linting."""
    return {"findings": tools.ruff.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def shellcheck(ctx: Context, tree: Path, changed: list[str] | None = None):
    """ShellCheck -- shell script defects."""
    return {"findings": tools.shellcheck.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def sqlfluff(ctx: Context, tree: Path, changed: list[str] | None = None):
    """sqlfluff -- SQL lint."""
    return {"findings": tools.sqlfluff.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def tflint(ctx: Context, tree: Path, changed: list[str] | None = None):
    """tflint -- Terraform linting."""
    return {"findings": tools.tflint.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def trivy(ctx: Context, tree: Path, changed: list[str] | None = None):
    """trivy -- vulnerability / misconfig / secret scanning across IaC and."""
    return {"findings": tools.trivy.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def trufflehog(ctx: Context, tree: Path, changed: list[str] | None = None):
    """trufflehog -- committed-credential scanning."""
    return {"findings": tools.trufflehog.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def vale(ctx: Context, tree: Path, changed: list[str] | None = None):
    """vale -- prose lint for docs."""
    return {"findings": tools.vale.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def yamllint(ctx: Context, tree: Path, changed: list[str] | None = None):
    """yamllint -- YAML lint."""
    return {"findings": tools.yamllint.check(ctx, tree, changed)}


@task(outputs={"findings": "rw.findings.v1"})
def zizmor(ctx: Context, tree: Path, changed: list[str] | None = None):
    """zizmor -- GitHub Actions workflow security scanning."""
    return {"findings": tools.zizmor.check(ctx, tree, changed)}
