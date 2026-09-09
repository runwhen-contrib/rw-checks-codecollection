"""rw-checks capability tasks: `checkout` (setup), `ruff` and `gitleaks`
(tasks). Argv for each tool matches docs/static-checks/CONTRACT.md's
`operations[].run`, carried over unchanged.
"""

from __future__ import annotations

from pathlib import Path

from runwhen_capability import Context, setup, task


@setup(outputs=["tree", "changed"])
def checkout(ctx: Context, repo_url: str, sha: str, base_sha: str | None = None):
    tree = ctx.git.checkout(repo_url, sha, credential="repo")
    changed = ctx.git.changed_files(tree, base_sha) if base_sha else None
    return {"tree": tree, "changed": changed}


@task(outputs={"findings": "rw.findings.v1"})
def ruff(ctx: Context, tree: Path, changed: list[str] | None):
    proc = ctx.run(["ruff", "check", "--output-format=sarif", "."], cwd=tree)
    findings = ctx.sarif.parse(proc.stdout, root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": ctx.findings.fingerprint(findings)}


@task(outputs={"findings": "rw.findings.v1"})
def gitleaks(ctx: Context, tree: Path):
    proc = ctx.run(
        [
            "gitleaks",
            "detect",
            "--source",
            ".",
            "--report-format",
            "sarif",
            "--report-path",
            "/dev/stdout",
            "--no-banner",
            "--exit-code",
            "0",
        ],
        cwd=tree,
    )
    findings = ctx.sarif.parse(proc.stdout, root=tree)
    return {"findings": ctx.findings.fingerprint(findings)}
