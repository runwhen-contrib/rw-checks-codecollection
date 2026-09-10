"""rw-checks capability tasks: `checkout` (setup), `ruff` and `gitleaks`
(tasks). Argv for each tool matches docs/static-checks/CONTRACT.md's
`operations[].run`, carried over unchanged.
"""

from __future__ import annotations

from pathlib import Path

from runwhen_capability import Context, setup, task

# ctx.run()'s CompletedProcess.returncode is never checked by the SDK itself
# -- each tool's exit-code semantics differ (a nonzero code can mean
# "findings" as easily as "the tool crashed"), so the tasks below are the
# only place that knows how to tell those apart. Without this, the only
# thing standing between "the tool crashed" and "0 findings" is json.loads
# happening to raise on empty/malformed stdout -- a crash that still emits
# well-formed empty SARIF reads as a clean, complete scan (FAILURE-POLICY.md's
# flagship row). Truncate stderr before folding it into the raised error so
# a runaway tool doesn't blow up the task's error string.
_STDERR_ERROR_LEN = 4000


def _tail(text: str) -> str:
    return text if len(text) <= _STDERR_ERROR_LEN else text[-_STDERR_ERROR_LEN:]


@setup(outputs=["tree", "changed"])
def checkout(ctx: Context, repo_url: str, sha: str, base_sha: str | None = None):
    tree = ctx.git.checkout(repo_url, sha, credential="repo")
    changed = ctx.git.changed_files(tree, base_sha) if base_sha else None
    return {"tree": tree, "changed": changed}


@task(outputs={"findings": "rw.findings.v1"})
def ruff(ctx: Context, tree: Path, changed: list[str] | None):
    proc = ctx.run(["ruff", "check", "--output-format=sarif", "."], cwd=tree)
    # ruff's exit code: 0 = clean, 1 = findings were found (the normal case
    # on a real PR, not a failure), >=2 = ruff itself errored (bad config,
    # internal crash, unsupported invocation). Only >=2 is a tool failure.
    if proc.returncode >= 2:
        raise RuntimeError(f"ruff exited {proc.returncode}: {_tail(proc.stderr)}")
    findings = ctx.sarif.parse(proc.stdout, root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": ctx.findings.cap(ctx.findings.fingerprint(findings))}


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
    # --exit-code 0 above means gitleaks never sets a nonzero code for
    # findings (those are only in the SARIF report) -- any nonzero code here
    # is the tool itself failing, not "leaks found".
    if proc.returncode != 0:
        raise RuntimeError(f"gitleaks exited {proc.returncode}: {_tail(proc.stderr)}")
    findings = ctx.sarif.parse(proc.stdout, root=tree)
    return {"findings": ctx.findings.cap(ctx.findings.fingerprint(findings))}
