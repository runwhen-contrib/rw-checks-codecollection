"""rw-checks capability tasks: `checkout` (setup), the SARIF-emitting check
tasks (`ruff`, `gitleaks`, `trivy`, `osv_scanner`, `checkov`, `zizmor`,
`tflint`), and the adapter-based check tasks (everything below tflint, which
run a tool's own JSON/text output through capabilities/rw-checks/adapters.py
instead of ctx.sarif.parse). Argv for each tool is taken verbatim from
tests/fixtures/tools/capture.log -- the exact invocation captured against the
real built image that produced parseable output for that tool. Do not "clean
up" an argv without re-capturing; a plausible-looking flag change is exactly
how these silently regress back to zero findings. Where capture.log points a
tool at tests/fixtures/sample-repo's own layout (a hardcoded "src"/"docs"/
"policy" subdirectory), the task below points at "." or discovers files
instead -- a real target repo does not share that fixture's layout -- and
says so in a comment.
"""

from __future__ import annotations

import sys
from pathlib import Path

from runwhen_capability import Context, setup, task

# tasks.py is loaded by runwhen_capability.loader via
# importlib.util.spec_from_file_location under a generated module name, so it
# is never part of a package -- a plain `import adapters` has nothing to
# resolve it against. Put this file's own directory on sys.path first, the
# same fix tests/test_adapters.py uses to import the same module directly.
sys.path.insert(0, str(Path(__file__).parent))
import adapters  # noqa: E402


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
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def gitleaks(ctx: Context, tree: Path):
    # gitleaks writes ZERO bytes to --report-path when it is a pipe (which
    # is what ctx.run's capture_output=True gives it), even though it still
    # finds leaks and exits 0 -- ctx.sarif.parse("") then raises
    # JSONDecodeError. Reporting to a real file under ctx.workdir (the
    # per-request scope dir, wiped every request -- NOT /tmp, which is not)
    # and reading it back afterwards is the only invocation that actually
    # works: tests/fixtures/tools/capture.log records 50KB / 2 results this
    # way vs 0 bytes through /dev/stdout. No secret scan should be
    # diff-filtered: a secret committed before this diff is still a leaked
    # secret.
    report = ctx.workdir / "gitleaks.sarif"
    ctx.run(
        [
            "gitleaks",
            "dir",
            ".",
            "--report-format",
            "sarif",
            "--report-path",
            str(report),
            "--no-banner",
            "--exit-code",
            "0",
        ],
        cwd=tree,
    )
    findings = ctx.sarif.parse(report.read_text(), root=tree)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def trivy(ctx: Context, tree: Path):
    # Vulnerability/misconfig/secret scan: not diff-filtered, same reasoning
    # as gitleaks -- an existing vulnerability doesn't stop being one just
    # because this diff didn't touch the affected file.
    proc = ctx.run(
        ["trivy", "fs", "--format", "sarif", "--quiet", "--scanners", "vuln,misconfig,secret", "."],
        cwd=tree,
    )
    findings = ctx.sarif.parse(proc.stdout, root=tree)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def osv_scanner(ctx: Context, tree: Path):
    # osv-scanner exits 1 when it finds vulnerabilities (capture.log: exit
    # 1, 197930B of valid SARIF) -- ctx.run does not raise on non-zero exit,
    # and that is correct here: a non-zero exit is the tool reporting
    # findings, not a tool failure. Dependency vulns are not diff-filtered,
    # for the same reason as gitleaks/trivy above.
    proc = ctx.run(["osv-scanner", "--format", "sarif", "-r", "."], cwd=tree)
    findings = ctx.sarif.parse(proc.stdout, root=tree)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def checkov(ctx: Context, tree: Path):
    # checkov's `-o/--output sarif` prints a banner to stdout and writes
    # nothing there -- the SARIF report lands on disk at
    # <--output-file-path>/results_sarif.sarif (tests/fixtures/tools/
    # capture.log). Write into a dir under ctx.workdir (the per-request
    # scope dir, wiped every request -- NOT /tmp) and read that file back.
    # checkov can exit non-zero when it reports findings; that is not a
    # task failure. IaC misconfigurations are not diff-filtered, same
    # reasoning as gitleaks/trivy/osv-scanner above.
    out_dir = ctx.workdir / "checkov-out"
    out_dir.mkdir(parents=True, exist_ok=True)
    ctx.run(
        ["checkov", "-d", ".", "--output", "sarif", "--output-file-path", str(out_dir)],
        cwd=tree,
    )
    report = out_dir / "results_sarif.sarif"
    findings = ctx.sarif.parse(report.read_text(), root=tree)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def zizmor(ctx: Context, tree: Path):
    # GitHub Actions security scan: not diff-filtered, same reasoning as
    # gitleaks/trivy/osv-scanner/checkov above.
    proc = ctx.run(
        ["zizmor", "--format", "sarif", "--no-progress", ".github/workflows"],
        cwd=tree,
    )
    findings = ctx.sarif.parse(proc.stdout, root=tree)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def tflint(ctx: Context, tree: Path, changed: list[str] | None):
    # Lint tool (like ruff), not a security/vuln scan -- diff-filtered.
    # tflint exits 2 when it reports findings (capture.log: exit 2, 2384B
    # of valid SARIF) -- ctx.run does not raise on non-zero exit, and that
    # is correct here: a non-zero exit is the tool reporting findings, not
    # a tool failure.
    proc = ctx.run(["tflint", "--format", "sarif", "--chdir", "infra"], cwd=tree)
    findings = ctx.sarif.parse(proc.stdout, root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


def _find_files(tree: Path, *patterns: str) -> list[str]:
    """Repo-relative paths (POSIX separators, `.git` excluded) matching any
    of `patterns` -- for tools with no directory-recursion mode of their own
    (shellcheck, hadolint), which must be handed every target file
    explicitly rather than a directory."""
    found: set[str] = set()
    for pattern in patterns:
        for p in tree.rglob(pattern):
            if p.is_file() and ".git" not in p.relative_to(tree).parts:
                found.add(p.relative_to(tree).as_posix())
    return sorted(found)


@task(outputs={"findings": "rw.findings.v1"})
def shellcheck(ctx: Context, tree: Path, changed: list[str] | None):
    # shellcheck has no directory/recursive mode -- capture.log points it at
    # one fixture script (scripts/deploy.sh); every *.sh file in the tree is
    # discovered and passed explicitly instead. No scripts found is not a
    # tool failure -- shellcheck simply isn't invoked.
    scripts = _find_files(tree, "*.sh")
    findings = []
    if scripts:
        proc = ctx.run(["shellcheck", "-f", "json1", *scripts], cwd=tree)
        findings = ctx.findings.from_records(adapters.shellcheck(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def hadolint(ctx: Context, tree: Path, changed: list[str] | None):
    # Same reasoning as shellcheck: hadolint lints exactly one Dockerfile per
    # invocation and has no directory mode, so every Dockerfile/Dockerfile.*
    # in the tree is discovered and passed explicitly.
    dockerfiles = _find_files(tree, "Dockerfile", "Dockerfile.*")
    findings = []
    if dockerfiles:
        proc = ctx.run(["hadolint", "-f", "json", *dockerfiles], cwd=tree)
        findings = ctx.findings.from_records(adapters.hadolint(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def yamllint(ctx: Context, tree: Path, changed: list[str] | None):
    # capture.log's `.` is already repo-wide; no fixture-specific path here.
    proc = ctx.run(["yamllint", "-f", "parsable", "."], cwd=tree)
    findings = ctx.findings.from_records(adapters.yamllint(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def actionlint(ctx: Context, tree: Path, changed: list[str] | None):
    # No workflow file given: actionlint's own project detection (walks up
    # to the enclosing repo -- tests/fixtures/tools/README.md) finds and
    # lints every workflow under .github/workflows on its own, which is the
    # repo-wide equivalent of capture.log's single hardcoded ci.yml.
    proc = ctx.run(["actionlint", "-format", "{{json .}}", "-no-color"], cwd=tree)
    findings = ctx.findings.from_records(adapters.actionlint(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def pylint(ctx: Context, tree: Path, changed: list[str] | None):
    # "." replaces capture.log's fixture-specific "src" dir. --recursive=y
    # (pylint >=2.14) is required for that to actually walk the whole repo --
    # without it a bare directory argument is only linted when it is itself
    # a package (has __init__.py).
    proc = ctx.run(
        ["pylint", "--output-format=json", "--exit-zero", "--recursive=y", "."], cwd=tree
    )
    findings = ctx.findings.from_records(adapters.pylint(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def sqlfluff(ctx: Context, tree: Path, changed: list[str] | None):
    # "." replaces capture.log's fixture-specific "db" dir; sqlfluff lint
    # recurses into whatever path it is given.
    proc = ctx.run(["sqlfluff", "lint", "--format", "json", "."], cwd=tree)
    findings = ctx.findings.from_records(adapters.sqlfluff(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def biome(ctx: Context, tree: Path, changed: list[str] | None):
    # "." replaces capture.log's fixture-specific "src" dir. capture.log
    # captured `biome lint`, not `biome ci` (adapters.py's docstring names
    # `ci` as the conceptual equivalent) -- `lint` is what was actually
    # proven to emit this JSON shape, so that is what runs here.
    proc = ctx.run(["biome", "lint", "--reporter=json", "."], cwd=tree)
    findings = ctx.findings.from_records(adapters.biome(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def ast_grep(ctx: Context, tree: Path, changed: list[str] | None):
    # No path argument in capture.log either: `ast-grep scan` already scans
    # the whole project rooted at cwd by default.
    proc = ctx.run(["ast-grep", "scan", "--json"], cwd=tree)
    findings = ctx.findings.from_records(adapters.ast_grep(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def regal(ctx: Context, tree: Path, changed: list[str] | None):
    # "." replaces capture.log's fixture-specific "policy" dir.
    proc = ctx.run(["regal", "lint", "--format", "json", "."], cwd=tree)
    findings = ctx.findings.from_records(adapters.regal(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def vale(ctx: Context, tree: Path, changed: list[str] | None):
    # "." replaces capture.log's fixture-specific "docs" dir.
    proc = ctx.run(["vale", "--output=JSON", "."], cwd=tree)
    findings = ctx.findings.from_records(adapters.vale(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def flake8(ctx: Context, tree: Path, changed: list[str] | None):
    # "." replaces capture.log's fixture-specific "src" dir; unlike pylint,
    # flake8 walks directories on its own without an extra flag.
    proc = ctx.run(["flake8", "--format=%(path)s:%(row)d:%(col)d:%(code)s:%(text)s", "."], cwd=tree)
    findings = ctx.findings.from_records(adapters.flake8(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def checkmake(ctx: Context, tree: Path, changed: list[str] | None):
    # checkmake lints exactly one file per invocation and has no directory
    # mode, so this stays pointed at the conventional top-level Makefile --
    # unlike "src"/"docs"/"policy" above, capture.log's `Makefile` is not a
    # fixture-specific path to generalise away. The delimited --format is
    # required per adapters.py's checkmake docstring: checkmake's default
    # table output cannot be parsed reliably. checkmake exits non-zero
    # (capture.log: exit 3) when it reports violations; that is not a task
    # failure.
    proc = ctx.run(
        [
            "checkmake",
            # NOTE: a real newline, not "\\n". checkmake applies the template PER
            # ITEM and emits nothing between items, so without a trailing
            # newline every violation lands on one line and the adapter
            # parses exactly one mangled record.
            "--format={{.Rule}}|{{.FileName}}|{{.LineNumber}}|{{.Violation}}\n",
            "Makefile",
        ],
        cwd=tree,
    )
    findings = ctx.findings.from_records(adapters.checkmake(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def dotenv_linter(ctx: Context, tree: Path, changed: list[str] | None):
    # "." replaces capture.log's fixture-specific ".env" file; dotenv-linter
    # walks a directory looking for every .env* file on its own.
    proc = ctx.run(["dotenv-linter", "."], cwd=tree)
    findings = ctx.findings.from_records(adapters.dotenv_linter(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def buf(ctx: Context, tree: Path, changed: list[str] | None):
    # No path argument in capture.log either: buf resolves its module from
    # buf.yaml/buf.work.yaml relative to cwd on its own.
    proc = ctx.run(["buf", "lint", "--error-format=json"], cwd=tree)
    findings = ctx.findings.from_records(adapters.buf(proc.stdout), root=tree)
    if changed:
        findings = ctx.findings.filter_changed(findings, changed)
    return {"findings": findings}


@task(outputs={"findings": "rw.findings.v1"})
def trufflehog(ctx: Context, tree: Path):
    # Secret scan, not a lint -- not diff-filtered, same reasoning as
    # gitleaks/trivy/osv-scanner/checkov/zizmor above: a secret committed
    # before this diff is still a leaked secret today. --no-verification is
    # required: verification means calling each provider with the
    # credential trufflehog just found, which this task must never do.
    # --exclude-paths (a file of newline-separated regexes, written under
    # ctx.workdir -- the per-request scope dir, wiped every request, NOT
    # /tmp) keeps trufflehog from walking .git/objects at all; the adapter
    # also drops any ".git/" path defensively, but the argv should not rely
    # on that backstop alone.
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
    findings = ctx.findings.from_records(adapters.trufflehog(proc.stdout), root=tree)
    return {"findings": findings}
