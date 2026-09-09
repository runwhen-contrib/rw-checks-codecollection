"""ctx.findings.filter_changed -- the changed-files diff filter
(CONTRACT.md: "Present -> emit only findings whose path is in files with
status != removed").
"""

from runwhen_capability import Context
from runwhen_capability.models import Finding


def make_finding(path: str, rule: str = "F401") -> Finding:
    return Finding(
        capability="rw-checks",
        operation="ruff",
        rule=rule,
        path=path,
        line=1,
        severity="warning",
        message="msg",
        context="import os",
    )


def test_filter_changed_keeps_only_listed_paths():
    ctx = Context(capability="rw-checks", operation="ruff", workdir="/tmp")
    findings = [make_finding("src/x.py"), make_finding("src/y.py"), make_finding("src/z.py")]

    got = ctx.findings.filter_changed(findings, ["src/x.py", "src/z.py"])

    assert [f.path for f in got] == ["src/x.py", "src/z.py"]


def test_filter_changed_empty_changed_list_allows_nothing():
    ctx = Context(capability="rw-checks", operation="ruff", workdir="/tmp")
    findings = [make_finding("src/x.py")]

    got = ctx.findings.filter_changed(findings, [])

    assert got == []
