"""ctx.findings.filter_changed / .fingerprint -- the changed-files diff
filter (CONTRACT.md: "Present -> emit only findings whose path is in files
with status != removed") and fingerprint assignment.
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


def test_fingerprint_fills_every_finding():
    ctx = Context(capability="rw-checks", operation="ruff", workdir="/tmp")
    findings = [make_finding("src/x.py"), make_finding("src/y.py", rule="E501")]

    got = ctx.findings.fingerprint(findings)

    assert all(f.fingerprint is not None for f in got)
    assert len(got[0].fingerprint) == 32
    # golden vector from test_fingerprint.py
    assert got[0].fingerprint == "a6fd84423d29e6f918a954ed952f8cfd"
    # different rule -> different fingerprint
    assert got[0].fingerprint != got[1].fingerprint


def test_fingerprint_does_not_mutate_input():
    ctx = Context(capability="rw-checks", operation="ruff", workdir="/tmp")
    findings = [make_finding("src/x.py")]

    ctx.findings.fingerprint(findings)

    assert findings[0].fingerprint is None
