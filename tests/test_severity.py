"""severity.py tests -- against the REAL SARIF captured in
tests/fixtures/tools/, same discipline test_adapters.py follows for the
non-SARIF tools: a policy is asserted against what the tool's SARIF actually
contains, not what its documentation claims. Severity is checked directly
against (rule_id, level, rule_properties) tuples pulled straight out of each
fixture, independent of path resolution -- these tools' captured SARIF
carries the ORIGINAL capture machine's absolute file:// paths, which never
resolve under any local worktree, and that is a path-normalisation concern
(sdk/runwhen_capability/sarif.py), not a severity one.

`test_sarif_wiring_calls_the_policy_per_result` proves the OTHER half:
ctx.sarif.parse actually calls the callback with the right per-result
rule_id/level/rule_properties, using tests/fixtures/repo (already
root-relative, already proven resolvable by test_sarif.py).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "capabilities" / "rw-checks"))

import severity  # noqa: E402
from runwhen_capability import Context  # noqa: E402
from runwhen_capability.sarif import severity as sarif_level_severity  # noqa: E402

TOOLS_FIXTURES = Path(__file__).parent / "fixtures" / "tools"
REPO_FIXTURES = Path(__file__).parent / "fixtures"


def _results(fname: str) -> list[tuple[str, str, dict]]:
    """(ruleId, level, rule_properties) for every result in a captured
    SARIF report -- rule_properties matched by id from
    runs[].tool.driver.rules[], the same lookup sarif.py's own
    `_rule_properties` performs, reimplemented here so this test doesn't
    depend on that private helper."""
    report = json.loads((TOOLS_FIXTURES / fname).read_text())
    out = []
    for run in report.get("runs", []):
        props_by_id = {}
        for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []:
            rid = rule.get("id")
            if rid:
                props_by_id[rid] = rule.get("properties") or {}
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "") or ""
            level = res.get("level", "") or ""
            out.append((rule_id, level, props_by_id.get(rule_id, {})))
    return out


# --- ruff ---------------------------------------------------------------


def test_ruff_pyflakes_is_error():
    by_rule = {
        rid: severity.ruff(rid, level, props) for rid, level, props in _results("ruff.sarif")
    }
    assert by_rule["F401"] == "error"
    assert by_rule["F841"] == "error"


def test_ruff_isort_is_note_despite_sarif_saying_error():
    results = _results("ruff.sarif")
    by_rule = {rid: (level, severity.ruff(rid, level, props)) for rid, level, props in results}
    level, mapped = by_rule["I001"]
    assert level == "error"  # ruff's own SARIF marks every rule "error"
    assert mapped == "note"  # the policy overrides it by rule-code prefix


# --- gitleaks -----------------------------------------------------------


def test_gitleaks_results_are_error():
    results = _results("gitleaks.sarif")
    assert results, "fixture should carry at least one detected credential"
    assert all(level == "" for _, level, _ in results), "gitleaks sets no SARIF level at all"
    assert all(severity.gitleaks(rid, level, props) == "error" for rid, level, props in results)


# --- trivy ----------------------------------------------------------------


def test_trivy_uses_security_severity_when_present():
    by_rule = {rid: props for rid, _, props in _results("trivy.sarif")}
    cve = by_rule["CVE-2018-18074"]
    assert cve["security-severity"] == "7.5"
    assert severity.trivy("CVE-2018-18074", "warning", cve) == "error"


def test_trivy_bands_follow_github_security_severity_convention():
    assert severity.trivy("x", "note", {"security-severity": "9.8"}) == "error"
    assert severity.trivy("x", "note", {"security-severity": "7.0"}) == "error"
    assert severity.trivy("x", "note", {"security-severity": "5.6"}) == "warning"
    assert severity.trivy("x", "note", {"security-severity": "2.0"}) == "note"


def test_trivy_every_captured_rule_carries_security_severity():
    """Every rule in the captured fixture -- CVEs and misconfig/secret rules
    (KSV-*, AWS-*, DS-*) alike -- carries `security-severity`, so the
    fallback path below is never exercised by real trivy output as
    captured. Pinning that here means the fallback test stays honestly
    synthetic instead of silently claiming fixture coverage it doesn't
    have."""
    assert all("security-severity" in props for _, _, props in _results("trivy.sarif"))


def test_trivy_falls_back_to_level_without_security_severity():
    # No captured trivy.sarif result lacks security-severity (see above) --
    # this exercises the fallback branch directly rather than claiming
    # fixture coverage the real capture doesn't have.
    assert severity.trivy("SOME-RULE", "error", {}) == sarif_level_severity("error")
    assert severity.trivy("SOME-RULE", "warning", {}) == sarif_level_severity("warning")
    assert severity.trivy("SOME-RULE", "note", {}) == sarif_level_severity("note")


# --- osv-scanner ------------------------------------------------------------


def test_osv_scanner_is_always_warning():
    results = _results("osv-scanner.sarif")
    assert results
    assert all(level == "warning" for _, level, _ in results)
    assert all(props == {} for _, _, props in results), "no severity metadata to discriminate on"
    assert all(
        severity.osv_scanner(rid, level, props) == "warning" for rid, level, props in results
    )


# --- checkov ----------------------------------------------------------------


def test_checkov_downgrades_sarif_error_to_warning():
    results = _results("checkov.sarif")
    assert len(results) == 39
    assert all(level == "error" for _, level, _ in results), (
        "checkov's SARIF marks everything error"
    )
    assert all(severity.checkov(rid, level, props) == "warning" for rid, level, props in results)


# --- zizmor / tflint: trust the level -------------------------------------


def test_zizmor_trusts_the_level():
    results = _results("zizmor.sarif")
    levels = {level for _, level, _ in results}
    assert levels == {"error", "warning"}, "fixture should carry both real levels"
    for rid, level, props in results:
        assert severity.zizmor(rid, level, props) == sarif_level_severity(level)


def test_tflint_trusts_the_level():
    results = _results("tflint.sarif")
    assert results
    for rid, level, props in results:
        assert severity.tflint(rid, level, props) == sarif_level_severity(level)


# --- SDK wiring: ctx.sarif.parse actually calls the callback per result -----


def test_sarif_wiring_calls_the_policy_per_result():
    ctx = Context(capability="rw-checks", operation="ruff", workdir=REPO_FIXTURES / "repo")
    text = (REPO_FIXTURES / "ruff.sarif").read_text()

    findings = ctx.sarif.parse(text, root=REPO_FIXTURES / "repo", severity=severity.ruff)

    by_rule = {f.rule: f.severity for f in findings}
    # F401 (pyflakes) -> error; E501 (pycodestyle) -> warning -- the OPPOSITE
    # of what this fixture's own SARIF levels would give under the default,
    # no-callback mapping (F401 "warning", E501 "error"; see
    # test_sarif.py's test_parse_ruff_relative_uris and the test below).
    assert by_rule["F401"] == "error"
    assert by_rule["E501"] == "warning"


def test_sarif_wiring_defaults_to_level_when_no_severity_given():
    """The `severity=` kwarg is optional; omitting it must behave exactly
    as before this change (a regression here silently changes every
    existing task that hasn't been wired to a policy yet). This fixture's
    own SARIF levels (F401 "warning", E501 "error") are the OPPOSITE of
    what severity.ruff's rule-prefix policy assigns them above -- proof the
    default path really does ignore rule_id and just map `level`."""
    ctx = Context(capability="rw-checks", operation="ruff", workdir=REPO_FIXTURES / "repo")
    text = (REPO_FIXTURES / "ruff.sarif").read_text()

    findings = ctx.sarif.parse(text, root=REPO_FIXTURES / "repo")

    by_rule = {f.rule: f.severity for f in findings}
    assert by_rule["F401"] == "warning"
    assert by_rule["E501"] == "error"
