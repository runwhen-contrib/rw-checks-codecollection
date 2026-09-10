"""Builders for `ctx.sarif.parse`'s optional `severity` callback
(sdk/runwhen_capability/sarif.py). SARIF's `level` means a different thing
-- or nothing at all -- for every tool: ruff marks EVERY result "error"
regardless of triviality, gitleaks' results carry no `level` key at all, and
checkov marks all 39 of its captured results "error". Feeding any of those
verbatim into a Check Run conclusion (failure iff some finding is "error")
makes the conclusion meaningless: either every run fails or none does,
independent of what the finding actually is.

Each function here is a BUILDER: it takes a tool module's own SEVERITY map
and returns the callback shape `ctx.sarif.parse` actually calls --
`(rule_id: str, level: str, rule_properties: dict) -> "error"|"warning"|"note"`.
The map is the tool module's, not this module's: the module's SEVERITY is
the only definition of a tool's policy, so a module cannot declare a map
that disagrees with what actually gets applied at run time. `rule_properties`
is the matching rule's `properties` dict from `runs[].tool.driver.rules[]`,
or `{}` when the rule carries none.

Each builder's logic is derived from the REAL fixtures in
tests/fixtures/tools/, the same discipline adapters.py follows for its
non-SARIF tools -- do not add a tool here, or change one, without checking
what its SARIF actually contains.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from runwhen_capability.sarif import severity as sarif_level_severity

Policy = Callable[[str, str, dict], str]


# --- from_level -----------------------------------------------------------
# zizmor, tflint: security tools whose SARIF levels are actually meaningful
# (tests/fixtures/tools/zizmor.sarif carries both "warning" and "error"
# across its 4 rules; tflint's SARIF is the same shape). Trust the level the
# tool itself reports, looked up in its own map, `note` for anything the map
# doesn't name -- same default the SDK's own level mapping uses.
def from_level(severity_map: Mapping[str, str]) -> Policy:
    def policy(rule_id: str, level: str, props: dict) -> str:
        return severity_map.get((level or "").lower(), "note")

    return policy


# --- by_rule_prefix ---------------------------------------------------------
# ruff: tests/fixtures/tools/ruff.sarif marks every result-bearing rule
# "error" -- ruff does not use `level` to distinguish severity at all. The
# rule CODE PREFIX is pyflakes/ruff's own vocabulary instead: F (pyflakes)
# and S (bandit security) are real defects; E/W (pycodestyle)/B (bugbear)
# are style; everything else (I isort, D docstrings, N, UP, C, PL, ...) is a
# nit, the map's own default of `note`.
def by_rule_prefix(severity_map: Mapping[str, str]) -> Policy:
    def policy(rule_id: str, level: str, props: dict) -> str:
        prefix = (rule_id or "")[:1].upper()
        return severity_map.get(prefix, "note")

    return policy


# --- by_cvss ----------------------------------------------------------------
# trivy: tests/fixtures/tools/trivy.sarif's CVE rules carry a
# `security-severity` property (a numeric string, GitHub code-scanning's own
# convention -- e.g. "7.5"), preferred over SARIF `level`: it is what trivy
# itself already derived from CVSS for exactly this purpose. Bands follow
# GitHub's own security-severity convention (critical >= 9.0, high >= 7.0,
# medium >= 4.0, else low), looked up in the tool's own map. Every rule in
# the captured fixture -- CVEs and misconfig/secret rules (KSV-*, AWS-*,
# DS-*) alike -- happens to carry `security-severity`, so the plain-`level`
# fallback is not exercised by that capture; it stays in as a defensive
# default for whatever trivy output does omit it (its docs don't guarantee
# every rule always sets this property).
def by_cvss(severity_map: Mapping[str, str]) -> Policy:
    def policy(rule_id: str, level: str, props: dict) -> str:
        raw = props.get("security-severity")
        if raw is not None:
            try:
                score = float(raw)
            except (TypeError, ValueError):
                score = None
            if score is not None:
                if score >= 9.0:
                    band = "critical"
                elif score >= 7.0:
                    band = "high"
                elif score >= 4.0:
                    band = "medium"
                else:
                    band = "low"
                return severity_map.get(band, sarif_level_severity(level))
        return sarif_level_severity(level)

    return policy


# --- constant ---------------------------------------------------------------
# gitleaks, osv-scanner, checkov: each has exactly one severity, regardless
# of rule_id/level/rule_properties -- gitleaks because every result is a
# detected credential and there is no lower-severity class to distinguish
# from (its SARIF carries no `level` key at all); osv-scanner because its
# SARIF gives nothing to discriminate a critical CVE from a low one (every
# rule "warning", no severity metadata in `properties`); checkov because its
# OSS output carries no severity to discriminate on either (every result
# SARIF level "error", which passed through verbatim would fail every IaC
# repo checkov ever runs against). Each module's SEVERITY is the honest
# single-value map documenting that (empty) vocabulary, e.g. `{"": "error"}`.
def constant(severity_map: Mapping[str, str]) -> Policy:
    value = next(iter(severity_map.values()))

    def policy(rule_id: str, level: str, props: dict) -> str:
        return value

    return policy
