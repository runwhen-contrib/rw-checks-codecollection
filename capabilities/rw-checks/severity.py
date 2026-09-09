"""Per-tool severity policy for `ctx.sarif.parse`'s optional `severity`
callback (sdk/runwhen_capability/sarif.py). SARIF's `level` means a
different thing -- or nothing at all -- for every tool: ruff marks EVERY
result "error" regardless of triviality, gitleaks' results carry no `level`
key at all, and checkov marks all 39 of its captured results "error".
Feeding any of those verbatim into a Check Run conclusion (failure iff some
finding is "error") makes the conclusion meaningless: either every run fails
or none does, independent of what the finding actually is.

Every function below matches the callback shape `ctx.sarif.parse` calls:
`(rule_id: str, level: str, rule_properties: dict) -> "error"|"warning"|"note"`.
`rule_properties` is the matching rule's `properties` dict from
`runs[].tool.driver.rules[]`, or `{}` when the rule carries none.

Each policy is derived from the REAL fixtures in tests/fixtures/tools/, the
same discipline adapters.py follows for its non-SARIF tools -- do not add a
tool here, or change one, without checking what its SARIF actually contains.
"""

from __future__ import annotations

from runwhen_capability.sarif import severity as sarif_level_severity


# --- ruff ---------------------------------------------------------------
# tests/fixtures/tools/ruff.sarif: all 3 result-bearing rules (F401, F841,
# I001) carry SARIF level "error" -- ruff does not use `level` to
# distinguish severity at all. The rule CODE PREFIX is pyflakes/ruff's own
# vocabulary instead: F (pyflakes: undefined name, unused import) and S
# (bandit security, when the ruff-bandit ruleset is enabled) are real
# defects; E/W (pycodestyle) and B (bugbear) are style; everything else
# (I isort, D docstrings, N, UP, C, PL, ...) is a nit. Mapping on `level`
# here would fail a Check Run on an import-ordering violation exactly as
# hard as an undefined name.
def ruff(rule_id: str, level: str, props: dict) -> str:
    prefix = (rule_id or "")[:1].upper()
    if prefix in ("F", "S"):
        return "error"
    if prefix in ("E", "W", "B"):
        return "warning"
    return "note"


# --- gitleaks -----------------------------------------------------------
# tests/fixtures/tools/gitleaks.sarif: no result carries a `level` key at
# all -- gitleaks never sets one. Every gitleaks result is a detected
# credential; there is no lower-severity class of gitleaks finding to
# distinguish from, so every result is an error.
def gitleaks(rule_id: str, level: str, props: dict) -> str:
    return "error"


# --- trivy ----------------------------------------------------------------
# tests/fixtures/tools/trivy.sarif: CVE rules carry a `security-severity`
# property (a numeric string, GitHub code-scanning's own convention -- e.g.
# "7.5") and `cvssv3_baseScore`. `security-severity` is preferred: it is
# what trivy itself already derived from CVSS for exactly this purpose.
# Bands follow GitHub's own security-severity convention (critical >= 9.0,
# high >= 7.0, medium >= 4.0, else low); critical/high collapse to our
# `error`, medium to `warning`, low to `note`. Every rule in the captured
# fixture -- CVEs and misconfig/secret rules (KSV-*, AWS-*, DS-*) alike --
# happens to carry `security-severity`, so the plain-`level` fallback below
# is not exercised by that capture; it stays in as a defensive default for
# whatever trivy output does omit it (its docs don't guarantee every rule
# always sets this property).
def trivy(rule_id: str, level: str, props: dict) -> str:
    raw = props.get("security-severity")
    if raw is not None:
        try:
            score = float(raw)
        except (TypeError, ValueError):
            score = None
        if score is not None:
            if score >= 7.0:
                return "error"
            if score >= 4.0:
                return "warning"
            return "note"
    return sarif_level_severity(level)


# --- osv-scanner ------------------------------------------------------------
# tests/fixtures/tools/osv-scanner.sarif: all 17 rules carry SARIF level
# "warning" and no severity metadata in `properties` at all -- unlike
# trivy, osv-scanner's SARIF output gives us nothing to discriminate a
# critical CVE from a low one. Every result is a dependency vulnerability,
# so `warning` (not `note`) is the honest default; getting per-CVE severity
# would mean parsing osv-scanner's JSON output (which does carry a
# `database_specific.severity`/CVSS vector) instead of its SARIF -- a
# bigger change than this policy function, left for a future task.
def osv_scanner(rule_id: str, level: str, props: dict) -> str:
    return "warning"


# --- checkov ----------------------------------------------------------------
# tests/fixtures/tools/checkov.sarif: all 39 results are marked SARIF level
# "error" -- passing that through would fail every IaC repo checkov ever
# runs against. checkov's OSS output carries no severity to discriminate on
# (no `security-severity` property, nothing in `properties` at all), so
# `warning` is the least-wrong uniform mapping: visible on every PR without
# making an IaC misconfiguration finding auto-fail the build.
def checkov(rule_id: str, level: str, props: dict) -> str:
    return "warning"


# --- zizmor -------------------------------------------------------------
# tests/fixtures/tools/zizmor.sarif: a security tool whose SARIF levels are
# actually meaningful -- both "warning" and "error" are present across its
# 4 rules. Trust them: error stays error, warning stays warning, anything
# else (there is no "note"/"none" in the fixture, but SARIF permits it)
# falls back to `note`, same as the SDK's own default mapping.
def zizmor(rule_id: str, level: str, props: dict) -> str:
    return sarif_level_severity(level)


# --- tflint -------------------------------------------------------------
# tests/fixtures/tools/tflint.sarif: same reasoning as zizmor -- trust the
# level tflint reports rather than inventing a rule-id-based policy it
# gives no evidence for.
def tflint(rule_id: str, level: str, props: dict) -> str:
    return sarif_level_severity(level)
