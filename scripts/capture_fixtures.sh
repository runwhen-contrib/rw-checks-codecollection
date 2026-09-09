#!/usr/bin/env sh
# Capture each tool's REAL output against tests/fixtures/sample-repo, so the
# adapters in capabilities/rw-checks/adapters.py are written against what the
# tools actually emit rather than against their documentation.
#
# Run INSIDE the built image, with the repo mounted:
#   docker run --rm --platform linux/amd64 \
#     -v "$PWD:/src" -w /src rw-checks:pinned \
#     sh scripts/capture_fixtures.sh
#
# Writes tests/fixtures/tools/<name>.<ext> plus a capture.log recording each
# tool's argv and exit code. A tool that fails is recorded, not skipped --
# the log IS the finding: it tells us which argv are wrong before any adapter
# is written against them.
set -u

SRC="${SRC:-tests/fixtures/sample-repo}"

# Run against a real git checkout, not the source tree. This is not cosmetic:
#   - semgrep scans only files tracked by git ("all files not listed by
#     `git ls-files` were skipped") and finds NOTHING in a plain directory;
#   - actionlint's project detection walks UP to the enclosing repo, so from
#     an untracked subdirectory it lints the WRONG repo's workflows;
#   - gitleaks `detect` reads git history.
# The runtime always hands tasks a real checkout, so capturing against one is
# both the faithful and the working choice.
REPO="$(mktemp -d)/repo"
mkdir -p "$REPO"
cp -a "$SRC/." "$REPO/"
( cd "$REPO" \
  && git init -q . \
  && git add -A \
  && git -c user.email=fixtures@runwhen.local -c user.name=fixtures \
        commit -qm "fixture corpus" ) >/dev/null 2>&1
OUT="${OUT:-tests/fixtures/tools}"
mkdir -p "$OUT"
LOG="$OUT/capture.log"
: > "$LOG"

cap() {
  name="$1"; ext="$2"; shift 2
  printf '%-16s ' "$name"
  out="$OUT/$name.$ext"
  # cd into the repo so every tool sees repo-relative paths -- the paths in
  # the captured output are part of what the adapter is tested against.
  ( cd "$REPO" && "$@" ) > "$out" 2> "$OUT/$name.stderr" ; rc=$?
  size=$(wc -c < "$out" | tr -d ' ')
  echo "=== $name (exit $rc, ${size}B) :: $*" >> "$LOG"
  if [ "$size" -gt 2 ]; then
    echo "ok    exit=$rc ${size}B"
    rm -f "$OUT/$name.stderr"
  else
    echo "EMPTY exit=$rc -- $(head -c 160 "$OUT/$name.stderr" 2>/dev/null | tr '\n' ' ')"
    head -20 "$OUT/$name.stderr" >> "$LOG" 2>/dev/null
  fi
}

echo "--- SARIF-native ---"
cap ruff        sarif ruff check --output-format=sarif .
cap gitleaks    sarif sh -c 'gitleaks dir . --report-format sarif --report-path /tmp/gl.sarif --no-banner --exit-code 0 >/dev/null 2>&1; cat /tmp/gl.sarif'
cap trivy       sarif trivy fs --format sarif --quiet --scanners vuln,misconfig,secret .
cap osv-scanner sarif osv-scanner --format sarif -r .
cap checkov     sarif sh -c 'd=$(mktemp -d); checkov -d . --output sarif --output-file-path "$d" >/dev/null 2>&1; cat "$d/results_sarif.sarif"'
cap zizmor      sarif zizmor --format sarif --no-progress .github/workflows
cap tflint      sarif tflint --format sarif --chdir infra
cap semgrep     sarif semgrep scan --sarif --quiet --config=p/default --metrics=off .

echo "--- JSON ---"
cap shellcheck  json shellcheck -f json1 scripts/deploy.sh
cap hadolint    json hadolint -f json Dockerfile
cap actionlint  json actionlint -format '{{json .}}' -no-color .github/workflows/ci.yml
cap pylint      json pylint --output-format=json --exit-zero src
cap sqlfluff    json sqlfluff lint --format json db
cap trufflehog  jsonl trufflehog filesystem . --json --no-update --no-verification
cap biome       json biome lint --reporter=json src
cap ast-grep    json ast-grep scan --json
cap regal       json regal lint --format json policy
cap buf         json buf lint --error-format=json
cap vale        json vale --output=JSON docs

echo "--- text ---"
cap yamllint    txt yamllint -f parsable .
cap flake8      txt flake8 '--format=%(path)s:%(row)d:%(col)d:%(code)s:%(text)s' src
cap checkmake   txt checkmake Makefile
cap dotenv      txt dotenv-linter .env

echo
echo "--- summary ---"
grep -c '^===' "$LOG" | sed 's/^/tools attempted: /'
