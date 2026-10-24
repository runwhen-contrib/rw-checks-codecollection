#!/usr/bin/env sh
# Run every artifact-tools task once inside a built image, as the image's own
# non-root user, and check the answers.
#
# Usage: scripts/smoke_artifact_tools.sh <image>
#
# The image's `rwtask run` takes the request and a scope directory, both on a
# bind mount. The scope directory holds the input artifact where a relay-less
# run reads it (.rw-artifacts/inputs/source) and receives the output artifacts
# under .rw-artifacts/. It is made world-writable because the image runs as
# uid 1000, which is not necessarily the uid that owns the mount.
#
# The request runs five tasks: grep, jq, sql and slice, which must succeed, and
# a sql query that reads a file outside the artifact, which must fail. That last
# one is the point of running here and not only in the unit tests: it proves the
# query sandbox holds in the image that ships.
#
# RUN_CMD swaps the docker command for another one that takes `--request <file>
# --workdir <dir>`, so the same request and assertions can be checked without
# Docker. Example, from a checkout, with the local venv's bin on PATH for `rg`:
#
#     RUN_CMD=".venv-artifact-tools/bin/rwtask run capabilities/artifact-tools" \
#         scripts/smoke_artifact_tools.sh
set -eu

IMG="${1:-}"
if [ -z "${RUN_CMD:-}" ] && [ -z "${IMG}" ]; then
  echo "usage: $0 <image>   (or set RUN_CMD)" >&2
  exit 2
fi

dir="$(mktemp -d)"
out="$(mktemp)"
# The container may leave files in directories it created itself that the host
# user cannot delete; that is not a smoke-test failure.
trap 'rm -rf "${dir}" "${out}" 2>/dev/null || true' EXIT

mkdir -p "${dir}/.rw-artifacts/inputs"
cat > "${dir}/.rw-artifacts/inputs/source" <<'EOF'
{"level":"error","n":1}
{"level":"info","n":2}
{"level":"error","n":3}
{"level":"warn","n":4}
{"level":"error","n":5}
EOF
chmod -R a+rwX "${dir}"

cat > "${dir}/request.json" <<'EOF'
{
  "version": 1,
  "tasks": [
    {"task": "grep", "inputs": {"source": "art_smoke", "pattern": "error"}},
    {"task": "jq", "inputs": {"source": "art_smoke", "filter": ".n"}},
    {"task": "sql", "inputs": {"source": "art_smoke", "query": "select count(*) as c from t", "format": "jsonl"}},
    {"task": "slice", "inputs": {"source": "art_smoke", "fromLine": 1, "toLine": 3}},
    {"task": "sql", "inputs": {"source": "art_smoke", "query": "select * from read_csv_auto('/etc/passwd')", "format": "jsonl"}}
  ]
}
EOF
chmod a+r "${dir}/request.json"

# stdout is the result envelope; the log goes to stderr and stays in the CI log.
if [ -n "${RUN_CMD:-}" ]; then
  # RUN_CMD is a command line, so it is split on purpose.
  # shellcheck disable=SC2086
  ${RUN_CMD} --request "${dir}/request.json" --workdir "${dir}" > "${out}"
else
  docker run --rm -v "${dir}:/w" "${IMG}" \
    rwtask run capabilities/artifact-tools --request /w/request.json --workdir /w > "${out}"
fi

python3 - "${out}" "${dir}" <<'PY'
import json
import pathlib
import sys

envelope_path, scope = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
raw = envelope_path.read_text()


def fail(message):
    print(f"smoke_artifact_tools: {message}", file=sys.stderr)
    print("--- result envelope ---", file=sys.stderr)
    print(raw, file=sys.stderr)
    sys.exit(1)


try:
    tasks = json.loads(raw)["tasks"]
except (ValueError, KeyError) as exc:
    fail(f"the output is not a result envelope: {exc}")

source = (scope / ".rw-artifacts" / "inputs" / "source").read_text().splitlines(keepends=True)
errors = sum(1 for line in source if "error" in line)

if [t["task"] for t in tasks] != ["grep", "jq", "sql", "slice", "sql"]:
    fail(f"unexpected task list: {[t['task'] for t in tasks]}")
grep, jq, sql, slice_, escape = tasks

for t in (grep, jq, sql, slice_):
    if t["status"] != "ok":
        fail(f"{t['task']} should succeed, got {t['status']}: {t['error']}")

result = grep["outputs"]["result"]
if result["totalMatches"] != errors or len(result["matches"]) != errors:
    fail(f"grep: expected {errors} matches, got {result['totalMatches']}")

result = jq["outputs"]["result"]
expected = "\n".join(str(n) for n in range(1, len(source) + 1))
if result["output"] != expected:
    fail(f"jq: expected {expected!r}, got {result['output']!r}")

result = sql["outputs"]["result"]
if result["rows"] != [[len(source)]]:
    fail(f"sql: expected a count of {len(source)}, got {result['rows']}")

slice_file = scope / ".rw-artifacts" / "slice"
if not slice_file.is_file():
    fail(f"slice: no artifact file at {slice_file}")
if slice_file.read_text().splitlines(keepends=True) != source[:2]:
    fail(f"slice: expected lines 1-2 of the source, got {slice_file.read_text()!r}")

if escape["status"] != "failed":
    fail(f"the sql query reading /etc/passwd should fail, got {escape['status']}")
if "root:" in raw:
    fail("the sql query reading /etc/passwd leaked file content into the envelope")

print("smoke_artifact_tools: grep, jq, sql and slice ok; the file-reading query failed as it must")
PY
