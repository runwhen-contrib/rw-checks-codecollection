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
# uid 1000, which is not necessarily the uid that owns the mount. For the same
# reason the output files are not read back from the host: the SDK writes them
# owner-only, as uid 1000, and the host user is a different uid. The slice is
# checked through the artifact ref in the envelope, which is derived from the
# file's content, and only its existence is checked on disk.
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
err="$(mktemp)"
# The container may leave files in directories it created itself that the host
# user cannot delete; that is not a smoke-test failure.
trap 'rm -rf "${dir}" "${out}" "${err}" 2>/dev/null || true' EXIT

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

# stdout is the result envelope; the log goes to stderr, which is kept and
# printed below so that it reaches the CI log either way.
status=0
if [ -n "${RUN_CMD:-}" ]; then
  # RUN_CMD is a command line, so it is split on purpose.
  # shellcheck disable=SC2086
  ${RUN_CMD} --request "${dir}/request.json" --workdir "${dir}" > "${out}" 2> "${err}" || status=$?
else
  docker run --rm -v "${dir}:/w" "${IMG}" \
    rwtask run capabilities/artifact-tools --request /w/request.json --workdir /w \
    > "${out}" 2> "${err}" || status=$?
fi
cat "${err}" >&2
if [ "${status}" -ne 0 ]; then
  echo "smoke_artifact_tools: the run command exited with status ${status}" >&2
  echo "--- result envelope (stdout) ---" >&2
  cat "${out}" >&2
  exit 1
fi

python3 - "${out}" "${dir}" <<'PY'
import hashlib
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


def check():
    try:
        tasks = json.loads(raw)["tasks"]
    except (ValueError, KeyError, TypeError) as exc:
        fail(f"the output is not a result envelope: {exc}")

    source = (scope / ".rw-artifacts" / "inputs" / "source").read_bytes().splitlines(keepends=True)
    errors = sum(1 for line in source if b"error" in line)

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

    # Only the file's existence is checked here, not its bytes: it belongs to
    # the container's uid and is owner-only (see the header). Its content is
    # checked through the ref, which a local run derives from the sha256 of
    # exactly the bytes it wrote: "local_" and the first 32 hex digits.
    slice_file = scope / ".rw-artifacts" / "slice"
    if not slice_file.is_file():
        fail(f"slice: no artifact file at {slice_file}")
    want = "local_" + hashlib.sha256(b"".join(source[:2])).hexdigest()[:32]
    got = slice_["outputs"]["slice"]["$artifact"]
    if got != want:
        fail(f"slice: expected the artifact {want} (lines 1-2 of the source), got {got}")

    if escape["status"] != "failed":
        fail(f"the sql query reading /etc/passwd should fail, got {escape['status']}")
    # An unrelated failure must not pass as "the sandbox held": the error has to
    # be DuckDB refusing the file access.
    error = escape["error"] or ""
    if "Permission Error" not in error or "disabled by configuration" not in error:
        fail(f"the sql query reading /etc/passwd failed for another reason: {error!r}")
    if "root:" in raw:
        fail("the sql query reading /etc/passwd leaked file content into the envelope")

    print("smoke_artifact_tools: grep, jq, sql and slice ok; the file-reading query was refused")


try:
    check()
except Exception as exc:  # noqa: BLE001 -- whatever goes wrong, the envelope must be printed
    fail(f"{type(exc).__name__}: {exc}")
PY
