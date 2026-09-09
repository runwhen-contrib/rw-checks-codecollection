# rw-checks-codecollection

RunWhen CodeCollection of static-check capabilities (ruff, gitleaks, ...) -- a **capability
image**, built on the `runwhen_capability` SDK and its `rwtask` task host, not a Robot
codebundle collection.

## What this is

This repository ships:

- **`sdk/runwhen_capability/`** -- a small, Robot-free Python SDK. Tasks are plain Python
  functions; the SDK owns every boundary (inputs, outputs, credentials, subprocesses, SARIF
  parsing, fingerprinting). It also provides `rwtask`, the task host: `rwtask serve` long-polls
  a runner over plain HTTP/JSON, and `rwtask run` is the same code path against the local
  filesystem, for development.
- **`capabilities/rw-checks/`** -- the `rw-checks` capability: a manifest
  (`manifest.yaml`), its tasks (`tasks.py`: `checkout` setup, `ruff` and `gitleaks` tasks),
  and the JSON Schema exported from the SDK's models (`schemas/findings.json`).

See `docs/static-checks/CAPABILITY-CONTRACT.md` and `docs/static-checks/EXECUTOR-CONTRACT.md`
in `runwhen-auto` for the binding contracts this package implements -- the manifest shape, the
finding shape, the fingerprint formula, and the wire between papi, the runner and this image.
This README is just an entry point.

## Developing a task locally

A capability author needs no cluster. `rwtask run` is the reference implementation: the same
code the task host runs in production, against the local filesystem.

```
pip install -e ".[dev]"

cat > /tmp/request.json <<'JSON'
{
  "version": 1,
  "setup": {
    "task": "checkout",
    "inputs": { "repoUrl": "https://github.com/octocat/Hello-World.git", "sha": "master" }
  },
  "tasks": [
    { "task": "ruff", "inputs": { "tree": "${setup.tree}", "changed": "${setup.changed}" } },
    { "task": "gitleaks", "inputs": { "tree": "${setup.tree}" } }
  ]
}
JSON

rwtask run capabilities/rw-checks --request /tmp/request.json
```

Prints the `ResultEnvelope` (setup + per-task status/outputs/error) as JSON. A private repo
needs a `credentials.json` (`{"repo": "<token>"}`) passed via `--credentials`; a public repo
needs none -- `ctx.git.checkout()` degrades to an anonymous fetch when no credential is bound.

## Running the image directly

```
docker build -t rw-checks:dev .
docker run --rm rw-checks:dev rwtask --help
docker run --rm rw-checks:dev ruff --version
docker run --rm rw-checks:dev gitleaks version
```

In production the image is not driven directly: `rwtask serve --relay <url> --pool <poolId>`
long-polls the runner as a warm executor (see `EXECUTOR-CONTRACT.md`'s "Wire 2"), executing one
request (`setup` + N tasks) at a time and posting the result back.

## Tests

```
make test        # python -m pytest -q
make lint         # ruff check .
make fmt-check    # ruff format --check .
make schemas      # regenerate capabilities/*/schemas/findings.json from the SDK's models
```
