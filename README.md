# rw-checks-codecollection

RunWhen CodeCollection of static-check capabilities (ruff, gitleaks, ...) -- a **capability
image**, built on the `runwhen_capability` SDK and its `rwtask` task host, not a Robot
codebundle collection.

## What this is

This repository ships:

- **`sdk/runwhen_capability/`** -- a small, Robot-free Python SDK. Tasks are plain Python
  functions; the SDK owns every boundary (inputs, outputs, credentials, subprocesses, SARIF
  parsing). It also provides `rwtask`, the task host: `rwtask serve` long-polls
  a runner over plain HTTP/JSON, and `rwtask run` is the same code path against the local
  filesystem, for development.
- **`capabilities/rw-checks/`** -- the `rw-checks` capability: a manifest
  (`manifest.yaml`), its tasks (`tasks.py`: `checkout` setup plus 19 check tasks -- `ruff`,
  `gitleaks`, `osv_scanner`, `checkov`, `zizmor`, `tflint`, `shellcheck`, `hadolint`,
  `yamllint`, `actionlint`, `pylint`, `sqlfluff`, `biome`, `ast_grep`, `regal`, `vale`,
  `flake8`, `dotenv_linter`, `buf`), and the JSON Schema exported from the SDK's models
  (`schemas/findings.json`).

See `docs/static-checks/CAPABILITY-CONTRACT.md` and `docs/static-checks/EXECUTOR-CONTRACT.md`
in `runwhen-auto` for the binding contracts this package implements -- the manifest shape, the
finding shape, and the wire between papi, the runner and this image. This README is just an
entry point.

## How a check runs

Every check runs only against the PR's changed files -- never the whole tree
(`docs/static-checks/DIFF-SCOPED-CHECKS.md` in `runwhen-auto`). Each check module exposes two
functions, driven by the generic runner (`tools/_runner.run_check`):

- `applicable(ctx, tree, changed)` -- never executes the tool. Narrows `changed` to the files
  this check is eligible for (file-pattern match, CI-duplicate skip, nearest applicable config,
  a per-config-group safety guard) and groups them into one or more invocations (files, config,
  cwd).
- `check(ctx, tree, inv)` -- runs the tool on exactly `inv.files`, using `inv.config` from
  `inv.cwd`, and returns findings with repo-relative paths.

Each invocation runs in one of four lanes:

- **A -- root run.** One invocation for the whole check; the tool resolves each file's config
  itself, or the config is fixed-location.
- **B -- one run per config.** One invocation per resolved config, run from that config's
  directory, so relative paths inside the config keep working.
- **C -- scratch view.** The eligible files (and config) are hard-linked into
  `ctx.workdir/view-<check>/` and the tool runs against that view alone -- used by gitleaks,
  which only accepts a directory target.
- **D -- module run.** tflint and buf run against their module/workspace root (`--chdir`,
  `--path`) so the tool keeps correctness context, but only changed-file findings are kept.

Checks are either **config-gated** (a file only runs once a recognised config applies to it --
ruff, pylint, flake8, biome, yamllint, sqlfluff, ast-grep, regal, vale, buf, tflint) or
**always-on** (gitleaks, osv-scanner, zizmor, actionlint, checkov, hadolint, shellcheck,
dotenv-linter: they use a config if present but never require one). A check that has nothing
to run explains why in `FindingsResult.skipped` -- no diff available, no matching changed
files, no config applies, an unsafe config, or (osv-scanner only) `api.osv.dev` being
unreachable.

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

Image == capability, 1:1 (`sdk/runwhen_capability/loader.py`'s `discover_capability_dir`
docstring): `rw-checks` and `rw-worktree` are different execution modes (stateless vs.
stateful) and must be separate executor pools, so each gets its own Dockerfile, built from
the same SDK layer.

```
docker build -f Dockerfile.rw-checks -t rw-checks:dev .
docker run --rm rw-checks:dev rwtask --help
docker run --rm rw-checks:dev ruff --version
docker run --rm rw-checks:dev gitleaks version

docker build -f Dockerfile.rw-worktree -t rw-worktree:dev .
docker run --rm rw-worktree:dev rwtask --help
docker run --rm rw-worktree:dev git --version
```

In production neither image is driven directly: `rwtask serve --relay <url> --pool <poolId>`
long-polls the runner as a warm executor (see `EXECUTOR-CONTRACT.md`'s "Wire 2"), executing one
request (`setup` + N tasks) at a time and posting the result back. Each image's `CMD` already
bakes in its own `--capability-dir` so it never has to guess which capability it is serving.

## Tests

```
make test        # python -m pytest -q
make lint         # ruff check .
make fmt-check    # ruff format --check .
make schemas      # regenerate capabilities/*/schemas/findings.json from the SDK's models
```
