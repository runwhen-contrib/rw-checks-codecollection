# rw-checks-codecollection

RunWhen CodeCollection of static-check capabilities (ruff, gitleaks, ...) -- a **capability
image**, built on the `runwhen_capability` SDK and its `rwtask` task host, not a Robot
codebundle collection.

## What this is

This repository's capabilities are built on
[runwhen-capability](https://github.com/runwhen-contrib/runwhen-capability) -- a small,
Robot-free Python SDK (`runwhen_capability`) and its `rwtask` task host, pinned to a release in
`pyproject.toml`. Tasks are plain Python functions; the SDK owns every boundary (inputs, outputs,
credentials, subprocesses, SARIF parsing). `rwtask serve` long-polls a runner over plain
HTTP/JSON, and `rwtask run` is the same code path against the local filesystem, for development.

This repository ships:

- **`capabilities/rw-checks/`** -- the `rw-checks` capability: a manifest
  (`manifest.yaml`), its tasks (`tasks.py`: `checkout` setup plus 19 check tasks -- `ruff`,
  `gitleaks`, `osv_scanner`, `checkov`, `zizmor`, `tflint`, `shellcheck`, `hadolint`,
  `yamllint`, `actionlint`, `pylint`, `sqlfluff`, `biome`, `ast_grep`, `regal`, `vale`,
  `flake8`, `dotenv_linter`, `buf`), and the JSON Schema exported from the SDK's models
  (`schemas/findings.v1.json`).

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

Image == capability, 1:1 (`runwhen_capability/loader.py`'s `discover_capability_dir`
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

## Manifest label

Neither `manifest.yaml` declares an `image:` key -- an image cannot know its own digest. Instead
each image carries its own manifest as an OCI label, `com.runwhen.capability.manifest.v1`: the
base64 (no line breaks) of that capability's `manifest.yaml`, verbatim. CI computes it at build
time with `rwtask label capabilities/<name>` and bakes it in via the `CAPABILITY_MANIFEST_B64` build
arg, so the codecollection catalog can discover a capability's manifest straight off the pushed
image, without a platform release.

To inspect the label on a published image (no pull needed; both images are multi-arch, and the
label is identical on every platform):

```
# crane -- resolves the index to the current platform's image config
crane config --platform linux/amd64 <ref> | jq -r '.config.Labels["com.runwhen.capability.manifest.v1"]' | base64 -d

# docker buildx -- .Image is keyed by platform for a multi-arch index
docker buildx imagetools inspect <ref> --format '{{ json (index .Image "linux/amd64") }}' \
  | jq -r '.config.Labels["com.runwhen.capability.manifest.v1"]' | base64 -d
```

## Schemas label

Each image also carries a second OCI label, `com.runwhen.capability.schemas.v1`: base64 of a
compact, sorted-key JSON object holding **every** file under that capability's `schemas/`
directory -- not only the ones the current manifest references -- keyed `schemas/<filename>`. CI
computes it with `rwtask label --schemas capabilities/<name>` and bakes it in via the
`CAPABILITY_SCHEMAS_B64` build arg, right next to the manifest label above. Publishing the whole
directory, rather than only the referenced files, means an image always carries every schema
version it has ever shipped, so the catalog (cc-catalog-svc) can keep resolving an old run's
schema forever, even after the manifest moves its `schema:` ref on to a newer file.

Schema filenames are `<name>.v<N>.json` (`N` >= 1, e.g. `findings.v1.json`), and **a published one
never changes or is deleted**. Every schema file is generated from an SDK model by `rwtask
schemas`, which reads the list under `[tool.rwtask.schemas]` in `pyproject.toml`; CI runs
`rwtask schemas --check`. A shape change is a new file at the next version -- replace the model's
entry there with `<name>.v<N+1>.json`, run `make schemas`, and the manifest's `schema:` ref moves
to the new file; the old file stays exactly as it was, forever.
`scripts/check_schema_immutability.py --base <ref>` enforces this in CI (on every pull request and
push): it fails if any `<name>.v<N>.json` that existed at `<ref>` changed or disappeared --
compared as canonical JSON, so a whitespace-only reformat is fine -- or if any file under a
capability's `schemas/` doesn't match that versioned naming pattern.

A schema shape change is not automatically a consumer-facing break, and nothing enforces this
mechanically: bump the output `kind` a task declares (e.g. `rw.findings.v1` -> `rw.findings.v2`)
only when a platform consumer must handle the new shape differently.

To inspect this label on a published image, the same two commands as above work, with
`com.runwhen.capability.schemas.v1` in place of `com.runwhen.capability.manifest.v1`.

## Tests

```
make test        # python -m pytest -q
make lint         # ruff check .
make fmt-check    # ruff format --check .
make schemas      # rwtask schemas: regenerate capabilities/*/schemas/*.v<N>.json from the SDK's models
```

```
python3 scripts/check_schema_immutability.py --base origin/main   # or any other git ref
```
