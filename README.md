# rw-checks-codecollection

RunWhen CodeCollection of static-check capabilities (ruff, gitleaks, ...) on the capability/operation contract.

## What this is

This repository packages static analysis tools into a single image, plus a **capability
manifest** (`.runwhen/capabilities/rw-checks.yaml`) that describes it in terms the platform
already understands. A **capability** is the packaged unit — one manifest, one digest-pinned
image (`rw-checks` is a capability); an **operation** is one invocable entry point inside it
(`ruff`, `gitleaks` are operations). Unlike the other codecollections in this org, this
repository ships no Robot codebundles — it exists purely to run static checks against a
repository's worktree and emit SARIF.

See `docs/static-checks/CONTRACT.md` in `runwhen-auto` for the manifest shape, the SARIF
frame format, and how findings flow from here into the platform. That file is the binding
source of truth; this README is just an entry point.

## Running an operation locally

Each operation's `run:` command in the manifest is just an argv — you can invoke it directly
against a checkout with `docker run`, no platform involved:

```
docker run --rm -v "$PWD:/w" -w /w <image> ruff check --output-format=sarif .
docker run --rm -v "$PWD:/w" -w /w <image> gitleaks detect --source . --report-format sarif --report-path /dev/stdout --no-banner --exit-code 0
```

Replace `<image>` with the tag CI published (see `.runwhen/capabilities/rw-checks.yaml` for
the pinned digest) or with a local build:

```
docker build --build-arg BASE_IMAGE=ghcr.io/runwhen-contrib/rw-base-runtime:latest -t rw-checks:dev .
docker run --rm -v "$PWD:/w" -w /w rw-checks:dev ruff check --output-format=sarif .
```

In production this collection is not driven directly: `rwcheck` (in `runwhen-runner`) is the
harness that runs each operation, fingerprints findings, filters them against the PR's changed
files, and emits the NDJSON frames the platform consumes.
