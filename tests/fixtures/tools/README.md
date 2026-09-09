# Captured tool output

Real output from each tool, produced by `scripts/capture_fixtures.sh` running
inside the built `rw-checks` image against `tests/fixtures/sample-repo`.

**These are captures, not hand-written examples.** Adapters in
`capabilities/rw-checks/adapters.py` are written and tested against these, so
a test that passes here passes against what the tool actually emits. Writing
fixtures from a tool's documentation is how you get a green suite that fails
on real data.

Regenerate after any tool version bump:

    docker build --platform linux/amd64 -f Dockerfile.rw-checks -t rw-checks:pinned .
    docker run --rm --platform linux/amd64 --user root \
      -v "$PWD:/src" -w /src rw-checks:pinned sh scripts/capture_fixtures.sh

`capture.log` records every tool's exact argv and exit code -- it is the
record of which invocation actually produces parseable output.

## The capture runs against a real git checkout

`capture_fixtures.sh` copies the sample repo to a temp dir and `git init`s it.
This is not incidental:

- **semgrep scans only files tracked by git.** In a plain directory it reports
  `all files not listed by git ls-files were skipped` and finds nothing -- it
  returned 0 findings until this was fixed, then 10.
- **actionlint's project detection walks UP** to the enclosing repository, so
  from an untracked subdirectory it lints the wrong repo's workflows.
- **gitleaks `detect` reads git history.**

The runtime always hands a task a real checkout, so this is also the faithful
shape.

## Deviations from raw capture

- `semgrep.sarif` -- `runs[].tool.driver.rules` trimmed to only the rules the
  results reference (1074 -> 10). Results are untouched. The full array is
  ~2 MB of ruleset metadata that no adapter reads.

## Secrets in the sample repo are fake

`sample-repo/src/config.py` contains syntactically valid, deliberately
non-functional token shapes so gitleaks and trufflehog have something to
match. Real AWS documentation keys (`AKIAIOSFODNN7EXAMPLE`) are allowlisted
by both tools by design, which is why the first capture found nothing.
