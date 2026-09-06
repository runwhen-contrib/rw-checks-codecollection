# Base runtime image — rw-base-runtime ships:
#   - Python 3 + the worker binary + the standard CLI tooling
#     (kubectl, aws, az, gcloud, helm, istioctl, gh, pwsh, jq, yq, skopeo,
#      linear-cli, claude, cursor)
#   - rw-core-keywords pip-installed system-wide (RW.Core / RW.platform /
#     RW.fetchsecrets / etc.)
#   - The robot-runtime helper scripts at /home/runwhen/robot-runtime/
#     (entrypoint.sh, runrobot.{sh,py}, RWP.py, metrics_daemon.py, ...)
#
# Source: https://github.com/runwhen-contrib/rw-base-runtime
#
# Override at build time to pin a specific runtime sha (production tag
# suffix) or to test against a BYO base, e.g.:
#
#   docker build \
#     --build-arg BASE_IMAGE=ghcr.io/runwhen-contrib/rw-base-runtime:<sha7> \
#     ...
#
# The CI workflow (.github/workflows/build-push.yaml) resolves the
# `runtime_ref` dispatch input to an rw-base-runtime commit sha and
# bakes that sha into the resulting image tag suffix.
ARG BASE_IMAGE=ghcr.io/runwhen-contrib/rw-base-runtime:latest
FROM ${BASE_IMAGE}
USER root

# Populated by buildx for the platform currently being built (amd64/arm64).
# Used below to pick the right gitleaks release tarball.
ARG TARGETARCH

# Pin every static-check tool's version here so a Dockerfile diff is the
# only thing that changes it.
ARG RUFF_VERSION=0.16.6
ARG GITLEAKS_VERSION=8.30.1

ENV RUNWHEN_HOME=/home/runwhen
ENV PATH "$PATH:/usr/local/bin:/home/runwhen/.local/bin"

# Install ruff — pinned, from PyPI.
RUN pip install --no-cache-dir "ruff==${RUFF_VERSION}"

# Install gitleaks — pinned, from the official release tarball for
# TARGETARCH, sha256-verified against the checksums gitleaks publishes
# alongside each release (no `go install`, no unverified curl-pipe).
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) GITLEAKS_ARCH=x64;   GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;; \
      arm64) GITLEAKS_ARCH=arm64; GITLEAKS_SHA256=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz"; \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    chmod +x /usr/local/bin/gitleaks; \
    rm -f /tmp/gitleaks.tar.gz

# Set up directories and permissions.
#
# Codecollection contents MUST land at ${RUNWHEN_HOME}/collection (NOT
# /codecollection). PAPI emits RW_PATH_TO_ROBOT=$(RUNWHEN_HOME)/collection/
# codebundles/<bundle>/sli.robot and runrobot.{sh,py} only know how to
# resolve under /home/runwhen/collection — a mismatch surfaces as
# `FileNotFoundError: Could not find the robot file in any known locations.`
RUN mkdir -p $RUNWHEN_HOME/collection
WORKDIR $RUNWHEN_HOME/collection

# Copy files into container with correct ownership
COPY --chown=runwhen:0 . .

# Check and install requirements if requirements.txt exists
RUN if [ -f "requirements.txt" ]; then pip install --no-cache-dir -r requirements.txt; else echo "requirements.txt not found, skipping pip install"; fi

# Add runwhen user to sudoers with no password prompt
RUN echo "runwhen ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Set RunWhen Temp Dir
RUN mkdir -p /var/tmp/runwhen && chmod 1777 /var/tmp/runwhen
ENV TMPDIR=/var/tmp/runwhen

# Adjust permissions for runwhen user
RUN chown runwhen:0 -R $RUNWHEN_HOME/collection

# rw-base-runtime's ENTRYPOINT (entrypoint.sh) unconditionally launches the
# robot runtime / worker regardless of CMD — correct for Robot codebundle
# images, but this collection has no Robot content. Its operations are
# plain argv commands (see the CONTRACT's `run:` field, e.g.
# ["ruff", "check", ...]) meant to be executed directly via
# `docker run <image> <argv...>`, so reset the entrypoint to none.
ENTRYPOINT []

# Switch to runwhen user
USER runwhen
