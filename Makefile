.PHONY: install schemas test lint fmt fmt-check artifact-tools-venv test-artifact-tools

# artifact-tools runs against the standalone capability SDK, which cannot share
# a virtualenv with the vendored sdk/ that `make install` puts in place. Its
# behaviour tests (tests-artifact-tools/) therefore get a venv of their own.
ARTIFACT_TOOLS_VENV ?= .venv-artifact-tools
# The interpreter that creates that venv. It must be Python 3.12 (the image's).
PYTHON ?= python3.12

install:
	python3 -m pip install -e ".[dev]"

schemas:
	python3 scripts/export_schemas.py

test:
	python3 -m pytest -q

lint:
	ruff check .

fmt:
	ruff format .

fmt-check:
	ruff format --check .

# A Python 3.12 venv: the hash-checked lock (binary wheels only), then the SDK pin
# without its dependencies (the lock already carries them), then pytest.
# `pip check` fails if the lock has drifted from what the SDK needs. The tests
# also need rg and jq on PATH.
artifact-tools-venv:
	$(PYTHON) -m venv $(ARTIFACT_TOOLS_VENV)
	$(ARTIFACT_TOOLS_VENV)/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements-artifact-tools.txt
	$(ARTIFACT_TOOLS_VENV)/bin/python -m pip install --no-deps -r requirements-artifact-tools-sdk.txt
	$(ARTIFACT_TOOLS_VENV)/bin/python -m pip check
	$(ARTIFACT_TOOLS_VENV)/bin/python -m pip install pytest

test-artifact-tools:
	$(ARTIFACT_TOOLS_VENV)/bin/python -m pytest -q tests-artifact-tools
