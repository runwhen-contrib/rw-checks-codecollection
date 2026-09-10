.PHONY: install schemas test lint fmt fmt-check

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
