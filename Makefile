.PHONY: install schemas test lint fmt fmt-check

install:
	python3 -m pip install -e ".[dev]"

schemas:
	rwtask schemas

test:
	python3 -m pytest -q

lint:
	ruff check .

fmt:
	ruff format .

fmt-check:
	ruff format --check .
