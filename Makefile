.DEFAULT_GOAL := all
.PHONY: install lint format typecheck test test-integration test-quick clean all prek-install prek

install:
	uv sync

lint:
	uv run ruff check src/ tests/
	uv run ruff format --check src/ tests/

format:
	uv run ruff format src/ tests/
	uv run ruff check --fix src/ tests/

typecheck:
	uv run pyright

test:
	uv run pytest

test-integration:
	uv run pytest -m integration --tb=long

test-quick:
	uv run pytest -x --no-header -q

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .cache/ dist/ *.egg-info src/*.egg-info

prek-install:
	uvx prek install

prek:
	uvx prek run --all-files

all: install lint typecheck test
