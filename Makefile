.DEFAULT_GOAL := all
.PHONY: install lint format typecheck test test-quick clean all

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

test-quick:
	uv run pytest -x --no-header -q

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .cache/ dist/ *.egg-info src/*.egg-info

all: install lint typecheck test
