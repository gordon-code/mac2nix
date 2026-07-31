.DEFAULT_GOAL := all
.PHONY: install lint format typecheck test test-integration test-vm test-nix prewarm-vm pull-base-vm test-quick clean all prek-install prek

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

# Pull-if-missing, shared by test-integration/test-vm rather than each duplicating
# the pinned digest. Uses mac2nix.vm.manager.pull_base_image_if_missing() (exact-name
# match + `tart clone <ref> <name>`) rather than a plain-text `tart list | grep`, which
# false-positives: an OCI pull caches under its full registry/repo@digest string, which
# contains "macos-tahoe-base" as a substring without actually being named that.
# Always operates on the one canonical pinned name/digest pair (its own defaults) —
# deliberately ignores MAC2NIX_BASE_VM, since passing only `name=` without a matching
# `image_ref=` would silently clone the unrelated pinned macos-tahoe-base image and
# tag it under whatever name MAC2NIX_BASE_VM names (e.g. mac2nix-nix-base), producing
# a VM that looks prewarmed by name but has no Nix installed. A prewarmed image is
# only ever created for real by `make prewarm-vm`; this target's only job is to
# guarantee the fallback pinned image exists.
pull-base-vm:
	uv run python -c "import asyncio; from mac2nix.vm.manager import pull_base_image_if_missing; asyncio.run(pull_base_image_if_missing())"

test-integration: pull-base-vm
	uv run pytest -m integration --tb=long

test-vm: pull-base-vm
	uv run pytest -m nix_vm --tb=long

test-nix:
	uv run pytest -m nix_build --tb=long

prewarm-vm:
	uv run python scripts/prewarm_vm.py

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
