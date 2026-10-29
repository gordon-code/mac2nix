"""Real nix build/run test for mac2nix's own root flake.nix.

Marked `nix_build` (never skipped). Before this PR, flake.nix's only
consumer was `Validator._scan_vm()`'s local-source override, exercised
only by `nix_vm`-marked tests -- which always skip in this project's CI
(no `tart` on GitHub-hosted runners). A syntax/evaluation error here would
otherwise pass `make test`/`make test-nix` completely undetected, silently
reproducing the exact "nix run mechanism doesn't actually work" gap this
PR found and fixed.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.nix_build

_REPO_ROOT = Path(__file__).resolve().parent.parent


def test_own_flake_check() -> None:
    result = subprocess.run(
        ["nix", "flake", "check"],  # noqa: S607
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"nix flake check failed (exit {result.returncode}):\n{result.stderr}"


def test_own_flake_app_runs_for_real() -> None:
    result = subprocess.run(
        ["nix", "run", ".", "--", "--version"],  # noqa: S607
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"nix run . -- --version failed (exit {result.returncode}):\n{result.stderr}"
    assert "mac2nix" in result.stdout
