"""Real `nix flake check`/`nix build` integration test against a freshly-scaffolded, hosted framework.

Marked `nix_build` — excluded from the default `pytest`/`make test` run,
invoked via `make test-nix`. Unlike the parse-only `nix` marker (Task 3),
this test NEVER calls `pytest.skip()`: if `nix`/`age`/`sops` aren't on PATH,
or there's no network access to resolve flake inputs, the test fails
loudly. A silently-skipped integration test would defeat the entire point
of this PR.

Known, accepted tradeoff: there is no committed `flake.lock` for this
throwaway scaffold, so `nix flake lock` resolves `nixpkgs` (tracked as
`nixos-unstable`) to whatever commit is current at test-run time. A failure
here can be caused by an unrelated upstream nixpkgs regression, not a bug
in mac2nix's own templates — this is a deliberate scope boundary (pinning
the *shipped* scaffold's own `nixpkgs` input would carry that same
staleness into every real user's deployed flake), not an oversight. This
test requires live network access and is not fully hermetic.

Real-environment note: `add_host()`'s age key path is derived from
*username* alone (`/Users/{username}/.config/sops/age/keys.txt`), with no
override at that level — by design, see `scaffold.py`. Rather than touching
that real path (which would either collide with a developer's own real sops
key, or fail outright on a machine that already has one configured — exactly
the audience most likely to have nix/age/sops all on PATH and be running
this never-skip test), this test redirects the key to `tmp_path` via the
same `_redirect_age_keys()` monkeypatch used by `test_scaffold.py`/
`test_add_host.py`. It still exercises real `age-keygen`/`sops` end-to-end —
just at a location this test fully owns.
"""

from __future__ import annotations

import getpass
import subprocess
from pathlib import Path

import pytest

from mac2nix.generators.scaffold import add_host, init_framework
from tests._scaffold_helpers import _redirect_age_keys

pytestmark = pytest.mark.nix_build

_HOSTNAME = "mac2nix-nix-build-test"


def test_scaffold_builds_for_real(tmp_path: Path) -> None:
    """init_framework() + add_host() must produce a flake that actually `nix build`s."""
    output_dir = tmp_path / "mac2nix-scaffold"
    username = getpass.getuser()

    init_framework(output_dir)
    with _redirect_age_keys(tmp_path / "age-keys"):
        add_host(output_dir, _HOSTNAME, username, confirm_backup=lambda _fingerprint: True)

    lock_result = subprocess.run(
        ["nix", "flake", "lock"],  # noqa: S607
        cwd=output_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert lock_result.returncode == 0, f"nix flake lock failed (exit {lock_result.returncode}):\n{lock_result.stderr}"

    build_result = subprocess.run(  # noqa: S603
        ["nix", "build", f".#darwinConfigurations.{_HOSTNAME}.system", "--no-link"],  # noqa: S607
        cwd=output_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build_result.returncode == 0, f"nix build failed (exit {build_result.returncode}):\n{build_result.stderr}"
