"""Real `nix-darwin switch` applied directly to the machine running this test — no VM.

Marked `nix_darwin_switch`, excluded from the default `pytest`/`make test`
run. Unlike `test_scaffold_vm.py` (the Tart-VM-based equivalent, kept for
local development on real Apple Silicon hardware), this test applies the
generated config to whatever real system runs it — safe only because a
GitHub Actions runner is itself fully disposable, destroyed after the job
completes. It must NEVER run on a developer's actual machine: the gate below
skips unless `GITHUB_ACTIONS=true`, GitHub Actions' own environment variable
(not something set on a real dev machine by accident), so a bare `pytest -m
nix_darwin_switch` locally skips safely by default rather than mutating a
real system.

Nested macOS virtualization is categorically unsupported on GitHub-hosted
runners (confirmed via GitHub's own documentation — an Apple Virtualization
Framework limitation, not a Tart-specific one), so `test_scaffold_vm.py`'s
Tart-based approach cannot run there at all. Running natively sidesteps that
wall entirely, at the cost of testing against an already-provisioned CI
image rather than a pristine machine — `lib/helpers.nix`'s
`nix-homebrew.autoMigrate = true` exists specifically to let this test
(and any real user migrating an already-Homebrew Mac) apply cleanly despite
that.

The age key must land at the exact real path (`/Users/<username>/.config/
sops/age/keys.txt`) `lib/helpers.nix`'s `sops.age.keyFile` expects — unlike
`test_scaffold_builds_for_real`'s redirected key (fine for a build-only
check), a real switch reads that literal path at apply time and cannot be
redirected. Fails loudly if a key already exists there rather than silently
reusing or overwriting it — should never happen on a fresh CI runner, and
if it does, that's worth knowing about rather than masking.
"""

from __future__ import annotations

import asyncio
import getpass
import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from mac2nix.generators.scaffold import add_host, init_framework

pytestmark = pytest.mark.nix_darwin_switch

_HOSTNAME = "mac2nix-native-switch-test"


def _is_github_actions() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"


@pytest.fixture
def real_age_key() -> Iterator[Path]:
    if not _is_github_actions():
        pytest.skip("only runs under GITHUB_ACTIONS=true — never against a real developer machine")

    username = getpass.getuser()
    key_path = Path(f"/Users/{username}/.config/sops/age/keys.txt")
    if key_path.exists():
        pytest.fail(
            f"a real sops age key already exists at {key_path} — refusing to overwrite or reuse it. "
            "This should never happen on a fresh CI runner."
        )

    try:
        yield key_path
    finally:
        key_path.unlink(missing_ok=True)


def test_scaffold_switches_for_real_natively(real_age_key: Path, tmp_path: Path) -> None:
    """init_framework() + add_host() must produce a config that really `nix run nix-darwin -- switch`es."""
    username = getpass.getuser()
    output_dir = tmp_path / "mac2nix-scaffold"

    init_framework(output_dir)
    add_host(output_dir, _HOSTNAME, username, confirm_backup=lambda _fingerprint: True)

    assert real_age_key.is_file(), "add_host() should have written the real age key to the real expected path"

    nix_bin = shutil.which("nix")
    assert nix_bin is not None, "nix must be installed on this runner before this test can apply anything"
    sudo_bin = shutil.which("sudo")
    assert sudo_bin is not None, "sudo must be available to run nix-darwin's system activation"

    async def _run() -> tuple[int, str, str]:
        # nix-darwin's system activation now always runs as root (per
        # `system.primaryUser`'s own purpose) — `-n` fails fast with a clear
        # error instead of hanging for the full timeout if passwordless sudo
        # isn't actually available, rather than silently waiting on a prompt
        # that will never come. The absolute `nix_bin` path (not a bare `nix`
        # on PATH) avoids sudo's restricted `secure_path` not including
        # wherever Nix installed its own binaries.
        proc = await asyncio.create_subprocess_exec(
            sudo_bin,
            "-n",
            nix_bin,
            "run",
            "nix-darwin",
            "--",
            "switch",
            "--flake",
            f".#{_HOSTNAME}",
            cwd=output_dir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=900)
        return proc.returncode or 0, stdout.decode(), stderr.decode()

    returncode, out, err = asyncio.run(_run())
    assert returncode == 0, (
        f"sudo nix run nix-darwin -- switch failed (exit {returncode}):\nstdout:\n{out}\nstderr:\n{err}"
    )
