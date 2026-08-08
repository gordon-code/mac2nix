"""Real PIV-card-authenticates-against-sudo-PAM test, applied natively — no VM.

Marked `nix_darwin_switch`, same skip-unless-`GITHUB_ACTIONS=true` guard as
`test_scaffold_switch_native.py` — never runs against a real developer
machine. Unlike that test, this one requires two more environment
variables (`MAC2NIX_PIV_VENDOR_ID`/`MAC2NIX_PIV_PRODUCT_ID`) that only exist
when `pr-checks.yaml`'s discovery step (`scripts/discover_usb_device.py`)
found a usable baseline USB device on this specific runner — if it didn't,
the CI workflow's own conditional skips the step that would run this test
entirely, which is a deliberate, documented fallback (see
hack/plans/fix-vm-tahoe-base-image-1785337468-migration-mvp.md's Task 10
Step 5), not something this test itself needs to handle.

Must run *after* `test_scaffold_switch_native.py`'s own switch step in the
CI workflow, never before or concurrently — see
`scripts/provision_piv_emulation.py`'s own docstring and this project's
security review: this test's own switch (with the PIV option enabled)
splices a live PAM module into this runner's real `/etc/pam.d/sudo_local`
for the remainder of the job, and nothing else in that job may still depend
on plain-password `sudo` succeeding once it does.
"""

from __future__ import annotations

import asyncio
import getpass
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from mac2nix.generators.scaffold import add_host, init_framework
from tests._scaffold_helpers import _nix_config_env_prefix_args

pytestmark = pytest.mark.nix_darwin_switch

_HOSTNAME = "mac2nix-piv-sudo-native-test"


def _is_github_actions() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _enable_yubikey_piv_sudo(output_dir: Path, hostname: str) -> None:
    config_path = output_dir / "hosts" / "darwin" / hostname / "configuration.nix"
    content = config_path.read_text()
    marker = "system.stateVersion = 7;"
    replacement = f"{marker}\n  mac2nix.yubikeyPivSudo.enable = true;"
    config_path.write_text(content.replace(marker, replacement))


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


@pytest.fixture
def discovered_usb_device() -> tuple[int, int]:
    """The USB device pr-checks.yaml's discovery step found on this runner.

    Fails loudly (not skips) if these are missing while GITHUB_ACTIONS=true —
    the workflow's own conditional step is what decides whether this test
    runs at all; if it ran, the env vars must be present.
    """
    vendor_id = os.environ.get("MAC2NIX_PIV_VENDOR_ID")
    product_id = os.environ.get("MAC2NIX_PIV_PRODUCT_ID")
    if not vendor_id or not product_id:
        raise AssertionError(
            "MAC2NIX_PIV_VENDOR_ID/MAC2NIX_PIV_PRODUCT_ID are not set — this test should only ever "
            "run from pr-checks.yaml's conditional step, after scripts/discover_usb_device.py found "
            "a usable device."
        )
    return int(vendor_id), int(product_id)


def test_piv_card_authenticates_against_sudo_pam_natively(
    real_age_key: Path, discovered_usb_device: tuple[int, int], tmp_path: Path
) -> None:
    """A real virtual PIV card, provisioned directly on this runner, authenticates via pam_p11."""
    username = getpass.getuser()
    output_dir = tmp_path / "mac2nix-scaffold"
    vendor_id, product_id = discovered_usb_device

    init_framework(output_dir)
    add_host(output_dir, _HOSTNAME, username, confirm_backup=lambda _fingerprint: True)
    _enable_yubikey_piv_sudo(output_dir, _HOSTNAME)

    assert real_age_key.is_file(), "add_host() should have written the real age key to the real expected path"

    nix_bin = shutil.which("nix")
    assert nix_bin is not None, "nix must be installed on this runner before this test can apply anything"
    sudo_bin = shutil.which("sudo")
    assert sudo_bin is not None, "sudo must be available to run nix-darwin's system activation"
    nix_config_prefix = _nix_config_env_prefix_args()

    async def _switch() -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            sudo_bin,
            "-n",
            *nix_config_prefix,
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

    returncode, out, err = asyncio.run(_switch())
    assert returncode == 0, (
        f"sudo nix run nix-darwin -- switch failed (exit {returncode}):\nstdout:\n{out}\nstderr:\n{err}"
    )

    repo_root = Path(__file__).resolve().parents[2]
    provision_script = repo_root / "scripts" / "provision_piv_emulation.py"
    provision_result = subprocess.run(  # noqa: S603
        [
            sudo_bin,
            "-n",
            nix_bin,
            "run",
            "nixpkgs#python3",
            "--",
            str(provision_script),
            "--vendor-id",
            str(vendor_id),
            "--product-id",
            str(product_id),
        ],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    assert provision_result.returncode == 0, (
        f"PIV emulation provisioning failed:\nstdout:\n{provision_result.stdout}\nstderr:\n{provision_result.stderr}"
    )

    pamtester_result = subprocess.run(  # noqa: S603
        ["bash", "-c", f"echo 123456 | {nix_bin} run nixpkgs#pamtester -- sudo_local {username} authenticate"],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert pamtester_result.returncode == 0, (
        f"pamtester authentication failed:\nstdout:\n{pamtester_result.stdout}\nstderr:\n{pamtester_result.stderr}"
    )
