"""Real PIV-card-authenticates-against-sudo-PAM test, applied natively — no VM.

Marked `nix_darwin_switch`, same skip-unless-`GITHUB_ACTIONS=true` guard as
`test_scaffold_switch_native.py` — never runs against a real developer
machine.

Must run *after* `test_scaffold_switch_native.py`'s own switch step in the
CI workflow, never before or concurrently — see
`scripts/provision_piv_emulation.py`'s own docstring and this project's
security review: this test's own switch (with the PIV option enabled)
splices a live PAM module into this runner's real `/etc/pam.d/sudo_local`
for the remainder of the job, and nothing else in that job may still depend
on plain-password `sudo` succeeding once it does.

`scripts/provision_piv_emulation.py` no longer needs a discovered USB
device at all (see its own docstring): it registers vpcd via its own
reader.conf mechanism against a self-hosted pcscd
(nix/piv-emulation/pcsc-stack.nix), not macOS's proprietary
CryptoTokenKit/ifdreader daemon, which is what actually needed a
VID/PID-matched USB device to spoof.

This matters concretely for this leg, not just architecturally: a separate
session (hack/PROJECT.md's "native-runner leg validated against real GHA
hardware" entry, 2026-08-12) confirmed via three real CI runs that
`runs-on: macos-latest` exposes exactly two USB devices, byte-for-byte
identical to Tart's own baseline, and both are HID-claimed the same way --
`scripts/discover_usb_device.py` now correctly excludes both as unusable,
which means this test's own CI step (gated on a device being discovered)
currently never actually executes on a real runner; it always lands on the
documented "no usable device, skip" fallback instead. The self-hosted-pcscd
mechanism needs no discovered device at all, so it removes the reason that
fallback exists in the first place -- but that has not yet been verified
against a real `macos-latest` runner (this session's own verification was
against a real Tart VM only). `MAC2NIX_PIV_VENDOR_ID`/
`MAC2NIX_PIV_PRODUCT_ID`, `scripts/discover_usb_device.py`, and
`pr-checks.yaml`'s conditional gating on them are consequently no longer
load-bearing for this leg, but are left in place un-deleted pending a real
CI run confirming the new mechanism actually works here too -- a CI
workflow change is a higher-stakes, harder-to-verify-locally edit than the
Python it gates, and is deliberately out of scope for this session.
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


def test_piv_card_authenticates_against_sudo_pam_natively(real_age_key: Path, tmp_path: Path) -> None:
    """A real virtual PIV card, provisioned directly on this runner, authenticates via pam_p11."""
    username = getpass.getuser()
    output_dir = tmp_path / "mac2nix-scaffold"

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
        ],
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    assert provision_result.returncode == 0, (
        f"PIV emulation provisioning failed:\nstdout:\n{provision_result.stdout}\nstderr:\n{provision_result.stderr}"
    )

    # Real "sudo" PAM authentication, never a nix-built PAM-testing tool like
    # pamtester -- see tests/vm/test_piv_sudo_vm.py's own _sudo_authenticate
    # docstring for the full, VM-confirmed reasoning: nix-built binaries and
    # nixpkgs' own libpam.2.dylib are rejected outright by AppleMobileFileIntegrity
    # ("Unrecoverable CT signature issue"), and OpenPAM's own
    # openpam_check_path_owner_perms() independently refuses to load any module
    # from /nix/store at all ("insecure ownership or permissions") -- both
    # confirmed via a direct `log show` capture, regardless of which PAM service
    # is targeted or how its policy is written. Only a real, Apple-signed
    # /usr/bin/sudo can drive this PAM chain successfully.
    #
    # This runner's own sudo has no NOPASSWD override (unlike Tart's base
    # image, see _sudo_authenticate's docstring) -- GitHub-hosted macOS
    # runners require a real password for sudo by default -- so no
    # NOPASSWD-removal step is needed here.
    #
    # -k invalidates any cached sudo timestamp first, so this always exercises
    # a real PAM authentication rather than a cached credential. -S reads the
    # password from stdin. -v only validates/refreshes credentials -- no
    # command execution needed to prove authentication succeeded or failed.
    sudo_auth_result = subprocess.run(  # noqa: S603
        ["bash", "-c", f"echo 123456 | {sudo_bin} -k -S -v"],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert sudo_auth_result.returncode == 0, (
        f"sudo authentication failed:\nstdout:\n{sudo_auth_result.stdout}\nstderr:\n{sudo_auth_result.stderr}"
    )
