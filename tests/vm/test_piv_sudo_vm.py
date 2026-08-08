"""Real VM-based E2E test: a virtual PIV card authenticating against the sudo PAM path.

Marked `nix_vm` — no-skip once `tart` is present, same contract as every
other `nix_vm` test in this codebase (the earlier idea of softening this
given vpcd's own documented macOS-version sensitivity was considered and
explicitly rejected; see hack/PROJECT.md's "Task 10 (YubiKey PIV) expanded"
entry).

Proves `security.nix`'s `mac2nix.yubikeyPivSudo.enable` PAM wiring actually
authenticates against a real card -- not just that it builds (Step 1's
nix_build-marked tests already cover that). Uses vpcd + jcardsim + PivApplet
(nix/piv-emulation/, scripts/provision_piv_emulation.py) instead of a
physical YubiKey, per this plan's own research spike
(hack/research/feat-migration-mvp-pr1-1786215169-piv-smartcard-emulation-tart-macos.md).

The spoof target (Virtual USB Keyboard, idVendor 1452 / idProduct 33029) was
confirmed live this session via `ioreg -p IOUSB -l` against a real Tart
guest -- it is not documented anywhere upstream, it was discovered here.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from mac2nix.generators.scaffold import add_host, init_framework
from mac2nix.vm._utils import VMError, async_run_command
from mac2nix.vm.manager import TartVMManager
from mac2nix.vm.validator import Validator

pytestmark = pytest.mark.nix_vm

_HOSTNAME = "mac2nix-piv-sudo-vm-test"

# Tart's base images ship a real, pre-existing "admin" account -- same
# default TartVMManager itself uses for SSH. Mirrors test_scaffold_vm.py's
# own reasoning for reusing this account rather than a synthetic one.
_VM_USERNAME = "admin"

# Confirmed live this session via a real ioreg spike against macos-tahoe-base
# -- a baseline synthetic USB device Virtualization.framework always
# provides for guest keyboard input, present with zero configuration.
_VENDOR_ID = 1452
_PRODUCT_ID = 33029

_REMOTE_PIV_ROOT = "/tmp/mac2nix-piv"
_NIX_PROFILE_SOURCE_CMD = ". /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh"


def _enable_yubikey_piv_sudo(output_dir: Path, hostname: str) -> None:
    """Patch a registered host's configuration.nix to set `mac2nix.yubikeyPivSudo.enable = true;`.

    Mirrors how a real user enables the option -- hand-editing their host's
    own configuration.nix -- rather than inventing a test-only override.
    """
    config_path = output_dir / "hosts" / "darwin" / hostname / "configuration.nix"
    content = config_path.read_text()
    marker = "system.stateVersion = 7;"
    replacement = f"{marker}\n  mac2nix.yubikeyPivSudo.enable = true;"
    config_path.write_text(content.replace(marker, replacement))


async def _copy_age_key_to_vm(vm: TartVMManager, local_key_path: Path, username: str) -> None:
    """SCP the local age key into the VM at the exact path `lib/helpers.nix` expects.

    Identical to test_scaffold_vm.py's own helper -- not shared via import
    across test modules, matching this codebase's existing convention of
    small per-file test helpers over cross-test-module coupling.
    """
    ip = await vm.get_ip()
    if not ip:
        raise VMError("Cannot copy age key — VM has no IP address")

    remote_dir = f"/Users/{username}/.config/sops/age"
    ok, _out, err = await vm.exec_command(["mkdir", "-p", remote_dir])
    if not ok:
        raise VMError(f"mkdir {remote_dir!r} failed: {err.strip()}")

    scp_cmd = [
        "sshpass",
        "-e",
        "scp",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        str(local_key_path),
        f"{vm.vm_user}@{ip}:{remote_dir}/keys.txt",
    ]
    returncode, _stdout, stderr = await async_run_command(scp_cmd, timeout=30, env={"SSHPASS": vm.vm_password})
    if returncode != 0:
        raise VMError(f"scp age key to VM failed (exit {returncode}): {stderr.strip()}")

    ok, _out, err = await vm.exec_command(["chmod", "600", f"{remote_dir}/keys.txt"])
    if not ok:
        raise VMError(f"chmod age key in VM failed: {err.strip()}")


async def _switch_scaffold(vm: TartVMManager, validator: Validator, output_dir: Path, local_key_path: Path) -> None:
    """Real `nix run nix-darwin -- switch`, reusing test_scaffold_vm.py's exact fixups verbatim."""
    await validator._copy_flake_to_vm(output_dir)
    await _copy_age_key_to_vm(vm, local_key_path, _VM_USERNAME)
    await validator._bootstrap_nix_darwin()

    move_cmd = (
        "if [ -f /etc/nix/nix.custom.conf ]; then "
        "sudo mv /etc/nix/nix.custom.conf /etc/nix/nix.custom.conf.before-nix-darwin; "
        "fi"
    )
    ok, _out, err = await vm.exec_command(["bash", "-c", move_cmd])
    if not ok:
        raise VMError(f"Failed to move aside /etc/nix/nix.custom.conf: {err.strip()}")

    ok, _out, err = await vm.exec_command(["sudo", "rm", "-rf", "/opt/homebrew"], timeout=60)
    if not ok:
        raise VMError(f"Failed to remove pre-existing Homebrew: {err.strip()}")

    switch_cmd = (
        f"cd {validator._REMOTE_FLAKE_DIR}"
        " && . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh"
        f" && sudo -n $(command -v nix) run nix-darwin -- switch --flake .#{_HOSTNAME}"
    )
    ok, out, err = await vm.exec_command(["bash", "-c", switch_cmd], timeout=900)
    if not ok:
        raise VMError(f"nix run nix-darwin -- switch failed:\nstdout:\n{out}\nstderr:\n{err}")


async def _copy_provisioning_assets(vm: TartVMManager, validator: Validator) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    ok, _out, err = await vm.exec_command(["mkdir", "-p", _REMOTE_PIV_ROOT])
    if not ok:
        raise VMError(f"mkdir {_REMOTE_PIV_ROOT!r} failed: {err.strip()}")
    await validator._copy_flake_to_vm(
        repo_root / "scripts", remote_dir=f"{_REMOTE_PIV_ROOT}/scripts", what="provisioning script"
    )
    await validator._copy_flake_to_vm(
        repo_root / "nix", remote_dir=f"{_REMOTE_PIV_ROOT}/nix", what="piv-emulation derivations"
    )


async def _run_provisioning(vm: TartVMManager) -> None:
    provision_cmd = (
        f"{_NIX_PROFILE_SOURCE_CMD}"
        f" && cd {_REMOTE_PIV_ROOT}"
        f" && sudo -n $(command -v nix) run nixpkgs#python3 -- scripts/provision_piv_emulation.py"
        f" --vendor-id {_VENDOR_ID} --product-id {_PRODUCT_ID}"
    )
    ok, out, err = await vm.exec_command(["bash", "-c", provision_cmd], timeout=1800)
    if not ok:
        raise VMError(f"PIV emulation provisioning failed:\nstdout:\n{out}\nstderr:\n{err}")


async def _pamtester_authenticate(vm: TartVMManager, *, pin: str) -> tuple[bool, str, str]:
    cmd = (
        f"{_NIX_PROFILE_SOURCE_CMD} && echo {pin} | nix run nixpkgs#pamtester -- sudo_local {_VM_USERNAME} authenticate"
    )
    return await vm.exec_command(["bash", "-c", cmd], timeout=60)


def test_piv_card_authenticates_against_sudo_pam(
    nix_darwin_vm: TartVMManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real virtual PIV card, once provisioned, authenticates via pam_p11 against sudo_local."""
    key_root = tmp_path / "age-keys"

    def _fake_age_key_path(username: str, key_dir: Path | None = None) -> Path:
        return (key_dir or key_root / username) / "keys.txt"

    monkeypatch.setattr("mac2nix.generators.scaffold._age_key_path", _fake_age_key_path)

    output_dir = tmp_path / "mac2nix-scaffold"
    init_framework(output_dir)
    add_host(output_dir, _HOSTNAME, _VM_USERNAME, confirm_backup=lambda _fingerprint: True)
    _enable_yubikey_piv_sudo(output_dir, _HOSTNAME)

    local_key_path = _fake_age_key_path(_VM_USERNAME)

    async def _run() -> tuple[bool, str, str]:
        validator = Validator(nix_darwin_vm)
        await _switch_scaffold(nix_darwin_vm, validator, output_dir, local_key_path)
        await _copy_provisioning_assets(nix_darwin_vm, validator)
        await _run_provisioning(nix_darwin_vm)

        # Attribution matters: touchIdAuth sits before pam_p11 in the same
        # `sufficient` chain (lib.mkAfter) and is unconditional. A bare
        # "authentication succeeded" assertion could pass for an unrelated
        # reason on hardware with no biometric sensor -- masking a broken
        # PIV path entirely. The negative case below is what actually proves
        # attribution, not this call alone.
        return await _pamtester_authenticate(nix_darwin_vm, pin="123456")

    ok, out, err = asyncio.run(_run())
    assert ok, f"pamtester authentication failed:\nstdout:\n{out}\nstderr:\n{err}"


def test_piv_card_wrong_pin_fails_authentication(
    nix_darwin_vm: TartVMManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative case: proves the prior test's success is attributable to the PIV path specifically.

    A test that can never fail regardless of whether the PIV wiring works is
    not real coverage -- this is that check.
    """
    key_root = tmp_path / "age-keys"

    def _fake_age_key_path(username: str, key_dir: Path | None = None) -> Path:
        return (key_dir or key_root / username) / "keys.txt"

    monkeypatch.setattr("mac2nix.generators.scaffold._age_key_path", _fake_age_key_path)

    output_dir = tmp_path / "mac2nix-scaffold"
    init_framework(output_dir)
    add_host(output_dir, _HOSTNAME, _VM_USERNAME, confirm_backup=lambda _fingerprint: True)
    _enable_yubikey_piv_sudo(output_dir, _HOSTNAME)

    local_key_path = _fake_age_key_path(_VM_USERNAME)

    async def _run() -> tuple[bool, str, str]:
        validator = Validator(nix_darwin_vm)
        await _switch_scaffold(nix_darwin_vm, validator, output_dir, local_key_path)
        await _copy_provisioning_assets(nix_darwin_vm, validator)
        await _run_provisioning(nix_darwin_vm)

        return await _pamtester_authenticate(nix_darwin_vm, pin="000000")

    ok, out, _err = asyncio.run(_run())
    assert not ok, f"pamtester authenticated with a wrong PIN — PIV path is not actually gating auth:\n{out}"
