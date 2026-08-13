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

Registers vpcd via its own reader.conf mechanism against a self-hosted
pcscd (nix/piv-emulation/pcsc-stack.nix) -- never macOS's proprietary
CryptoTokenKit/ifdreader daemon, which requires spoofing a USB device's
VID/PID and is a confirmed dead end on Tart specifically (its only two
synthetic USB devices are already claimed by macOS's own HIDDriverKit
stack, so ifdreader registers vpcd's driver bundle but never gets a live
reader instance for it -- see hack/PROJECT.md's "real VM debugging session"
entry for the full diagnostic trail). No USB device, real or synthetic, is
involved in this test at all as a result.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from mac2nix.generators.scaffold import add_host, init_framework
from mac2nix.vm._utils import VMError, async_run_command, is_transient_auth_failure
from mac2nix.vm.manager import TartVMManager
from mac2nix.vm.validator import Validator

pytestmark = pytest.mark.nix_vm

_HOSTNAME = "mac2nix-piv-sudo-vm-test"

# Tart's base images ship a real, pre-existing "admin" account -- same
# default TartVMManager itself uses for SSH. Mirrors test_scaffold_vm.py's
# own reasoning for reusing this account rather than a synthetic one.
_VM_USERNAME = "admin"

_REMOTE_PIV_ROOT = "/tmp/mac2nix-piv"
_NIX_PROFILE_SOURCE_CMD = ". /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh"

# Swaps `pkgs.opensc` (which security.nix's PAM wiring references directly,
# `${pkgs.opensc}/lib/opensc-pkcs11.so`) for a build linked against
# nixpkgs' own pcsclite instead of Apple's proprietary PCSC.framework --
# necessary because this test authenticates against an *emulated* card,
# only reachable through the self-hosted pcscd
# scripts/provision_piv_emulation.py starts, never through Apple's
# CryptoTokenKit/ifdreader daemon. Injected only into this generated *test*
# scaffold's own configuration.nix -- the real
# templates/scaffold/modules/darwin/security.nix that real users get is
# never touched, and always resolves `pkgs.opensc` to the stock,
# Apple-PCSC-linked build, which is exactly correct for a real Mac talking
# to a real YubiKey.
#
# Deliberately duplicated (not shared via import) with nix/piv-emulation/
# pcsc-stack.nix's identical-looking override: that file overrides a
# separately-pinned nixpkgs used only to build the provisioning tools
# themselves, while this overlay is evaluated within *this scaffold's own*
# flake (a different nixpkgs revision, resolved via its own flake.lock) --
# a flake can't import a file outside its own source tree under pure
# evaluation, so the same override logic has to exist in both places.
_OPENSC_PCSCLITE_OVERLAY = """
  nixpkgs.overlays = [
    (final: prev: {
      pcsclite = prev.pcsclite.overrideAttrs (old: {
        postPatch = builtins.replaceStrings
          [ ''"$lib/lib/libpcsclite_real.so.1"'' ]
          [ ''"$lib/lib/libpcsclite_real.1.dylib"'' ]
          old.postPatch;
      });
      opensc = prev.opensc.overrideAttrs (old: {
        buildInputs = old.buildInputs ++ [ final.pcsclite ];
        configureFlags = old.configureFlags ++ [
          ("--with-pcsc-provider=${prev.lib.getLib final.pcsclite}/lib/libpcsclite"
            + prev.stdenv.hostPlatform.extensions.sharedLibrary)
        ];
      });
    })
  ];
"""


def _enable_yubikey_piv_sudo(output_dir: Path, hostname: str) -> None:
    """Patch a registered host's configuration.nix to set `mac2nix.yubikeyPivSudo.enable = true;`.

    Mirrors how a real user enables the option -- hand-editing their host's
    own configuration.nix -- rather than inventing a test-only override.
    Also injects `_OPENSC_PCSCLITE_OVERLAY` (see its own comment above).
    """
    config_path = output_dir / "hosts" / "darwin" / hostname / "configuration.nix"
    content = config_path.read_text()
    marker = "system.stateVersion = 7;"
    replacement = f"{marker}\n  mac2nix.yubikeyPivSudo.enable = true;\n{_OPENSC_PCSCLITE_OVERLAY}"
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
        # PreferredAuthentications/PubkeyAuthentication: see
        # async_ssh_exec()'s own comment in _utils.py — without these, ssh
        # tries the calling machine's own default identity files first,
        # which can exhaust the VM's MaxAuthTries before password auth is
        # ever offered. Confirmed as the real, reproducible cause of a
        # "Too many authentication failures" failure here, not flakiness.
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        str(local_key_path),
        f"{vm.vm_user}@{ip}:{remote_dir}/keys.txt",
    ]
    returncode, _stdout, stderr = await async_run_command(scp_cmd, timeout=30, env={"SSHPASS": vm.vm_password})
    if returncode != 0 and is_transient_auth_failure(stderr):
        # Same boot-settling auth race as TartVMManager.exec_command() —
        # confirmed empirically here across real VM runs, not flakiness.
        await asyncio.sleep(3)
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
    )
    ok, out, err = await vm.exec_command(["bash", "-c", provision_cmd], timeout=1800)
    if not ok:
        raise VMError(f"PIV emulation provisioning failed:\nstdout:\n{out}\nstderr:\n{err}")


async def _remove_nopasswd_sudoers(vm: TartVMManager) -> None:
    """Remove Tart's `admin-nopasswd` sudoers override so `sudo` actually authenticates.

    Real, necessary prerequisite discovered this session, not a cosmetic
    change: Tart's base image ships `/etc/sudoers.d/admin-nopasswd`
    (`(ALL) NOPASSWD: ALL`, confirmed via a direct VM `sudo -l`) purely for
    CI/automation convenience. With it present, *any* `sudo` invocation for
    `admin` skips PAM authentication entirely (`pam_authenticate()` is never
    called) -- meaning a test built on real `sudo` would "pass" or "fail"
    for a reason having nothing to do with pam_p11 or the PIV card at all.
    Real Macs never ship this file; it's a Tart-image-only default this
    test must undo to get real coverage. `sudo -n` still works to remove it
    (NOPASSWD is still in effect for *this* command).
    """
    ok, _out, err = await vm.exec_command(["sudo", "-n", "rm", "-f", "/etc/sudoers.d/admin-nopasswd"])
    if not ok:
        raise VMError(f"Failed to remove admin-nopasswd sudoers override: {err.strip()}")


async def _sudo_authenticate(vm: TartVMManager, *, pin: str) -> tuple[bool, str, str]:
    """Authenticate via a real `sudo` invocation -- never a PAM-testing tool like pamtester.

    This replaces an earlier `pamtester`-based design that could never have
    worked on this macOS version, for a reason unrelated to PIV/pcscd
    entirely: real diagnostic evidence (a direct VM `log show` capture)
    shows the kernel's AppleMobileFileIntegrity subsystem rejecting
    nix-built pamtester and nixpkgs' own `libpam.2.dylib` outright
    ("Unrecoverable CT signature issue, bailing out"), and OpenPAM's own
    `openpam_check_path_owner_perms()` separately refusing to load *any*
    module from `/nix/store` at all ("insecure ownership or permissions")
    -- both confirmed via the unified log, not inferred. This holds
    regardless of which PAM service is targeted or how its policy is
    written (a fully self-contained, nix-store-only "test" service using
    nixpkgs' own `pam_permit.so` for every management group was tried and
    hit the identical failure) -- it is a structural property of using any
    nix-built, non-Apple-signed process to drive PAM on this macOS version,
    not a configuration bug.

    Real `/usr/bin/sudo`, linked against Apple's own signed
    `libpam.2.dylib`, has neither problem -- the same mechanism nix-darwin's
    own `security.pam.services.sudo_local.reattach` option already relies
    on in production to load `pam_reattach.so` from the nix store.
    Confirmed directly on a real VM: with `admin-nopasswd` removed (see
    `_remove_nopasswd_sudoers`), `echo admin | sudo -k -S -v` exits 0 for
    the real account password and 1 for a wrong one -- clean, real PAM
    gating, zero AMFI/OpenPAM path-security failures.

    `-k` invalidates any cached sudo timestamp first (otherwise a prior
    successful auth in the same session could skip PAM entirely, the same
    class of false-pass `admin-nopasswd` caused). `-S` reads the PIN from
    stdin instead of a TTY. `-v` only validates/refreshes credentials --
    no command execution needed to prove authentication succeeded or
    failed.
    """
    cmd = f"echo {pin} | sudo -k -S -v"
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
        await _remove_nopasswd_sudoers(nix_darwin_vm)

        # Attribution matters: touchIdAuth sits before pam_p11 in the same
        # `sufficient` chain (lib.mkAfter) and is unconditional. A bare
        # "authentication succeeded" assertion could pass for an unrelated
        # reason on hardware with no biometric sensor -- masking a broken
        # PIV path entirely. The negative case below is what actually proves
        # attribution, not this call alone.
        return await _sudo_authenticate(nix_darwin_vm, pin="123456")

    ok, out, err = asyncio.run(_run())
    assert ok, f"sudo authentication failed:\nstdout:\n{out}\nstderr:\n{err}"


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
        await _remove_nopasswd_sudoers(nix_darwin_vm)

        return await _sudo_authenticate(nix_darwin_vm, pin="000000")

    ok, out, err = asyncio.run(_run())
    # A wrong PIN must not simply produce pam_p11's own rejection message --
    # it must produce the SAME kind of failure pattern real `sudo` gives for
    # any wrong credential (a clean, real "Sorry, try again."/exit-1 PAM
    # rejection), not an "Initialization failure"/"System error" that would
    # also occur if the PAM stack itself were broken (see `_sudo_authenticate`'s
    # own docstring for why that distinction was invisible to the earlier
    # pamtester-based design). Asserting only `not ok` here would be a lazily
    # evaluated, always-true-looking check for either case; the `out`/`err`
    # content is inspected precisely so a broken stack can't masquerade as a
    # correctly rejected wrong PIN.
    assert not ok, f"sudo authenticated with a wrong PIN — PIV path is not actually gating auth:\n{out}"
    broken_stack_msg = (
        f"sudo rejected the wrong PIN, but with a PAM-stack-broken error, not a real credential "
        f"rejection:\nstdout:\n{out}\nstderr:\n{err}"
    )
    assert "system error" not in err.lower(), broken_stack_msg
    assert "initialization failure" not in err.lower(), broken_stack_msg
