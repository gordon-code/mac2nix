"""Real VM-based apply-and-verify test for the bare, host-registered scaffold — no domains yet.

Marked `nix_vm` (Step 10's shared marker, registered in pyproject.toml): the
`nix_darwin_vm` fixture skips this test if `tart` is unavailable, otherwise
it must run to completion and pass, no further internal skipping.

This is the first point in the whole plan that any generated nix-darwin
configuration is actually applied to a running system, however minimal — it
proves the scaffold's own module wiring (`lib/helpers.nix`'s
`mkDarwinSystem`, `modules/darwin/default.nix`'s imports, sops-nix's
`sops.age.keyFile`/`sops.defaultSopsFile` wiring, `modules/darwin/homebrew.nix`'s
activation-policy stub) actually activates cleanly on its own, independent
of any later domain generator's correctness. No `Validator`/fidelity
comparison is needed here — there is no scanned domain data yet for any
generator to reproduce; this is a simple pass/fail activation check.
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

_HOSTNAME = "mac2nix-scaffold-vm-test"

# Tart's base images ship with a real, pre-existing "admin" account — the
# same default TartVMManager itself uses for SSH (vm_user="admin"). Using it
# here too means the macOS account nix-darwin configures via
# users.users.<name> and the account the age key is placed under both refer
# to a real account that actually exists inside the VM.
_VM_USERNAME = "admin"


async def _copy_age_key_to_vm(vm: TartVMManager, local_key_path: Path, username: str) -> None:
    """SCP the local age key into the VM at the exact path `lib/helpers.nix` expects.

    Mirrors ``Validator._copy_flake_to_vm()``'s sshpass/scp security pattern
    (SSHPASS env var, never argv, no shell=True) for a single file rather
    than a directory tree. Never logs key content — only file paths, which
    aren't secret.
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

    # age-keygen already chmod 0600'd the local file, but scp doesn't
    # guarantee preserving that mode remotely — set it explicitly, matching
    # generate_age_key()'s own "never assume the tool set it correctly" rule.
    ok, _out, err = await vm.exec_command(["chmod", "600", f"{remote_dir}/keys.txt"])
    if not ok:
        raise VMError(f"chmod age key in VM failed: {err.strip()}")


def test_scaffold_switches_for_real(
    nix_darwin_vm: TartVMManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """init_framework() + add_host() must produce a config that really `nix run nix-darwin -- switch`es."""
    # add_host()'s real age-key path always resolves to /Users/<username>/... on
    # whatever machine runs this test, with no override at that level (by
    # design). Redirect it to a scratch dir so this never touches the actual
    # host machine's real home directory — the VM-side path (what the
    # deployed config actually references) is unaffected, since that's a
    # separate, explicit SCP destination below.
    key_root = tmp_path / "age-keys"

    def _fake_age_key_path(username: str, key_dir: Path | None = None) -> Path:
        return (key_dir or key_root / username) / "keys.txt"

    monkeypatch.setattr("mac2nix.generators.scaffold._age_key_path", _fake_age_key_path)

    output_dir = tmp_path / "mac2nix-scaffold"
    init_framework(output_dir)
    add_host(output_dir, _HOSTNAME, _VM_USERNAME, confirm_backup=lambda _fingerprint: True)

    local_key_path = _fake_age_key_path(_VM_USERNAME)

    async def _run() -> tuple[bool, str, str]:
        validator = Validator(nix_darwin_vm)
        await validator._copy_flake_to_vm(output_dir)
        await _copy_age_key_to_vm(nix_darwin_vm, local_key_path, _VM_USERNAME)
        await validator._bootstrap_nix_darwin()

        # nix-darwin's system activation now always runs as root (per
        # system.primaryUser's own purpose) — plain `nix run` fails with
        # "system activation must now be run as root". `sudo -n` fails fast
        # rather than hanging on a password prompt if passwordless sudo isn't
        # actually available. `$(command -v nix)` resolves nix's absolute
        # path in the current (profile-sourced) shell *before* handing it to
        # sudo, since sudo's own secure_path won't include wherever the
        # nix-daemon profile put it on PATH.
        switch_cmd = (
            f"cd {validator._REMOTE_FLAKE_DIR}"
            " && . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh"
            f" && sudo -n $(command -v nix) run nix-darwin -- switch --flake .#{_HOSTNAME}"
        )
        return await nix_darwin_vm.exec_command(["bash", "-c", switch_cmd], timeout=900)

    ok, out, err = asyncio.run(_run())
    assert ok, f"nix run nix-darwin -- switch failed:\nstdout:\n{out}\nstderr:\n{err}"
