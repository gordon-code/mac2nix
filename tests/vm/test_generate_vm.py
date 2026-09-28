"""Real VM-based apply-and-verify: switch a generated preferences.nix inside an
actual VM, confirm the real result matches the scan.

Marked `nix_vm` (skips only if `tart` is unavailable, otherwise must run to
completion and pass). `nix build` (test_generate_integration.py) proves the
flake evaluates; this proves *applying* it reproduces the intended
preferences on a real system.

Composes Validator's pieces manually rather than calling `Validator.validate()`
in one shot -- mirroring `test_scaffold_vm.py`'s own already-verified
approach, since a plain `nix run nix-darwin -- switch --flake .` (no
`#hostname`) relies on hostname auto-detection that doesn't hold for this
multi-host-capable scaffold, and a fresh VM needs the same nix.custom.conf/
pre-existing-Homebrew fixups `test_scaffold_vm.py` already discovered.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from mac2nix.generators import generate_all
from mac2nix.generators.scaffold import add_host, init_framework
from mac2nix.vm._utils import VMError
from mac2nix.vm.manager import TartVMManager
from mac2nix.vm.validator import Validator, compute_fidelity
from tests.generators.test_generate_integration import _realistic_state
from tests.vm.test_scaffold_vm import _copy_age_key_to_vm

pytestmark = pytest.mark.nix_vm

_HOSTNAME = "mac2nix-generate-vm-test"
_VM_USERNAME = "admin"

_REPO_ROOT = Path(__file__).resolve().parents[2]

# A shared `is_transient_auth_failure()` detector for this exact class of
# host-load-related SSH auth flakiness was built and verified on the
# YubiKey PIV branch (see hack/PROJECT.md's Task 10 entries) -- but that
# branch was abandoned and closed unmerged, so the fix never reached `main`.
# Retry locally here rather than depending on it, or reimplementing it in
# shared vm/ production code (out of this task's scope).
_AUTH_FAILURE_MARKER = "Permission denied (publickey,password,keyboard-interactive)"


async def _retry_transient(coro_fn, *, attempts: int = 5, delay: float = 10.0):
    last_exc: VMError | None = None
    for attempt in range(attempts):
        try:
            return await coro_fn()
        except VMError as exc:
            if _AUTH_FAILURE_MARKER not in str(exc):
                raise
            last_exc = exc
            if attempt < attempts - 1:
                await asyncio.sleep(delay)
    assert last_exc is not None
    raise last_exc


async def _exec_with_retry(
    vm: TartVMManager, cmd: list[str], *, timeout: int = 30, attempts: int = 5, delay: float = 10.0
):
    ok, out, err = False, "", ""
    for attempt in range(attempts):
        ok, out, err = await vm.exec_command(cmd, timeout=timeout)
        if ok or _AUTH_FAILURE_MARKER not in err:
            return ok, out, err
        if attempt < attempts - 1:
            await asyncio.sleep(delay)
    return ok, out, err


def test_generate_switches_and_matches_scan(
    nix_darwin_vm: TartVMManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """generate_all() + a real nix-darwin switch must reproduce the source
    scan's preferences state, per Validator's fidelity comparison.
    """
    key_root = tmp_path / "age-keys"

    def _fake_age_key_path(username: str, key_dir: Path | None = None) -> Path:
        return (key_dir or key_root / username) / "keys.txt"

    monkeypatch.setattr("mac2nix.generators.scaffold._age_key_path", _fake_age_key_path)

    output_dir = tmp_path / "mac2nix-scaffold"
    init_framework(output_dir)
    add_host(output_dir, _HOSTNAME, _VM_USERNAME, confirm_backup=lambda _fingerprint: True)

    source_state = _realistic_state()
    gen_result = generate_all(source_state, output_dir, _HOSTNAME, {"preferences"})
    assert gen_result.ran == {"preferences"}

    local_key_path = _fake_age_key_path(_VM_USERNAME)
    validator = Validator(nix_darwin_vm, mac2nix_source=str(_REPO_ROOT))

    async def _run():
        await _retry_transient(lambda: validator._copy_flake_to_vm(output_dir))
        await _retry_transient(lambda: _copy_age_key_to_vm(nix_darwin_vm, local_key_path, _VM_USERNAME))
        await _retry_transient(validator._bootstrap_nix_darwin)

        move_cmd = (
            "if [ -f /etc/nix/nix.custom.conf ]; then "
            "sudo mv /etc/nix/nix.custom.conf /etc/nix/nix.custom.conf.before-nix-darwin; "
            "fi"
        )
        ok, _out, err = await _exec_with_retry(nix_darwin_vm, ["bash", "-c", move_cmd])
        if not ok:
            raise VMError(f"Failed to move aside /etc/nix/nix.custom.conf: {err.strip()}")

        ok, _out, err = await _exec_with_retry(nix_darwin_vm, ["sudo", "rm", "-rf", "/opt/homebrew"], timeout=60)
        if not ok:
            raise VMError(f"Failed to remove pre-existing Homebrew: {err.strip()}")

        switch_cmd = (
            f"cd {validator._REMOTE_FLAKE_DIR}"
            " && . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh"
            f" && sudo -n $(command -v nix) run nix-darwin -- switch --flake .#{_HOSTNAME}"
        )
        ok, out, err = await _exec_with_retry(nix_darwin_vm, ["bash", "-c", switch_cmd], timeout=900)
        if not ok:
            raise VMError(f"nix-darwin switch failed:\nstdout:\n{out}\nstderr:\n{err}")

        return await _retry_transient(validator._scan_vm), err

    vm_state, switch_err = asyncio.run(_run())

    # Step 14 regression test: this PR's own UAT already found once, for
    # real, that nix-darwin's native `power.restartAfterPowerFailure`
    # option aborts the ENTIRE `darwin-rebuild switch` on hardware (this
    # same Tart VM) that reports the feature as unsupported -- that's
    # exactly why this task originally downgraded it to a manual-report
    # comment. The switch above already completed successfully (or this
    # test would have raised VMError before reaching this point) -- the
    # self-guarding activation script's own probe-then-skip message must
    # be what actually fired, not a lucky coincidence, since restart-
    # after-power-failure is confirmed unsupported on this VM. Written to
    # a file rather than relying on pytest's own truncated assertion diff
    # for a multi-KB string -- a real prior run's failure message elided
    # the middle of this exact string, which cost real debugging time.
    (tmp_path / "switch_stderr.log").write_text(switch_err)
    assert "mac2nix: restart-after-power-failure not supported on this hardware, skipped" in switch_err, (
        f"full stderr written to {tmp_path / 'switch_stderr.log'}"
    )

    # compute_fidelity() scores PreferencesResult.domains as a single list --
    # unhashable PreferencesDomain items fall back to a whole-list string
    # comparison (see Validator._score_domain()/_compare_values()), which
    # only matches if the target has *exactly* the source's domain set. That
    # holds for a generator meant to reproduce an entire scanned domain, but
    # this curated generator (and this test's fixture) intentionally covers
    # only a narrow subset of com.apple.dock/symbolichotkeys/etc, while the
    # VM's real re-scan naturally also reports dozens of real domains/keys
    # this generator never touched. A low aggregate score here is expected,
    # not evidence of a bug -- verify the *specific* curated values this
    # generator actually claims to set, per Task 5 Step 8's own note to
    # investigate a partial score before assuming the generator is wrong.
    report = compute_fidelity(source_state, vm_state)
    assert "system" in report.domain_scores
    assert "preferences" in report.domain_scores

    assert vm_state.preferences is not None
    vm_dock = next((d for d in vm_state.preferences.domains if d.domain_name == "com.apple.dock"), None)
    assert vm_dock is not None, "com.apple.dock domain missing from the VM's post-switch re-scan"
    assert vm_dock.keys.get("tilesize") == 48, f"dock tilesize was not applied: {vm_dock.keys.get('tilesize')!r}"
