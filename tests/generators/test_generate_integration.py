"""Real `nix flake lock`/`nix build` integration test — the assembled flake, with
real curated-preferences output, actually evaluates.

Marked `nix_build` — excluded from the default `pytest`/`make test` run,
invoked via `make test-nix`. Like `test_scaffold_integration.py`, this test
NEVER calls `pytest.skip()`: if `nix`/`age`/`sops` aren't on PATH, or
there's no network access to resolve flake inputs, the test fails loudly.

This is the first point any *generated, data-driven* Nix content (as
opposed to the static scaffold templates) gets evaluated for real — proving
`preferences.nix`'s Jinja2-rendered output is not just individually
`nix-instantiate --parse`-valid (test_preferences.py's own `-m nix` test)
but actually composes correctly with the rest of the flake.
"""

from __future__ import annotations

import getpass
import subprocess
from pathlib import Path

import pytest

from mac2nix.generators import generate_all
from mac2nix.generators.scaffold import add_host, init_framework
from mac2nix.models.preferences import PreferencesDomain, PreferencesResult
from mac2nix.models.system import SystemConfig
from mac2nix.models.system_state import SystemState
from tests._scaffold_helpers import _nix_extra_access_tokens_args, _redirect_age_keys

pytestmark = pytest.mark.nix_build

_HOSTNAME = "mac2nix-generate-nix-build-test"


def _realistic_state() -> SystemState:
    """Covers all four render buckets: NATIVE (dock, plus power settings --
    including a POWER_SETTING_MAP-mapped sleep/boolean key, not just an
    unmapped one -- a real `nix build` failure caught power.sleep.* needing
    `null | positive-int | "never"`, not a raw scanned string, so this
    fixture must actually exercise that coercion path), CUSTOM_PREFS
    (symbolichotkeys-shaped), ACTIVATION_SCRIPT (wallpaper), and a
    non-skipped MANUAL_REPORT (an unmapped pmset key).
    """
    domains = [
        PreferencesDomain(domain_name="com.apple.dock", keys={"tilesize": 48}),
        PreferencesDomain(
            domain_name="com.apple.symbolichotkeys",
            keys={"AppleSymbolicHotKeys": {"32": {"enabled": 0}}},
        ),
    ]
    system = SystemConfig(
        hostname=_HOSTNAME,
        power_settings={
            "ac_power.sleep": "0",  # POWER_SETTING_MAP-mapped -> power.sleep.computer ("never")
            "battery_power.displaysleep": "10",  # POWER_SETTING_MAP-mapped -> power.sleep.display (int)
            "ac_power.womp": "1",  # POWER_SETTING_MAP-mapped -> networking.wakeOnLan.enable (bool)
            "ac_power.autorestart": "0",  # POWER_SETTING_MAP-mapped -> power.restartAfterPowerFailure (bool)
            "ac_power.hibernatemode": "3",  # not in POWER_SETTING_MAP -> MANUAL_REPORT
        },
        wallpaper_path=Path("/System/Library/Desktop Pictures/The Cliffs.heic"),
    )
    return SystemState(
        hostname=_HOSTNAME,
        macos_version="26.0",
        architecture="arm64",
        preferences=PreferencesResult(domains=domains),
        system=system,
    )


def test_generate_builds_for_real(tmp_path: Path) -> None:
    output_dir = tmp_path / "mac2nix-scaffold"
    username = getpass.getuser()
    token_args = _nix_extra_access_tokens_args()

    init_framework(output_dir)
    with _redirect_age_keys(tmp_path / "age-keys"):
        add_host(output_dir, _HOSTNAME, username, confirm_backup=lambda _fingerprint: True)

    result = generate_all(_realistic_state(), output_dir, _HOSTNAME, {"preferences"})
    assert result.ran == {"preferences"}
    assert (output_dir / "hosts" / "darwin" / _HOSTNAME / "preferences.nix").is_file()

    lock_result = subprocess.run(  # noqa: S603
        ["nix", "flake", "lock", *token_args],  # noqa: S607
        cwd=output_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert lock_result.returncode == 0, f"nix flake lock failed (exit {lock_result.returncode}):\n{lock_result.stderr}"

    build_result = subprocess.run(  # noqa: S603
        ["nix", "build", f".#darwinConfigurations.{_HOSTNAME}.system", "--no-link", *token_args],  # noqa: S607
        cwd=output_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build_result.returncode == 0, f"nix build failed (exit {build_result.returncode}):\n{build_result.stderr}"
