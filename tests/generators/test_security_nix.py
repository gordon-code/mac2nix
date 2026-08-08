"""Parse/eval/build checks for `modules/darwin/security.nix`'s YubiKey PIV sudo option.

`test_options_structure` (marker `nix`) only checks the module parses —
`--parse` never evaluates the module system, so it can't prove the option
actually renders the PAM line correctly. `test_evaluation`/
`test_build_with_option_enabled` (marker `nix_build`, never skipped) close
that gap with a real `nix eval`/`nix build` against a freshly-scaffolded
flake, mirroring `test_scaffold_integration.py`'s own real-build pattern.
"""

from __future__ import annotations

import getpass
import shutil
import subprocess
from pathlib import Path

import pytest

from mac2nix.generators.scaffold import add_host, init_framework
from tests._scaffold_helpers import _nix_extra_access_tokens_args, _redirect_age_keys

_HOSTNAME_DISABLED = "mac2nix-piv-disabled"
_HOSTNAME_ENABLED = "mac2nix-piv-enabled"


@pytest.fixture
def require_nix_instantiate() -> None:
    if shutil.which("nix-instantiate") is None:
        pytest.skip("nix-instantiate not on PATH")


@pytest.mark.nix
def test_options_structure(require_nix_instantiate: None) -> None:
    """The rendered security.nix module is syntactically valid Nix."""
    module_path = Path(__file__).parents[2] / "src/mac2nix/templates/scaffold/modules/darwin/security.nix"
    result = subprocess.run(  # noqa: S603
        ["nix-instantiate", "--parse", str(module_path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"nix-instantiate --parse failed:\n{result.stderr}"


def _enable_yubikey_piv_sudo(output_dir: Path, hostname: str) -> None:
    """Patch a registered host's configuration.nix to set `mac2nix.yubikeyPivSudo.enable = true;`.

    Mirrors how a real user enables the option — hand-editing their host's
    own configuration.nix — rather than inventing a test-only override
    mechanism.
    """
    config_path = output_dir / "hosts" / "darwin" / hostname / "configuration.nix"
    content = config_path.read_text()
    marker = "system.stateVersion = 7;"
    replacement = f"{marker}\n  mac2nix.yubikeyPivSudo.enable = true;"
    config_path.write_text(content.replace(marker, replacement))


@pytest.mark.nix_build
def test_evaluation(tmp_path: Path) -> None:
    """The PAM line is present when enabled and absent when disabled."""
    output_dir = tmp_path / "mac2nix-scaffold"
    # Two distinct usernames -- generate_age_key() refuses to reuse an
    # existing key across hosts, and this test never applies a real switch,
    # so neither username needs to match a real system account.
    username_disabled = f"{getpass.getuser()}-piv-disabled"
    username_enabled = f"{getpass.getuser()}-piv-enabled"
    token_args = _nix_extra_access_tokens_args()

    init_framework(output_dir)
    with _redirect_age_keys(tmp_path / "age-keys"):
        add_host(output_dir, _HOSTNAME_DISABLED, username_disabled, confirm_backup=lambda _fp: True)
        add_host(output_dir, _HOSTNAME_ENABLED, username_enabled, confirm_backup=lambda _fp: True)
    _enable_yubikey_piv_sudo(output_dir, _HOSTNAME_ENABLED)

    lock_result = subprocess.run(  # noqa: S603
        ["nix", "flake", "lock", *token_args],  # noqa: S607
        cwd=output_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert lock_result.returncode == 0, f"nix flake lock failed:\n{lock_result.stderr}"

    for hostname, should_contain in ((_HOSTNAME_DISABLED, False), (_HOSTNAME_ENABLED, True)):
        attr = f".#darwinConfigurations.{hostname}.config.security.pam.services.sudo_local.text"
        eval_cmd = ["nix", "eval", "--raw", attr, *token_args]
        eval_result = subprocess.run(  # noqa: S603
            eval_cmd,
            cwd=output_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        assert eval_result.returncode == 0, f"nix eval failed for {hostname}:\n{eval_result.stderr}"
        contains_pam_line = "pam_p11.so" in eval_result.stdout and "opensc-pkcs11.so" in eval_result.stdout
        assert contains_pam_line == should_contain, (
            f"{hostname}: expected pam_p11 line present={should_contain}, got stdout:\n{eval_result.stdout}"
        )


@pytest.mark.nix_build
def test_build_with_option_enabled(tmp_path: Path) -> None:
    """A full darwin system build succeeds with the option enabled, exercising pam_p11/opensc for real."""
    output_dir = tmp_path / "mac2nix-scaffold"
    username = getpass.getuser()
    token_args = _nix_extra_access_tokens_args()

    init_framework(output_dir)
    with _redirect_age_keys(tmp_path / "age-keys"):
        add_host(output_dir, _HOSTNAME_ENABLED, username, confirm_backup=lambda _fp: True)
    _enable_yubikey_piv_sudo(output_dir, _HOSTNAME_ENABLED)

    lock_result = subprocess.run(  # noqa: S603
        ["nix", "flake", "lock", *token_args],  # noqa: S607
        cwd=output_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert lock_result.returncode == 0, f"nix flake lock failed:\n{lock_result.stderr}"

    build_result = subprocess.run(  # noqa: S603
        ["nix", "build", f".#darwinConfigurations.{_HOSTNAME_ENABLED}.system", "--no-link", *token_args],  # noqa: S607
        cwd=output_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build_result.returncode == 0, f"nix build failed:\n{build_result.stderr}"
