"""Tests for the mac2nix.onepassword module.

Most tests mock `op` entirely. TestStoreAgeKeyRealOp additionally exercises
the real `op` CLI, opted into via MAC2NIX_TEST_OP_VAULT, so a real 1Password
CLI JSON-schema change (e.g. the "uuid" vs "id" field) gets caught even
though the mocked tests above can only assert their own guess at the schema.
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mac2nix import onepassword


class TestAvailability:
    def test_is_available_true_when_on_path(self) -> None:
        with patch("mac2nix.onepassword.shutil.which", return_value="/usr/local/bin/op"):
            assert onepassword.is_available() is True

    def test_is_available_false_when_missing(self) -> None:
        with patch("mac2nix.onepassword.shutil.which", return_value=None):
            assert onepassword.is_available() is False

    def test_is_signed_in_true_on_zero_exit(self) -> None:
        with patch("mac2nix.onepassword.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            assert onepassword._is_signed_in() is True

    def test_is_signed_in_false_on_nonzero_exit(self) -> None:
        with patch("mac2nix.onepassword.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            assert onepassword._is_signed_in() is False


class TestStoreAgeKey:
    def test_raises_when_op_not_available(self, tmp_path: Path) -> None:
        key_path = tmp_path / "keys.txt"
        key_path.write_text("age-secret-key")

        with (
            patch("mac2nix.onepassword.is_available", return_value=False),
            pytest.raises(onepassword.OnePasswordError, match="not installed"),
        ):
            onepassword.store_age_key(key_path, vault="Private", title="t")

    def test_raises_when_create_fails(self, tmp_path: Path) -> None:
        """Covers the not-signed-in case too, since store_age_key() no longer pre-checks
        _is_signed_in() — see its own docstring for why (op whoami can report "not signed
        in" while the vault is still genuinely usable). The real `op document create`
        call's own error message is the source of truth instead.
        """
        key_path = tmp_path / "keys.txt"
        key_path.write_text("age-secret-key")

        with (
            patch("mac2nix.onepassword.is_available", return_value=True),
            patch("mac2nix.onepassword.subprocess.run") as mock_run,
        ):
            mock_run.return_value.returncode = 1
            mock_run.return_value.stderr = "vault is locked"
            with pytest.raises(onepassword.OnePasswordError, match="vault is locked"):
                onepassword.store_age_key(key_path, vault="Private", title="t")

    def test_raises_when_create_output_is_not_json(self, tmp_path: Path) -> None:
        key_path = tmp_path / "keys.txt"
        key_path.write_text("age-secret-key")

        with (
            patch("mac2nix.onepassword.is_available", return_value=True),
            patch("mac2nix.onepassword.subprocess.run") as mock_run,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "not json"
            with pytest.raises(onepassword.OnePasswordError, match="unexpected output"):
                onepassword.store_age_key(key_path, vault="Private", title="t")

    def test_raises_when_create_output_is_missing_uuid_field(self, tmp_path: Path) -> None:
        """A real `op document create --format json` response uses "uuid", not "id" —
        regression guard for that exact field-name mismatch (caught via a real op
        invocation, since a mock can only ever assert its own guess at the schema).
        """
        key_path = tmp_path / "keys.txt"
        key_path.write_text("age-secret-key")

        with (
            patch("mac2nix.onepassword.is_available", return_value=True),
            patch("mac2nix.onepassword.subprocess.run") as mock_run,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps({"id": "item123"})
            with pytest.raises(onepassword.OnePasswordError, match="unexpected output"):
                onepassword.store_age_key(key_path, vault="Private", title="t")

    def test_raises_when_verify_read_fails(self, tmp_path: Path) -> None:
        key_path = tmp_path / "keys.txt"
        key_path.write_text("age-secret-key")

        create_result = MagicMock(returncode=0, stdout=json.dumps({"uuid": "item123"}))
        verify_result = MagicMock(returncode=1, stderr=b"item not found")

        with (
            patch("mac2nix.onepassword.is_available", return_value=True),
            patch("mac2nix.onepassword.subprocess.run", side_effect=[create_result, verify_result]),
            pytest.raises(onepassword.OnePasswordError, match="item not found"),
        ):
            onepassword.store_age_key(key_path, vault="Private", title="t")

    def test_raises_when_readback_content_mismatches(self, tmp_path: Path) -> None:
        key_path = tmp_path / "keys.txt"
        key_path.write_text("age-secret-key")

        create_result = MagicMock(returncode=0, stdout=json.dumps({"uuid": "item123"}))
        verify_result = MagicMock(returncode=0, stdout=b"wrong-content")

        with (
            patch("mac2nix.onepassword.is_available", return_value=True),
            patch("mac2nix.onepassword.subprocess.run", side_effect=[create_result, verify_result]),
            pytest.raises(onepassword.OnePasswordError, match="did not match"),
        ):
            onepassword.store_age_key(key_path, vault="Private", title="t")

    def test_succeeds_when_readback_matches(self, tmp_path: Path) -> None:
        key_path = tmp_path / "keys.txt"
        key_path.write_text("age-secret-key")

        create_result = MagicMock(returncode=0, stdout=json.dumps({"uuid": "item123"}))
        verify_result = MagicMock(returncode=0, stdout=key_path.read_bytes())

        with (
            patch("mac2nix.onepassword.is_available", return_value=True),
            patch("mac2nix.onepassword.subprocess.run", side_effect=[create_result, verify_result]) as mock_run,
        ):
            item_id = onepassword.store_age_key(key_path, vault="Private", title="my title")

        assert item_id == "item123"
        create_call = mock_run.call_args_list[0]
        assert create_call.args[0] == [
            "op",
            "document",
            "create",
            str(key_path),
            "--title",
            "my title",
            "--vault",
            "Private",
            "--format",
            "json",
        ]


# ---------------------------------------------------------------------------
# store_age_key() — real 1Password CLI integration (opt-in, op_cli-marked)
# ---------------------------------------------------------------------------


class _OpTestVaultUnavailableError(Exception):
    """Raised by _resolve_op_test_vault() when a precondition is missing.

    Split out from the op_test_vault fixture below so each of the three skip
    conditions is independently unit-testable (TestResolveOpTestVault) without
    pytest.skip() aborting the very test that's checking the branch logic.
    """


def _resolve_op_test_vault() -> str:
    """Order matters: op must be on PATH before checking sign-in, which must be
    checked before the vault env var — each check assumes the previous one passed."""
    if not onepassword.is_available():
        raise _OpTestVaultUnavailableError("op CLI not on PATH")
    if not onepassword._is_signed_in():
        raise _OpTestVaultUnavailableError("not signed in to 1Password CLI (op whoami failed)")
    vault = os.environ.get("MAC2NIX_TEST_OP_VAULT")
    if not vault:
        raise _OpTestVaultUnavailableError("MAC2NIX_TEST_OP_VAULT not set — skipping real op CLI integration test")
    return vault


class TestResolveOpTestVault:
    """Runs in the default suite (not op_cli-marked) — unlike the real op_cli tier,
    where only whichever precondition is actually missing on a given machine gets
    exercised, these force each of the three skip branches independently."""

    def test_skips_when_op_not_available(self) -> None:
        with (
            patch("tests.test_onepassword.onepassword.is_available", return_value=False),
            pytest.raises(_OpTestVaultUnavailableError, match="not on PATH"),
        ):
            _resolve_op_test_vault()

    def test_skips_when_not_signed_in(self) -> None:
        with (
            patch("tests.test_onepassword.onepassword.is_available", return_value=True),
            patch("tests.test_onepassword.onepassword._is_signed_in", return_value=False),
            pytest.raises(_OpTestVaultUnavailableError, match="not signed in"),
        ):
            _resolve_op_test_vault()

    def test_skips_when_vault_env_var_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MAC2NIX_TEST_OP_VAULT", raising=False)
        with (
            patch("tests.test_onepassword.onepassword.is_available", return_value=True),
            patch("tests.test_onepassword.onepassword._is_signed_in", return_value=True),
            pytest.raises(_OpTestVaultUnavailableError, match="MAC2NIX_TEST_OP_VAULT not set"),
        ):
            _resolve_op_test_vault()

    def test_returns_vault_when_all_preconditions_met(self) -> None:
        with (
            patch("tests.test_onepassword.onepassword.is_available", return_value=True),
            patch("tests.test_onepassword.onepassword._is_signed_in", return_value=True),
            patch.dict(os.environ, {"MAC2NIX_TEST_OP_VAULT": "mac2nix-test"}),
        ):
            assert _resolve_op_test_vault() == "mac2nix-test"


@pytest.fixture
def op_test_vault() -> str:
    """Skip unless a real, signed-in `op` CLI and a caller-designated test
    vault are both available. This tier writes a real item into a real
    1Password vault, so it must never run against someone's account by
    accident — MAC2NIX_TEST_OP_VAULT must be set explicitly to the name of a
    vault that's safe to use for throwaway test items (e.g. a dedicated
    "mac2nix-test" vault, never "Private").
    """
    try:
        return _resolve_op_test_vault()
    except _OpTestVaultUnavailableError as exc:
        pytest.skip(str(exc))


@pytest.mark.op_cli
class TestStoreAgeKeyRealOp:
    def test_round_trip_against_real_vault(self, tmp_path: Path, op_test_vault: str) -> None:
        key_path = tmp_path / "keys.txt"
        key_path.write_text("age-secret-key-for-mac2nix-test\n")
        title = f"mac2nix-test-{uuid.uuid4()}"

        item_id = onepassword.store_age_key(key_path, vault=op_test_vault, title=title)
        try:
            assert item_id
        finally:
            subprocess.run(  # noqa: S603
                ["op", "document", "delete", item_id, "--vault", op_test_vault],  # noqa: S607
                capture_output=True,
                check=False,
            )
