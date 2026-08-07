"""Tests for the mac2nix.onepassword module — all `op` calls mocked, no real CLI needed."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

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
            assert onepassword.is_signed_in() is True

    def test_is_signed_in_false_on_nonzero_exit(self) -> None:
        with patch("mac2nix.onepassword.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            assert onepassword.is_signed_in() is False


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
        is_signed_in() — see its own docstring for why (op whoami can report "not signed
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

        create_result = type("R", (), {"returncode": 0, "stdout": json.dumps({"uuid": "item123"})})()
        verify_result = type("R", (), {"returncode": 1, "stderr": b"item not found"})()

        with (
            patch("mac2nix.onepassword.is_available", return_value=True),
            patch("mac2nix.onepassword.subprocess.run", side_effect=[create_result, verify_result]),
            pytest.raises(onepassword.OnePasswordError, match="item not found"),
        ):
            onepassword.store_age_key(key_path, vault="Private", title="t")

    def test_raises_when_readback_content_mismatches(self, tmp_path: Path) -> None:
        key_path = tmp_path / "keys.txt"
        key_path.write_text("age-secret-key")

        create_result = type("R", (), {"returncode": 0, "stdout": json.dumps({"uuid": "item123"})})()
        verify_result = type("R", (), {"returncode": 0, "stdout": b"wrong-content"})()

        with (
            patch("mac2nix.onepassword.is_available", return_value=True),
            patch("mac2nix.onepassword.subprocess.run", side_effect=[create_result, verify_result]),
            pytest.raises(onepassword.OnePasswordError, match="did not match"),
        ):
            onepassword.store_age_key(key_path, vault="Private", title="t")

    def test_succeeds_when_readback_matches(self, tmp_path: Path) -> None:
        key_path = tmp_path / "keys.txt"
        key_path.write_text("age-secret-key")

        create_result = type("R", (), {"returncode": 0, "stdout": json.dumps({"uuid": "item123"})})()
        verify_result = type("R", (), {"returncode": 0, "stdout": key_path.read_bytes()})()

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
