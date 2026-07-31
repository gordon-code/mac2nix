"""Tests for the mac2nix add-host CLI command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from mac2nix.cli import main
from mac2nix.generators.scaffold import init_framework
from tests._scaffold_helpers import _has_add_host_crypto_deps, _redirect_age_keys

require_add_host_crypto_deps = pytest.mark.skipif(
    not _has_add_host_crypto_deps(), reason="age-keygen and/or sops not on PATH"
)


@require_add_host_crypto_deps
class TestAddHostCommand:
    def test_registered(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "add-host" in result.output

    def test_succeeds_end_to_end_with_confirmed_input(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with _redirect_age_keys(tmp_path / "age-keys"):
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="CONFIRMED\n",
            )

        assert result.exit_code == 0, result.output
        assert (output_dir / "hosts" / "darwin" / "myhost" / "configuration.nix").is_file()
        assert (output_dir / "hosts" / "darwin" / "myhost" / ".mac2nix-meta.json").is_file()
        assert (output_dir / "users" / "alice.nix").is_file()
        assert (output_dir / "secrets" / "myhost.yaml").is_file()
        assert "myhost" in (output_dir / "flake.nix").read_text()
        assert "myhost" in (output_dir / ".sops.yaml").read_text()

    def test_declining_confirmation_aborts_with_no_files_left(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with _redirect_age_keys(tmp_path / "age-keys"):
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="nope\n",
            )

        assert result.exit_code != 0
        assert not (output_dir / "hosts" / "darwin" / "myhost").exists()
        assert not (output_dir / "users" / "alice.nix").exists()
        assert not (output_dir / "secrets" / "myhost.yaml").exists()
        assert "myhost" not in (output_dir / "flake.nix").read_text()

    def test_rerun_against_same_hostname_fails_cleanly(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)
        runner = CliRunner()

        with _redirect_age_keys(tmp_path / "age-keys"):
            first = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="CONFIRMED\n",
            )
            assert first.exit_code == 0, first.output

            second = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="CONFIRMED\n",
            )

        assert second.exit_code != 0
        assert "already registered" in second.output

    def test_non_init_directory_fails_cleanly(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "not-a-framework"
        output_dir.mkdir()

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
            input="CONFIRMED\n",
        )

        assert result.exit_code != 0
        assert "mac2nix" in result.output.lower() or "framework" in result.output.lower()


class TestAddHostValidation:
    """--hostname/--username character-allowlist rejection — no crypto tools required."""

    def test_invalid_hostname_rejected_before_any_crypto_call(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with patch("mac2nix.generators.scaffold.subprocess.run") as mock_run:
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "../evil", "--username", "alice"],
            )

        assert result.exit_code != 0
        assert "hostname" in result.output.lower()
        mock_run.assert_not_called()
        assert not (output_dir / "hosts").exists()

    def test_invalid_username_rejected_before_any_crypto_call(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with patch("mac2nix.generators.scaffold.subprocess.run") as mock_run:
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", 'foo"bar'],
            )

        assert result.exit_code != 0
        assert "username" in result.output.lower()
        mock_run.assert_not_called()
        assert not (output_dir / "hosts").exists()
