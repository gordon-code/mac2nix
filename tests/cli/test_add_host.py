"""Tests for the mac2nix add-host CLI command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner

from mac2nix import onepassword
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
                input="y\nn\nn\n",
            )

        assert result.exit_code == 0, result.output
        assert (output_dir / "hosts" / "darwin" / "myhost" / "configuration.nix").is_file()
        assert (output_dir / "hosts" / "darwin" / "myhost" / ".mac2nix-meta.json").is_file()
        assert (output_dir / "users" / "alice.nix").is_file()
        assert (output_dir / "secrets" / "myhost.yaml").is_file()
        assert result.output.count("age key fingerprint:") == 1
        assert "myhost" in (output_dir / "flake.nix").read_text()
        assert "myhost" in (output_dir / ".sops.yaml").read_text()

    def test_declining_confirmation_reprompts_then_aborts_on_eof(self, tmp_path: Path) -> None:
        """Answering "n" must reprompt (not abort outright) — only exhausting stdin aborts."""
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with _redirect_age_keys(tmp_path / "age-keys"):
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="n\n",
            )

        assert result.exit_code != 0
        assert "please back it up before continuing" in result.output
        assert not (output_dir / "hosts" / "darwin" / "myhost").exists()
        assert not (output_dir / "users" / "alice.nix").exists()
        assert not (output_dir / "secrets" / "myhost.yaml").exists()
        assert "myhost" not in (output_dir / "flake.nix").read_text()

    def test_declining_confirmation_reprompts_until_confirmed(self, tmp_path: Path) -> None:
        """Two "n" answers must not abort — only when the caller eventually answers "y"."""
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with _redirect_age_keys(tmp_path / "age-keys"):
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="n\nn\ny\nn\nn\n",
            )

        assert result.exit_code == 0, result.output
        assert result.output.count("please back it up before continuing") == 2
        assert (output_dir / "hosts" / "darwin" / "myhost").exists()

    def test_rerun_against_same_hostname_fails_cleanly(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)
        runner = CliRunner()

        with _redirect_age_keys(tmp_path / "age-keys"):
            first = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="y\nn\nn\n",
            )
            assert first.exit_code == 0, first.output

            second = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="y\nn\nn\n",
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
            input="y\nn\nn\n",
        )

        assert result.exit_code != 0
        assert "mac2nix" in result.output.lower() or "framework" in result.output.lower()

    def test_register_another_host_loop_registers_second_host(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with _redirect_age_keys(tmp_path / "age-keys"):
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="y\ny\nmyhost2\nbob\naarch64-darwin\ny\nn\nn\n",
            )

        assert result.exit_code == 0, result.output
        assert (output_dir / "hosts" / "darwin" / "myhost").exists()
        assert (output_dir / "hosts" / "darwin" / "myhost2").exists()
        assert (output_dir / "users" / "bob.nix").exists()
        assert "myhost2" in (output_dir / "flake.nix").read_text()

    def test_register_another_host_rejects_invalid_hostname_then_reprompts(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with _redirect_age_keys(tmp_path / "age-keys"):
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="y\ny\n../evil\nmyhost2\nbob\naarch64-darwin\ny\nn\nn\n",
            )

        assert result.exit_code == 0, result.output
        assert (output_dir / "hosts" / "darwin" / "myhost2").exists()

    def test_op_vault_success_skips_manual_confirmation(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with (
            _redirect_age_keys(tmp_path / "age-keys"),
            patch("mac2nix.cli.onepassword.store_age_key", return_value="item123") as mock_store,
        ):
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice", "--op-vault", "Private"],
                input="n\nn\n",
            )

        assert result.exit_code == 0, result.output
        assert "Backed up to 1Password vault 'Private' (item item123)" in result.output
        assert "Have you backed up the private key" not in result.output
        mock_store.assert_called_once()
        kwargs = mock_store.call_args.kwargs
        assert kwargs["vault"] == "Private"
        assert "myhost" in kwargs["title"]
        assert "alice" in kwargs["title"]
        assert (output_dir / "hosts" / "darwin" / "myhost").exists()

    def test_op_vault_failure_falls_back_to_manual_confirmation(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with (
            _redirect_age_keys(tmp_path / "age-keys"),
            patch(
                "mac2nix.cli.onepassword.store_age_key",
                side_effect=onepassword.OnePasswordError("not signed in"),
            ),
        ):
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice", "--op-vault", "Private"],
                input="y\nn\nn\n",
            )

        assert result.exit_code == 0, result.output
        assert "1Password backup failed (not signed in)" in result.output
        assert "Have you backed up the private key" in result.output
        assert (output_dir / "hosts" / "darwin" / "myhost").exists()

    def test_flake_lock_prompt_invokes_nix_when_confirmed(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with (
            _redirect_age_keys(tmp_path / "age-keys"),
            patch("mac2nix.cli._run_nix_flake_lock") as mock_lock,
        ):
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="y\nn\ny\n",
            )

        assert result.exit_code == 0, result.output
        mock_lock.assert_called_once_with(output_dir)

    def test_flake_lock_prompt_defaults_to_yes_on_bare_enter(self, tmp_path: Path) -> None:
        """Pressing Enter (no explicit y/n) at the flake-lock prompt must run it, not skip it."""
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with (
            _redirect_age_keys(tmp_path / "age-keys"),
            patch("mac2nix.cli._run_nix_flake_lock") as mock_lock,
        ):
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="y\nn\n\n",
            )

        assert result.exit_code == 0, result.output
        assert "Run `nix flake lock` now? [Y/n]" in result.output
        mock_lock.assert_called_once_with(output_dir)

    def test_flake_lock_prompt_reports_failure(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        with (
            _redirect_age_keys(tmp_path / "age-keys"),
            patch(
                "mac2nix.cli._run_nix_flake_lock",
                side_effect=click.ClickException("nix flake lock failed (exit 1)"),
            ),
        ):
            result = runner.invoke(
                main,
                ["add-host", str(output_dir), "--hostname", "myhost", "--username", "alice"],
                input="y\nn\ny\n",
            )

        assert result.exit_code != 0
        assert "nix flake lock failed" in result.output


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
