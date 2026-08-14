"""Tests for the mac2nix generate CLI command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from mac2nix.cli import main
from mac2nix.generators.scaffold import init_framework
from mac2nix.models.preferences import PreferencesDomain, PreferencesResult
from mac2nix.models.system import SystemConfig
from mac2nix.models.system_state import SystemState
from tests._generate_helpers import _register_fake_host


def _write_scan_file(path: Path) -> None:
    domains = [PreferencesDomain(domain_name="com.apple.dock", keys={"tilesize": 48})]
    state = SystemState(
        hostname="h",
        macos_version="26.0",
        architecture="arm64",
        preferences=PreferencesResult(domains=domains),
        system=SystemConfig(hostname="h"),
    )
    state.to_json(path)


class TestGenerateCommand:
    def test_registered(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "generate" in result.output

    def test_produces_preferences_and_prints_summary(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)
        _register_fake_host(output_dir, "myhost")
        scan_file = tmp_path / "scan.json"
        _write_scan_file(scan_file)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["generate", str(output_dir), "--hostname", "myhost", "--scan-file", str(scan_file)],
        )

        assert result.exit_code == 0, result.output
        assert (output_dir / "hosts" / "darwin" / "myhost" / "preferences.nix").is_file()
        assert "preferences" in result.output

    def test_non_scaffolded_directory_fails_and_writes_nothing(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "not-a-repo"
        output_dir.mkdir()
        scan_file = tmp_path / "scan.json"
        _write_scan_file(scan_file)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["generate", str(output_dir), "--hostname", "myhost", "--scan-file", str(scan_file)],
        )

        assert result.exit_code != 0
        assert not (output_dir / "hosts").exists()

    def test_unregistered_hostname_fails_before_any_scan(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)
        scan_file = tmp_path / "scan.json"
        _write_scan_file(scan_file)

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["generate", str(output_dir), "--hostname", "ghost-host", "--scan-file", str(scan_file)],
        )

        assert result.exit_code != 0
        assert "ghost-host" in result.output
        assert not (output_dir / "hosts" / "darwin" / "ghost-host").exists()

    def test_unallowed_domain_rejected_before_scan_or_write(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)
        _register_fake_host(output_dir, "myhost")
        scan_file = tmp_path / "scan.json"
        _write_scan_file(scan_file)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "generate",
                str(output_dir),
                "--hostname",
                "myhost",
                "--scan-file",
                str(scan_file),
                "--domains",
                "homebrew",
            ],
        )

        assert result.exit_code != 0
        assert not (output_dir / "hosts" / "darwin" / "myhost" / "preferences.nix").exists()

    def test_unreadable_flake_nix_fails_cleanly_not_a_raw_traceback(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)
        flake_path = output_dir / "flake.nix"
        flake_path.chmod(0o000)

        try:
            runner = CliRunner()
            result = runner.invoke(main, ["generate", str(output_dir), "--hostname", "myhost"])
        finally:
            flake_path.chmod(0o644)

        assert result.exit_code != 0
        assert result.exc_info is not None
        assert result.exc_info[0] is SystemExit
        assert "Failed to read" in result.output

    def test_unreadable_hosts_dir_fails_cleanly_not_a_raw_traceback(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)
        hosts_dir = output_dir / "hosts"
        hosts_dir.mkdir()
        hosts_dir.chmod(0o000)

        try:
            runner = CliRunner()
            result = runner.invoke(main, ["generate", str(output_dir), "--hostname", "myhost"])
        finally:
            hosts_dir.chmod(0o755)

        assert result.exit_code != 0
        assert result.exc_info is not None
        assert result.exc_info[0] is SystemExit
        assert "Failed to check" in result.output

    def test_invalid_scan_file_fails_cleanly(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)
        _register_fake_host(output_dir, "myhost")
        scan_file = tmp_path / "scan.json"
        scan_file.write_text("not valid json{{{")

        runner = CliRunner()
        result = runner.invoke(
            main,
            ["generate", str(output_dir), "--hostname", "myhost", "--scan-file", str(scan_file)],
        )

        assert result.exit_code != 0
        assert "Failed to load scan file" in result.output

    def test_path_traversal_hostname_rejected(self, tmp_path: Path) -> None:
        """`--hostname` must go through the same allowlist add-host uses -- otherwise
        host_dir = output_dir / "hosts" / "darwin" / hostname escapes output_dir
        for a value like "../../../../tmp".
        """
        output_dir = tmp_path / "repo"
        init_framework(output_dir)

        runner = CliRunner()
        result = runner.invoke(main, ["generate", str(output_dir), "--hostname", "../../evil"])

        assert result.exit_code != 0
        assert not (tmp_path / "evil").exists()

    def test_inline_scan_success_when_no_scan_file_given(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)
        _register_fake_host(output_dir, "myhost")

        domains = [PreferencesDomain(domain_name="com.apple.dock", keys={"tilesize": 48})]
        state = SystemState(
            hostname="h",
            macos_version="26.0",
            architecture="arm64",
            preferences=PreferencesResult(domains=domains),
            system=SystemConfig(hostname="h"),
        )

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            runner = CliRunner()
            result = runner.invoke(main, ["generate", str(output_dir), "--hostname", "myhost"])

        assert result.exit_code == 0, result.output
        assert (output_dir / "hosts" / "darwin" / "myhost" / "preferences.nix").is_file()

    def test_inline_scan_runtime_error_fails_cleanly(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        init_framework(output_dir)
        _register_fake_host(output_dir, "myhost")

        with patch("mac2nix.cli.run_scan", new=AsyncMock(side_effect=RuntimeError("orchestrator failed"))):
            runner = CliRunner()
            result = runner.invoke(main, ["generate", str(output_dir), "--hostname", "myhost"])

        assert result.exit_code != 0
        assert "orchestrator failed" in result.output
        assert not (output_dir / "hosts" / "darwin" / "myhost" / "preferences.nix").exists()
