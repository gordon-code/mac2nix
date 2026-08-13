"""Tests for the mac2nix generate CLI command."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from mac2nix.cli import main
from mac2nix.generators.scaffold import _read_template, _render_placeholders, init_framework
from mac2nix.models.preferences import PreferencesDomain, PreferencesResult
from mac2nix.models.system import SystemConfig
from mac2nix.models.system_state import SystemState


def _register_fake_host(output_dir: Path, hostname: str, username: str = "testuser") -> Path:
    """Register a host without real age-keygen/sops -- the generate CLI never touches
    secrets, only configuration.nix and .mac2nix-meta.json.
    """
    host_dir = output_dir / "hosts" / "darwin" / hostname
    host_dir.mkdir(parents=True)
    template = _read_template("hosts", "darwin", "configuration.nix")
    (host_dir / "configuration.nix").write_text(_render_placeholders(template, hostname, username))
    meta = {"hostname": hostname, "username": username, "system": "aarch64-darwin", "age_public_key": "age1fake"}
    (host_dir / ".mac2nix-meta.json").write_text(json.dumps(meta))
    return host_dir


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
