"""Tests for the mac2nix validate and discover CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from mac2nix.cli import main
from mac2nix.models.system_state import SystemState
from mac2nix.vm.discovery import DiscoveryResult
from mac2nix.vm.validator import DomainScore, FidelityReport

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_state(**kwargs: object) -> SystemState:
    defaults: dict[str, object] = {
        "hostname": "test-mac",
        "macos_version": "15.3.0",
        "architecture": "arm64",
    }
    defaults.update(kwargs)
    return SystemState(**defaults)  # type: ignore[arg-type]


def _make_fidelity(score: float = 0.95) -> FidelityReport:
    return FidelityReport(
        overall_score=score,
        domain_scores={
            "homebrew": DomainScore(
                domain="homebrew",
                score=score,
                total_fields=10,
                matching_fields=int(score * 10),
                mismatches=[],
            )
        },
        mismatches=[],
    )


def _make_discovery_result(package: str = "ripgrep") -> DiscoveryResult:
    return DiscoveryResult(
        package=package,
        package_type="brew",
        created_files=["/opt/homebrew/bin/rg"],
        modified_files=[],
        deleted_files=[],
        executables_found={"apps": [], "binaries": ["/opt/homebrew/bin/rg"]},
    )


# ---------------------------------------------------------------------------
# validate command — registration and help
# ---------------------------------------------------------------------------


class TestValidateCommandRegistration:
    def test_validate_registered(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "validate" in result.output

    def test_validate_help_shows_options(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["validate", "--help"])
        assert result.exit_code == 0
        assert "--flake-path" in result.output
        assert "--scan-file" in result.output
        assert "--base-vm" in result.output
        assert "--vm-user" in result.output
        assert "--vm-password" in result.output


# ---------------------------------------------------------------------------
# validate command — tart not available
# ---------------------------------------------------------------------------


class TestValidateTartUnavailable:
    def test_exits_with_error_when_tart_missing(self, tmp_path: Path) -> None:
        scan_file = tmp_path / "state.json"
        scan_file.write_text(_make_state().to_json())
        flake_dir = tmp_path / "flake"
        flake_dir.mkdir()

        runner = CliRunner()
        with patch("mac2nix.vm.manager.TartVMManager.is_available", return_value=False):
            result = runner.invoke(
                main,
                ["validate", "--flake-path", str(flake_dir), "--scan-file", str(scan_file)],
            )

        assert result.exit_code != 0
        assert "tart" in result.output.lower()


# ---------------------------------------------------------------------------
# validate command — successful run
# ---------------------------------------------------------------------------


class TestValidateSuccess:
    def test_validate_calls_asyncio_run(self, tmp_path: Path) -> None:
        scan_file = tmp_path / "state.json"
        scan_file.write_text(_make_state().to_json())
        flake_dir = tmp_path / "flake"
        flake_dir.mkdir()

        called_with_coroutine = False

        runner = CliRunner()
        with (
            patch("mac2nix.vm.manager.TartVMManager.is_available", return_value=True),
            patch("mac2nix.cli.asyncio.run") as mock_run,
        ):

            def fake_run(coro: object) -> None:  # type: ignore[return]
                nonlocal called_with_coroutine
                called_with_coroutine = coro is not None
                # Close the coroutine to avoid RuntimeWarning
                if hasattr(coro, "close"):
                    coro.close()

            mock_run.side_effect = fake_run
            result = runner.invoke(
                main,
                ["validate", "--flake-path", str(flake_dir), "--scan-file", str(scan_file)],
            )

        assert result.exit_code == 0
        assert called_with_coroutine, "asyncio.run was not called with a coroutine"

    def test_missing_scan_file_exits_nonzero(self, tmp_path: Path) -> None:
        flake_dir = tmp_path / "flake"
        flake_dir.mkdir()

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "validate",
                "--flake-path",
                str(flake_dir),
                "--scan-file",
                str(tmp_path / "nonexistent.json"),
            ],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# discover command — registration and help
# ---------------------------------------------------------------------------


class TestDiscoverCommandRegistration:
    def test_discover_registered(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "discover" in result.output

    def test_discover_help_shows_options(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["discover", "--help"])
        assert result.exit_code == 0
        assert "--package" in result.output
        assert "--type" in result.output
        assert "--base-vm" in result.output
        assert "--output" in result.output


# ---------------------------------------------------------------------------
# discover command — tart not available
# ---------------------------------------------------------------------------


class TestDiscoverTartUnavailable:
    def test_exits_with_error_when_tart_missing(self) -> None:
        runner = CliRunner()
        with patch("mac2nix.vm.manager.TartVMManager.is_available", return_value=False):
            result = runner.invoke(main, ["discover", "--package", "ripgrep"])

        assert result.exit_code != 0
        assert "tart" in result.output.lower()


# ---------------------------------------------------------------------------
# discover command — successful run
# ---------------------------------------------------------------------------


class TestDiscoverSuccess:
    def test_prints_json_to_stdout(self) -> None:
        discovery = _make_discovery_result("ripgrep")
        json_out = discovery.model_dump_json(indent=2)

        def fake_run(coro: object) -> str:
            if hasattr(coro, "close"):
                coro.close()
            return json_out

        runner = CliRunner()
        with (
            patch("mac2nix.vm.manager.TartVMManager.is_available", return_value=True),
            patch("mac2nix.cli.asyncio.run", side_effect=fake_run),
        ):
            result = runner.invoke(main, ["discover", "--package", "ripgrep"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["package"] == "ripgrep"
        assert data["package_type"] == "brew"

    def test_writes_json_to_file(self, tmp_path: Path) -> None:
        discovery = _make_discovery_result("ripgrep")
        json_out = discovery.model_dump_json(indent=2)
        out_file = tmp_path / "result.json"

        def fake_run(coro: object) -> str:
            if hasattr(coro, "close"):
                coro.close()
            return json_out

        runner = CliRunner()
        with (
            patch("mac2nix.vm.manager.TartVMManager.is_available", return_value=True),
            patch("mac2nix.cli.asyncio.run", side_effect=fake_run),
        ):
            result = runner.invoke(
                main,
                ["discover", "--package", "ripgrep", "--output", str(out_file)],
            )

        assert result.exit_code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert data["package"] == "ripgrep"

    def test_cask_type_accepted(self) -> None:
        discovery = _make_discovery_result("firefox")
        json_out = discovery.model_dump_json(indent=2)

        def fake_run(coro: object) -> str:
            if hasattr(coro, "close"):
                coro.close()
            return json_out

        runner = CliRunner()
        with (
            patch("mac2nix.vm.manager.TartVMManager.is_available", return_value=True),
            patch("mac2nix.cli.asyncio.run", side_effect=fake_run),
        ):
            result = runner.invoke(
                main,
                ["discover", "--package", "firefox", "--type", "cask"],
            )

        assert result.exit_code == 0

    def test_invalid_type_rejected(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["discover", "--package", "foo", "--type", "pip"])
        assert result.exit_code != 0
