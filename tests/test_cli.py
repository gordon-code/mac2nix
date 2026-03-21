"""Tests for the mac2nix scan CLI command."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from mac2nix.cli import main
from mac2nix.models.system_state import SystemState

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_state(**kwargs: Any) -> SystemState:
    defaults: dict[str, Any] = {
        "hostname": "test-mac",
        "macos_version": "15.3.0",
        "architecture": "arm64",
    }
    defaults.update(kwargs)
    return SystemState(**defaults)


def _extract_json(output: str) -> str:
    """Extract the first JSON object from mixed CLI output (stdout+stderr mixed by CliRunner)."""
    start = output.find("{")
    if start == -1:
        return output
    return output[start:]


# ---------------------------------------------------------------------------
# CLI command registration
# ---------------------------------------------------------------------------


class TestCliCommandRegistration:
    def test_scan_command_is_registered(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])

        assert result.exit_code == 0
        assert "scan" in result.output

    def test_scan_help_shows_output_option(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])

        assert result.exit_code == 0
        assert "--output" in result.output or "-o" in result.output

    def test_scan_help_shows_scanner_option(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])

        assert result.exit_code == 0
        assert "--scanner" in result.output or "-s" in result.output


# ---------------------------------------------------------------------------
# Basic invocation
# ---------------------------------------------------------------------------


class TestScanCommandBasic:
    def test_scan_exits_zero(self) -> None:
        runner = CliRunner()
        state = _make_state()

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            result = runner.invoke(main, ["scan"])

        assert result.exit_code == 0

    def test_scan_outputs_valid_json(self) -> None:
        runner = CliRunner()
        state = _make_state()

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            result = runner.invoke(main, ["scan"])

        assert result.exit_code == 0
        try:
            # CliRunner mixes stderr+stdout; extract the JSON portion
            parsed = json.loads(_extract_json(result.output))
        except json.JSONDecodeError:
            pytest.fail(f"scan output does not contain valid JSON: {result.output!r}")

        assert parsed["hostname"] == "test-mac"
        assert parsed["macos_version"] == "15.3.0"
        assert parsed["architecture"] == "arm64"

    def test_scan_json_round_trips(self) -> None:
        runner = CliRunner()
        state = _make_state()

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            result = runner.invoke(main, ["scan"])

        assert result.exit_code == 0
        recovered = SystemState.from_json(_extract_json(result.output))
        assert recovered.hostname == state.hostname
        assert recovered.macos_version == state.macos_version
        assert recovered.architecture == state.architecture


# ---------------------------------------------------------------------------
# --output / -o option
# ---------------------------------------------------------------------------


class TestScanOutputOption:
    def test_output_writes_to_file(self, tmp_path: Path) -> None:
        runner = CliRunner()
        state = _make_state()
        output_file = tmp_path / "scan.json"

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            result = runner.invoke(main, ["scan", "--output", str(output_file)])

        assert result.exit_code == 0
        assert output_file.exists()
        parsed = json.loads(output_file.read_text())
        assert parsed["hostname"] == "test-mac"

    def test_short_flag_o_works(self, tmp_path: Path) -> None:
        runner = CliRunner()
        state = _make_state()
        output_file = tmp_path / "scan-short.json"

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            result = runner.invoke(main, ["scan", "-o", str(output_file)])

        assert result.exit_code == 0
        assert output_file.exists()

    def test_output_to_file_stdout_is_not_json_blob(self, tmp_path: Path) -> None:
        """When --output is given, stdout should not be the full JSON blob."""
        runner = CliRunner()
        state = _make_state()
        output_file = tmp_path / "scan.json"

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            result = runner.invoke(main, ["scan", "--output", str(output_file)])

        assert result.exit_code == 0
        # stdout should be empty when output goes to a file (summary goes to stderr)
        assert "scan_timestamp" not in result.output

    def test_output_creates_parent_dirs(self, tmp_path: Path) -> None:
        runner = CliRunner()
        state = _make_state()
        output_file = tmp_path / "nested" / "dir" / "scan.json"

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            result = runner.invoke(main, ["scan", "--output", str(output_file)])

        assert result.exit_code == 0
        assert output_file.exists()


# ---------------------------------------------------------------------------
# --scanner / -s option
# ---------------------------------------------------------------------------


class TestScanScannerOption:
    def test_scanner_short_flag_accepted(self) -> None:
        runner = CliRunner()
        state = _make_state()

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            result = runner.invoke(main, ["scan", "-s", "display"])

        assert result.exit_code == 0

    def test_scanner_repeatable(self) -> None:
        runner = CliRunner()
        state = _make_state()

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            result = runner.invoke(main, ["scan", "--scanner", "display", "--scanner", "audio"])

        assert result.exit_code == 0

    def test_unknown_scanner_exits_nonzero(self) -> None:
        runner = CliRunner()

        result = runner.invoke(main, ["scan", "--scanner", "bogus_scanner_xyz_nonexistent"])

        assert result.exit_code != 0

    def test_no_scanner_option_exits_zero(self) -> None:
        runner = CliRunner()
        state = _make_state()

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            result = runner.invoke(main, ["scan"])

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Progress on stderr
# ---------------------------------------------------------------------------


class TestScanProgressOutput:
    def test_json_portion_is_parseable(self) -> None:
        """When no --output flag, the JSON portion of output must be parseable."""
        runner = CliRunner()
        state = _make_state()

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            result = runner.invoke(main, ["scan"])

        assert result.exit_code == 0
        try:
            json.loads(_extract_json(result.output))
        except json.JSONDecodeError:
            pytest.fail(f"output does not contain valid JSON: {result.output!r}")


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestScanErrorHandling:
    def test_orchestrator_runtime_error_exits_nonzero(self) -> None:
        runner = CliRunner()

        with patch("mac2nix.cli.run_scan", new=AsyncMock(side_effect=RuntimeError("orchestrator failed"))):
            result = runner.invoke(main, ["scan"])

        assert result.exit_code != 0

    def test_orchestrator_non_runtime_error_exits_nonzero(self) -> None:
        runner = CliRunner()

        with patch("mac2nix.cli.run_scan", new=AsyncMock(side_effect=OSError("disk full"))):
            result = runner.invoke(main, ["scan"])

        assert result.exit_code != 0

    def test_summary_shown_after_writing_to_file(self, tmp_path: Path) -> None:
        """After a successful scan to file, the output file must exist."""
        runner = CliRunner()
        state = _make_state()
        output_file = tmp_path / "scan.json"

        with patch("mac2nix.cli.run_scan", new=AsyncMock(return_value=state)):
            result = runner.invoke(main, ["scan", "--output", str(output_file)])

        assert result.exit_code == 0
        assert output_file.exists()
