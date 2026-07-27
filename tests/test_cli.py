"""Tests for the mac2nix scan CLI command."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner
from rich.console import Console

from mac2nix.cli import _build_scan_table, _status_icon, main
from mac2nix.models.system_state import SystemState
from mac2nix.scan_report import ScannerOutcome, ScannerStatus

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


def _render_table(outcomes: dict[str, ScannerOutcome], order: list[str], width: int = 100) -> str:
    console = Console(record=True, width=width)
    console.print(_build_scan_table(outcomes, order))
    return console.export_text()


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


# ---------------------------------------------------------------------------
# _status_icon / _build_scan_table
# ---------------------------------------------------------------------------


class TestStatusIcon:
    def test_skipped_is_visually_distinct_from_success(self) -> None:
        assert _status_icon(ScannerStatus.SKIPPED) != _status_icon(ScannerStatus.SUCCESS)


class TestBuildScanTablePending:
    def test_scanner_with_no_outcome_yet_still_shows_its_name(self) -> None:
        """Regression test: previously a pending scanner (e.g. "applications") never appeared."""
        text = _render_table({}, ["applications"])

        assert "applications" in text


class TestBuildScanTableSuccess:
    def test_success_row_has_no_warning_or_error_detail_and_no_sub_rows(self) -> None:
        outcomes = {"shell": ScannerOutcome(name="shell", status=ScannerStatus.SUCCESS, elapsed=0.3)}

        text = _render_table(outcomes, ["shell"])

        assert "shell" in text
        assert "warning" not in text.lower()
        assert "error" not in text.lower()
        assert "↳" not in text


class TestBuildScanTableWarning:
    def test_warning_row_shows_short_detail_with_full_warning_and_hint_as_sub_rows(self) -> None:
        message = "Permission denied reading plist (TCC-protected): /Library/Preferences/x.plist"
        outcomes = {
            "preferences": ScannerOutcome(
                name="preferences",
                status=ScannerStatus.WARNING,
                elapsed=1.2,
                warnings=(message,),
            )
        }

        # wide console avoids line-wrapping the hint, so substring checks are exact
        text = _render_table(outcomes, ["preferences"], width=200)
        lines = text.splitlines()
        main_row = next(line for line in lines if "preferences" in line)

        assert "1 warning(s)" in main_row
        assert message not in main_row
        assert message in text
        assert "Grant Full Disk Access" in text

    def test_long_warning_wraps_within_column_instead_of_widening_table(self) -> None:
        long_message = (
            "Command exited 1: ['plutil', '-convert', 'xml1', '-o', '-', "
            "'/Users/example/Library/Preferences/net.screensolutions.something.plist'] "
            "stderr: Property List error: Unexpected character W at line 1"
        )
        outcomes = {
            "preferences": ScannerOutcome(
                name="preferences",
                status=ScannerStatus.WARNING,
                elapsed=1.2,
                warnings=(long_message,),
            )
        }

        # A console much wider than the column's max_width -- if the column weren't
        # capped, Rich would render the whole message on one very long line.
        text = _render_table(outcomes, ["preferences"], width=200)
        lines = [line for line in text.splitlines() if line.strip()]

        assert not any(len(line) > 120 for line in lines), (
            "no rendered line should approach the full 200-column console width"
        )
        assert not any(long_message in line for line in lines), "the full message must not fit on a single line"

    def test_root_only_permission_warning_does_not_suggest_full_disk_access(self) -> None:
        message = (
            "Permission denied reading plist (root-only, not a Full Disk Access issue): "
            "/Library/Preferences/com.apple.apsd.plist"
        )
        outcomes = {
            "preferences": ScannerOutcome(
                name="preferences",
                status=ScannerStatus.WARNING,
                elapsed=1.2,
                warnings=(message,),
            )
        }

        # Message content may be word-wrapped within the message column's max width
        # (see test_long_warning_wraps_within_column_instead_of_widening_table), so
        # check for distinct short fragments rather than the whole string verbatim.
        text = _render_table(outcomes, ["preferences"], width=200)

        assert "root-only" in text
        assert "apsd.plist" in text
        assert "Grant Full Disk Access" not in text
        assert "owned by root" in text


class TestBuildScanTableError:
    def test_error_row_shows_short_detail_and_full_message_once_in_sub_row(self) -> None:
        message = "RuntimeError: boom failure"
        outcomes = {
            "homebrew": ScannerOutcome(
                name="homebrew",
                status=ScannerStatus.ERROR,
                elapsed=0.5,
                error=message,
            )
        }

        text = _render_table(outcomes, ["homebrew"], width=200)
        lines = text.splitlines()
        main_row = next(line for line in lines if "homebrew" in line)

        assert "error" in main_row
        assert message not in main_row
        assert text.count(message) == 1

    def test_error_row_with_warnings_shows_both_warnings_before_error(self) -> None:
        warning_message = "some warning"
        error_message = "RuntimeError: boom"
        outcomes = {
            "homebrew": ScannerOutcome(
                name="homebrew",
                status=ScannerStatus.ERROR,
                elapsed=0.5,
                warnings=(warning_message,),
                error=error_message,
            )
        }

        text = _render_table(outcomes, ["homebrew"], width=200)

        assert warning_message in text
        assert error_message in text
        assert text.index(warning_message) < text.index(error_message)


class TestBuildScanTableSkipped:
    def test_skipped_row_renders_distinctly_from_success_row(self) -> None:
        outcomes = {
            "docker": ScannerOutcome(name="docker", status=ScannerStatus.SKIPPED, elapsed=0.0),
            "shell": ScannerOutcome(name="shell", status=ScannerStatus.SUCCESS, elapsed=0.1),
        }

        text = _render_table(outcomes, ["docker", "shell"])
        lines = text.splitlines()
        docker_row = next(line for line in lines if "docker" in line)
        shell_row = next(line for line in lines if "shell" in line)

        skipped_icon, _ = _status_icon(ScannerStatus.SKIPPED)
        success_icon, _ = _status_icon(ScannerStatus.SUCCESS)
        assert skipped_icon in docker_row
        assert success_icon in shell_row
        assert skipped_icon != success_icon


# ---------------------------------------------------------------------------
# Live table integration: summary tally and general warnings
# ---------------------------------------------------------------------------


class TestScanCommandSummaryTally:
    def test_summary_line_includes_status_tally(self) -> None:
        runner = CliRunner()
        state = _make_state()

        async def fake_run_scan(
            scanners: list[str] | None = None,
            progress_callback: Any = None,
            log_handler: Any = None,
        ) -> SystemState:
            if progress_callback is not None:
                progress_callback(ScannerOutcome(name="shell", status=ScannerStatus.SUCCESS, elapsed=0.1))
                progress_callback(
                    ScannerOutcome(
                        name="preferences",
                        status=ScannerStatus.WARNING,
                        elapsed=0.2,
                        warnings=("some warning",),
                    )
                )
            return state

        with patch("mac2nix.cli.run_scan", new=fake_run_scan):
            result = runner.invoke(main, ["scan"])

        assert result.exit_code == 0
        assert "1 success" in result.output
        assert "1 completed with warnings" in result.output


class TestScanCommandGeneralWarnings:
    def test_unattributed_warnings_shown_as_general_warnings_section(self) -> None:
        runner = CliRunner()
        state = _make_state()
        unattributed_message = "prefetch warning: system_profiler slow to respond"

        async def fake_run_scan(
            scanners: list[str] | None = None,
            progress_callback: Any = None,
            log_handler: Any = None,
        ) -> SystemState:
            if log_handler is not None:
                log_handler.unattributed.append(unattributed_message)
            return state

        with patch("mac2nix.cli.run_scan", new=fake_run_scan):
            result = runner.invoke(main, ["scan"])

        assert result.exit_code == 0
        assert "General warnings" in result.output
        assert unattributed_message in result.output
