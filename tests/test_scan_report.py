"""Tests for the scan_report module: outcome data model, log capture, remediation hints."""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from mac2nix.scan_report import (
    ScannerOutcome,
    ScannerStatus,
    attribute_to_scanner,
    capture_scanner_logs,
    get_remediation_hint,
)


class TestScannerOutcome:
    def test_construction_with_defaults(self) -> None:
        outcome = ScannerOutcome(name="shell", status=ScannerStatus.SUCCESS, elapsed=0.1)

        assert outcome.name == "shell"
        assert outcome.status == ScannerStatus.SUCCESS
        assert outcome.elapsed == 0.1
        assert outcome.warnings == ()
        assert outcome.error is None

    def test_construction_with_warnings_and_error(self) -> None:
        outcome = ScannerOutcome(
            name="homebrew",
            status=ScannerStatus.ERROR,
            elapsed=1.5,
            warnings=("warn 1", "warn 2"),
            error="RuntimeError: boom",
        )

        assert outcome.warnings == ("warn 1", "warn 2")
        assert outcome.error == "RuntimeError: boom"

    def test_is_frozen(self) -> None:
        outcome = ScannerOutcome(name="shell", status=ScannerStatus.SUCCESS, elapsed=0.1)

        with pytest.raises(AttributeError):
            outcome.name = "other"  # type: ignore[misc]


class TestCaptureScannerLogsConcurrency:
    def test_isolates_concurrent_scanners_warnings(self) -> None:
        barrier = threading.Barrier(2)

        def _run(name: str, message: str) -> None:
            barrier.wait()
            with attribute_to_scanner(name):
                logging.getLogger(f"mac2nix.scanners.{name}").warning(message)

        with capture_scanner_logs() as handler, ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(_run, "fake_a", "warn A"),
                executor.submit(_run, "fake_b", "warn B"),
            ]
            for future in futures:
                future.result()

        assert handler.pop_records("fake_a") == ["warn A"]
        assert handler.pop_records("fake_b") == ["warn B"]


class TestUnattributedWarnings:
    def test_warning_without_attribution_lands_in_unattributed(self) -> None:
        with capture_scanner_logs() as handler:
            logging.getLogger("mac2nix.orchestrator").warning("unattributed warning")

        assert handler.unattributed == ["unattributed warning"]
        assert handler.records == {}

    def test_unattributed_warning_never_attributed_to_a_scanner(self) -> None:
        with capture_scanner_logs() as handler:
            with attribute_to_scanner("fake_a"):
                logging.getLogger("mac2nix.scanners.fake_a").warning("warn A")
            logging.getLogger("mac2nix.orchestrator").warning("unattributed warning")

        assert handler.unattributed == ["unattributed warning"]
        assert handler.pop_records("fake_a") == ["warn A"]


class TestPopRecords:
    def test_pop_records_clears_entry(self) -> None:
        with capture_scanner_logs() as handler:
            with attribute_to_scanner("fake_a"):
                logging.getLogger("mac2nix.scanners.fake_a").warning("warn A")

            assert handler.pop_records("fake_a") == ["warn A"]
            assert handler.pop_records("fake_a") == []

    def test_pop_records_missing_scanner_returns_empty(self) -> None:
        with capture_scanner_logs() as handler:
            assert handler.pop_records("never_ran") == []


class TestCaptureScannerLogsTeardown:
    def test_propagate_restored_after_exception(self) -> None:
        logger = logging.getLogger("mac2nix")

        def _raise_inside_capture() -> None:
            with capture_scanner_logs():
                assert logger.propagate is False
                msg = "boom"
                raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="boom"):
            _raise_inside_capture()

        assert logger.propagate is True

    def test_handler_removed_after_exception(self) -> None:
        logger = logging.getLogger("mac2nix")
        handlers_before = list(logger.handlers)

        def _raise_inside_capture() -> None:
            with capture_scanner_logs():
                msg = "boom"
                raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="boom"):
            _raise_inside_capture()

        assert logger.handlers == handlers_before


class TestSanitizeForDisplay:
    def test_strips_ansi_escape_sequence(self) -> None:
        with capture_scanner_logs() as handler, attribute_to_scanner("fake_a"):
            logging.getLogger("mac2nix.scanners.fake_a").warning("clear screen: \x1b[2J\x1b[H done")

        records = handler.pop_records("fake_a")
        assert len(records) == 1
        assert "\x1b" not in records[0]
        assert "clear screen: [2J[H done" in records[0]

    def test_preserves_tab_and_newline(self) -> None:
        with capture_scanner_logs() as handler, attribute_to_scanner("fake_a"):
            logging.getLogger("mac2nix.scanners.fake_a").warning("col1\tcol2\nline2")

        records = handler.pop_records("fake_a")
        assert records == ["col1\tcol2\nline2"]

    def test_strips_c1_control_character(self) -> None:
        with capture_scanner_logs() as handler, attribute_to_scanner("fake_a"):
            logging.getLogger("mac2nix.scanners.fake_a").warning("csi: \x9b2J done")

        records = handler.pop_records("fake_a")
        assert len(records) == 1
        assert "\x9b" not in records[0]
        assert "csi: 2J done" in records[0]


class TestGetRemediationHint:
    def test_plist_permission_denied_pattern(self) -> None:
        hint = get_remediation_hint("Permission denied reading plist: /Library/Preferences/x.plist")

        assert hint is not None
        assert "Full Disk Access" in hint

    def test_brew_timeout_message_from_run_command(self) -> None:
        message = "Command timed out after 30s: ['brew', 'bundle', 'dump', '--file=-']"

        hint = get_remediation_hint(message)

        assert hint is not None
        assert "brew bundle dump" in hint

    def test_brew_bundle_dump_message_from_homebrew_scanner(self) -> None:
        message = "Unable to enumerate Homebrew state via 'brew bundle dump'"

        hint = get_remediation_hint(message)

        assert hint is not None
        assert "brew bundle dump" in hint

    def test_negative_case_returns_none(self) -> None:
        assert get_remediation_hint("some unrelated message") is None
