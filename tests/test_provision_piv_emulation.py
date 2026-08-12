"""Tests for scripts/provision_piv_emulation.py — mocked subprocess-level orchestration checks.

Real verification of this script happens in tests/vm/test_piv_sudo_vm.py and
tests/vm/test_piv_sudo_native.py (actual VM/CI runs) — these tests only
assert each stage is invoked with the right arguments in the right order.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import provision_piv_emulation
import pytest


def _completed(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


class TestInstallVpcdBundle:
    def test_patches_info_plist_with_hex_vendor_and_product_id(self, tmp_path: Path) -> None:
        with (
            patch("provision_piv_emulation._DRIVER_DEST", tmp_path / "ifd-vpcd.bundle"),
            patch("provision_piv_emulation._run", return_value=_completed()) as mock_run,
        ):
            provision_piv_emulation._install_vpcd_bundle(tmp_path / "store-path", vendor_id=1452, product_id=33029)

        calls = [c.args[0] for c in mock_run.call_args_list]
        plutil_calls = [c for c in calls if "plutil" in c]
        assert any('["0x05ac"]' in " ".join(c) for c in plutil_calls), plutil_calls
        assert any('["0x8105"]' in " ".join(c) for c in plutil_calls), plutil_calls

    def test_removes_existing_bundle_before_copying(self, tmp_path: Path) -> None:
        existing = tmp_path / "ifd-vpcd.bundle"
        existing.mkdir()
        with (
            patch("provision_piv_emulation._DRIVER_DEST", existing),
            patch("provision_piv_emulation._run", return_value=_completed()) as mock_run,
        ):
            provision_piv_emulation._install_vpcd_bundle(tmp_path / "store-path", vendor_id=1, product_id=2)

        first_call = mock_run.call_args_list[0].args[0]
        assert first_call[:3] == ["sudo", "rm", "-rf"]


class TestStartJcardsim:
    def test_raises_if_process_exits_immediately(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)  # _start_jcardsim writes jcardsim-mac2nix.cfg to the CWD
        dead_process = MagicMock()
        dead_process.poll.return_value = 1
        with (
            patch("provision_piv_emulation.subprocess.Popen", return_value=dead_process),
            patch("provision_piv_emulation.time.sleep"),
            pytest.raises(provision_piv_emulation.ProvisioningError, match="exited immediately"),
        ):
            provision_piv_emulation._start_jcardsim(tmp_path / "jcardsim.jar", tmp_path / "pivapplet-classes")

    def test_returns_process_when_still_running(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)  # _start_jcardsim writes jcardsim-mac2nix.cfg to the CWD
        live_process = MagicMock()
        live_process.poll.return_value = None
        with (
            patch("provision_piv_emulation.subprocess.Popen", return_value=live_process),
            patch("provision_piv_emulation.time.sleep"),
        ):
            result = provision_piv_emulation._start_jcardsim(tmp_path / "jcardsim.jar", tmp_path / "pivapplet-classes")
        assert result is live_process


class TestWaitForVpcdListener:
    def test_returns_immediately_once_listener_accepts(self) -> None:
        with (
            patch("provision_piv_emulation.socket.create_connection") as mock_connect,
            patch("provision_piv_emulation.time.sleep") as mock_sleep,
        ):
            provision_piv_emulation._wait_for_vpcd_listener(max_attempts=5)
        assert mock_connect.call_count == 1
        mock_sleep.assert_not_called()

    def test_retries_on_connection_refused_then_succeeds(self) -> None:
        call_count = 0

        def _flaky_connect(*_args: object, **_kwargs: object) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionRefusedError("Connection refused")
            return MagicMock()

        with (
            patch("provision_piv_emulation.socket.create_connection", side_effect=_flaky_connect),
            patch("provision_piv_emulation.time.sleep") as mock_sleep,
        ):
            provision_piv_emulation._wait_for_vpcd_listener(max_attempts=5)
        assert call_count == 3
        assert mock_sleep.call_count == 2

    def test_raises_after_exhausting_attempts(self) -> None:
        with (
            patch(
                "provision_piv_emulation.socket.create_connection",
                side_effect=ConnectionRefusedError("Connection refused"),
            ),
            patch("provision_piv_emulation.time.sleep"),
            patch("provision_piv_emulation._run", return_value=_completed(stdout="diagnostic output")) as mock_run,
            pytest.raises(provision_piv_emulation.ProvisioningError, match="never started listening"),
        ):
            provision_piv_emulation._wait_for_vpcd_listener(max_attempts=3)
        commands = [c.args[0][0] for c in mock_run.call_args_list]
        assert commands == ["system_profiler", "log"]

    def test_error_includes_diagnostic_output(self) -> None:
        with (
            patch(
                "provision_piv_emulation.socket.create_connection",
                side_effect=ConnectionRefusedError("Connection refused"),
            ),
            patch("provision_piv_emulation.time.sleep"),
            patch("provision_piv_emulation._run", return_value=_completed(stdout="(null):(null) ifd-vpcd.bundle")),
            pytest.raises(provision_piv_emulation.ProvisioningError, match=r"\(null\):\(null\)"),
        ):
            provision_piv_emulation._wait_for_vpcd_listener(max_attempts=3)


class TestWaitForCard:
    def test_returns_immediately_once_card_visible(self) -> None:
        with (
            patch("provision_piv_emulation._run", return_value=_completed(stdout="... PIV ...")) as mock_run,
            patch("provision_piv_emulation.time.sleep") as mock_sleep,
        ):
            provision_piv_emulation._wait_for_card(max_attempts=5)
        assert mock_run.call_count == 1
        mock_sleep.assert_not_called()

    def test_raises_after_exhausting_attempts(self) -> None:
        with (
            patch("provision_piv_emulation._run", return_value=_completed(stdout="nothing here")) as mock_run,
            patch("provision_piv_emulation.time.sleep"),
            pytest.raises(provision_piv_emulation.ProvisioningError, match="did not appear"),
        ):
            provision_piv_emulation._wait_for_card(max_attempts=3, delay_seconds=0)
        assert mock_run.call_count == 3


class TestProvisionOrchestration:
    def test_runs_stages_in_order_and_cleans_up_jcardsim(self, tmp_path: Path) -> None:
        process = MagicMock()
        calls: list[str] = []

        def _record(name: str) -> MagicMock:
            def _fn(*_args: object, **_kwargs: object) -> object:
                calls.append(name)
                return None

            return MagicMock(side_effect=_fn)

        with (
            patch("provision_piv_emulation.shutil.which", return_value="/usr/bin/nix-build"),
            patch("provision_piv_emulation._nix_build", side_effect=lambda attr: tmp_path / attr),
            patch("provision_piv_emulation._install_vpcd_bundle", _record("install_vpcd")),
            patch("provision_piv_emulation._wait_for_vpcd_listener", _record("wait_for_vpcd_listener")),
            patch(
                "provision_piv_emulation._start_jcardsim",
                MagicMock(side_effect=lambda *_a: (calls.append("start_jcardsim"), process)[1]),
            ),
            patch("provision_piv_emulation._select_applet", _record("select_applet")),
            patch("provision_piv_emulation._wait_for_card", _record("wait_for_card")),
            patch("provision_piv_emulation._provision_piv_slot", _record("provision_piv_slot")),
            patch("provision_piv_emulation._export_certificate", _record("export_certificate")),
            patch("pathlib.Path.glob", return_value=[tmp_path / "jcardsim.jar"]),
        ):
            provision_piv_emulation.provision(vendor_id=1452, product_id=33029)

        assert calls == [
            "install_vpcd",
            "wait_for_vpcd_listener",
            "start_jcardsim",
            "select_applet",
            "wait_for_card",
            "provision_piv_slot",
            "export_certificate",
        ]
        process.terminate.assert_called_once()

    def test_raises_if_nix_build_not_on_path(self) -> None:
        with (
            patch("provision_piv_emulation.shutil.which", return_value=None),
            pytest.raises(provision_piv_emulation.ProvisioningError, match="nix-build is not on PATH"),
        ):
            provision_piv_emulation.provision(vendor_id=1, product_id=2)


class TestMain:
    def test_returns_1_and_logs_on_provisioning_error(self) -> None:
        with (
            patch("sys.argv", ["provision_piv_emulation.py", "--vendor-id", "1452", "--product-id", "33029"]),
            patch(
                "provision_piv_emulation.provision",
                side_effect=provision_piv_emulation.ProvisioningError("boom"),
            ),
            patch("provision_piv_emulation.logger") as mock_logger,
        ):
            assert provision_piv_emulation.main() == 1
        mock_logger.error.assert_called_once()

    def test_returns_0_on_success(self) -> None:
        with (
            patch("sys.argv", ["provision_piv_emulation.py", "--vendor-id", "1452", "--product-id", "33029"]),
            patch("provision_piv_emulation.provision"),
        ):
            assert provision_piv_emulation.main() == 0
