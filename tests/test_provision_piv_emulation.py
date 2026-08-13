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


class TestWriteReaderConf:
    def test_writes_libpath_pointing_at_the_bundle(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        vpcd_bundle = tmp_path / "store-path" / "ifd-vpcd.bundle"
        with patch("provision_piv_emulation._run", return_value=_completed()) as mock_run:
            provision_piv_emulation._write_reader_conf(vpcd_bundle)

        written_conf = (tmp_path / "vpcd.reader.conf").read_text()
        assert f"LIBPATH      {vpcd_bundle}" in written_conf
        assert "FRIENDLYNAME" in written_conf
        # No VID/PID anywhere -- the whole point of registering via
        # reader.conf instead of macOS's Info.plist/USB-hotplug mechanism.
        assert "VendorID" not in written_conf
        assert "ProductID" not in written_conf

        calls = [c.args[0] for c in mock_run.call_args_list]
        assert calls[0][:3] == ["sudo", "mkdir", "-p"]
        assert calls[1][:2] == ["sudo", "cp"]

    def test_writes_to_real_reader_conf_d_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        with patch("provision_piv_emulation._run", return_value=_completed()) as mock_run:
            provision_piv_emulation._write_reader_conf(tmp_path / "ifd-vpcd.bundle")

        calls = [c.args[0] for c in mock_run.call_args_list]
        assert str(provision_piv_emulation._READER_CONF_PATH) in calls[1]


class TestStartPcscd:
    def test_raises_if_process_exits_immediately(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        dead_process = MagicMock()
        dead_process.poll.return_value = 1
        with (
            patch("provision_piv_emulation._run", return_value=_completed()),
            patch("provision_piv_emulation.subprocess.Popen", return_value=dead_process),
            patch("provision_piv_emulation.time.sleep"),
            pytest.raises(provision_piv_emulation.ProvisioningError, match="exited immediately"),
        ):
            provision_piv_emulation._start_pcscd(tmp_path / "bin" / "pcscd")

    def test_returns_process_when_still_running(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        live_process = MagicMock()
        live_process.poll.return_value = None
        with (
            patch("provision_piv_emulation._run", return_value=_completed()) as mock_run,
            patch("provision_piv_emulation.subprocess.Popen", return_value=live_process) as mock_popen,
            patch("provision_piv_emulation.time.sleep"),
        ):
            result = provision_piv_emulation._start_pcscd(tmp_path / "bin" / "pcscd")

        assert result is live_process
        # Runs detached (survives past this script's own exit) -- the
        # pamtester step that needs it runs afterward, in a separate SSH
        # call.
        assert mock_popen.call_args.kwargs["start_new_session"] is True
        mkdir_calls = [c.args[0] for c in mock_run.call_args_list if c.args[0][:2] == ["sudo", "mkdir"]]
        assert any(str(provision_piv_emulation._PCSCD_IPC_DIR) in call for call in mkdir_calls)


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
            provision_piv_emulation._start_jcardsim(
                tmp_path / "jdk", tmp_path / "jcardsim.jar", tmp_path / "pivapplet-classes"
            )

    def test_returns_process_when_still_running(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)  # _start_jcardsim writes jcardsim-mac2nix.cfg to the CWD
        live_process = MagicMock()
        live_process.poll.return_value = None
        with (
            patch("provision_piv_emulation.subprocess.Popen", return_value=live_process) as mock_popen,
            patch("provision_piv_emulation.time.sleep"),
        ):
            result = provision_piv_emulation._start_jcardsim(
                tmp_path / "jdk", tmp_path / "jcardsim.jar", tmp_path / "pivapplet-classes"
            )
        assert result is live_process
        # Runs detached (survives past this script's own exit) -- the
        # pamtester step that needs it runs afterward, in a separate SSH
        # call.
        assert mock_popen.call_args.kwargs["start_new_session"] is True


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

    def test_raises_after_exhausting_attempts(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        with (
            patch(
                "provision_piv_emulation.socket.create_connection",
                side_effect=ConnectionRefusedError("Connection refused"),
            ),
            patch("provision_piv_emulation.time.sleep"),
            patch("provision_piv_emulation._run", return_value=_completed(stdout="reader.conf contents")) as mock_run,
            pytest.raises(provision_piv_emulation.ProvisioningError, match="never started listening"),
        ):
            provision_piv_emulation._wait_for_vpcd_listener(max_attempts=3)
        commands = [c.args[0] for c in mock_run.call_args_list]
        assert commands == [["sudo", "cat", str(provision_piv_emulation._READER_CONF_PATH)]]

    def test_error_includes_pcscd_log_when_present(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pcscd.log").write_text("RFLoadReader failed: 0x80100014")
        with (
            patch(
                "provision_piv_emulation.socket.create_connection",
                side_effect=ConnectionRefusedError("Connection refused"),
            ),
            patch("provision_piv_emulation.time.sleep"),
            patch("provision_piv_emulation._run", return_value=_completed()),
            pytest.raises(provision_piv_emulation.ProvisioningError, match="RFLoadReader failed"),
        ):
            provision_piv_emulation._wait_for_vpcd_listener(max_attempts=3)


class TestSelectApplet:
    def test_invokes_the_built_opensc_tool_with_full_aid(self, tmp_path: Path) -> None:
        with patch("provision_piv_emulation._run", return_value=_completed()) as mock_run:
            provision_piv_emulation._select_applet(tmp_path)
        called = mock_run.call_args.args[0]
        assert called[0] == str(tmp_path / "bin" / "opensc-tool")
        assert provision_piv_emulation._SELECT_APPLET_APDU in called


class TestWaitForCard:
    def test_returns_immediately_once_card_visible(self, tmp_path: Path) -> None:
        with (
            patch(
                "provision_piv_emulation._run",
                return_value=_completed(stdout="0    Yes             Virtual PCD 00 00"),
            ) as mock_run,
            patch("provision_piv_emulation.time.sleep") as mock_sleep,
        ):
            provision_piv_emulation._wait_for_card(tmp_path, max_attempts=5)
        assert mock_run.call_count == 1
        mock_sleep.assert_not_called()

    def test_raises_after_exhausting_attempts(self, tmp_path: Path) -> None:
        with (
            patch(
                "provision_piv_emulation._run",
                return_value=_completed(stdout="0    No              Virtual PCD 00 00"),
            ) as mock_run,
            patch("provision_piv_emulation.time.sleep"),
            pytest.raises(provision_piv_emulation.ProvisioningError, match="did not appear"),
        ):
            provision_piv_emulation._wait_for_card(tmp_path, max_attempts=3, delay_seconds=0)
        assert mock_run.call_count == 3


class TestProvisionPivSlot:
    def test_uses_virtual_reader_filter_not_yubikey_default(self, tmp_path: Path) -> None:
        # yubico-piv-tool's own `-r` default is "Yubikey", which never
        # matches vpcd's "Virtual PCD ..." reader name -- a real,
        # previously-latent bug (see _READER_NAME_FILTER's own comment).
        with patch("provision_piv_emulation._run", return_value=_completed()) as mock_run:
            provision_piv_emulation._provision_piv_slot(tmp_path)

        for call in mock_run.call_args_list:
            cmd = call.args[0]
            assert cmd[0] == str(tmp_path / "bin" / "yubico-piv-tool")
            assert "-r" in cmd
            assert cmd[cmd.index("-r") + 1] == "Virtual"

    def test_runs_generate_then_selfsign_then_import(self, tmp_path: Path) -> None:
        with patch("provision_piv_emulation._run", return_value=_completed()) as mock_run:
            provision_piv_emulation._provision_piv_slot(tmp_path)

        actions = [call.args[0][call.args[0].index("-a") + 1] for call in mock_run.call_args_list]
        assert actions == ["generate", "verify-pin", "import-certificate"]


class TestProvisionOrchestration:
    def test_runs_stages_in_order_without_terminating_anything(self, tmp_path: Path) -> None:
        # pcscd and jcardsim must both survive past provision()'s own
        # return -- the pamtester authentication step that needs them runs
        # afterward, in a separate SSH call. This is real behavior this
        # test protects: the original script used to call
        # jcardsim_process.terminate() in a finally block, which would have
        # broken that later step the moment it was ever reached.
        calls: list[str] = []

        def _record(name: str) -> MagicMock:
            def _fn(*_args: object, **_kwargs: object) -> object:
                calls.append(name)
                return None

            return MagicMock(side_effect=_fn)

        with (
            patch("provision_piv_emulation.shutil.which", return_value="/usr/bin/nix-build"),
            patch("provision_piv_emulation._nix_build", side_effect=lambda attr: tmp_path / attr),
            patch("provision_piv_emulation._write_reader_conf", _record("write_reader_conf")),
            patch("provision_piv_emulation._start_pcscd", _record("start_pcscd")),
            patch("provision_piv_emulation._wait_for_vpcd_listener", _record("wait_for_vpcd_listener")),
            patch("provision_piv_emulation._start_jcardsim", _record("start_jcardsim")),
            patch("provision_piv_emulation._select_applet", _record("select_applet")),
            patch("provision_piv_emulation._wait_for_card", _record("wait_for_card")),
            patch("provision_piv_emulation._provision_piv_slot", _record("provision_piv_slot")),
            patch("provision_piv_emulation._export_certificate", _record("export_certificate")),
            patch("pathlib.Path.glob", return_value=[tmp_path / "jcardsim.jar"]),
        ):
            provision_piv_emulation.provision()

        assert calls == [
            "write_reader_conf",
            "start_pcscd",
            "wait_for_vpcd_listener",
            "start_jcardsim",
            "select_applet",
            "wait_for_card",
            "provision_piv_slot",
            "export_certificate",
        ]

    def test_raises_if_nix_build_not_on_path(self) -> None:
        with (
            patch("provision_piv_emulation.shutil.which", return_value=None),
            pytest.raises(provision_piv_emulation.ProvisioningError, match="nix-build is not on PATH"),
        ):
            provision_piv_emulation.provision()


class TestMain:
    def test_returns_1_and_logs_on_provisioning_error(self) -> None:
        with (
            patch("sys.argv", ["provision_piv_emulation.py"]),
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
            patch("sys.argv", ["provision_piv_emulation.py"]),
            patch("provision_piv_emulation.provision"),
        ):
            assert provision_piv_emulation.main() == 0
