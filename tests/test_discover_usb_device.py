"""Tests for scripts/discover_usb_device.py — parsing against real, captured ioreg output.

The fixture below is a trimmed excerpt of `ioreg -p IOUSB -l` output
actually captured against a live Tart macOS guest this session (see
hack/PROJECT.md's "Task 10 (YubiKey PIV) expanded" entry) — not synthesized.
"""

from __future__ import annotations

from unittest.mock import patch

import discover_usb_device

_REAL_TART_IOREG_EXCERPT = """
+-o AppleUSBXHCIPCI@0e000000  <class AppleUSBXHCIPCI, id 0x1000001d8>
  |   {
  |     "IOClass" = "AppleUSBXHCIPCI"
  |   }
  |
  +-o Virtual USB Digitizer@0ea00000  <class IOUSBHostDevice, id 0x10000028b>
  |   {
  |     "sessionID" = 36244451
  |     "idProduct" = 33030
  |     "USB Product Name" = "Virtual USB Digitizer"
  |     "USB Vendor Name" = "Apple Inc."
  |     "idVendor" = 1452
  |   }
  |
  +-o Virtual USB Keyboard@0e900000  <class IOUSBHostDevice, id 0x100000291>
      {
        "sessionID" = 38530570
        "idProduct" = 33029
        "USB Product Name" = "Virtual USB Keyboard"
        "USB Vendor Name" = "Apple Inc."
        "idVendor" = 1452
      }
"""

_IOREG_WITH_SMARTCARD_READER = """
+-o Yubico YubiKey CCID@0e900000  <class IOUSBHostDevice, id 0x100000291>
    {
      "idProduct" = 1031
      "USB Product Name" = "YubiKey CCID Smart Card Reader"
      "idVendor" = 4176
    }
"""


class TestFindCandidates:
    def test_parses_real_tart_ioreg_output(self) -> None:
        candidates = discover_usb_device._find_candidates(_REAL_TART_IOREG_EXCERPT)
        assert ("Virtual USB Digitizer", 1452, 33030) in candidates
        assert ("Virtual USB Keyboard", 1452, 33029) in candidates

    def test_no_candidates_in_empty_output(self) -> None:
        assert discover_usb_device._find_candidates("") == []


class TestFindUsableDevice:
    def test_returns_first_non_smartcard_device(self, capsys) -> None:
        with patch(
            "discover_usb_device.subprocess.run",
            return_value=type("Result", (), {"returncode": 0, "stdout": _REAL_TART_IOREG_EXCERPT, "stderr": ""})(),
        ):
            result = discover_usb_device.find_usable_device()
        assert result == (1452, 33030)  # Digitizer appears first in the fixture
        # Diagnostic candidate list goes to stderr, never stdout (which feeds GITHUB_OUTPUT).
        err = capsys.readouterr().err
        assert "Virtual USB Digitizer" in err
        assert "Virtual USB Keyboard" in err

    def test_excludes_smartcard_class_devices(self, capsys) -> None:
        with patch(
            "discover_usb_device.subprocess.run",
            return_value=type("Result", (), {"returncode": 0, "stdout": _IOREG_WITH_SMARTCARD_READER, "stderr": ""})(),
        ):
            result = discover_usb_device.find_usable_device()
        assert result is None
        assert "[excluded" in capsys.readouterr().err

    def test_returns_none_when_ioreg_fails(self, capsys) -> None:
        with patch(
            "discover_usb_device.subprocess.run",
            return_value=type("Result", (), {"returncode": 1, "stdout": "", "stderr": "denied"})(),
        ):
            result = discover_usb_device.find_usable_device()
        assert result is None
        assert "denied" in capsys.readouterr().err


class TestMain:
    def test_prints_vendor_and_product_id_and_returns_0(self, capsys) -> None:
        with patch("discover_usb_device.find_usable_device", return_value=(1452, 33029)):
            exit_code = discover_usb_device.main()
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "vendor_id=1452" in captured.out
        assert "product_id=33029" in captured.out

    def test_returns_1_with_no_output_when_nothing_found(self, capsys) -> None:
        with patch("discover_usb_device.find_usable_device", return_value=None):
            exit_code = discover_usb_device.main()
        assert exit_code == 1
        assert capsys.readouterr().out == ""
