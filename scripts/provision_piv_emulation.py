"""Register a virtual PIV card with a self-hosted PC/SC stack, for real E2E sudo/PAM testing.

Runs *locally* on whatever machine needs the virtual card (a Tart VM guest,
or a native CI runner) -- it is not a remote-orchestration script like
scripts/prewarm_vm.py, so it uses plain synchronous subprocess calls.

Never touches macOS's own proprietary CryptoTokenKit/ifdreader PCSC service.
That daemon only accepts drivers that present as USB CCID devices (spoofing
a real or synthetic device's VID/PID in the driver bundle's Info.plist), and
on Tart specifically this is a confirmed dead end: Tart's only two synthetic
USB devices (keyboard, digitizer) are already claimed by macOS's own
HIDDriverKit stack, so ifdreader registers the driver bundle but never gets
a live reader instance for it. Instead this runs a *self-hosted* pcscd
(nix/piv-emulation/pcsc-stack.nix) that honors vpcd's own documented
reader.conf.d registration -- a static, non-hotplug reader entry with no
VID/PID and no USB device involved at all (see vpcd.nix and pcsc-stack.nix's
own comments for the full rationale). Verified end-to-end on real hardware:
pcscd sees the reader, jcardsim/PivApplet present a real ATR through it, and
PKCS#11 login+sign+verify all succeed.

Orchestrates, in order (see hack/plans/fix-vm-tahoe-base-image-1785337468-migration-mvp.md's
Task 10 Step 3 for the full research trail behind each choice):

1. Build vpcd/pcsclite/opensc/yubicoPivTool/jcardsim/pivapplet via the local
   Nix derivations in nix/piv-emulation/ (never vendored binaries -- see
   PROJECT.md).
2. Register vpcd as a static PC/SC reader via /etc/reader.conf.d/vpcd.
3. Start our own pcscd as a detached background daemon.
4. Start jcardsim's VSmartCard remote interface with a PivApplet-configured
   jcardsim.cfg, also detached -- both it and pcscd stay running after this
   script exits, since the PAM authentication step that needs them runs
   afterward, in a separate SSH call.
5. Select the applet via its full AID (yubico-piv-tool's own SELECT only
   sends the 5-byte PIV RID, which jcardsim/PivApplet reject as an unknown
   applet unless the full AID has already been selected once).
6. Poll our own opensc-tool until the emulated card appears (bounded retry
   -- this is a hard failure if it never appears, not a soft skip; see Task
   10 Step 4's own no-skip contract).
7. Provision the card's PIV slot 9a via yubico-piv-tool (a fresh card has
   no usable keys -- arekinath/PivApplet#23's most-cited bug report was
   exactly this being mistaken for a broken emulator).
8. Export the freshly-generated certificate into
   ~/.eid/authorized_certificates -- the automated equivalent of
   docs/runbooks/yubikey-piv.md's own manual cert-export step.

Usage: ``uv run python scripts/provision_piv_emulation.py``
"""

from __future__ import annotations

import argparse
import logging
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_PIV_AID = "A000000308000010000100"
_SELECT_APPLET_APDU = "80 b8 00 00 12 0b a0 00 00 03 08 00 00 10 00 01 00 05 00 00 02 0F 0F 7f"
_DEFAULT_PIN = "123456"

# yubico-piv-tool's own `-r` default is "Yubikey" -- it would never match
# vpcd's "Virtual PCD ..." reader name. Confirmed real bug: this was never
# caught before because provisioning always failed earlier (at the old
# VID/PID registration step) before yubico-piv-tool ever ran against an
# emulated card.
_READER_NAME_FILTER = "Virtual"

_READER_CONF_PATH = Path("/etc/reader.conf.d/vpcd")
_PCSCD_IPC_DIR = Path("/run/pcscd")
_JCARDSIM_HOST = "127.0.0.1"
_JCARDSIM_VPCD_PORT = 35963


class ProvisioningError(Exception):
    """Raised when any provisioning stage fails."""


def _run(cmd: list[str], *, timeout: int = 30, check: bool = True) -> subprocess.CompletedProcess[str]:
    logger.debug("Running: %s", cmd)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
    if check and result.returncode != 0:
        raise ProvisioningError(f"{cmd!r} failed (exit {result.returncode}): {result.stderr.strip()}")
    return result


_PIV_EMULATION_DIR = Path(__file__).resolve().parent.parent / "nix" / "piv-emulation"


def _nix_build(attr: str) -> Path:
    # nix-build against the plain expression, not `nix build .#attr` --
    # mac2nix's own repo has no top-level flake.nix (only the generated
    # scaffold template does, under src/mac2nix/templates/scaffold/).
    result = _run(
        ["nix-build", str(_PIV_EMULATION_DIR), "-A", attr, "--no-out-link"],
        timeout=1800,
    )
    return Path(result.stdout.strip())


def _write_reader_conf(vpcd_bundle: Path) -> None:
    """Register vpcd as an always-available, non-hotplug PC/SC reader.

    No VID/PID and no USB device involved -- pcsclite treats reader.conf.d
    entries as static "serial" readers (see vpcd.nix's own comment for the
    full rationale). This is the whole reason macOS's proprietary
    CryptoTokenKit/ifdreader VID/PID-spoofing mechanism -- and its
    Tart-specific HID-claim dead end -- never comes into play at all.
    """
    reader_conf = (
        f'FRIENDLYNAME "Virtual PCD"\nDEVICENAME   /dev/null:0x8C7B\nLIBPATH      {vpcd_bundle}\nCHANNELID    0x8C7B\n'
    )
    tmp_conf = Path("vpcd.reader.conf")
    tmp_conf.write_text(reader_conf)
    _run(["sudo", "mkdir", "-p", str(_READER_CONF_PATH.parent)])
    _run(["sudo", "cp", str(tmp_conf), str(_READER_CONF_PATH)])


def _start_pcscd(pcscd_bin: Path) -> subprocess.Popen[str]:
    """Start our own pcscd as a detached background daemon.

    Never Apple's proprietary daemon -- this pcscd (nixpkgs' own build)
    honors reader.conf.d's static reader registration, which is what lets
    vpcd register without a real or virtual USB device at all. `-f` keeps
    logs on stdout (captured to pcscd.log here) instead of syslog, so a
    failure carries its own diagnostics; `start_new_session=True` detaches
    it from this SSH session so it survives past this script's own exit --
    the pamtester authentication step that needs it runs afterward, in a
    separate SSH call.
    """
    _run(["sudo", "mkdir", "-p", str(_PCSCD_IPC_DIR)], check=False)
    log_path = Path("pcscd.log")
    with log_path.open("w") as log_file:
        process = subprocess.Popen(  # noqa: S603
            ["sudo", str(pcscd_bin), "-f", "-d"],  # noqa: S607
            stdout=log_file,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
    time.sleep(1)
    if process.poll() is not None:
        raise ProvisioningError(f"pcscd exited immediately:\n{log_path.read_text()}")
    return process


def _wait_for_vpcd_listener(max_attempts: int = 30, delay_seconds: float = 1.0) -> None:
    """Poll until vpcd's TCP listener accepts a connection.

    pcscd loads vpcd's driver synchronously during its own startup (real,
    observed behavior: "IFDHCreateChannel() Waiting for virtual ICC" appears
    in pcscd's own log within milliseconds of "daemon ready") -- but this
    script's own process starting pcscd doesn't guarantee that sequence has
    finished by the time control returns here. jcardsim's VSmartCard is the
    TCP *client* side of that socket (it dials out, it never listens --
    confirmed via a real local repro: a bare `java ... VSmartCard` run
    against a not-yet-ready port raised `java.net.ConnectException:
    Connection refused` immediately). Without this wait, starting VSmartCard
    too early is a real, reproducible race, not flakiness.
    """
    last_error: OSError | None = None
    for attempt in range(max_attempts):
        try:
            with socket.create_connection((_JCARDSIM_HOST, _JCARDSIM_VPCD_PORT), timeout=2):
                return
        except OSError as exc:
            last_error = exc
            logger.debug("vpcd listener not ready yet (attempt %d/%d): %s", attempt + 1, max_attempts, exc)
            time.sleep(delay_seconds)

    pcscd_log = Path("pcscd.log")
    pcscd_log_contents = pcscd_log.read_text() if pcscd_log.exists() else "(no pcscd.log found)"
    reader_conf = _run(["sudo", "cat", str(_READER_CONF_PATH)], check=False)
    raise ProvisioningError(
        f"vpcd never started listening on {_JCARDSIM_HOST}:{_JCARDSIM_VPCD_PORT}: {last_error}\n"
        f"{_READER_CONF_PATH}:\n{reader_conf.stdout}\n"
        f"pcscd log:\n{pcscd_log_contents}"
    )


def _start_jcardsim(jdk_path: Path, jcardsim_jar: Path, pivapplet_classes: Path) -> subprocess.Popen[str]:
    jcardsim_cfg = Path("jcardsim-mac2nix.cfg")
    jcardsim_cfg.write_text(
        f"com.licel.jcardsim.card.applet.0.AID={_PIV_AID}\n"
        f"com.licel.jcardsim.card.applet.0.Class=net.cooperi.pivapplet.PivApplet\n"
        f"com.licel.jcardsim.vsmartcard.host={_JCARDSIM_HOST}\n"
        f"com.licel.jcardsim.vsmartcard.port={_JCARDSIM_VPCD_PORT}\n"
    )
    classpath = f"{pivapplet_classes}:{jcardsim_jar}"
    log_path = Path("jcardsim.log")
    # Captured to a real file (not a pipe) and detached via
    # start_new_session=True -- this process must survive past this
    # script's own exit for the same reason pcscd does (see _start_pcscd).
    # A silent crash here previously required a separate local repro to
    # diagnose (real incident: jcardsim's VSmartCard is a TCP *client* that
    # fails fast with a ConnectException if vpcd isn't listening yet, which
    # a bare poll then misreported as "process exited immediately", i.e. a
    # build problem it never was).
    java_bin = str(jdk_path / "bin" / "java")
    with log_path.open("w") as log_file:
        process = subprocess.Popen(  # noqa: S603
            [java_bin, "-noverify", "-cp", classpath, "com.licel.jcardsim.remote.VSmartCard", str(jcardsim_cfg)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
    time.sleep(2)  # let the remote interface bind before anything tries to select the applet
    if process.poll() is not None:
        raise ProvisioningError(f"jcardsim's VSmartCard process exited immediately:\n{log_path.read_text()}")
    return process


def _select_applet(opensc_path: Path, reader_pattern: str = "Virtual PCD 00 00") -> None:
    opensc_tool = opensc_path / "bin" / "opensc-tool"
    _run([str(opensc_tool), "-r", reader_pattern, "-s", _SELECT_APPLET_APDU])


def _wait_for_card(opensc_path: Path, max_attempts: int = 10, delay_seconds: int = 3) -> None:
    opensc_tool = opensc_path / "bin" / "opensc-tool"
    for attempt in range(max_attempts):
        result = _run([str(opensc_tool), "--list-readers"], check=False)
        if re.search(r"Yes\s+Virtual PCD", result.stdout):
            return
        logger.debug("Card not yet visible (attempt %d/%d)", attempt + 1, max_attempts)
        time.sleep(delay_seconds)
    raise ProvisioningError(f"Emulated PIV card did not appear after {max_attempts} attempts")


def _provision_piv_slot(yubico_piv_tool_path: Path) -> None:
    # A freshly-started card has no usable keys -- arekinath/PivApplet#23's
    # most-cited bug report was exactly this being mistaken for a broken
    # emulator. Slot 9a, RSA (yubico-piv-tool's default), matching the
    # pre-built PivApplet .cap's own RSA/EC/AES/3DES feature set.
    yubico_piv_tool = str(yubico_piv_tool_path / "bin" / "yubico-piv-tool")
    _run([yubico_piv_tool, "-r", _READER_NAME_FILTER, "-a", "generate", "-s", "9a", "-o", "pubkey.pem"])
    _run(
        [
            yubico_piv_tool,
            "-r",
            _READER_NAME_FILTER,
            "-a",
            "verify-pin",
            "-P",
            _DEFAULT_PIN,
            "-a",
            "selfsign-certificate",
            "-s",
            "9a",
            "-i",
            "pubkey.pem",
            "-S",
            "/CN=mac2nix-piv-emulation/",
            "-o",
            "cert.pem",
        ]
    )
    _run([yubico_piv_tool, "-r", _READER_NAME_FILTER, "-a", "import-certificate", "-s", "9a", "-i", "cert.pem"])


def _export_certificate() -> None:
    eid_dir = Path.home() / ".eid"
    eid_dir.mkdir(mode=0o755, exist_ok=True)
    cert_pem = Path("cert.pem").read_text()
    authorized = eid_dir / "authorized_certificates"
    with authorized.open("a") as f:
        f.write(cert_pem)
    authorized.chmod(0o644)


def provision() -> None:
    """Run the full provisioning sequence. Raises ProvisioningError on any failure."""
    if shutil.which("nix-build") is None:
        raise ProvisioningError("nix-build is not on PATH -- required to build the PIV emulation stack")

    vpcd_path = _nix_build("vpcd")
    pcsclite_path = _nix_build("pcsclite")
    opensc_path = _nix_build("opensc")
    yubico_piv_tool_path = _nix_build("yubicoPivTool")
    jdk_path = _nix_build("jdk")
    jcardsim_path = _nix_build("jcardsim")
    pivapplet_path = _nix_build("pivapplet")

    _write_reader_conf(vpcd_path / "ifd-vpcd.bundle")
    _start_pcscd(pcsclite_path / "bin" / "pcscd")
    _wait_for_vpcd_listener()

    jcardsim_jar_candidates = list((jcardsim_path / "share").glob("**/jcardsim*.jar")) or list(
        jcardsim_path.glob("**/jcardsim*.jar")
    )
    if not jcardsim_jar_candidates:
        raise ProvisioningError(f"No jcardsim jar found under {jcardsim_path}")

    # pcscd and jcardsim are deliberately left running (not terminated) --
    # both need to stay alive for the PAM authentication step that runs
    # afterward, in a separate SSH call. Leaving them running on a
    # provisioning failure too is also the right call here: it preserves
    # live diagnostic state instead of tearing it down before anyone can
    # inspect it.
    _start_jcardsim(jdk_path, jcardsim_jar_candidates[0], pivapplet_path)
    _select_applet(opensc_path)
    _wait_for_card(opensc_path)
    _provision_piv_slot(yubico_piv_tool_path)
    _export_certificate()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()

    try:
        provision()
    except ProvisioningError as exc:
        logger.error("PIV emulation provisioning failed: %s", exc)
        return 1
    logger.info("Virtual PIV card provisioned and ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
