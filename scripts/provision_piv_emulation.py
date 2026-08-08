"""Register a virtual PIV card with macOS's smartcard stack, for real E2E sudo/PAM testing.

Runs *locally* on whatever machine needs the virtual card (a Tart VM guest,
or a native CI runner) -- it is not a remote-orchestration script like
scripts/prewarm_vm.py, so it uses plain synchronous subprocess calls.

Orchestrates, in order (see hack/plans/fix-vm-tahoe-base-image-1785337468-migration-mvp.md's
Task 10 Step 3 for the full research trail behind each choice):

1. Build vpcd/jcardsim/pivapplet via the local Nix derivations in
   nix/piv-emulation/ (never vendored binaries -- see PROJECT.md).
2. Start jcardsim's VSmartCard remote interface with a PivApplet-configured
   jcardsim.cfg.
3. Select the applet via its AID.
4. Copy vpcd's built ifd-vpcd.bundle to the real system driver directory and
   patch its Info.plist with the caller-supplied vendor/product ID -- the
   Nix store copy is read-only, so patching happens on a real filesystem
   copy, never in the store. Restart the driver host (not a full reboot).
5. Poll `system_profiler SPSmartCardsDataType` until the emulated card
   appears (bounded retry -- this is a hard failure if it never appears,
   not a soft skip; see Task 10 Step 4's own no-skip contract).
6. Provision the card's PIV slot 9a via yubico-piv-tool (a fresh card has
   no usable keys -- arekinath/PivApplet#23's most-cited bug report was
   exactly this being mistaken for a broken emulator).
7. Export the freshly-generated certificate into
   ~/.eid/authorized_certificates -- the automated equivalent of
   docs/runbooks/yubikey-piv.md's own manual cert-export step.

Usage: ``uv run python scripts/provision_piv_emulation.py --vendor-id 1452 --product-id 33029``
"""

from __future__ import annotations

import argparse
import logging
import shutil
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_PIV_AID = "A000000308000010000100"
_SELECT_APPLET_APDU = "80 b8 00 00 12 0b a0 00 00 03 08 00 00 10 00 01 00 05 00 00 02 0F 0F 7f"
_DEFAULT_PIN = "123456"
_DRIVER_DEST = Path("/usr/local/libexec/SmartCardServices/drivers/ifd-vpcd.bundle")
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


def _install_vpcd_bundle(vpcd_store_path: Path, vendor_id: int, product_id: int) -> None:
    if _DRIVER_DEST.exists():
        _run(["sudo", "rm", "-rf", str(_DRIVER_DEST)])
    _run(["sudo", "mkdir", "-p", str(_DRIVER_DEST.parent)])
    _run(["sudo", "cp", "-R", str(vpcd_store_path / "ifd-vpcd.bundle"), str(_DRIVER_DEST.parent)])

    info_plist = _DRIVER_DEST / "Contents" / "Info.plist"
    # Info.plist stores these as single-element arrays of hex strings
    # (verified against a real build this session -- ["0x18d1"] style, not
    # a bare string) -- plutil's -json replace matches that shape exactly.
    _run(
        [
            "sudo",
            "plutil",
            "-replace",
            "ifdVendorID",
            "-json",
            f'["0x{vendor_id:04x}"]',
            str(info_plist),
        ]
    )
    _run(
        [
            "sudo",
            "plutil",
            "-replace",
            "ifdProductID",
            "-json",
            f'["0x{product_id:04x}"]',
            str(info_plist),
        ]
    )

    # Not a full reboot -- vsmartcard's own docs and a 2025 real-world
    # resolution (frankmorgner/vsmartcard#303) confirm a driver-daemon
    # restart is sufficient.
    _run(["sudo", "killall", "-SIGKILL", "-m", ".*com.apple.ifdreader"], check=False)


def _start_jcardsim(jcardsim_jar: Path, pivapplet_classes: Path) -> subprocess.Popen[bytes]:
    jcardsim_cfg = Path("jcardsim-mac2nix.cfg")
    jcardsim_cfg.write_text(
        f"com.licel.jcardsim.card.applet.0.AID={_PIV_AID}\n"
        f"com.licel.jcardsim.card.applet.0.Class=net.cooperi.pivapplet.PivApplet\n"
        f"com.licel.jcardsim.vsmartcard.host={_JCARDSIM_HOST}\n"
        f"com.licel.jcardsim.vsmartcard.port={_JCARDSIM_VPCD_PORT}\n"
    )
    classpath = f"{pivapplet_classes}:{jcardsim_jar}"
    process = subprocess.Popen(  # noqa: S603
        ["java", "-noverify", "-cp", classpath, "com.licel.jcardsim.remote.VSmartCard", str(jcardsim_cfg)],  # noqa: S607
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)  # let the remote interface bind before anything tries to select the applet
    if process.poll() is not None:
        raise ProvisioningError(
            "jcardsim's VSmartCard process exited immediately -- check jcardsim/PivApplet build output"
        )
    return process


def _select_applet(reader_pattern: str = "Virtual PCD 00 00") -> None:
    _run(["opensc-tool", "-r", reader_pattern, "-s", _SELECT_APPLET_APDU])


def _wait_for_card(max_attempts: int = 10, delay_seconds: int = 3) -> None:
    for attempt in range(max_attempts):
        result = _run(["system_profiler", "SPSmartCardsDataType"], check=False)
        if "Virtual PCD" in result.stdout or "PIV" in result.stdout:
            return
        logger.debug("Card not yet visible (attempt %d/%d)", attempt + 1, max_attempts)
        time.sleep(delay_seconds)
    raise ProvisioningError(f"Emulated PIV card did not appear in system_profiler after {max_attempts} attempts")


def _provision_piv_slot() -> None:
    # A freshly-started card has no usable keys -- arekinath/PivApplet#23's
    # most-cited bug report was exactly this being mistaken for a broken
    # emulator. Slot 9a, RSA (yubico-piv-tool's default), matching the
    # pre-built PivApplet .cap's own RSA/EC/AES/3DES feature set.
    _run(["yubico-piv-tool", "-a", "generate", "-s", "9a", "-o", "pubkey.pem"])
    _run(
        [
            "yubico-piv-tool",
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
    _run(["yubico-piv-tool", "-a", "import-certificate", "-s", "9a", "-i", "cert.pem"])


def _export_certificate() -> None:
    eid_dir = Path.home() / ".eid"
    eid_dir.mkdir(mode=0o755, exist_ok=True)
    cert_pem = Path("cert.pem").read_text()
    authorized = eid_dir / "authorized_certificates"
    with authorized.open("a") as f:
        f.write(cert_pem)
    authorized.chmod(0o644)


def provision(vendor_id: int, product_id: int) -> None:
    """Run the full provisioning sequence. Raises ProvisioningError on any failure."""
    if shutil.which("nix-build") is None:
        raise ProvisioningError("nix-build is not on PATH -- required to build vpcd/jcardsim/pivapplet")

    vpcd_path = _nix_build("vpcd")
    jcardsim_path = _nix_build("jcardsim")
    pivapplet_path = _nix_build("pivapplet")

    _install_vpcd_bundle(vpcd_path, vendor_id, product_id)

    jcardsim_jar_candidates = list((jcardsim_path / "share").glob("**/jcardsim*.jar")) or list(
        jcardsim_path.glob("**/jcardsim*.jar")
    )
    if not jcardsim_jar_candidates:
        raise ProvisioningError(f"No jcardsim jar found under {jcardsim_path}")

    process = _start_jcardsim(jcardsim_jar_candidates[0], pivapplet_path)
    try:
        _select_applet()
        _wait_for_card()
        _provision_piv_slot()
        _export_certificate()
    finally:
        process.terminate()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vendor-id", type=int, required=True, help="USB vendor ID (decimal) to spoof for vpcd")
    parser.add_argument("--product-id", type=int, required=True, help="USB product ID (decimal) to spoof for vpcd")
    args = parser.parse_args()

    try:
        provision(args.vendor_id, args.product_id)
    except ProvisioningError as exc:
        logger.error("PIV emulation provisioning failed: %s", exc)
        return 1
    logger.info("Virtual PIV card provisioned and ready.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
