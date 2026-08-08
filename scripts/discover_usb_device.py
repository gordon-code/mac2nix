"""Discover a baseline USB device on this machine, for vpcd's macOS registration trick.

vpcd registers as a macOS smartcard reader driver by spoofing an arbitrary,
unrelated USB device's vendor/product ID in its Info.plist (see
nix/piv-emulation/vpcd.nix's own docstring for the full mechanism). A Tart
VM guest always has one (confirmed live this session: a synthetic
"Virtual USB Keyboard"), but a real GitHub Actions runner's baseline USB
population has never been checked by anyone -- this script is that check,
run as its own CI step before attempting PIV emulation on a native runner.

Excludes any device that already self-identifies as smart-card-class
hardware, since reusing a real CCID reader's own VID/PID is a confirmed
real-world failure mode (frankmorgner/vsmartcard#303) rather than a
theoretical one.

Prints `vendor_id=<int>` and `product_id=<int>` (decimal) to stdout for the
first suitable device found, one per line, and exits 0. Exits 1 with no
output if no suitable device exists.

Usage: ``uv run python scripts/discover_usb_device.py``
"""

from __future__ import annotations

import re
import subprocess
import sys

# Names that indicate the device is already a smart-card-class reader --
# reusing its VID/PID is the confirmed vsmartcard#303 failure mode, not a
# theoretical concern.
_EXCLUDED_NAME_PATTERNS = re.compile(r"smart\s*card|ccid|piv|yubikey", re.IGNORECASE)

_NAME_FIELD_RE = re.compile(r'"USB Product Name"\s*=\s*"([^"]+)"')
_VENDOR_FIELD_RE = re.compile(r'"idVendor"\s*=\s*(\d+)')
_PRODUCT_FIELD_RE = re.compile(r'"idProduct"\s*=\s*(\d+)')


def _find_candidates(ioreg_output: str) -> list[tuple[str, int, int]]:
    """Parse `ioreg -p IOUSB -l` output for (name, vendor_id, product_id) tuples.

    ioreg's per-device property order reflects the kernel's own internal
    dictionary insertion order, not a fixed or alphabetical schema -- a real
    capture against a live Tart guest this session showed idProduct, then
    USB Product Name, then idVendor, an order that doesn't match either of
    two hand-guessed alternatives tried first. Each field is matched
    independently within its own device block instead of assuming any
    particular sequential order between them.
    """
    candidates: list[tuple[str, int, int]] = []
    # Split on device entry boundaries (a `+-o <Name>@` line starts each).
    for block in re.split(r"\n\s*\+-o ", ioreg_output)[1:]:
        name_match = _NAME_FIELD_RE.search(block)
        vendor_match = _VENDOR_FIELD_RE.search(block)
        product_match = _PRODUCT_FIELD_RE.search(block)
        if not (name_match and vendor_match and product_match):
            continue
        candidates.append((name_match.group(1), int(vendor_match.group(1)), int(product_match.group(1))))
    return candidates


def find_usable_device() -> tuple[int, int] | None:
    result = subprocess.run(["ioreg", "-p", "IOUSB", "-l"], capture_output=True, text=True, timeout=30, check=False)  # noqa: S607
    if result.returncode != 0:
        return None

    for name, vendor_id, product_id in _find_candidates(result.stdout):
        if _EXCLUDED_NAME_PATTERNS.search(name):
            continue
        return vendor_id, product_id
    return None


def main() -> int:
    device = find_usable_device()
    if device is None:
        return 1
    vendor_id, product_id = device
    print(f"vendor_id={vendor_id}")  # noqa: T201 -- intentional stdout contract, consumed by CI
    print(f"product_id={product_id}")  # noqa: T201
    return 0


if __name__ == "__main__":
    sys.exit(main())
