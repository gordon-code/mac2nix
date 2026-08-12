"""Discover a baseline USB device on this machine, for vpcd's macOS registration trick.

vpcd registers as a macOS smartcard reader driver by spoofing an arbitrary,
unrelated USB device's vendor/product ID in its Info.plist (see
nix/piv-emulation/vpcd.nix's own docstring for the full mechanism). A Tart
VM guest always has a candidate device (confirmed live this session: a
synthetic "Virtual USB Keyboard"/"Virtual USB Digitizer" pair), and a real
GitHub Actions macos-latest runner turned out to expose the identical pair
(same VID/PID) -- but neither is actually *usable* for this trick (see the
HID-exclusion note below). This script is the CI step that checks a given
runner's own USB population and applies that real-world knowledge before
attempting PIV emulation on a native runner.

Excludes any device that already self-identifies as smart-card-class
hardware, since reusing a real CCID reader's own VID/PID is a confirmed
real-world failure mode (frankmorgner/vsmartcard#303) rather than a
theoretical one.

Also excludes HID input-class devices (keyboard/mouse/trackpad/digitizer),
confirmed unusable, not merely risky: real diagnostic evidence from both a
live Tart guest and a real GitHub Actions macos-latest runner shows
HIDDriverKit already claims these devices' interfaces before CryptoTokenKit/
CCID's ifd-vpcd driver can obtain a live reader instance for them -- vpcd's
own bundle registers fine (visible in system_profiler's "Reader Drivers"
list) but "Readers:" stays permanently empty regardless of which HID
device's VID/PID it spoofs (see hack/PROJECT.md's Task 10 entries). Both of
this runner class's only two candidate devices ("Virtual USB Keyboard",
"Virtual USB Digitizer" -- identical VID/PID to Tart's own baseline, which
is why a real GitHub Actions runner is itself a Virtualization.framework
guest) were tried across separate real CI runs and both hit this exact
failure. Excluding them up front means discovery correctly reports "no
usable device" instead of picking one that is provably doomed to fail.

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

# Names that indicate a HID input-class device -- confirmed unusable this
# session (see this module's own docstring), not a theoretical concern
# either: HIDDriverKit claims these before CryptoTokenKit/CCID can.
_HID_INPUT_NAME_PATTERNS = re.compile(r"keyboard|mouse|trackpad|touchpad|digitizer|pointing", re.IGNORECASE)

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
        print(f"ioreg failed (exit {result.returncode}): {result.stderr.strip()}", file=sys.stderr)  # noqa: T201
        return None

    # Diagnostic only (stderr, never GITHUB_OUTPUT) -- this runner's own USB
    # population has no prior precedent, unlike Tart's confirmed-live
    # baseline (see this module's own docstring), so every candidate this
    # run actually saw needs to be visible in the CI log even when a device
    # is "found" -- the first non-excluded candidate is not automatically a
    # *usable* one (see hack/PROJECT.md's Task 10 HIDDriverKit finding).
    candidates = _find_candidates(result.stdout)
    print(f"ioreg found {len(candidates)} USB device candidate(s):", file=sys.stderr)  # noqa: T201
    for name, vendor_id, product_id in candidates:
        print(f"  - {name!r} vendor={vendor_id} product={product_id}{_exclusion_reason(name)}", file=sys.stderr)  # noqa: T201

    for name, vendor_id, product_id in candidates:
        if _exclusion_reason(name):
            continue
        return vendor_id, product_id
    return None


def _exclusion_reason(name: str) -> str:
    if _EXCLUDED_NAME_PATTERNS.search(name):
        return " [excluded: smartcard-class name]"
    if _HID_INPUT_NAME_PATTERNS.search(name):
        return " [excluded: HID input-class device, confirmed unusable -- HIDDriverKit claims it first]"
    return ""


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
