"""Pre-warm a Nix-enabled Tart base image for fast local VM-based validation.

Every ``Validator.validate()`` run installs Nix from scratch inside a fresh
VM clone — correct, but slow when repeated often during local development.
This script bakes a customized, persistent base image once: pull the pinned
``macos-tahoe-base`` image if missing, clone it into ``mac2nix-nix-base``,
install Nix inside it, then stop (without deleting). Any later clone of
``mac2nix-nix-base`` already has Nix installed, and
``Validator._bootstrap_nix_darwin()``'s own idempotency check skips
reinstalling it.

Rerun this whenever you want to refresh the baked-in Nix version.

Usage: ``uv run python scripts/prewarm_vm.py`` (or ``make prewarm-vm``).
"""

from __future__ import annotations

import asyncio
import logging
import sys

from mac2nix.vm._utils import VMError
from mac2nix.vm.manager import BASE_IMAGE_NAME, BASE_IMAGE_REF, TartVMManager, pull_base_image_if_missing
from mac2nix.vm.validator import NIX_INSTALLER_URL

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

PREWARMED_VM_NAME = "mac2nix-nix-base"


async def _install_nix(vm: TartVMManager) -> None:
    """Run the same Nix-install steps as Validator._bootstrap_nix_darwin().

    Reuses NIX_INSTALLER_URL from validator.py rather than a second copy, but
    calls exec_command() directly (this is a one-shot bake, not the
    per-validate-run path Validator itself owns).
    """
    installer_path = "/tmp/nix-installer.sh"  # noqa: S108

    logger.info("Downloading Nix installer...")
    # Two things collide here, verified empirically against a real VM: (1)
    # curl on this VM's own build rejects the combined "--proto=https" form
    # outright ("option --proto=https: is unknown"); (2) the separate-argv
    # form ["--proto", "=https"] hits the VM's remote login shell (zsh),
    # which treats a bare leading-"=" word as its own command-path-expansion
    # syntax and fails with "https not found" before curl ever runs.
    # Wrapping in `bash -c` with `=https` single-quoted sidesteps both: bash
    # has no equals-expansion, and curl accepts the quoted, space-separated
    # two-word form.
    download_cmd = f"curl --proto '=https' --tlsv1.2 -sSf -L {NIX_INSTALLER_URL} -o {installer_path}"
    ok, _out, err = await vm.exec_command(["bash", "-c", download_cmd], timeout=60)
    if not ok:
        raise VMError(f"Failed to download Nix installer: {err.strip()}")

    ok, _out, err = await vm.exec_command(["chmod", "+x", installer_path])
    if not ok:
        raise VMError(f"chmod +x nix-installer.sh failed: {err.strip()}")

    logger.info("Installing Nix (this can take a few minutes)...")
    ok, _out, err = await vm.exec_command([installer_path, "install", "--no-confirm"], timeout=300)
    if not ok:
        raise VMError(f"Nix installation failed: {err.strip()}")

    logger.info("Nix installed successfully")


async def _prewarm() -> None:
    if not TartVMManager.is_available():
        raise VMError("tart CLI is not available — install tart to prewarm a VM")

    await pull_base_image_if_missing(name=BASE_IMAGE_NAME, image_ref=BASE_IMAGE_REF)

    logger.info("Cloning %r -> %r", BASE_IMAGE_NAME, PREWARMED_VM_NAME)
    vm = TartVMManager(BASE_IMAGE_NAME)
    await vm.clone(PREWARMED_VM_NAME)
    await vm.start()
    try:
        await _install_nix(vm)
    finally:
        # Deliberately not deleted — the whole point is a persistent, reusable
        # disk other clones can be made from.
        await vm.stop()

    logger.info("%r is ready. Pass --base-vm %s to skip the Nix install wait.", PREWARMED_VM_NAME, PREWARMED_VM_NAME)


def main() -> int:
    try:
        asyncio.run(_prewarm())
    except VMError as exc:
        logger.error("prewarm failed: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
