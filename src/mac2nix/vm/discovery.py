"""DiscoveryRunner — app config path discovery via VM install diffing."""

from __future__ import annotations

import asyncio
import logging
import re
import shlex
import uuid
from datetime import UTC, datetime

from pydantic import BaseModel

from mac2nix.vm._utils import VMError
from mac2nix.vm.comparator import FileSystemComparator
from mac2nix.vm.manager import TartVMManager

logger = logging.getLogger(__name__)

# Remote snapshot paths inside the VM.
_REMOTE_BEFORE = "/tmp/mac2nix-before.txt"  # noqa: S108
_REMOTE_AFTER = "/tmp/mac2nix-after.txt"  # noqa: S108

# Directories searched for new executables/app bundles.
_EXEC_SEARCH_DIRS = (
    "/Applications",
    "/System/Applications",
    "/opt/homebrew/bin",
    "/usr/local/bin",
)

# Binary options tried to trigger config file creation.
_BINARY_PROBE_OPTIONS = ("--version", "--help", "-v")

# CFBundleExecutable must be a bare filename — no path separators or shell metacharacters.
_SAFE_EXECUTABLE_NAME = re.compile(r"^[A-Za-z0-9_.\- ]+$")


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class DiscoveryResult(BaseModel):
    package: str
    package_type: str
    created_files: list[str]
    modified_files: list[str]
    deleted_files: list[str]
    executables_found: dict[str, list[str]]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class DiscoveryRunner:
    """Orchestrates VM clone + filesystem diff to discover app config paths.

    Workflow per :meth:`discover` call:
    1. Clone the base VM and start it.
    2. Pre-installation filesystem snapshot.
    3. Install the package via ``brew install [--cask]``.
    4. Settle (5 s).
    5. Find newly created executables and app bundles.
    6. Execute them to trigger config file creation, then wait 10 s.
    7. Post-installation filesystem snapshot.
    8. Diff created/deleted files; apply noise filters.
    9. Cleanup the clone (always, even on error).

    :param vm: :class:`TartVMManager` configured with the base VM name and
        SSH credentials. The manager must NOT have an active clone yet —
        :meth:`discover` creates a fresh clone per run.
    """

    def __init__(self, vm: TartVMManager) -> None:
        self._vm = vm

    async def discover(
        self,
        package: str,
        package_type: str = "brew",
    ) -> DiscoveryResult:
        """Run the full discovery workflow for *package*.

        Clone/start failures re-raise as :exc:`VMError`. Install failures and
        snapshot failures return a :class:`DiscoveryResult` with empty file
        lists so callers can distinguish "couldn't run" from "nothing changed".
        Cleanup always runs.
        """
        clone_name = f"mac2nix-discover-{package.replace('/', '-')}-{uuid.uuid4().hex[:8]}"
        comparator = FileSystemComparator(self._vm)

        try:
            # Step 1: Clone and start — failure here is fatal (raises VMError).
            await self._vm.clone(clone_name)
            await self._vm.start()

            # Step 2: Pre-installation snapshot.
            try:
                await comparator.snapshot(_REMOTE_BEFORE)
            except VMError as exc:
                logger.error("Pre-snapshot failed for %r: %s", package, exc)
                return self._empty_result(package, package_type)

            # Step 3: Install the package.
            install_ok = await self._install_package(package, package_type)
            if not install_ok:
                return self._empty_result(package, package_type)

            # Step 4: Settle.
            await asyncio.sleep(5)

            # Step 5 & 6: Find and execute new executables.
            install_timestamp = datetime.now(UTC)
            executables = await self._find_new_executables(package)
            await self._execute_found(executables)

            # Step 7: Post-installation snapshot.
            try:
                await comparator.snapshot(_REMOTE_AFTER)
            except VMError as exc:
                logger.error("Post-snapshot failed for %r: %s", package, exc)
                return self._empty_result(package, package_type, executables)

            # Step 8: Diff.
            created = await comparator.get_created_files(_REMOTE_BEFORE, _REMOTE_AFTER)
            deleted = await comparator.get_deleted_files(_REMOTE_BEFORE, _REMOTE_AFTER)
            modified = await comparator.get_modified_files(install_timestamp)

            return DiscoveryResult(
                package=package,
                package_type=package_type,
                created_files=created,
                modified_files=modified,
                deleted_files=deleted,
                executables_found=executables,
            )

        finally:
            # Step 9: Always cleanup.
            await self._vm.cleanup()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_result(
        package: str,
        package_type: str,
        executables_found: dict[str, list[str]] | None = None,
    ) -> DiscoveryResult:
        return DiscoveryResult(
            package=package,
            package_type=package_type,
            created_files=[],
            modified_files=[],
            deleted_files=[],
            executables_found=executables_found or {},
        )

    async def _install_package(self, package: str, package_type: str) -> bool:
        """Install *package* via brew. Returns True on success."""
        # Use bash -c with shlex.quote to prevent shell injection via package name.
        cask_flag = "--cask " if package_type == "cask" else ""
        install_cmd = f"brew install {cask_flag}{shlex.quote(package)}"

        logger.debug("Installing %r via: %s", package, install_cmd)
        ok, _out, err = await self._vm.exec_command(["bash", "-c", install_cmd], timeout=1800)
        if not ok:
            logger.warning("Installation failed for %r: %s", package, err.strip())
        return ok

    async def _find_new_executables(self, package: str) -> dict[str, list[str]]:
        """Return new .app bundles and binaries created since the pre-snapshot."""
        executables: dict[str, list[str]] = {"apps": [], "binaries": []}

        search_dirs = " ".join(_EXEC_SEARCH_DIRS)
        temp_path = f"/tmp/mac2nix-exec-{package.replace('/', '-')}.txt"  # noqa: S108

        # Find all .app bundles and executable files/symlinks in well-known dirs.
        find_pipeline = (
            f"find {search_dirs}"
            r" \( -name '*.app' -type d -o \( -type f -o -type l \) -perm +111 \)"
            " -maxdepth 2 2>/dev/null"
            f" | sort > {shlex.quote(temp_path)}"
        )
        ok, _out, err = await self._vm.exec_command(["bash", "-c", find_pipeline], timeout=30)
        if not ok:
            logger.warning("Failed to find executables for %r: %s", package, err.strip())
            return executables

        # comm -13: lines only in second file = newly appeared since before-snapshot.
        comm_cmd = f"comm -13 {shlex.quote(_REMOTE_BEFORE)} {shlex.quote(temp_path)}"
        ok, out, err = await self._vm.exec_command(["bash", "-c", comm_cmd], timeout=15)

        # Best-effort cleanup of temp file.
        await self._vm.exec_command(["rm", "-f", temp_path], timeout=5)

        if not ok:
            logger.warning("Failed to compare executable lists for %r: %s", package, err.strip())
            return executables

        for raw_path in out.strip().splitlines():
            stripped = raw_path.strip()
            if not stripped:
                continue
            if stripped.endswith(".app"):
                executables["apps"].append(stripped)
            else:
                executables["binaries"].append(stripped)

        logger.debug(
            "Found %d app(s) and %d binary/binaries for %r",
            len(executables["apps"]),
            len(executables["binaries"]),
            package,
        )
        return executables

    async def _execute_found(self, executables: dict[str, list[str]]) -> None:
        """Launch found executables to trigger config file creation."""
        if not executables["apps"] and not executables["binaries"]:
            return

        # Launch .app bundles in background via their CFBundleExecutable.
        for app_path in executables["apps"]:
            q_app = shlex.quote(app_path)
            ok, out, err = await self._vm.exec_command(
                [
                    "bash",
                    "-c",
                    f"sudo xattr -rc {q_app} >/dev/null 2>&1 || true;"
                    f" defaults read {shlex.quote(app_path + '/Contents/Info.plist')} CFBundleExecutable",
                ],
            )
            if ok:
                executable_name = out.strip()
                if not _SAFE_EXECUTABLE_NAME.match(executable_name):
                    logger.warning("Suspicious CFBundleExecutable %r in %s — skipping", executable_name, app_path)
                    continue
                launch_cmd = (
                    f"{shlex.quote(app_path + '/Contents/MacOS/' + executable_name)} >/dev/null 2>&1 & sleep 0.1"
                )
                await self._vm.exec_command(["bash", "-c", launch_cmd], timeout=2)
                logger.debug("Launched app bundle: %s", app_path)
            else:
                logger.debug("Could not identify executable in %s: %s", app_path, err.strip())

        # Probe binaries with --version / --help to trigger config writes.
        if executables["binaries"]:
            probe_parts = []
            for binary in executables["binaries"]:
                q_bin = shlex.quote(binary)
                for option in _BINARY_PROBE_OPTIONS:
                    probe_parts.append(
                        f"sudo xattr -c {q_bin} 2>/dev/null; timeout 5 {q_bin} {option} >/dev/null 2>&1;"
                    )
            probe_parts.append("true")  # Always succeed
            probe_cmd = " ".join(probe_parts)
            timeout = len(executables["binaries"]) * 5 + 3
            await self._vm.exec_command(["bash", "-c", probe_cmd], timeout=timeout)

        # Allow executables time to write their config files.
        logger.debug("Waiting 10s for executables to write config files")
        await asyncio.sleep(10)
