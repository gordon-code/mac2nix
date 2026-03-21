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
_REMOTE_BEFORE_EXEC = "/tmp/mac2nix-before-exec.txt"  # noqa: S108

# Directories searched for new executables/app bundles.
_EXEC_SEARCH_DIRS = (
    "/Applications",
    "/System/Applications",
    "/opt/homebrew/bin",
    "/usr/local/bin",
)

# Binary options tried to trigger config file creation.
_BINARY_PROBE_OPTIONS = ("--version", "--help", "-v")

# Homebrew package names: lowercase, digits, @, dot, underscore, hyphen, slash (for taps).
_SAFE_PACKAGE_NAME = re.compile(r"^[a-zA-Z0-9@._/\-]+$")


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
        if not _SAFE_PACKAGE_NAME.match(package):
            raise VMError(f"Invalid package name: {package!r}")

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

            # Step 2b: Pre-installation executable snapshot (absolute paths).
            if not await self._snapshot_executables(_REMOTE_BEFORE_EXEC):
                logger.error("Pre-exec snapshot failed for %r — executable discovery will be skipped", package)
                return self._empty_result(package, package_type)

            # Step 3: Install the package.
            install_ok = await self._install_package(package, package_type)
            if not install_ok:
                return self._empty_result(package, package_type)

            # Step 4: Settle.
            await asyncio.sleep(5)

            # Step 5 & 6: Find and execute new executables.
            install_timestamp = datetime.now(UTC)
            executables = await self._find_new_executables(package, _REMOTE_BEFORE_EXEC)
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

    @staticmethod
    def _build_exec_find_pipeline(save_path: str) -> str:
        """Build a find pipeline for executable discovery, saving sorted results to *save_path*."""
        search_dirs = " ".join(shlex.quote(d) for d in _EXEC_SEARCH_DIRS)
        return (
            f"find {search_dirs} -maxdepth 2"
            r" \( -name '*.app' -type d -o \( -type f -o -type l \) -perm +111 \)"
            " 2>/dev/null"
            f" | sort > {shlex.quote(save_path)}"
        )

    async def _snapshot_executables(self, save_path: str) -> bool:
        """Snapshot executable locations to *save_path* (absolute paths, sorted)."""
        pipeline = self._build_exec_find_pipeline(save_path)
        ok, _out, err = await self._vm.exec_command(["bash", "-c", pipeline], timeout=30)
        if not ok:
            logger.warning("Failed to snapshot executables to %s: %s", save_path, err.strip())
        return ok

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

    async def _find_new_executables(self, package: str, before_exec_path: str) -> dict[str, list[str]]:
        """Return new .app bundles and binaries created since the pre-exec snapshot."""
        executables: dict[str, list[str]] = {"apps": [], "binaries": []}

        temp_path = f"/tmp/mac2nix-exec-{package.replace('/', '-')}.txt"  # noqa: S108

        # Same find pipeline format as _snapshot_executables (shared via _build_exec_find_pipeline).
        find_pipeline = self._build_exec_find_pipeline(temp_path)
        ok, _out, err = await self._vm.exec_command(["bash", "-c", find_pipeline], timeout=30)
        if not ok:
            logger.warning("Failed to find executables for %r: %s", package, err.strip())
            return executables

        # comm -13: lines only in second file = newly appeared since before-exec snapshot.
        comm_cmd = f"comm -13 {shlex.quote(before_exec_path)} {shlex.quote(temp_path)}"
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
        # Single SSH call per app: xattr clear + plist read + name validation + launch.
        for app_path in executables["apps"]:
            q_app = shlex.quote(app_path)
            q_plist = shlex.quote(app_path + "/Contents/Info.plist")
            probe_script = (
                f"sudo xattr -rc {q_app} >/dev/null 2>&1 || true; "
                f"exe=$(defaults read {q_plist} CFBundleExecutable 2>/dev/null) || exit 0; "
                # Validate executable name — bare alphanumeric + dots/hyphens/underscores/spaces.
                f'printf "%s" "$exe" | grep -qxE "^[A-Za-z0-9_. -]+$" || exit 0; '
                f'{q_app}/Contents/MacOS/"$exe" >/dev/null 2>&1 & sleep 0.1'
            )
            ok, _out, err = await self._vm.exec_command(["bash", "-c", probe_script], timeout=5)
            if ok:
                logger.debug("Probed app bundle: %s", app_path)
            else:
                logger.debug("Could not probe %s: %s", app_path, err.strip())

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
