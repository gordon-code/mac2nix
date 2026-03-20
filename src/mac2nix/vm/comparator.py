"""FileSystemComparator — VM filesystem snapshot and diff engine."""

from __future__ import annotations

import logging
import re
import shlex
from datetime import datetime

from mac2nix.vm._utils import VMError
from mac2nix.vm.manager import TartVMManager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Noise filter patterns (10 categories, adapted from macbook-config-mirror)
# ---------------------------------------------------------------------------

_FILTER_PATTERNS: dict[str, list[str]] = {
    # Apple system services that commonly create metadata
    "apple_services": [
        r".*com\.apple\..*",
    ],
    # System directories with frequently changing metadata
    "system_directories": [
        r"/private/var/(spool|run|sntpd|sntp|select|rpc|protected|networkd|netboot|msgs|mail|ma|logs|log|folders|db|empty|dirs_cleaner)/.*",
        r"/private/tmp/.*",
        r"/private/etc/cups/.*",
        r"/private/var/tmp/.*",
        r"/Volumes/.*_Cryptex/\.fseventsd/.*",
    ],
    # Library directories that contain system-managed data
    "library_system_data": [
        (
            r".*/Library/(Saved Application State|DataDeliveryServices|DoNotDisturb"
            r"|HomeKit|PPM|Passes|Suggestions|UnifiedAssetFramework|TRM"
            r"|MemoryMaintenance|MediaRemote|Mail|Logs|Keychains|HTTPStorages|Audio"
            r"|Caches|Receipts|Bluetooth|CoreAnalytics|OSAnalytics|Trial|Assistant"
            r"|Messages|Photos|Biome|Metadata|IdentityServices|AppleMediaServices"
            r"|DuetExpertCenter|IntelligencePlatform|News)/.*"
        ),
        r".*/Library/Application Support/(AddressBook|CallHistoryDB|FaceTime|CrashReporter|DiskImages).*",
        r".*/Library/Daemon Containers/.*/Data/ActionTranscript/System/local/.*",
    ],
    # Development and documentation files from Homebrew
    "homebrew_noise": [
        r"/opt/homebrew/\.git.*",
        r"/opt/homebrew/Cellar/go/.*",
        r"/opt/homebrew(/Cellar/[^/]+/[^/]+)?/(share|include)/.*",
        r"/opt/homebrew/Library/Homebrew/(vendor|test|unpack_strategy|rubocops|sorbet|utils)/.*",
        r"/opt/homebrew/Library/Homebrew/.*\.rb$",
        r"/opt/homebrew/Library/Taps/.*/\.git/.*",
    ],
    # Application framework internals (not app-specific)
    "app_internals": [
        r"/Applications/.*/Contents/Frameworks/.*",
        r"/Applications/.*/Contents/_CodeSignature/.*",
        r"/Applications/.*/Contents/Resources/.*",
    ],
    # Database temporary files
    "database_files": [
        r".*\.[^.]*(db|sqlite(3)?)-(shm|wal)$",
        r".*\.db\..*\.migrated$",
    ],
    # Cache directories
    "caches": [
        r".*/Caches/.*",
        r".*/\.?cache/.*",  # matches both /cache/ and /.cache/
        r".*/\.Spotlight-V100/.*",
    ],
    # Common temporary and system files
    "temp_and_system": [
        r".*/\.DS_Store$",
        r".*\.swp$",
        r".*\.tmp$",
        r".*\.git/.*",
        r".*\.localized$",
    ],
    # Test artifacts from the scanning process
    "test_artifacts": [
        r"/Users/.*/before\.txt$",
        r"/Users/.*/after\.txt$",
    ],
    # Files that always change between snapshots
    "always_modified": [
        r"/private/var/root/Library/Preferences/SubmitDiagInfo\.plist",
        r"/private/var/root/Library/ContainerManager/System/boot\.txt",
        r"/Library/Updates/ProductMetadata\.plist",
        r"/Library/Preferences/SystemConfiguration/OSThermalStatus\.plist",
        r"/Library/Preferences/SystemConfiguration/NetworkInterfaces\.plist",
        r"/Library/Printers/InstalledPrinters\.plist",
        r"/opt/homebrew/var/homebrew/locks/update",
        r"/opt/homebrew/etc/paths",
        r"/Users/.*/Library/Shortcuts/ToolKit/Tools-prod.*\.sqlite",
        r"/Users/.*/Library/Sharing/AutoUnlock/pairing-records\.plist",
        r"/Users/.*/Library/Sharing/AirDropHashDB/AirDropHashDB\.airdrop_dbv4",
        r"/Users/.*/Library/Safari/PasswordBreachStore\.plist",
        r"/Users/.*/Library/Preferences/pbs\.plist",
        r"/Users/.*/Library/Preferences/no_backup/commcenter_runtime_storage\.plist",
        r"/Users/.*/Library/Preferences/diagnostics_agent\.plist",
        r"/Users/.*/Library/PersonalizationPortrait/Topics/ScoreCache",
        r"/Users/.*/Library/ContainerManager/boot\.txt",
        r"/Users/.*/.zshenv",
        r"/Users/.*/.zsh_history",
        r"/Users/.*/Library/Preferences/ContextStoreAgent\.plist",
        r"/Users/.*/Library/Preferences/\.GlobalPreferences\.plist",
    ],
}

# Compile once at import time.
_COMPILED_PATTERNS: list[re.Pattern[str]] = []
for _category, _pats in _FILTER_PATTERNS.items():
    for _pat in _pats:
        try:
            _COMPILED_PATTERNS.append(re.compile(_pat))
        except re.error:
            logger.warning("Invalid noise filter regex (skipped): %r", _pat)


# ---------------------------------------------------------------------------
# Default exclude directories for find commands
# ---------------------------------------------------------------------------

_DEFAULT_EXCLUDE_DIRS: list[str] = ["Spotlight", "Caches", "AssetsV2", "Pictures"]

# Directory names interpolated into shell find commands must be safe.
_SAFE_DIRNAME = re.compile(r"^[\w.\- ]+$")


class FileSystemComparator:
    """Async filesystem snapshot and diff engine for VM-based package discovery.

    Takes before/after filesystem snapshots via remote ``find`` commands through
    :class:`~mac2nix.vm.manager.TartVMManager`, computes created/deleted/modified
    file lists, and applies noise filters.

    :param vm: Active :class:`TartVMManager` with a running clone.
    :param scan_root: Remote root to scan (default ``'/System/Volumes/Data'``).
    :param exclude_dirs: Directory names to prune during find (default list
        includes Spotlight, Caches, AssetsV2, Pictures).
    """

    def __init__(
        self,
        vm: TartVMManager,
        scan_root: str = "/System/Volumes/Data",
        exclude_dirs: list[str] | None = None,
    ) -> None:
        self._vm = vm
        self._scan_root = scan_root
        self._exclude_dirs: list[str] = exclude_dirs if exclude_dirs is not None else list(_DEFAULT_EXCLUDE_DIRS)
        for d in self._exclude_dirs:
            if not _SAFE_DIRNAME.match(d):
                raise ValueError(f"Invalid exclude directory name (must be alphanumeric/dot/hyphen/space): {d!r}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_find_pipeline(self, save_path: str) -> str:
        """Return a shell pipeline string that snapshots the filesystem to *save_path*."""
        prune_parts = " -or ".join(f'-path "*/{d}"' for d in self._exclude_dirs)
        prune_clause = f'\\( {prune_parts} -or -name ".localized" \\) -prune -or -print'
        quoted_root = shlex.quote(self._scan_root)
        quoted_save = shlex.quote(save_path)
        # Use awk substr to strip the scan_root prefix — no regex, no injection risk.
        prefix_len = len(self._scan_root) + 1  # +1 to also skip trailing separator
        return (
            f"sudo find {quoted_root} {prune_clause} 2>/dev/null"
            f" | awk '{{print substr($0, {prefix_len})}}'"
            f" | sort > {quoted_save}"
        )

    # ------------------------------------------------------------------
    # Public async API
    # ------------------------------------------------------------------

    async def snapshot(self, save_path: str) -> None:
        """Take a sorted filesystem snapshot on the VM and save it to *save_path*.

        Runs a remote ``find | sed | sort > path`` pipeline via bash.
        Raises :exc:`VMError` if the command fails.
        """
        pipeline = self._build_find_pipeline(save_path)
        logger.debug("Taking snapshot → %s", save_path)
        success, _out, err = await self._vm.exec_command(["bash", "-c", pipeline], timeout=45)
        if not success:
            raise VMError(f"snapshot to {save_path!r} failed: {err.strip()}")
        logger.debug("Snapshot complete: %s", save_path)

    async def get_created_files(self, before_path: str, after_path: str) -> list[str]:
        """Return files that appear in *after_path* but not in *before_path*.

        Uses remote ``comm -13`` (lines unique to the second file).
        """
        cmd = f"comm -13 {shlex.quote(before_path)} {shlex.quote(after_path)}"
        success, out, err = await self._vm.exec_command(["bash", "-c", cmd], timeout=45)
        if not success:
            logger.warning("get_created_files failed: %s", err.strip())
        return self.filter_noise(out.strip().splitlines())

    async def get_deleted_files(self, before_path: str, after_path: str) -> list[str]:
        """Return files that appear in *before_path* but not in *after_path*.

        Uses remote ``comm -23`` (lines unique to the first file).
        """
        cmd = f"comm -23 {shlex.quote(before_path)} {shlex.quote(after_path)}"
        success, out, err = await self._vm.exec_command(["bash", "-c", cmd], timeout=45)
        if not success:
            logger.warning("get_deleted_files failed: %s", err.strip())
        return self.filter_noise(out.strip().splitlines())

    async def get_modified_files(
        self,
        since: datetime,
        scan_root: str | None = None,
    ) -> list[str]:
        """Return files modified after *since* that existed before *since*.

        Uses remote ``find -newermt`` + ``stat`` + ``awk`` to exclude newly
        created files (birth time >= cutoff). Results are noise-filtered.

        :param since: Datetime threshold (files modified after this instant).
        :param scan_root: Override the instance scan root for this call.
        """
        root = scan_root if scan_root is not None else self._scan_root
        prune_parts = " -or ".join(f'-path "*/{d}"' for d in self._exclude_dirs)
        prune_clause = f'\\( {prune_parts} -or -name ".localized" \\) -prune -or'
        ts_iso = since.replace(microsecond=0).isoformat()
        cutoff = int(since.timestamp())
        quoted_root = shlex.quote(root)
        prefix_len = len(root) + 1

        pipeline = (
            f"sudo find {quoted_root} {prune_clause}"
            f" -type f -newermt {shlex.quote(ts_iso)}"
            f" -exec stat -f '%B %N' {{}} + 2>/dev/null"
            f" | awk -v cutoff={cutoff} '$1 < cutoff {{ print substr($0, index($0, $2)) }}'"
            f" | awk '{{print substr($0, {prefix_len})}}'"
            f" | sort"
        )

        logger.debug("Finding modified files since %s in %s", ts_iso, root)
        success, out, err = await self._vm.exec_command(["bash", "-c", pipeline], timeout=45)
        if not success:
            logger.warning("get_modified_files failed: %s", err.strip())
        return self.filter_noise(out.strip().splitlines())

    # ------------------------------------------------------------------
    # Noise filtering
    # ------------------------------------------------------------------

    def filter_noise(self, files: list[str]) -> list[str]:
        """Filter *files* against all compiled noise patterns.

        Empty strings are discarded. Each remaining path is tested against the
        module-level compiled patterns; the first match causes the path to be
        excluded.

        Returns the filtered list.
        """
        result: list[str] = []
        for raw in files:
            stripped = raw.strip()
            if not stripped:
                continue
            if not any(p.search(stripped) for p in _COMPILED_PATTERNS):
                result.append(stripped)

        filtered_count = len(files) - len(result)
        if filtered_count > 0:
            logger.debug("Noise filter: removed %d of %d paths", filtered_count, len(files))

        return result
