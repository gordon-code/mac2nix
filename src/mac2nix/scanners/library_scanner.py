"""Library scanner — discovers ~/Library content, app configs, and system bundles."""

from __future__ import annotations

import contextlib
import logging
import os
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mac2nix.models.files import (
    AppConfigEntry,
    BundleEntry,
    ConfigFileType,
    KeyBindingEntry,
    LibraryDirEntry,
    LibraryFileEntry,
    LibraryResult,
    WorkflowEntry,
)
from mac2nix.scanners._utils import (
    NON_CONFIG_EXTENSIONS,
    WALK_SKIP_DIRS,
    WALK_SKIP_SUFFIXES,
    hash_file,
    parallel_walk_dirs,
    read_plist_safe,
    run_command,
)
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

# --- App config constants ---

_EXTENSION_MAP: dict[str, ConfigFileType] = {
    ".json": ConfigFileType.JSON,
    ".plist": ConfigFileType.PLIST,
    ".toml": ConfigFileType.TOML,
    ".yaml": ConfigFileType.YAML,
    ".yml": ConfigFileType.YAML,
    ".xml": ConfigFileType.XML,
    ".conf": ConfigFileType.CONF,
    ".cfg": ConfigFileType.CONF,
    ".ini": ConfigFileType.CONF,
    ".sqlite": ConfigFileType.DATABASE,
    ".db": ConfigFileType.DATABASE,
    ".sqlite3": ConfigFileType.DATABASE,
}

_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# --- Library audit constants ---

_COVERED_DIRS: dict[str, str] = {
    "Preferences": "preferences",
    "Application Support": "library",
    "Fonts": "fonts",
    "LaunchAgents": "launch_agents",
    "Containers": "preferences+library",
    "Group Containers": "library",
    "FontCollections": "fonts",
    "SyncedPreferences": "preferences",
}

_TRANSIENT_DIRS = frozenset(
    {
        "Caches",
        "Logs",
        "Saved Application State",
        "Cookies",
        "HTTPStorages",
        "WebKit",
        "Messages",
        "Calendars",
        "Reminders",
        "Metadata",
        "Updates",
        "Autosave Information",
    }
)

_SENSITIVE_KEY_PATTERNS = {"_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIAL", "_AUTH"}

# Redacts values in key=value / key: value lines where the key contains a sensitive word.
# Uses separator-prefixed compound patterns ([_.-]key, [_.-]token, etc.) to avoid false
# positives on words like "monkey", "turkey", "keyboard". Standalone patterns (password,
# secret, token) are anchored to the start of the key. Handles JSON quoted keys.
_SENSITIVE_VALUE_RE = re.compile(
    r'^(\s*"?(?:\S*[_.\-](?:key|token|secret|password|credential|auth)'
    r'|password|passwd|secret|token)"?\s*[:=]\s*).+',
    re.IGNORECASE | re.MULTILINE,
)


_SYSTEM_SCAN_PATTERNS: dict[str, str] = {
    "Extensions": "*.kext",
    "PreferencePanes": "*.prefPane",
    "Screen Savers": "*.saver",
    "QuickLook": "*.qlgenerator",
}

_BUNDLE_EXTENSIONS = frozenset(
    {
        ".component",
        ".vst",
        ".saver",
        ".prefPane",
        ".qlgenerator",
        ".plugin",
        ".kext",
    }
)


def _redact_sensitive_keys(data: dict[str, Any]) -> None:
    """Recursively redact sensitive keys from a plist dict."""
    for key in list(data.keys()):
        if any(p in key.upper() for p in _SENSITIVE_KEY_PATTERNS):
            data[key] = "***REDACTED***"
        elif isinstance(data[key], dict):
            _redact_sensitive_keys(data[key])
        elif isinstance(data[key], list):
            for item in data[key]:
                if isinstance(item, dict):
                    _redact_sensitive_keys(item)


@register("library")
class LibraryScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "library"

    def scan(self) -> LibraryResult:
        home = Path.home()
        home_lib = home / "Library"

        # --- Library directory audit ---
        directories = self._audit_directories(home_lib)
        uncovered_files: list[LibraryFileEntry] = []
        workflows: list[WorkflowEntry] = []
        bundles: list[BundleEntry] = []
        key_bindings = self._scan_key_bindings(home_lib)
        spelling_words, spelling_dicts = self._scan_spelling(home_lib)
        text_replacements = self._scan_text_replacements(home_lib)
        input_methods = self._scan_bundles_in_dir(home_lib / "Input Methods")
        keyboard_layouts = self._list_files_by_extension(home_lib / "Keyboard Layouts", ".keylayout")
        color_profiles = self._list_files_by_extension(home_lib / "ColorSync" / "Profiles", ".icc", ".icm")
        compositions = self._list_files_by_extension(home_lib / "Compositions", ".qtz")
        scripts = self._scan_scripts(home_lib)

        # Capture uncovered files, workflows, and bundles from uncovered directories
        uncovered_dirs = [d.path for d in directories if d.covered_by_scanner is None and d.name not in _TRANSIENT_DIRS]
        captured = parallel_walk_dirs(uncovered_dirs, self._capture_uncovered_dir)
        for files, wf, bdl in captured:
            uncovered_files.extend(files)
            workflows.extend(wf)
            bundles.extend(bdl)
        # Scan workflows from known Workflows/Services dirs
        for wf_dir_name in ["Workflows", "Services"]:
            wf_dir = home_lib / wf_dir_name
            if wf_dir.is_dir():
                workflows.extend(self._scan_workflows(wf_dir))

        # Sort parallel-aggregated lists for deterministic output
        uncovered_files.sort(key=lambda e: str(e.path))
        workflows.sort(key=lambda e: str(e.path))
        bundles.sort(key=lambda e: str(e.path))

        # --- App config scanning ---
        entries = self._scan_app_configs(home_lib)

        # --- system library bundles ---
        system_bundles = self._scan_system_library()

        return LibraryResult(
            app_configs=entries,
            bundles=bundles,
            directories=directories,
            uncovered_files=uncovered_files,
            workflows=workflows,
            key_bindings=key_bindings,
            spelling_words=spelling_words,
            spelling_dictionaries=spelling_dicts,
            input_methods=input_methods,
            keyboard_layouts=keyboard_layouts,
            color_profiles=color_profiles,
            compositions=compositions,
            scripts=scripts,
            text_replacements=text_replacements,
            system_bundles=system_bundles,
        )

    # --- App config scanning ---

    def _scan_app_configs(self, home_lib: Path) -> list[AppConfigEntry]:
        """Walk Application Support, Group Containers, and Containers for app configs."""
        scan_dirs = [
            home_lib / "Application Support",
            home_lib / "Group Containers",
        ]

        # Add Containers app support dirs
        containers_dir = home_lib / "Containers"
        if containers_dir.is_dir():
            try:
                for container in sorted(containers_dir.iterdir()):
                    app_support = container / "Data" / "Library" / "Application Support"
                    if app_support.is_dir() and os.access(app_support, os.R_OK):
                        scan_dirs.append(app_support)
            except PermissionError:
                logger.warning("Permission denied reading: %s", containers_dir)

        all_app_dirs: list[Path] = []
        for base_dir in scan_dirs:
            if not base_dir.is_dir():
                continue
            try:
                app_dirs = sorted(base_dir.iterdir())
            except PermissionError:
                logger.warning("Permission denied reading: %s", base_dir)
                continue
            for app_dir in app_dirs:
                if not app_dir.is_dir():
                    continue
                if not os.access(app_dir, os.R_OK):
                    logger.debug("Skipping TCC-protected directory: %s", app_dir)
                    continue
                all_app_dirs.append(app_dir)

        batched = parallel_walk_dirs(all_app_dirs, self._scan_app_dir)
        entries = [e for batch in batched for e in batch]
        entries.sort(key=lambda e: (e.app_name, str(e.path)))
        return entries

    def _scan_app_dir(self, app_dir: Path) -> list[AppConfigEntry]:
        app_name = app_dir.name
        entries: list[AppConfigEntry] = []

        try:
            for dirpath, dirnames, filenames in os.walk(app_dir, followlinks=False):
                # Prune skipped directories in-place
                dirnames[:] = [d for d in dirnames if d not in WALK_SKIP_DIRS and not d.endswith(WALK_SKIP_SUFFIXES)]

                for filename in filenames:
                    filepath = Path(dirpath) / filename
                    ext = filepath.suffix.lower()

                    # Skip non-config files before any syscall
                    if ext in NON_CONFIG_EXTENSIONS:
                        continue

                    try:
                        stat = filepath.stat()
                    except OSError:
                        continue

                    # Skip files over 10MB
                    if stat.st_size > _MAX_FILE_SIZE:
                        continue

                    file_type = _EXTENSION_MAP.get(ext, ConfigFileType.UNKNOWN)
                    scannable = file_type != ConfigFileType.DATABASE

                    content_hash = hash_file(filepath) if scannable else None
                    modified_time = datetime.fromtimestamp(stat.st_mtime, tz=UTC)

                    entries.append(
                        AppConfigEntry(
                            app_name=app_name,
                            path=filepath,
                            file_type=file_type,
                            content_hash=content_hash,
                            scannable=scannable,
                            modified_time=modified_time,
                        )
                    )
        except PermissionError:
            logger.warning("Permission denied reading app config dir: %s", app_dir)

        return entries

    # --- Library audit scanning ---

    def _audit_directories(self, lib_path: Path) -> list[LibraryDirEntry]:
        """Walk top-level ~/Library directories and collect metadata."""
        if not lib_path.is_dir():
            return []

        try:
            children = [c for c in sorted(lib_path.iterdir()) if c.is_dir()]
        except PermissionError:
            logger.warning("Permission denied reading: %s", lib_path)
            return []

        def _compute_entry(child: Path) -> LibraryDirEntry:
            covered = _COVERED_DIRS.get(child.name)
            file_count, total_size, newest_mod = self._dir_stats(child)
            return LibraryDirEntry(
                name=child.name,
                path=child,
                file_count=file_count,
                total_size_bytes=total_size,
                covered_by_scanner=covered,
                has_user_content=covered is None and child.name not in _TRANSIENT_DIRS,
                newest_modification=newest_mod,
            )

        entries = parallel_walk_dirs(children, _compute_entry)
        entries.sort(key=lambda e: e.name)
        return entries

    @staticmethod
    def _dir_stats(path: Path) -> tuple[int | None, int | None, datetime | None]:
        """Get file count, total size, and newest modification for a directory."""
        try:
            file_count = 0
            total_size = 0
            newest = 0.0
            for entry in path.iterdir():
                if entry.is_symlink():
                    continue
                try:
                    st = entry.stat()
                    file_count += 1
                    total_size += st.st_size
                    newest = max(newest, st.st_mtime)
                except OSError:
                    continue
            newest_dt = datetime.fromtimestamp(newest, tz=UTC) if newest > 0 else None
            return file_count, total_size, newest_dt
        except PermissionError:
            return None, None, None

    def _capture_uncovered_dir(
        self, dir_path: Path
    ) -> tuple[list[LibraryFileEntry], list[WorkflowEntry], list[BundleEntry]]:
        """Capture files, workflows, and bundles from an uncovered directory."""
        files: list[LibraryFileEntry] = []
        workflows: list[WorkflowEntry] = []
        bundles: list[BundleEntry] = []

        try:
            for dirpath, dirnames, filenames in os.walk(dir_path, followlinks=False):
                for filename in filenames:
                    filepath = Path(dirpath) / filename
                    entry = self._classify_file(filepath)
                    if entry is not None:
                        files.append(entry)
                # Check dirnames for workflow/bundle directories
                # and prune known non-config directories in a single pass
                kept: list[str] = []
                for dirname in dirnames:
                    sub_path = Path(dirpath) / dirname
                    if dirname.endswith(".workflow"):
                        wf = self._parse_workflow(sub_path)
                        if wf is not None:
                            workflows.append(wf)
                    elif any(dirname.endswith(ext) for ext in _BUNDLE_EXTENSIONS):
                        bundles.append(self._parse_bundle(sub_path))
                    elif dirname not in WALK_SKIP_DIRS and not dirname.endswith(WALK_SKIP_SUFFIXES):
                        kept.append(dirname)
                dirnames[:] = kept
        except PermissionError:
            logger.warning("Permission denied walking: %s", dir_path)

        return files, workflows, bundles

    def _classify_file(self, filepath: Path) -> LibraryFileEntry | None:
        """Classify and capture a file from an uncovered directory."""
        suffix = filepath.suffix.lower()

        if suffix in NON_CONFIG_EXTENSIONS:
            return None

        try:
            stat = filepath.stat()
        except OSError:
            return None

        size = stat.st_size
        file_type = suffix.lstrip(".") if suffix else "unknown"
        plist_content: dict[str, Any] | None = None
        text_content: str | None = None
        content_hash: str | None = None

        # Only do expensive IO on known config file types
        if suffix == ".plist":
            raw_plist = read_plist_safe(filepath)
            if isinstance(raw_plist, dict):
                plist_content = raw_plist
                _redact_sensitive_keys(plist_content)
            content_hash = hash_file(filepath)
            strategy = "plist_capture" if plist_content else "hash_only"
        elif suffix in {".txt", ".md", ".cfg", ".conf", ".ini", ".yaml", ".yml", ".json", ".xml", ".toml"}:
            content_hash = hash_file(filepath)
            if size < 65536:
                with contextlib.suppress(OSError):
                    raw_text = filepath.read_text(errors="replace")
                    text_content = _SENSITIVE_VALUE_RE.sub(r"\1***REDACTED***", raw_text)
            strategy = "text_capture" if text_content else "hash_only"
        elif suffix in _BUNDLE_EXTENSIONS:
            strategy = "bundle"
        else:
            # Non-config file: record path + size only, no IO
            strategy = "metadata_only"

        return LibraryFileEntry(
            path=filepath,
            file_type=file_type,
            content_hash=content_hash,
            plist_content=plist_content,
            text_content=text_content,
            migration_strategy=strategy,
            size_bytes=size,
        )

    def _scan_key_bindings(self, lib_path: Path) -> list[KeyBindingEntry]:
        """Read DefaultKeyBinding.dict from KeyBindings directory."""
        kb_file = lib_path / "KeyBindings" / "DefaultKeyBinding.dict"
        if not kb_file.is_file():
            return []

        data = read_plist_safe(kb_file)
        if not isinstance(data, dict):
            return []

        entries: list[KeyBindingEntry] = []
        for key, action in data.items():
            if isinstance(action, (str, dict)):
                entries.append(KeyBindingEntry(key=key, action=action))
        return entries

    def _scan_spelling(self, lib_path: Path) -> tuple[list[str], list[str]]:
        """Read user spelling words and dictionaries."""
        words: list[str] = []
        dicts: list[str] = []
        spelling_dir = lib_path / "Spelling"
        if not spelling_dir.is_dir():
            return words, dicts

        local_dict = spelling_dir / "LocalDictionary"
        if local_dict.is_file():
            try:
                content = local_dict.read_text()
                words = [w.strip() for w in content.splitlines() if w.strip()]
            except OSError:
                pass

        try:
            for f in sorted(spelling_dir.iterdir()):
                if f.is_file() and f.name != "LocalDictionary":
                    dicts.append(f.name)
        except PermissionError:
            pass

        return words, dicts

    def _scan_text_replacements(self, lib_path: Path) -> list[dict[str, str]]:
        """Read text replacements from TextReplacements.db."""
        db_path = lib_path / "KeyboardServices" / "TextReplacements.db"
        if not db_path.is_file():
            return []

        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)
            try:
                cursor = conn.execute("SELECT ZSHORTCUT, ZPHRASE FROM ZTEXTREPLACEMENTENTRY")
                return [{"shortcut": row[0], "phrase": row[1]} for row in cursor.fetchall() if row[0] and row[1]]
            finally:
                conn.close()
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            logger.warning("Failed to read TextReplacements.db: %s", exc)
            return []

    def _scan_workflows(self, wf_dir: Path) -> list[WorkflowEntry]:
        """Scan .workflow bundles in a directory."""
        workflows: list[WorkflowEntry] = []
        if not wf_dir.is_dir():
            return workflows
        try:
            for item in sorted(wf_dir.iterdir()):
                if item.suffix == ".workflow" and item.is_dir():
                    wf = self._parse_workflow(item)
                    if wf is not None:
                        workflows.append(wf)
        except PermissionError:
            pass
        return workflows

    @staticmethod
    def _parse_workflow(wf_path: Path) -> WorkflowEntry | None:
        """Parse a .workflow bundle."""
        info_plist = wf_path / "Contents" / "Info.plist"
        identifier: str | None = None
        definition: dict[str, Any] | None = None

        if info_plist.is_file():
            data = read_plist_safe(info_plist)
            if isinstance(data, dict):
                identifier = data.get("CFBundleIdentifier")

        doc_plist = wf_path / "Contents" / "document.wflow"
        if doc_plist.is_file():
            raw = read_plist_safe(doc_plist)
            if isinstance(raw, dict):
                _redact_sensitive_keys(raw)
                definition = raw

        return WorkflowEntry(
            name=wf_path.stem,
            path=wf_path,
            identifier=identifier,
            workflow_definition=definition,
        )

    def _scan_bundles_in_dir(self, dir_path: Path) -> list[BundleEntry]:
        """Scan bundles (by reading Info.plist) in a directory."""
        if not dir_path.is_dir():
            return []
        bundles: list[BundleEntry] = []
        try:
            for item in sorted(dir_path.iterdir()):
                if item.is_symlink() or not item.is_dir():
                    continue
                bundles.append(self._parse_bundle(item))
        except PermissionError:
            logger.debug("Permission denied reading: %s", dir_path)
        return bundles

    @staticmethod
    def _list_files_by_extension(dir_path: Path, *extensions: str) -> list[str]:
        """Scan files in a directory and return their names."""
        if not dir_path.is_dir():
            return []
        results: list[str] = []
        try:
            for f in sorted(dir_path.iterdir()):
                if f.is_file() and (not extensions or f.suffix.lower() in extensions):
                    results.append(f.name)
        except PermissionError:
            pass
        return results

    def _scan_scripts(self, lib_path: Path) -> list[str]:
        """Scan Scripts directory for script files."""
        scripts_dir = lib_path / "Scripts"
        if not scripts_dir.is_dir():
            return []

        scripts: list[str] = []
        try:
            for f in sorted(scripts_dir.iterdir()):
                if f.is_file():
                    if f.suffix == ".scpt":
                        # Try to decompile AppleScript
                        result = run_command(["osadecompile", str(f)], timeout=10)
                        if result is not None and result.returncode == 0:
                            scripts.append(f"{f.name}: {result.stdout[:200]}")
                        else:
                            scripts.append(f.name)
                    else:
                        scripts.append(f.name)
        except PermissionError:
            pass
        return scripts

    def _scan_system_library(self) -> list[BundleEntry]:
        """Scan /Library/ for user-installed items."""
        system_lib = Path("/Library")
        if not system_lib.is_dir():
            return []

        bundles: list[BundleEntry] = []

        # Scan specific directories for bundles
        for dir_name, pattern in _SYSTEM_SCAN_PATTERNS.items():
            scan_dir = system_lib / dir_name
            if not scan_dir.is_dir():
                continue
            try:
                for item in sorted(scan_dir.glob(pattern)):
                    if item.is_dir():
                        bundles.append(self._parse_bundle(item))
            except PermissionError:
                logger.debug("Permission denied reading: %s", scan_dir)

        bundles.extend(self._scan_audio_plugins(system_lib / "Audio" / "Plug-Ins"))

        # Input Methods and Keyboard Layouts
        for dir_name in ["Input Methods", "Keyboard Layouts"]:
            scan_dir = system_lib / dir_name
            if scan_dir.is_dir():
                bundles.extend(self._scan_bundles_in_dir(scan_dir))

        return bundles

    def _scan_audio_plugins(self, audio_plugins: Path) -> list[BundleEntry]:
        """Scan /Library/Audio/Plug-Ins for audio component bundles."""
        if not audio_plugins.is_dir():
            return []
        bundles: list[BundleEntry] = []
        try:
            for subdir in sorted(audio_plugins.iterdir()):
                if subdir.is_dir():
                    for item in sorted(subdir.iterdir()):
                        if item.is_dir() and item.suffix in _BUNDLE_EXTENSIONS:
                            bundles.append(self._parse_bundle(item))
        except PermissionError:
            pass
        return bundles

    @staticmethod
    def _parse_bundle(item: Path) -> BundleEntry:
        """Parse a bundle directory, reading Info.plist for metadata."""
        info_plist = item / "Contents" / "Info.plist"
        if not info_plist.is_file():
            info_plist = item / "Info.plist"

        bundle_id: str | None = None
        version: str | None = None

        if info_plist.is_file():
            data = read_plist_safe(info_plist)
            if isinstance(data, dict):
                bundle_id = data.get("CFBundleIdentifier")
                version = data.get("CFBundleShortVersionString")

        return BundleEntry(
            name=item.name,
            path=item,
            bundle_id=bundle_id,
            version=version,
            bundle_type=item.suffix.lstrip(".") if item.suffix else None,
        )
