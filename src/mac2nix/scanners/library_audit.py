"""Library audit scanner — discovers uncovered ~/Library and /Library content."""

from __future__ import annotations

import logging
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mac2nix.models.files import (
    BundleEntry,
    KeyBindingEntry,
    LibraryAuditResult,
    LibraryDirEntry,
    LibraryFileEntry,
    WorkflowEntry,
)
from mac2nix.scanners._utils import hash_file, read_plist_safe, run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_COVERED_DIRS: dict[str, str] = {
    "Preferences": "preferences",
    "Application Support": "app_config",
    "Fonts": "fonts",
    "LaunchAgents": "launch_agents",
    "Containers": "preferences+app_config",
    "Group Containers": "app_config",
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

_MAX_FILES_PER_DIR = 200

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


@register("library_audit")
class LibraryAuditScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "library_audit"

    def scan(self) -> LibraryAuditResult:
        home_lib = Path.home() / "Library"
        directories = self._audit_directories(home_lib)
        uncovered_files: list[LibraryFileEntry] = []
        workflows: list[WorkflowEntry] = []
        key_bindings = self._scan_key_bindings(home_lib)
        spelling_words, spelling_dicts = self._scan_spelling(home_lib)
        text_replacements = self._scan_text_replacements(home_lib)
        input_methods = self._scan_bundles_in_dir(home_lib / "Input Methods")
        keyboard_layouts = self._scan_file_hashes(home_lib / "Keyboard Layouts", ".keylayout")
        color_profiles = self._scan_file_hashes(home_lib / "ColorSync" / "Profiles", ".icc", ".icm")
        compositions = self._scan_file_hashes(home_lib / "Compositions", ".qtz")
        scripts = self._scan_scripts(home_lib)

        # Capture uncovered files and workflows from uncovered directories
        for d in directories:
            if d.covered_by_scanner is None and d.name not in _TRANSIENT_DIRS:
                files, wf = self._capture_uncovered_dir(d.path)
                uncovered_files.extend(files)
                workflows.extend(wf)

        # Scan workflows from known Workflows/Services dirs
        for wf_dir_name in ["Workflows", "Services"]:
            wf_dir = home_lib / wf_dir_name
            if wf_dir.is_dir():
                workflows.extend(self._scan_workflows(wf_dir))

        system_bundles = self._scan_system_library()

        return LibraryAuditResult(
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

    def _audit_directories(self, lib_path: Path) -> list[LibraryDirEntry]:
        """Walk top-level ~/Library directories and collect metadata."""
        if not lib_path.is_dir():
            return []

        entries: list[LibraryDirEntry] = []
        try:
            for child in sorted(lib_path.iterdir()):
                if not child.is_dir():
                    continue
                covered = _COVERED_DIRS.get(child.name)
                file_count, total_size, newest_mod = self._dir_stats(child)
                entries.append(
                    LibraryDirEntry(
                        name=child.name,
                        path=child,
                        file_count=file_count,
                        total_size_bytes=total_size,
                        covered_by_scanner=covered,
                        has_user_content=covered is None and child.name not in _TRANSIENT_DIRS,
                        newest_modification=newest_mod,
                    )
                )
        except PermissionError:
            logger.warning("Permission denied reading: %s", lib_path)

        return entries

    @staticmethod
    def _dir_stats(path: Path) -> tuple[int | None, int | None, datetime | None]:
        """Get file count, total size, and newest modification for a directory."""
        try:
            file_count = 0
            total_size = 0
            newest = 0.0
            for entry in path.iterdir():
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

    def _capture_uncovered_dir(self, dir_path: Path) -> tuple[list[LibraryFileEntry], list[WorkflowEntry]]:
        """Capture files from an uncovered directory (capped)."""
        files: list[LibraryFileEntry] = []
        workflows: list[WorkflowEntry] = []
        count = 0

        try:
            for dirpath, dirnames, filenames in os.walk(dir_path, followlinks=False):
                for filename in filenames:
                    if count >= _MAX_FILES_PER_DIR:
                        logger.warning(
                            "Reached %d file cap for directory: %s",
                            _MAX_FILES_PER_DIR,
                            dir_path,
                        )
                        return files, workflows
                    filepath = Path(dirpath) / filename
                    entry = self._classify_file(filepath)
                    if entry is not None:
                        files.append(entry)
                    count += 1
                # Check dirnames for workflow bundles (they're directories, not files)
                # and prune them + transient/cache subdirectories in a single pass
                _skip = {"Caches", "Cache", "Logs", "tmp", "__pycache__"}
                kept: list[str] = []
                for dirname in dirnames:
                    if dirname.endswith(".workflow"):
                        wf_path = Path(dirpath) / dirname
                        wf = self._parse_workflow(wf_path)
                        if wf is not None:
                            workflows.append(wf)
                    elif dirname not in _skip:
                        kept.append(dirname)
                dirnames[:] = kept
        except PermissionError:
            logger.warning("Permission denied walking: %s", dir_path)

        return files, workflows

    def _classify_file(self, filepath: Path) -> LibraryFileEntry | None:
        """Classify and capture a file from an uncovered directory."""
        try:
            stat = filepath.stat()
        except OSError:
            return None

        size = stat.st_size
        suffix = filepath.suffix.lower()
        file_type = suffix.lstrip(".") if suffix else "unknown"
        content_hash = hash_file(filepath)
        plist_content: dict[str, Any] | None = None
        text_content: str | None = None
        strategy = "hash_only"

        if suffix == ".plist":
            raw_plist = read_plist_safe(filepath)
            if isinstance(raw_plist, dict):
                plist_content = raw_plist
                _redact_sensitive_keys(plist_content)
                strategy = "plist_capture"
        elif suffix in {".txt", ".md", ".cfg", ".conf", ".ini", ".yaml", ".yml", ".json", ".xml"}:
            if size < 65536:
                try:
                    text_content = filepath.read_text(errors="replace")
                    strategy = "text_capture"
                except OSError:
                    pass
        elif suffix in _BUNDLE_EXTENSIONS:
            strategy = "bundle"

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
                if not item.is_dir():
                    continue
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
                bundles.append(
                    BundleEntry(
                        name=item.name,
                        path=item,
                        bundle_id=bundle_id,
                        version=version,
                        bundle_type=item.suffix.lstrip(".") if item.suffix else None,
                    )
                )
        except PermissionError:
            logger.debug("Permission denied reading: %s", dir_path)
        return bundles

    @staticmethod
    def _scan_file_hashes(dir_path: Path, *extensions: str) -> list[str]:
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
                        bundle = self._parse_system_bundle(item)
                        if bundle is not None:
                            bundles.append(bundle)
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
                            bundle = self._parse_system_bundle(item)
                            if bundle is not None:
                                bundles.append(bundle)
        except PermissionError:
            pass
        return bundles

    @staticmethod
    def _parse_system_bundle(item: Path) -> BundleEntry | None:
        """Parse a system-level bundle."""
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
