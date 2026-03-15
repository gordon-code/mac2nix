"""Shared utilities for scanner plugins."""

from __future__ import annotations

import errno
import hashlib
import logging
import plistlib
import shutil
import subprocess
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

logger = logging.getLogger(__name__)

WALK_SKIP_DIRS = frozenset(
    {
        # Caches & transient data
        "Caches",
        "Cache",
        "cache",
        ".cache",
        "GPUCache",
        "ShaderCache",
        "Code Cache",
        "CachedData",
        "Service Worker",
        "blob_storage",
        "IndexedDB",
        "GrShaderCache",
        "component_crx_cache",
        # Logs
        "Logs",
        "logs",
        "log",
        # VCS
        ".git",
        ".svn",
        ".hg",
        # Build artifacts & dependency trees
        "node_modules",
        "__pycache__",
        ".tox",
        ".nox",
        "DerivedData",
        "Build",
        ".build",
        "build",
        "target",
        "dist",
        ".next",
        ".nuxt",
        # Temp
        "tmp",
        "temp",
        ".tmp",
        # Trash
        ".Trash",
        ".Trashes",
        # Python packaging (biggest single source: 33K+ .py files on test system)
        "site-packages",
        ".venv",
        "venv",
        ".eggs",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".pytype",
        ".direnv",
        # Electron/Chromium (every Electron app generates these)
        "Crashpad",
        "Session Storage",
        "WebStorage",
        "Local Storage",
        "_locales",
        # macOS internal metadata
        ".Spotlight-V100",
        ".fseventsd",
        ".DocumentRevisions-V100",
        ".TemporaryItems",
        # Developer tools & large data stores
        "CoreSimulator",
        "DeviceSupport",
        "steamapps",
        "drive_c",
    }
)

NON_CONFIG_EXTENSIONS = frozenset(
    {
        # Source code (not user config — package/library files)
        ".py",
        ".pyi",
        ".pyc",
        ".pyo",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".c",
        ".cpp",
        ".cc",
        ".h",
        ".hpp",
        ".m",
        ".mm",
        ".swift",
        ".go",
        ".rs",
        ".java",
        ".class",
        ".jar",
        ".rb",
        ".pl",
        ".pm",
        ".lua",
        ".r",
        # Compiled/binary artifacts
        ".so",
        ".dylib",
        ".dll",
        ".o",
        ".a",
        ".lib",
        ".wasm",
        ".node",
        ".framework",
        ".exe",
        ".msi",
        # Media & images
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".icns",
        ".svg",
        ".webp",
        ".tiff",
        ".tif",
        ".heic",
        ".heif",
        ".mp3",
        ".mp4",
        ".m4a",
        ".m4v",
        ".wav",
        ".aac",
        ".flac",
        ".ogg",
        ".avi",
        ".mov",
        ".mkv",
        ".webm",
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
        ".eot",
        # Archives & compressed
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".dmg",
        ".iso",
        ".pkg",
        # Data files (not human-readable config)
        ".lance",
        ".parquet",
        ".arrow",
        ".feather",
        ".npy",
        ".npz",
        ".pickle",
        ".pkl",
        ".ldb",
        ".sst",
        # Web assets (Electron app bundles)
        ".css",
        ".scss",
        ".less",
        ".html",
        ".htm",
        # GPU shaders
        ".amd",
        ".glsl",
        ".hlsl",
        ".metal",
        # Debug & build
        ".map",
        ".d",
        ".dep",
        ".log",
        # Documents (not config)
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        # Email messages (~/Library/Mail can have 500K+ .emlx files)
        ".emlx",
        ".eml",
        ".mbox",
        # Misc non-config
        ".strings",
        ".nib",
        ".storyboard",
        ".typed",
        ".manifest",
    }
)

WALK_SKIP_SUFFIXES = (".noindex", ".lproj")


def parallel_walk_dirs[T](
    dirs: list[Path],
    process_fn: Callable[[Path], T],
    *,
    max_workers: int = 8,
) -> list[T]:
    """Walk multiple independent directory trees in parallel.

    Each directory in *dirs* is submitted as an independent work unit to a
    ThreadPoolExecutor. The *process_fn* receives a single directory Path and
    should return a result of type T. Exceptions in individual workers are
    logged and skipped.

    The function is designed to be called from a scanner's ``scan()`` method,
    which already runs inside ``asyncio.to_thread()`` via the orchestrator.
    The ThreadPoolExecutor provides a second level of parallelism within
    the scanner's thread.

    Note: callers run inside asyncio.to_thread() via the orchestrator, creating
    nested thread pools. Peak thread count is bounded (~8 per scanner x
    concurrent scanners) and well within OS limits.

    Args:
        dirs: Independent directory roots to process in parallel.
        process_fn: Function that processes one directory and returns a result.
        max_workers: Maximum concurrent workers (default 8, suitable for NVMe SSD).

    Returns:
        List of results from successful process_fn calls (order not guaranteed).
    """
    if not dirs:
        return []

    # For very small dir lists, skip the pool overhead
    if len(dirs) <= 2:
        results: list[T] = []
        for d in dirs:
            try:
                results.append(process_fn(d))
            except Exception:
                logger.exception("Failed to process directory: %s", d)
        return results

    results: list[T] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(dirs))) as pool:
        futures = {pool.submit(process_fn, d): d for d in dirs}
        for future in as_completed(futures):
            directory = futures[future]
            try:
                results.append(future.result())
            except Exception:
                logger.exception("Failed to process directory: %s", directory)
    return results


LAUNCHD_DIRS: list[tuple[Path, str]] = [
    (Path.home() / "Library" / "LaunchAgents", "user"),
    (Path("/Library/LaunchAgents"), "system"),
    (Path("/Library/LaunchDaemons"), "daemon"),
]


def sanitize_plist_values(obj: Any) -> Any:
    """Recursively convert non-JSON-safe plist values.

    plistlib returns datetime objects (for NSDate), bytes objects (for NSData),
    and UID objects that are not JSON-serializable. Convert them to strings/ints.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return f"<data:{len(obj)} bytes>"
    if isinstance(obj, plistlib.UID):
        return int(obj)
    if isinstance(obj, dict):
        return {k: sanitize_plist_values(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_plist_values(item) for item in obj]
    return obj


def run_command(
    cmd: list[str],
    *,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str] | None:
    """Run a subprocess command safely.

    Validates that the executable exists before running. Never uses shell=True.
    Returns None on any failure (command not found, non-zero exit, timeout).
    """
    executable = cmd[0]
    if shutil.which(executable) is None:
        logger.warning("Executable not found: %s", executable)
        return None

    logger.debug("Running command: %s", cmd)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %ds: %s", timeout, cmd)
        return None
    except FileNotFoundError:
        logger.warning("Executable not found during execution: %s", executable)
        return None


def read_plist_safe(path: Path) -> dict[str, Any] | list[Any] | None:
    """Read a plist file safely, returning None on failure.

    Handles both binary and XML plists. Converts datetime values to ISO strings
    since PreferenceValue does not include datetime.
    """
    try:
        with path.open("rb") as f:
            data = plistlib.load(f)
    except PermissionError as exc:
        if exc.errno == errno.EPERM:
            logger.debug("Skipping TCC-protected plist: %s", path)
        else:
            logger.warning("Permission denied reading plist: %s", path)
        return None
    except plistlib.InvalidFileException:
        logger.warning("Invalid plist file: %s", path)
        return None
    except (ValueError, OverflowError):
        # plistlib can't handle dates like year 0 (Apple's "no date" sentinel).
        # Fall back to plutil XML conversion which preserves dates as strings.
        data = _read_plist_via_plutil(path)
        if data is None:
            logger.warning("Plist contains unrepresentable data: %s", path)
            return None
    except OSError as exc:
        logger.warning("Failed to read plist %s: %s", path, exc)
        return None

    return sanitize_plist_values(data)


def _read_plist_via_plutil(path: Path) -> dict[str, Any] | None:
    """Fallback plist reader using plutil XML conversion.

    Parses the XML manually to handle dates that Python's datetime can't
    represent (e.g., year 0000, year 4001). Dates are kept as ISO strings.
    """
    result = run_command(["plutil", "-convert", "xml1", "-o", "-", str(path)])
    if result is None or result.returncode != 0:
        return None

    try:
        root = ElementTree.fromstring(result.stdout)  # noqa: S314
    except ElementTree.ParseError:
        return None

    top_dict = root.find("dict")
    if top_dict is None:
        return None

    return _parse_xml_dict(top_dict)


def _parse_xml_dict(element: ElementTree.Element) -> dict[str, Any]:
    """Parse a plist <dict> element into a Python dict."""
    result: dict[str, Any] = {}
    children = list(element)
    i = 0
    while i + 1 < len(children):
        if children[i].tag == "key":
            key = children[i].text or ""
            value_elem = children[i + 1]
            result[key] = _parse_xml_value(value_elem)
            i += 2
        else:
            i += 1
    return result


_XML_LITERAL_TAGS: dict[str, Any] = {"true": True, "false": False}


def _parse_xml_value(element: ElementTree.Element) -> Any:
    """Parse a plist value element into a Python object."""
    tag = element.tag
    text = element.text or ""

    if tag in _XML_LITERAL_TAGS:
        return _XML_LITERAL_TAGS[tag]
    if tag == "dict":
        return _parse_xml_dict(element)
    if tag == "array":
        return [_parse_xml_value(child) for child in element]
    # string, date, data → text; integer/real → parsed; unknown → text
    converters: dict[str, Any] = {"integer": int, "real": float}
    converter = converters.get(tag)
    return converter(text) if converter else text


def read_launchd_plists() -> list[tuple[Path, str, dict[str, Any]]]:
    """Read all launchd plists from LAUNCHD_DIRS.

    Returns list of (plist_path, source_key, parsed_data) tuples.
    Shared between launch_agents and cron scanners to avoid duplicate reads.
    """
    results: list[tuple[Path, str, dict[str, Any]]] = []
    for agent_dir, source_key in LAUNCHD_DIRS:
        if not agent_dir.is_dir():
            continue
        try:
            plist_files = sorted(agent_dir.glob("*.plist"))
        except PermissionError as exc:
            if exc.errno == errno.EPERM:
                logger.debug("Skipping TCC-protected directory: %s", agent_dir)
            else:
                logger.warning("Permission denied reading: %s", agent_dir)
            continue
        for plist_path in plist_files:
            data = read_plist_safe(plist_path)
            if isinstance(data, dict):
                results.append((plist_path, source_key, data))
    return results


def hash_file(path: Path, max_bytes: int = 65536) -> str | None:
    """Compute SHA-256 hash of a file's first max_bytes bytes. Returns None on error."""
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            h.update(f.read(max_bytes))
        return h.hexdigest()[:16]
    except (PermissionError, OSError):
        return None
