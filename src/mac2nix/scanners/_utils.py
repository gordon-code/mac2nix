"""Shared utilities for scanner plugins."""

from __future__ import annotations

import hashlib
import logging
import plistlib
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

LAUNCHD_DIRS: list[tuple[Path, str]] = [
    (Path.home() / "Library" / "LaunchAgents", "user"),
    (Path("/Library/LaunchAgents"), "system"),
    (Path("/Library/LaunchDaemons"), "daemon"),
]


def _convert_datetimes(obj: Any) -> Any:
    """Recursively convert datetime values to ISO 8601 strings.

    plistlib returns datetime objects for NSDate values, but PreferenceValue
    does not include datetime in its union type.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _convert_datetimes(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_convert_datetimes(item) for item in obj]
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


def read_plist_safe(path: Path) -> dict[str, Any] | None:
    """Read a plist file safely, returning None on failure.

    Handles both binary and XML plists. Converts datetime values to ISO strings
    since PreferenceValue does not include datetime.
    """
    try:
        with path.open("rb") as f:
            data = plistlib.load(f)
    except (plistlib.InvalidFileException, PermissionError, OSError) as exc:
        logger.warning("Failed to read plist %s: %s", path, exc)
        return None

    return _convert_datetimes(data)


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
        except PermissionError:
            logger.warning("Permission denied reading: %s", agent_dir)
            continue
        for plist_path in plist_files:
            data = read_plist_safe(plist_path)
            if data is not None:
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
