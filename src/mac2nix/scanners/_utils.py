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
from xml.etree import ElementTree

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
    except PermissionError:
        logger.debug("Permission denied reading plist: %s", path)
        return None
    except plistlib.InvalidFileException:
        logger.debug("Invalid plist file: %s", path)
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

    return _convert_datetimes(data)


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
    while i < len(children) - 1:
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
