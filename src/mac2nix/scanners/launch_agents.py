"""Launch agents scanner — discovers launchd agents, daemons, and login items."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from mac2nix.models.services import LaunchAgentEntry, LaunchAgentSource, LaunchAgentsResult
from mac2nix.scanners._utils import read_launchd_plists, run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_SOURCE_MAP: dict[str, LaunchAgentSource] = {
    "user": LaunchAgentSource.USER,
    "system": LaunchAgentSource.SYSTEM,
    "daemon": LaunchAgentSource.DAEMON,
}


@register
class LaunchAgentsScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "launch_agents"

    def scan(self) -> LaunchAgentsResult:
        entries: list[LaunchAgentEntry] = []

        # Scan plist directories using shared reader
        for plist_path, source_key, data in read_launchd_plists():
            source = _SOURCE_MAP[source_key]
            entry = self._parse_agent_data(plist_path, source, data)
            if entry is not None:
                entries.append(entry)

        # Login items via sfltool
        login_items = self._get_login_items()
        entries.extend(login_items)

        return LaunchAgentsResult(entries=entries)

    def _parse_agent_data(
        self, plist_path: Path, source: LaunchAgentSource, data: dict[str, Any]
    ) -> LaunchAgentEntry | None:
        label = data.get("Label")
        if not label:
            logger.warning("Launch agent plist missing Label: %s", plist_path)
            return None

        program = data.get("Program")
        program_arguments = data.get("ProgramArguments", [])
        run_at_load = data.get("RunAtLoad", False)

        return LaunchAgentEntry(
            label=label,
            program=program,
            program_arguments=program_arguments,
            run_at_load=run_at_load,
            source=source,
            plist_path=plist_path,
        )

    def _get_login_items(self) -> list[LaunchAgentEntry]:
        """Parse login items from sfltool dumpbtm output."""
        result = run_command(["sfltool", "dumpbtm"])
        if result is None or result.returncode != 0:
            return []

        entries: list[LaunchAgentEntry] = []
        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            logger.warning("Failed to parse sfltool dumpbtm output as JSON")
            return entries

        # sfltool output structure varies by macOS version — parse defensively
        items = data if isinstance(data, list) else data.get("items", data.get("loginItems", []))
        if not isinstance(items, list):
            return entries

        for item in items:
            if not isinstance(item, dict):
                continue
            label = item.get("name", item.get("label", item.get("bundleIdentifier", "")))
            if label:
                entries.append(
                    LaunchAgentEntry(
                        label=str(label),
                        source=LaunchAgentSource.LOGIN_ITEM,
                    )
                )

        return entries
