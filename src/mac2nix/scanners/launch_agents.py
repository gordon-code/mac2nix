"""Launch agents scanner — discovers launchd agents, daemons, and login items."""

from __future__ import annotations

import copy
import logging
import os
import re
from pathlib import Path
from typing import Any

from mac2nix.models.services import LaunchAgentEntry, LaunchAgentSource, LaunchAgentsResult
from mac2nix.scanners._utils import read_launchd_plists, run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_ITEM_HEADER = re.compile(r"#\d+:")

_SOURCE_MAP: dict[str, LaunchAgentSource] = {
    "user": LaunchAgentSource.USER,
    "system": LaunchAgentSource.SYSTEM,
    "daemon": LaunchAgentSource.DAEMON,
}

_SENSITIVE_ENV_PATTERNS = {"_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_CREDENTIAL", "_AUTH"}


@register("launch_agents")
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
            if not data:
                logger.debug("Empty launch agent plist: %s", plist_path)
            else:
                logger.warning("Launch agent plist has keys %s but no Label: %s", list(data.keys()), plist_path)
            return None

        program = data.get("Program")
        program_arguments = data.get("ProgramArguments", [])
        run_at_load = data.get("RunAtLoad", False)

        # Deep copy data for raw_plist to avoid mutating the shared cache
        raw_plist = copy.deepcopy(data)
        # Redact sensitive environment variables in raw_plist
        self._redact_sensitive_env(raw_plist)

        # Extract filtered environment variables
        env_vars = data.get("EnvironmentVariables")
        filtered_env: dict[str, str] | None = None
        if isinstance(env_vars, dict):
            filtered_env = {}
            for key, val in env_vars.items():
                if any(p in key.upper() for p in _SENSITIVE_ENV_PATTERNS):
                    filtered_env[key] = "***REDACTED***"
                else:
                    filtered_env[key] = str(val)

        return LaunchAgentEntry(
            label=label,
            program=program,
            program_arguments=program_arguments,
            run_at_load=run_at_load,
            source=source,
            plist_path=plist_path,
            raw_plist=raw_plist,
            working_directory=data.get("WorkingDirectory"),
            environment_variables=filtered_env,
            keep_alive=data.get("KeepAlive"),
            start_interval=data.get("StartInterval"),
            start_calendar_interval=data.get("StartCalendarInterval"),
            watch_paths=data.get("WatchPaths", []),
            queue_directories=data.get("QueueDirectories", []),
            stdout_path=data.get("StandardOutPath"),
            stderr_path=data.get("StandardErrorPath"),
            throttle_interval=data.get("ThrottleInterval"),
            process_type=data.get("ProcessType"),
            nice=data.get("Nice"),
            user_name=data.get("UserName"),
            group_name=data.get("GroupName"),
        )

    @staticmethod
    def _redact_sensitive_env(plist: dict[str, Any]) -> None:
        """Redact sensitive keys from EnvironmentVariables in the plist dict."""
        env_vars = plist.get("EnvironmentVariables")
        if not isinstance(env_vars, dict):
            return
        for key in list(env_vars.keys()):
            if any(p in key.upper() for p in _SENSITIVE_ENV_PATTERNS):
                env_vars[key] = "***REDACTED***"

    def _get_login_items(self) -> list[LaunchAgentEntry]:
        """Parse login items from sfltool dumpbtm text output.

        Filters to the current user's UID section and extracts items
        with type "login item".
        """
        result = run_command(["sfltool", "dumpbtm"])
        if result is None or result.returncode != 0:
            return []

        return self._parse_btm_text(result.stdout)

    def _parse_btm_text(self, text: str) -> list[LaunchAgentEntry]:
        """Parse the text output of sfltool dumpbtm."""
        uid = os.getuid()
        user_section = self._extract_user_section(text, uid)
        if not user_section:
            return []

        entries: list[LaunchAgentEntry] = []
        for item in self._iter_btm_items(user_section):
            item_type = item.get("Type", "")
            if "login item" not in item_type:
                continue
            name = item.get("Name", "")
            if not name or name == "(null)":
                name = item.get("Bundle Identifier", item.get("Identifier", ""))
            if name:
                disposition = item.get("Disposition", "")
                enabled = "enabled" in disposition
                entries.append(
                    LaunchAgentEntry(
                        label=name,
                        enabled=enabled,
                        source=LaunchAgentSource.LOGIN_ITEM,
                    )
                )
        return entries

    @staticmethod
    def _extract_user_section(text: str, uid: int) -> str:
        """Extract the section for a specific UID from dumpbtm output."""
        pattern = re.compile(rf"Records for UID {uid}\b")
        lines = text.splitlines()
        in_section = False
        section_lines: list[str] = []

        for line in lines:
            if pattern.search(line):
                in_section = True
                continue
            if in_section:
                # New UID section starts with "==="
                if line.startswith("===="):
                    # Check if this is the separator after our header or a new section
                    if section_lines:
                        break
                    continue
                section_lines.append(line)

        return "\n".join(section_lines)

    @staticmethod
    def _iter_btm_items(section: str) -> list[dict[str, str]]:
        """Parse individual items from a BTM section into key-value dicts."""
        items: list[dict[str, str]] = []
        current: dict[str, str] = {}

        for raw_line in section.splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            # Item boundary: " #N:"
            if _ITEM_HEADER.match(stripped):
                if current:
                    items.append(current)
                current = {}
                continue
            # Key-value pair: "Key: Value"
            if ": " in stripped:
                key, _, value = stripped.partition(": ")
                current[key.strip()] = value.strip()

        if current:
            items.append(current)
        return items
