"""Cron scanner — discovers cron entries and launchd scheduled tasks."""

from __future__ import annotations

import logging

from mac2nix.models.services import CronEntry, ScheduledTasks
from mac2nix.scanners._utils import read_launchd_plists, run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)


@register("cron")
class CronScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "cron"

    def scan(self) -> ScheduledTasks:
        cron_entries = self._get_cron_entries()
        launchd_scheduled = self._get_launchd_scheduled()
        return ScheduledTasks(cron_entries=cron_entries, launchd_scheduled=launchd_scheduled)

    def _get_cron_entries(self) -> list[CronEntry]:
        result = run_command(["crontab", "-l"])
        if result is None:
            return []
        # crontab -l returns exit code 1 with 'no crontab for user' — not an error
        if result.returncode != 0:
            if "no crontab" in result.stderr.lower():
                return []
            logger.warning("crontab -l failed: %s", result.stderr)
            return []

        entries: list[CronEntry] = []
        for raw_line in result.stdout.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Handle special schedule strings (@reboot, @daily, etc.)
            if stripped.startswith("@"):
                parts = stripped.split(None, 1)
                if len(parts) >= 2:
                    entries.append(CronEntry(schedule=parts[0], command=parts[1]))
            else:
                # Standard 5-field cron expression
                parts = stripped.split(None, 5)
                if len(parts) >= 6:
                    schedule = " ".join(parts[:5])
                    command = parts[5]
                    entries.append(CronEntry(schedule=schedule, command=command))

        return entries

    def _get_launchd_scheduled(self) -> list[str]:
        """Find launchd plists with StartCalendarInterval keys."""
        labels: list[str] = []
        for _plist_path, _source_key, data in read_launchd_plists():
            if "StartCalendarInterval" in data:
                label = data.get("Label")
                if label:
                    labels.append(str(label))
        return labels
