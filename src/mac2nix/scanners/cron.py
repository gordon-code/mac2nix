"""Cron scanner — discovers cron entries and launchd scheduled tasks."""

from __future__ import annotations

import logging

from mac2nix.models.services import CronEntry, LaunchdScheduledJob, ScheduledTasks
from mac2nix.scanners._utils import read_launchd_plists, run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)


@register("cron")
class CronScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "cron"

    def scan(self) -> ScheduledTasks:
        cron_entries, cron_env = self._get_cron_entries()
        launchd_scheduled = self._get_launchd_scheduled()
        return ScheduledTasks(
            cron_entries=cron_entries,
            launchd_scheduled=launchd_scheduled,
            cron_env=cron_env,
        )

    def _get_cron_entries(self) -> tuple[list[CronEntry], dict[str, str]]:
        result = run_command(["crontab", "-l"])
        if result is None:
            return [], {}
        # crontab -l returns exit code 1 with 'no crontab for user' — not an error
        if result.returncode != 0:
            if "no crontab" in result.stderr.lower():
                return [], {}
            logger.warning("crontab -l failed: %s", result.stderr)
            return [], {}

        entries: list[CronEntry] = []
        cron_env: dict[str, str] = {}
        for raw_line in result.stdout.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Parse environment variable assignments (KEY=value)
            if "=" in stripped and not stripped[0].isdigit() and not stripped.startswith("@"):
                key, _, value = stripped.partition("=")
                if key.isidentifier():
                    cron_env[key] = value
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

        return entries, cron_env

    def _get_launchd_scheduled(self) -> list[LaunchdScheduledJob]:
        """Find launchd plists with scheduling keys."""
        jobs: list[LaunchdScheduledJob] = []
        for _plist_path, _source_key, data in read_launchd_plists():
            label = data.get("Label")
            if not label:
                continue

            trigger_type: str | None = None
            if "StartCalendarInterval" in data:
                trigger_type = "calendar"
            elif "WatchPaths" in data:
                trigger_type = "watch"
            elif "QueueDirectories" in data:
                trigger_type = "queue"
            elif "StartInterval" in data:
                trigger_type = "interval"

            if trigger_type is None:
                continue

            # Normalize StartCalendarInterval to list form
            schedule_raw = data.get("StartCalendarInterval")
            if isinstance(schedule_raw, dict):
                schedule = [schedule_raw]
            elif isinstance(schedule_raw, list):
                schedule = schedule_raw
            else:
                schedule = []

            jobs.append(
                LaunchdScheduledJob(
                    label=str(label),
                    schedule=schedule,
                    program=data.get("Program"),
                    program_arguments=data.get("ProgramArguments", []),
                    watch_paths=data.get("WatchPaths", []),
                    queue_directories=data.get("QueueDirectories", []),
                    start_interval=data.get("StartInterval"),
                    trigger_type=trigger_type,
                )
            )
        return jobs
