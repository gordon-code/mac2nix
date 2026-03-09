"""Launch agent, shell, and scheduled task models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel


class LaunchAgentSource(StrEnum):
    USER = "user"  # ~/Library/LaunchAgents
    SYSTEM = "system"  # /Library/LaunchAgents
    DAEMON = "daemon"  # /Library/LaunchDaemons
    LOGIN_ITEM = "login_item"  # sfltool dumpbtm


class LaunchAgentEntry(BaseModel):
    label: str
    program: str | None = None
    program_arguments: list[str] = []
    run_at_load: bool = False
    enabled: bool = True
    source: LaunchAgentSource
    plist_path: Path | None = None


class LaunchAgentsResult(BaseModel):
    entries: list[LaunchAgentEntry] = []


class ShellConfig(BaseModel):
    shell_type: str  # fish, zsh, bash
    rc_files: list[Path] = []
    path_components: list[str] = []
    aliases: dict[str, str] = {}
    functions: list[str] = []
    env_vars: dict[str, str] = {}


class CronEntry(BaseModel):
    schedule: str  # cron expression
    command: str
    user: str | None = None


class ScheduledTasks(BaseModel):
    cron_entries: list[CronEntry] = []
    launchd_scheduled: list[str] = []  # labels of launchd jobs with StartCalendarInterval
