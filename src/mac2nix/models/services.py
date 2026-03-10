"""Launch agent, shell, and scheduled task models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

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
    raw_plist: dict[str, Any] = {}
    working_directory: str | None = None
    environment_variables: dict[str, str] | None = None
    keep_alive: bool | dict[str, Any] | None = None
    start_interval: int | None = None
    start_calendar_interval: dict[str, int] | list[dict[str, int]] | None = None
    watch_paths: list[str] = []
    queue_directories: list[str] = []
    stdout_path: str | None = None
    stderr_path: str | None = None
    throttle_interval: int | None = None
    process_type: str | None = None
    nice: int | None = None
    user_name: str | None = None
    group_name: str | None = None


class LaunchAgentsResult(BaseModel):
    entries: list[LaunchAgentEntry] = []


class ShellFramework(BaseModel):
    name: str
    path: Path | None = None
    plugins: list[str] = []
    theme: str | None = None


class ShellConfig(BaseModel):
    shell_type: str  # fish, zsh, bash
    rc_files: list[Path] = []
    path_components: list[str] = []
    aliases: dict[str, str] = {}
    functions: list[str] = []
    env_vars: dict[str, str] = {}
    conf_d_files: list[Path] = []
    completion_files: list[Path] = []
    sourced_files: list[Path] = []
    frameworks: list[ShellFramework] = []
    dynamic_commands: list[str] = []


class CronEntry(BaseModel):
    schedule: str  # cron expression
    command: str
    user: str | None = None


class LaunchdScheduledJob(BaseModel):
    label: str
    schedule: list[dict[str, int]] = []
    program: str | None = None
    program_arguments: list[str] = []
    watch_paths: list[str] = []
    queue_directories: list[str] = []
    start_interval: int | None = None
    trigger_type: str = "calendar"


class ScheduledTasks(BaseModel):
    cron_entries: list[CronEntry] = []
    launchd_scheduled: list[LaunchdScheduledJob] = []
    cron_env: dict[str, str] = {}
