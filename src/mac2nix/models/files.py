"""Dotfile, app config, and font models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel


class DotfileManager(StrEnum):
    GIT = "git"
    STOW = "stow"
    MANUAL = "manual"
    UNKNOWN = "unknown"


class DotfileEntry(BaseModel):
    path: Path
    content_hash: str | None = None
    managed_by: DotfileManager = DotfileManager.UNKNOWN
    symlink_target: Path | None = None


class DotfilesResult(BaseModel):
    entries: list[DotfileEntry]


class ConfigFileType(StrEnum):
    JSON = "json"
    PLIST = "plist"
    TOML = "toml"
    YAML = "yaml"
    XML = "xml"
    CONF = "conf"
    DATABASE = "database"
    UNKNOWN = "unknown"


class AppConfigEntry(BaseModel):
    app_bundle_id: str | None = None
    app_name: str
    path: Path
    file_type: ConfigFileType = ConfigFileType.UNKNOWN
    content_hash: str | None = None
    scannable: bool = True  # False for databases


class AppConfigResult(BaseModel):
    entries: list[AppConfigEntry]


class FontSource(StrEnum):
    USER = "user"  # ~/Library/Fonts
    SYSTEM = "system"  # /Library/Fonts


class FontEntry(BaseModel):
    name: str
    path: Path
    source: FontSource


class FontsResult(BaseModel):
    entries: list[FontEntry]
