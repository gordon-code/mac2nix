"""Dotfile, app config, font, and library audit models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class DotfileManager(StrEnum):
    GIT = "git"
    STOW = "stow"
    CHEZMOI = "chezmoi"
    YADM = "yadm"
    HOME_MANAGER = "home_manager"
    RCM = "rcm"
    MANUAL = "manual"
    UNKNOWN = "unknown"


class DotfileEntry(BaseModel):
    path: Path
    content_hash: str | None = None
    managed_by: DotfileManager = DotfileManager.UNKNOWN
    symlink_target: Path | None = None
    is_directory: bool = False
    file_count: int | None = None
    sensitive: bool = False


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
    modified_time: datetime | None = None


class AppConfigResult(BaseModel):
    entries: list[AppConfigEntry]


class FontSource(StrEnum):
    USER = "user"  # ~/Library/Fonts
    SYSTEM = "system"  # /Library/Fonts


class FontEntry(BaseModel):
    name: str
    path: Path
    source: FontSource


class FontCollection(BaseModel):
    name: str
    path: Path


class FontsResult(BaseModel):
    entries: list[FontEntry]
    collections: list[FontCollection] = []


class LibraryDirEntry(BaseModel):
    name: str
    path: Path
    file_count: int | None = None
    total_size_bytes: int | None = None
    covered_by_scanner: str | None = None
    has_user_content: bool = False
    newest_modification: datetime | None = None


class LibraryFileEntry(BaseModel):
    path: Path
    file_type: str | None = None
    content_hash: str | None = None
    plist_content: dict[str, Any] | None = None
    text_content: str | None = None
    migration_strategy: str | None = None
    size_bytes: int | None = None


class WorkflowEntry(BaseModel):
    name: str
    path: Path
    identifier: str | None = None
    workflow_definition: dict[str, Any] | None = None


class BundleEntry(BaseModel):
    name: str
    path: Path
    bundle_id: str | None = None
    version: str | None = None
    bundle_type: str | None = None


class KeyBindingEntry(BaseModel):
    key: str
    action: str | dict[str, Any]


class LibraryAuditResult(BaseModel):
    bundles: list[BundleEntry] = []
    directories: list[LibraryDirEntry] = []
    uncovered_files: list[LibraryFileEntry] = []
    workflows: list[WorkflowEntry] = []
    key_bindings: list[KeyBindingEntry] = []
    spelling_words: list[str] = []
    spelling_dictionaries: list[str] = []
    input_methods: list[BundleEntry] = []
    keyboard_layouts: list[str] = []
    color_profiles: list[str] = []
    compositions: list[str] = []
    scripts: list[str] = []
    text_replacements: list[dict[str, str]] = []
    system_bundles: list[BundleEntry] = []
