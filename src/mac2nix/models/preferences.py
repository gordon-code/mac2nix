"""macOS preferences domain models."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

# plist types: str, int, float, bool, bytes, list, dict, datetime
PreferenceValue = str | int | float | bool | bytes | list | dict


class PreferencesDomain(BaseModel):
    domain_name: str  # e.g. "com.apple.dock"
    source_path: Path | None = None  # e.g. ~/Library/Preferences/com.apple.dock.plist
    source: str = "disk"  # "disk", "synced", "cfprefsd"
    keys: dict[str, PreferenceValue]


class PreferencesResult(BaseModel):
    domains: list[PreferencesDomain]
