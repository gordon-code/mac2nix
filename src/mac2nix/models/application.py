"""Application and Homebrew models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel


class AppSource(StrEnum):
    APPSTORE = "appstore"
    CASK = "cask"
    MANUAL = "manual"


class BinarySource(StrEnum):
    BREW = "brew"
    CARGO = "cargo"
    GO = "go"
    PIPX = "pipx"
    NPM = "npm"
    GEM = "gem"
    SYSTEM = "system"
    MANUAL = "manual"


class InstalledApp(BaseModel):
    name: str
    bundle_id: str | None = None
    path: Path
    version: str | None = None
    source: AppSource


class PathBinary(BaseModel):
    name: str
    path: Path
    source: BinarySource
    version: str | None = None


class ApplicationsResult(BaseModel):
    apps: list[InstalledApp]
    path_binaries: list[PathBinary] = []
    xcode_path: str | None = None
    xcode_version: str | None = None
    clt_version: str | None = None


class BrewFormula(BaseModel):
    name: str
    version: str | None = None
    pinned: bool = False


class BrewCask(BaseModel):
    name: str
    version: str | None = None


class MasApp(BaseModel):
    name: str
    app_id: int
    version: str | None = None


class BrewService(BaseModel):
    name: str
    status: str
    user: str | None = None
    plist_path: Path | None = None


class HomebrewState(BaseModel):
    taps: list[str] = []
    formulae: list[BrewFormula] = []
    casks: list[BrewCask] = []
    mas_apps: list[MasApp] = []
    services: list[BrewService] = []
    prefix: str | None = None
