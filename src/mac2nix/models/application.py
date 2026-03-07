"""Application and Homebrew models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel


class AppSource(StrEnum):
    APPSTORE = "appstore"
    CASK = "cask"
    MANUAL = "manual"


class InstalledApp(BaseModel):
    name: str
    bundle_id: str | None = None
    path: Path
    version: str | None = None
    source: AppSource


class ApplicationsResult(BaseModel):
    apps: list[InstalledApp]


class BrewFormula(BaseModel):
    name: str
    version: str | None = None


class BrewCask(BaseModel):
    name: str
    version: str | None = None


class MasApp(BaseModel):
    name: str
    app_id: int
    version: str | None = None


class HomebrewState(BaseModel):
    taps: list[str] = []
    formulae: list[BrewFormula] = []
    casks: list[BrewCask] = []
    mas_apps: list[MasApp] = []
