"""Top-level aggregate model for macOS system state."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from mac2nix.models.application import ApplicationsResult, HomebrewState
from mac2nix.models.files import DotfilesResult, FontsResult, LibraryResult
from mac2nix.models.hardware import AudioConfig, DisplayConfig
from mac2nix.models.package_managers import (
    ContainersResult,
    NixState,
    PackageManagersResult,
    VersionManagersResult,
)
from mac2nix.models.preferences import PreferencesResult
from mac2nix.models.services import LaunchAgentsResult, ScheduledTasks, ShellConfig
from mac2nix.models.system import NetworkConfig, SecurityState, SystemConfig


class SystemState(BaseModel):
    """Aggregate model containing all scanner results.

    Each scanner domain is optional to support partial scans.
    """

    hostname: str
    scan_timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    macos_version: str
    architecture: str  # arm64, x86_64

    # Scanner domain results (optional — populated by individual scanners)
    preferences: PreferencesResult | None = None
    applications: ApplicationsResult | None = None
    homebrew: HomebrewState | None = None
    dotfiles: DotfilesResult | None = None
    fonts: FontsResult | None = None
    launch_agents: LaunchAgentsResult | None = None
    shell: ShellConfig | None = None
    network: NetworkConfig | None = None
    security: SecurityState | None = None
    system: SystemConfig | None = None
    display: DisplayConfig | None = None
    audio: AudioConfig | None = None
    cron: ScheduledTasks | None = None
    library: LibraryResult | None = None
    nix_state: NixState | None = None
    version_managers: VersionManagersResult | None = None
    package_managers: PackageManagersResult | None = None
    containers: ContainersResult | None = None

    def to_json(self, path: Path | None = None) -> str:
        """Serialize to JSON string. Optionally write to file."""
        data = self.model_dump_json(indent=2)
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)
        return data

    @classmethod
    def from_json(cls, source: str | Path) -> SystemState:
        """Deserialize from JSON string or file path."""
        if isinstance(source, Path):
            source = source.read_text()
        return cls.model_validate_json(source)
