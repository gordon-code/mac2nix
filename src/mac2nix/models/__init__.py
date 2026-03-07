"""mac2nix data models."""

from mac2nix.models.application import (
    ApplicationsResult,
    AppSource,
    BrewCask,
    BrewFormula,
    HomebrewState,
    InstalledApp,
    MasApp,
)
from mac2nix.models.files import (
    AppConfigEntry,
    AppConfigResult,
    ConfigFileType,
    DotfileEntry,
    DotfileManager,
    DotfilesResult,
    FontEntry,
    FontSource,
    FontsResult,
)
from mac2nix.models.hardware import AudioConfig, AudioDevice, DisplayConfig, Monitor
from mac2nix.models.preferences import PreferencesDomain, PreferencesResult, PreferenceValue
from mac2nix.models.services import (
    CronEntry,
    LaunchAgentEntry,
    LaunchAgentSource,
    LaunchAgentsResult,
    ScheduledTasks,
    ShellConfig,
)
from mac2nix.models.system import NetworkConfig, NetworkInterface, SecurityState, SystemConfig
from mac2nix.models.system_state import SystemState

__all__ = [
    "AppConfigEntry",
    "AppConfigResult",
    "AppSource",
    "ApplicationsResult",
    "AudioConfig",
    "AudioDevice",
    "BrewCask",
    "BrewFormula",
    "ConfigFileType",
    "CronEntry",
    "DisplayConfig",
    "DotfileEntry",
    "DotfileManager",
    "DotfilesResult",
    "FontEntry",
    "FontSource",
    "FontsResult",
    "HomebrewState",
    "InstalledApp",
    "LaunchAgentEntry",
    "LaunchAgentSource",
    "LaunchAgentsResult",
    "MasApp",
    "Monitor",
    "NetworkConfig",
    "NetworkInterface",
    "PreferenceValue",
    "PreferencesDomain",
    "PreferencesResult",
    "ScheduledTasks",
    "SecurityState",
    "ShellConfig",
    "SystemConfig",
    "SystemState",
]
