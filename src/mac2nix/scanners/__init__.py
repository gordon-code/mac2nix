"""Scanner plugins for macOS system state discovery."""

from mac2nix.scanners import (  # noqa: F401
    app_config,
    applications,
    audio,
    containers,
    cron,
    display,
    dotfiles,
    fonts,
    homebrew,
    launch_agents,
    library_audit,
    network,
    nix_state,
    package_managers_scanner,
    preferences,
    security,
    shell,
    system_scanner,
    version_managers,
)
from mac2nix.scanners.base import (
    SCANNER_REGISTRY,
    BaseScannerPlugin,
    get_all_scanners,
    get_scanner,
)

__all__ = [
    "SCANNER_REGISTRY",
    "BaseScannerPlugin",
    "get_all_scanners",
    "get_scanner",
]
