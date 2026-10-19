"""Mapping layer: macOS scan data to nix-darwin option paths.

Re-exports the public API of all nine mapping modules. `app_to_package`'s
`classify_app(name: str) -> AppClassification | None` (a raw name lookup) is
deliberately NOT re-exported at this level -- it would shadow this package's
own `classify_app(app: InstalledApp) -> ClassificationResult` (the
classifier's per-InstalledApp routing function). Reach it via
`mac2nix.mappings.app_to_package.classify_app` if needed.
"""

from __future__ import annotations

from mac2nix.mappings.app_config_registry import APP_CONFIG_REGISTRY, AppConfigInfo, get_app_config
from mac2nix.mappings.app_to_hm import APP_TO_HM_MODULE, HMModuleInfo, get_hm_module
from mac2nix.mappings.app_to_package import AppClassification, normalize_app_name
from mac2nix.mappings.brew_to_nixpkgs import (
    BREW_TO_NIXPKGS,
    VERSION_MANAGER_FORMULAE,
    NixpkgsEquivalent,
    get_nixpkgs_equivalent,
    is_unnecessary_in_nix,
)
from mac2nix.mappings.classifier import (
    ClassificationResult,
    ClassificationTier,
    classify_app,
    classify_app_config,
    classify_brew_formula,
    classify_dotfile,
    classify_font,
    classify_launch_agent,
    classify_network_setting,
    classify_preference,
    classify_security_setting,
    classify_shell_setting,
    classify_system_setting,
    classify_wallpaper,
)
from mac2nix.mappings.defaults_to_nix import (
    DEFAULTS_TO_NIX,
    DOMAIN_ALIASES,
    NixOption,
    get_nix_option,
    get_unmapped_keys,
)
from mac2nix.mappings.dotfile_to_hm import DOTFILE_TO_HM, get_hm_program
from mac2nix.mappings.ephemeral_filter import filter_ephemeral, is_ephemeral
from mac2nix.mappings.non_defaults_to_nix import (
    FONT_TO_NIXPKGS,
    LAUNCHD_KEYS_TO_DROP,
    LAUNCHD_LABEL_TO_SERVICE,
    NETWORKING_MAP,
    POWER_SETTING_MAP,
    SECURITY_MAP,
    SHELL_PROGRAM_MAP,
    TIMEZONE_NIX_OPTION,
    get_font_nixpkgs,
    get_launchd_service,
    get_power_nix_option,
    get_shell_program,
    is_launchd_key_droppable,
)

__all__ = [
    "APP_CONFIG_REGISTRY",
    "APP_TO_HM_MODULE",
    "BREW_TO_NIXPKGS",
    "DEFAULTS_TO_NIX",
    "DOMAIN_ALIASES",
    "DOTFILE_TO_HM",
    "FONT_TO_NIXPKGS",
    "LAUNCHD_KEYS_TO_DROP",
    "LAUNCHD_LABEL_TO_SERVICE",
    "NETWORKING_MAP",
    "POWER_SETTING_MAP",
    "SECURITY_MAP",
    "SHELL_PROGRAM_MAP",
    "TIMEZONE_NIX_OPTION",
    "VERSION_MANAGER_FORMULAE",
    "AppClassification",
    "AppConfigInfo",
    "ClassificationResult",
    "ClassificationTier",
    "HMModuleInfo",
    "NixOption",
    "NixpkgsEquivalent",
    "classify_app",
    "classify_app_config",
    "classify_brew_formula",
    "classify_dotfile",
    "classify_font",
    "classify_launch_agent",
    "classify_network_setting",
    "classify_preference",
    "classify_security_setting",
    "classify_shell_setting",
    "classify_system_setting",
    "classify_wallpaper",
    "filter_ephemeral",
    "get_app_config",
    "get_font_nixpkgs",
    "get_hm_module",
    "get_hm_program",
    "get_launchd_service",
    "get_nix_option",
    "get_nixpkgs_equivalent",
    "get_power_nix_option",
    "get_shell_program",
    "get_unmapped_keys",
    "is_ephemeral",
    "is_launchd_key_droppable",
    "is_unnecessary_in_nix",
    "normalize_app_name",
]
