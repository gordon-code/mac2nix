"""Four-tier classifier: routes scanned macOS settings to their nix-darwin destination.

Tier 1 (NATIVE) -> a typed nix-darwin option exists (system.defaults.* or a
non-defaults module option). Tier 2 (CUSTOM_PREFS) -> known domain/structure,
but no typed option; passed through generically (CustomUserPreferences,
CustomSystemPreferences, or a generic launchd.*.serviceConfig block). Tier 3
(ACTIVATION_SCRIPT) -> requires an imperative `defaults write`/similar at
activation time (binary data, root-level launchd daemons). Tier 4
(MANUAL_REPORT) -> no automated mapping; surfaced to the user, or (via
metadata.skipped) silently dropped as ephemeral noise.

This module is the integration point for all other mapping modules -- see
hack/PROJECT.md's "Mapping Layer Architecture" section for the tier
rationale and hack/swarm/roadmap-phase-1-mapping-layer-1784561690/ for the
architect plan and security design review this implementation follows.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any

from mac2nix.mappings import app_to_package
from mac2nix.mappings.app_config_registry import get_app_config
from mac2nix.mappings.app_to_hm import get_hm_module
from mac2nix.mappings.brew_to_nixpkgs import get_nixpkgs_equivalent, is_unnecessary_in_nix
from mac2nix.mappings.defaults_to_nix import get_nix_option
from mac2nix.mappings.dotfile_to_hm import get_hm_program
from mac2nix.mappings.ephemeral_filter import is_ephemeral
from mac2nix.mappings.non_defaults_to_nix import (
    ENVIRONMENT_MAP,
    NETWORKING_MAP,
    SECURITY_MAP,
    TIMEZONE_NIX_OPTION,
    get_font_nixpkgs,
    get_launchd_service,
    get_power_nix_option,
    get_shell_program,
    is_launchd_key_droppable,
)
from mac2nix.models.application import BrewFormula, InstalledApp
from mac2nix.models.files import DotfileEntry, FontEntry
from mac2nix.models.preferences import PreferencesDomain, PreferenceValue
from mac2nix.models.services import LaunchAgentEntry, LaunchAgentSource, ShellConfig
from mac2nix.scanners._utils import SENSITIVE_KEY_PATTERNS


class ClassificationTier(IntEnum):
    NATIVE = 1
    CUSTOM_PREFS = 2
    ACTIVATION_SCRIPT = 3
    MANUAL_REPORT = 4


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    """The routing decision for a single scanned setting.

    `destination` is a human-readable description of where the setting
    lands (a nix option path, "CustomUserPreferences", or a manual-report
    reason). `metadata` for Tier 3 entries must contain only structured
    data (domain/key/value_type/value) -- never a pre-built shell command
    string; escaping is a Phase 6 generator concern (SEC-2).
    """

    tier: ClassificationTier
    destination: str
    nix_path: str | None = None
    coercion: Callable[[Any], Any] | None = None
    metadata: dict[str, Any] | None = None


# sanitize_plist_values() (scanners/_utils.py) converts plist <data> blobs into
# this sentinel string before scanner output ever reaches this layer -- real
# `bytes` objects never appear here. Matching the sentinel is the only way to
# detect binary-origin values (SEC-3): isinstance(value, bytes) would be dead code.
_BINARY_SENTINEL_RE = re.compile(r"^<data:\d+ bytes>$")

# The Application Firewall's alf domain has no entry in DEFAULTS_TO_NIX (the
# module was removed from nix-darwin in June 2025); these are the only two
# alf plist keys with a confirmed, unambiguous SECURITY_MAP equivalent.
# Everything else in com.apple.alf (loggingenabled, exceptions, applications,
# ...) falls through to the generic Tier 2 CustomSystemPreferences path.
_ALF_DOMAIN = "com.apple.alf"
_ALF_KEY_ALIASES: dict[str, str] = {
    "globalstate": "firewall_enabled",
    "stealthenabled": "firewall_stealth_mode",
}


def _is_sensitive_key(key: str) -> bool:
    upper = key.upper()
    return any(pattern in upper for pattern in SENSITIVE_KEY_PATTERNS)


def _is_binary_sentinel(value: Any) -> bool:
    return isinstance(value, str) and bool(_BINARY_SENTINEL_RE.match(value))


def _preferences_tier2_destination(domain: PreferencesDomain) -> str:
    """Distinguish CustomUserPreferences vs CustomSystemPreferences by source_path.

    cfprefsd-only domains (source_path is None) default to CustomUserPreferences --
    most such domains reflect per-user cached settings with no system-wide plist.
    """
    if domain.source_path is not None and not str(domain.source_path).startswith(str(Path.home())):
        return "CustomSystemPreferences"
    return "CustomUserPreferences"


def _classify_preference_precheck(
    domain: PreferencesDomain, key: str, value: PreferenceValue
) -> ClassificationResult | None:
    """SEC-1/SEC-3 gating checks plus ephemeral-noise filtering, run before any tier routing."""
    if _is_sensitive_key(key):
        return ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination=f"manual report: key '{key}' in domain '{domain.domain_name}' matches a sensitive pattern",
            metadata={
                "potentially_sensitive": True,
                "reason": "key name matches sensitive pattern",
                "domain": domain.domain_name,
                "key": key,
                "value": "***REDACTED***",
            },
        )

    if _is_binary_sentinel(value):
        return ClassificationResult(
            tier=ClassificationTier.ACTIVATION_SCRIPT,
            destination=f"activationScripts: defaults write for {domain.domain_name} {key} (binary data)",
            metadata={
                "command_type": "defaults_write",
                "domain": domain.domain_name,
                "key": key,
                "value_type": "data",
                "value": value,
            },
        )

    if is_ephemeral(key, value):
        return ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination="skipped: ephemeral UI/runtime state, not reproducible config",
            metadata={
                "skipped": True,
                "reason": "ephemeral value (UI state, timestamp, cache, or transient identifier)",
            },
        )

    return None


def classify_preference(domain: PreferencesDomain, key: str, value: PreferenceValue) -> ClassificationResult:
    """Classify a single scanned (domain, key, value) preference triple."""
    precheck = _classify_preference_precheck(domain, key, value)
    if precheck is not None:
        return precheck

    domain_name = domain.domain_name
    if domain_name == _ALF_DOMAIN:
        alias = _ALF_KEY_ALIASES.get(key)
        alf_nix_path = SECURITY_MAP.get(alias) if alias is not None else None
        if alf_nix_path is not None:
            return ClassificationResult(
                tier=ClassificationTier.NATIVE,
                destination=alf_nix_path,
                nix_path=alf_nix_path,
                metadata={"domain": domain_name, "key": key, "alf_alias": alias},
            )

    option = get_nix_option(domain_name, key)
    if option is not None:
        conditions = option.conditions or {}
        tier_override = conditions.get("tier_override")
        if tier_override is None:
            metadata: dict[str, Any] = {"nix_type": option.nix_type}
            if conditions:
                metadata["conditions"] = conditions
            return ClassificationResult(
                tier=ClassificationTier.NATIVE,
                destination=option.nix_path,
                nix_path=option.nix_path,
                coercion=option.coercion,
                metadata=metadata,
            )
        return ClassificationResult(
            tier=ClassificationTier(tier_override),
            destination=_preferences_tier2_destination(domain),
            metadata={
                "native_nix_path_available": option.nix_path,
                "reason": "complex struct type not directly mappable to a typed nix-darwin option",
            },
        )

    return ClassificationResult(
        tier=ClassificationTier.CUSTOM_PREFS,
        destination=_preferences_tier2_destination(domain),
        metadata={"domain": domain_name, "key": key},
    )


def classify_launch_agent(entry: LaunchAgentEntry) -> ClassificationResult:
    """Classify a scanned LaunchAgent/LaunchDaemon/login item entry.

    Agents (user or system-scoped) route to Tier 2 generic serviceConfig
    passthrough, matching CustomUserPreferences' role for preferences: a
    known nix-darwin sink, but a whole-structure passthrough rather than a
    per-key typed mapping. Daemons run as root and route to Tier 3 --
    treated with the same activation-time caution as other privileged
    changes. Login items have no launchd-based nix-darwin equivalent at all.
    """
    service = get_launchd_service(entry.label)
    if service is not None:
        return ClassificationResult(
            tier=ClassificationTier.NATIVE,
            destination=service,
            nix_path=service,
            metadata={"label": entry.label},
        )

    if entry.source == LaunchAgentSource.LOGIN_ITEM:
        return ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination=f"manual report: login item '{entry.label}' has no nix-darwin equivalent",
            metadata={"label": entry.label, "source": entry.source.value},
        )

    cleaned_plist = {k: v for k, v in entry.raw_plist.items() if not is_launchd_key_droppable(k)}
    if entry.source == LaunchAgentSource.DAEMON:
        tier = ClassificationTier.ACTIVATION_SCRIPT
        destination = f'launchd.daemons."{entry.label}".serviceConfig'
    else:
        tier = ClassificationTier.CUSTOM_PREFS
        namespace = "user.agents" if entry.source == LaunchAgentSource.USER else "agents"
        destination = f'launchd.{namespace}."{entry.label}".serviceConfig'

    return ClassificationResult(
        tier=tier,
        destination=destination,
        nix_path=destination,
        metadata={"label": entry.label, "source": entry.source.value, "raw_plist": cleaned_plist},
    )


def classify_app(app: InstalledApp) -> ClassificationResult:
    """Classify a scanned installed application by its installation channel."""
    classification = app_to_package.classify_app(app.name)
    if classification is None:
        return ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination=f"manual report: unrecognized app '{app.name}', no package classification available",
            metadata={"app_name": app.name, "bundle_id": app.bundle_id},
        )

    if classification.source == "nixpkgs":
        return ClassificationResult(
            tier=ClassificationTier.NATIVE,
            destination="environment.systemPackages",
            nix_path=f"pkgs.{classification.package_name}",
            metadata={"source": "nixpkgs", "package_name": classification.package_name},
        )
    if classification.source == "cask":
        return ClassificationResult(
            tier=ClassificationTier.NATIVE,
            destination="homebrew.casks",
            nix_path="homebrew.casks",
            metadata={
                "source": "cask",
                "cask_name": classification.package_name,
                "nix_alternative": classification.nix_alternative,
            },
        )
    if classification.source == "appstore":
        return ClassificationResult(
            tier=ClassificationTier.NATIVE,
            destination="homebrew.masApps",
            nix_path="homebrew.masApps",
            metadata={
                "source": "appstore",
                "display_name": classification.package_name,
                "note": "app-id must be resolved from HomebrewState.mas_apps",
            },
        )
    return ClassificationResult(
        tier=ClassificationTier.MANUAL_REPORT,
        destination="pre-bundled with macOS, no installation action needed",
        metadata={"source": "system", "app_name": app.name},
    )


def classify_app_config(bundle_id: str) -> ClassificationResult:
    """Classify an app's Application Support (or equivalent) config location via app_config_registry.

    Registry entries flagged `scannable` route to Tier 2 as a candidate for
    further per-key analysis; entries flagged not scannable (opaque
    databases, encrypted vaults, LevelDB stores) and bundle IDs with no
    registry entry both route to Tier 4.
    """
    info = get_app_config(bundle_id)
    if info is None:
        return ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination=f"manual report: unknown app config location for bundle id '{bundle_id}'",
            metadata={"bundle_id": bundle_id},
        )

    metadata: dict[str, Any] = {
        "bundle_id": bundle_id,
        "config_paths": list(info.config_paths),
        "file_type": info.file_type.value,
        "notes": info.notes,
    }
    if info.scannable:
        return ClassificationResult(
            tier=ClassificationTier.CUSTOM_PREFS,
            destination="CustomUserPreferences: further scan recommended",
            metadata=metadata,
        )

    return ClassificationResult(
        tier=ClassificationTier.MANUAL_REPORT,
        destination=f"manual report: app config for '{bundle_id}' not scannable (e.g. database)",
        metadata=metadata,
    )


def classify_dotfile(entry: DotfileEntry) -> ClassificationResult:
    """Classify a scanned dotfile by its home-manager program module, if any."""
    hm_program = get_hm_program(entry.path)
    if hm_program is not None:
        return ClassificationResult(
            tier=ClassificationTier.NATIVE,
            destination=hm_program,
            nix_path=hm_program,
            metadata={"managed_by": entry.managed_by.value, "sensitive": entry.sensitive},
        )
    return ClassificationResult(
        tier=ClassificationTier.MANUAL_REPORT,
        destination=f"manual report: no home-manager program module found for dotfile '{entry.path}'",
        metadata={"managed_by": entry.managed_by.value, "sensitive": entry.sensitive},
    )


def classify_brew_formula(formula: BrewFormula) -> ClassificationResult:
    """Classify a scanned Homebrew formula by its nixpkgs equivalent."""
    if is_unnecessary_in_nix(formula.name):
        return ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination=f"skip: '{formula.name}' is a version manager redundant under Nix's declarative package model",
            metadata={"unnecessary_in_nix": True, "formula": formula.name},
        )

    equivalent = get_nixpkgs_equivalent(formula.name)
    if equivalent is None:
        return ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination=f"manual report: no nixpkgs equivalent for brew formula '{formula.name}'",
            metadata={"formula": formula.name},
        )

    metadata: dict[str, Any] = {"formula": formula.name, "nixpkgs_attr": equivalent.attr_name}
    if equivalent.note:
        metadata["note"] = equivalent.note
    hm_info = get_hm_module(formula.name)
    if hm_info is not None:
        metadata["hm_module_available"] = hm_info.module_path

    return ClassificationResult(
        tier=ClassificationTier.NATIVE,
        destination="environment.systemPackages",
        nix_path=f"pkgs.{equivalent.attr_name}",
        metadata=metadata,
    )


def classify_font(entry: FontEntry) -> ClassificationResult:
    """Classify a scanned font by its nixpkgs package, if any."""
    nix_attr = get_font_nixpkgs(entry.name)
    if nix_attr is None:
        return ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination=f"manual report: no nixpkgs package for font '{entry.name}'",
            metadata={"font_name": entry.name},
        )
    return ClassificationResult(
        tier=ClassificationTier.NATIVE,
        destination="fonts.packages",
        nix_path=nix_attr,
        metadata={"font_name": entry.name},
    )


def classify_system_setting(field_name: str, value: Any) -> ClassificationResult:
    """Classify a SystemConfig field: pmset power settings via POWER_SETTING_MAP,
    plus the standalone ``timezone`` field routed to TIMEZONE_NIX_OPTION.
    """
    if field_name == "timezone":
        return ClassificationResult(
            tier=ClassificationTier.NATIVE,
            destination=TIMEZONE_NIX_OPTION,
            nix_path=TIMEZONE_NIX_OPTION,
            metadata={"field_name": field_name, "value": value},
        )

    nix_path = get_power_nix_option(field_name)
    if nix_path is None:
        return ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination=f"manual report: no nix-darwin option for system setting '{field_name}'",
            metadata={"field_name": field_name, "value": value},
        )
    return ClassificationResult(
        tier=ClassificationTier.NATIVE,
        destination=nix_path,
        nix_path=nix_path,
        metadata={"field_name": field_name, "value": value},
    )


def classify_security_setting(field_name: str, value: Any) -> ClassificationResult:
    """Classify a SecurityState field against SECURITY_MAP."""
    nix_path = SECURITY_MAP.get(field_name)
    if nix_path is None:
        return ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination=f"manual report: no nix-darwin option for security setting '{field_name}'",
            metadata={"field_name": field_name, "value": value},
        )
    return ClassificationResult(
        tier=ClassificationTier.NATIVE,
        destination=nix_path,
        nix_path=nix_path,
        metadata={"field_name": field_name, "value": value},
    )


def classify_network_setting(field_name: str, value: Any) -> ClassificationResult:
    """Classify a SystemConfig/NetworkConfig field against NETWORKING_MAP."""
    nix_path = NETWORKING_MAP.get(field_name)
    if nix_path is None:
        return ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination=f"manual report: no nix-darwin option for network setting '{field_name}'",
            metadata={"field_name": field_name, "value": value},
        )
    return ClassificationResult(
        tier=ClassificationTier.NATIVE,
        destination=nix_path,
        nix_path=nix_path,
        metadata={"field_name": field_name, "value": value},
    )


def classify_shell_setting(config: ShellConfig) -> list[ClassificationResult]:
    """Classify a scanned shell configuration: program enablement, environment
    state (aliases/env vars/PATH), and any framework or dynamically-generated
    command with no direct nix-darwin equivalent.
    """
    results: list[ClassificationResult] = []

    nix_path = get_shell_program(config.shell_type)
    if nix_path is None:
        results.append(
            ClassificationResult(
                tier=ClassificationTier.MANUAL_REPORT,
                destination=f"manual report: no nix-darwin program mapping for shell type '{config.shell_type}'",
                metadata={"shell_type": config.shell_type},
            )
        )
    else:
        results.append(
            ClassificationResult(
                tier=ClassificationTier.NATIVE,
                destination=nix_path,
                nix_path=nix_path,
                metadata={"shell_type": config.shell_type},
            )
        )

    if config.aliases:
        destination = ENVIRONMENT_MAP["aliases"]
        results.append(
            ClassificationResult(
                tier=ClassificationTier.NATIVE,
                destination=destination,
                nix_path=destination,
                metadata={"aliases": config.aliases},
            )
        )

    if config.env_vars:
        destination = ENVIRONMENT_MAP["env_vars"]
        results.append(
            ClassificationResult(
                tier=ClassificationTier.NATIVE,
                destination=destination,
                nix_path=destination,
                metadata={"env_vars": config.env_vars},
            )
        )

    if config.path_components:
        destination = ENVIRONMENT_MAP["path_components"]
        results.append(
            ClassificationResult(
                tier=ClassificationTier.NATIVE,
                destination=destination,
                nix_path=destination,
                metadata={"path_components": config.path_components},
            )
        )

    if config.frameworks:
        results.append(
            ClassificationResult(
                tier=ClassificationTier.MANUAL_REPORT,
                destination="manual report: shell framework(s) have no direct nix-darwin equivalent",
                metadata={"frameworks": [framework.name for framework in config.frameworks]},
            )
        )

    if config.dynamic_commands:
        results.append(
            ClassificationResult(
                tier=ClassificationTier.MANUAL_REPORT,
                destination="manual report: dynamically-generated shell commands have no direct nix-darwin equivalent",
                metadata={"dynamic_commands": config.dynamic_commands},
            )
        )

    return results
