"""Curated macOS preferences generator: dock, Finder, screensaver, trackpad,
keyboard shortcuts, keyboard text replacements, battery/power, and wallpaper.

Narrow by design -- this is not the full 197-option Tier 1 sweep, just the
curated subset the migration MVP targets. See `hack/PROJECT.md`'s "Mapping
Layer Architecture" section for the four-tier classifier this generator
consumes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mac2nix.generators._nix_render import render_template
from mac2nix.mappings.classifier import (
    ClassificationResult,
    ClassificationTier,
    classify_preference,
    classify_system_setting,
    classify_wallpaper,
)
from mac2nix.models.preferences import PreferencesDomain
from mac2nix.models.system_state import SystemState

# [ASSUMPTION: detail] both domain lists are a starting point verified
# against known macOS defaults domains/keys, not exhaustively tested
# against every macOS version; refine against this PR's own UAT scan output.
CURATED_WHOLESALE_DOMAINS: frozenset[str] = frozenset(
    {
        "com.apple.dock",
        "com.apple.finder",
        "com.apple.screensaver",
        "com.apple.AppleMultitouchTrackpad",
        "com.apple.driver.AppleBluetoothMultitouch.trackpad",
        "com.apple.symbolichotkeys",  # has zero DEFAULTS_TO_NIX coverage -- see
        # module docstring; every key here lands in CUSTOM_PREFS, not NATIVE.
        # Included anyway since rendering handles both tiers.
    }
)

# NSGlobalDomain is far broader than the curated scope (appearance, window
# behavior, etc.) -- only these specific keys are curated.
CURATED_GLOBAL_DOMAIN_KEYS: frozenset[str] = frozenset(
    {
        "NSUserDictionaryReplacementItems",  # keyboard text replacements
        "KeyRepeat",
        "InitialKeyRepeat",
        "ApplePressAndHoldEnabled",
        "com.apple.trackpad.scaling",
        "com.apple.trackpad.forceClick",
        "com.apple.swipescrolldirection",
    }
)

# Both the disk-plist alias (".GlobalPreferences") and the cfprefsd-reported
# name (NSGlobalDomain) can appear as domain_name -- defaults_to_nix's own
# DOMAIN_ALIASES already resolves either form internally when classifying a
# key, so here we only need to recognize both literals as "the global
# domain" for filtering purposes, not reimplement alias resolution.
_GLOBAL_DOMAIN_NAMES = frozenset({"NSGlobalDomain", ".GlobalPreferences"})

_EMPTY_MODULE = "# preferences/system domain not scanned -- nothing to generate\n{ config, lib, pkgs, ... }:\n{\n}\n"

_TEMPLATE_NAME = "preferences.nix.j2"


@dataclass(frozen=True, slots=True)
class _CuratedItem:
    """A single curated setting awaiting tiered rendering.

    `value` is always sourced from the original scan (domain.keys[key],
    power_settings[field], or the wallpaper path itself) -- never from
    `result.metadata`, whose shape differs across the classify_* functions
    that can produce a `ClassificationResult` here. `domain`/`key` are only
    populated for preference-sourced items: they're needed to render
    CUSTOM_PREFS entries under `system.defaults.CustomUserPreferences.<domain>.<key>`,
    since `ClassificationResult.metadata` does NOT always carry them (the
    tier_override path for a complex-struct NATIVE option, e.g. dock's
    persistent-apps/persistent-others, sets metadata to
    {"native_nix_path_available", "reason"} instead).
    """

    value: Any
    result: ClassificationResult
    domain: str | None = None
    key: str | None = None


def _collect_preference_items(domains: list[PreferencesDomain]) -> list[_CuratedItem]:
    """Collect curated items from wholesale domains and the global-domain alias.

    `PreferencesScanner._discover_cfprefsd_domains()` only skips a cfprefsd
    domain name already present in `seen` -- and `seen` is populated from
    on-disk plist file *stems*, so the on-disk ".GlobalPreferences.plist"
    (stem ".GlobalPreferences") never matches the literal string
    "NSGlobalDomain" that `defaults domains` reports. This means a real scan
    of any Mac with a `.GlobalPreferences.plist` (virtually all of them)
    deterministically produces BOTH domains for the same underlying global
    preferences. When they disagree on a curated key's value, NSGlobalDomain
    (cfprefsd, live) wins over .GlobalPreferences (on-disk) explicitly here
    -- not by incidental scan-order -- because cfprefsd's in-memory cache is
    documented by Apple as the authoritative source: it batches writes to
    disk asynchronously, so the on-disk plist can lag the live value by
    design (the same reason `killall cfprefsd` is a real troubleshooting
    step for "my defaults write didn't take effect").
    """
    domain_names = {d.domain_name for d in domains}
    skip_stale_global_preferences_alias = "NSGlobalDomain" in domain_names

    items: list[_CuratedItem] = []
    for domain in domains:
        if domain.domain_name == ".GlobalPreferences" and skip_stale_global_preferences_alias:
            continue
        if domain.domain_name in CURATED_WHOLESALE_DOMAINS:
            keys_to_scan: list[str] = list(domain.keys)
        elif domain.domain_name in _GLOBAL_DOMAIN_NAMES:
            keys_to_scan = [k for k in domain.keys if k in CURATED_GLOBAL_DOMAIN_KEYS]
        else:
            continue

        for key in keys_to_scan:
            value = domain.keys[key]
            result = classify_preference(domain, key, value)
            items.append(_CuratedItem(value=value, result=result, domain=domain.domain_name, key=key))

    return items


def _collect_power_items(power_settings: dict[str, str]) -> list[_CuratedItem]:
    """Classify each pmset power setting via POWER_SETTING_MAP.

    `power_settings` keys carry a per-source-section prefix as scanned
    (e.g. "battery_power.displaysleep", "ac_power.sleep" -- see
    SystemScanner._get_power_settings()), but POWER_SETTING_MAP is keyed by
    the bare pmset key alone. Strip the prefix before classifying -- this is
    generator-layer, not mapping-layer, code (the mapping table itself needs
    no change for this domain).
    """
    items: list[_CuratedItem] = []
    for field_name, value in power_settings.items():
        bare_field_name = field_name.rsplit(".", 1)[-1]
        result = classify_system_setting(bare_field_name, value)
        items.append(_CuratedItem(value=value, result=result))
    return items


# power.sleep.{computer,display,harddisk} take `null | positive-int | "never"`
# -- confirmed via a real `nix build` failure ("A definition for option
# `power.sleep.computer' is not of type `null or positive integer, meaning
# >0, or value "never"'"). A scanned pmset value of "0" means "never sleep",
# not the integer 0, which isn't itself a valid positive integer. This is
# generator-layer, not mapping-layer, code -- classify_system_setting() has
# no pmset-specific type knowledge (no coercion attached), the same way
# _collect_power_items()'s section-prefix stripping already is.
_POWER_SLEEP_NIX_PATHS = frozenset({"power.sleep.computer", "power.sleep.display", "power.sleep.harddisk"})

# power.restartAfterPowerFailure / networking.wakeOnLan.enable are gated by
# nix-darwin's own systemsetup-backed activation scripts -- whether the
# TARGET machine's hardware supports either feature can't be known from a
# SOURCE-machine scan. Confirmed via a real `nix_vm` integration-test
# failure (not review): nix-darwin's modules/system/checks.nix ships
# `restartAfterPowerFailureIsSupported`, which fires whenever
# `config.power.restartAfterPowerFailure != null` -- true OR false, either
# one -- and calls `exit 2` inside the single `set -e` master activation
# script (modules/system/activation-scripts.nix), aborting the ENTIRE
# `darwin-rebuild switch`, not just this one setting. There is no safe
# boolean value; only leaving the option unset (its own `null` default)
# avoids the check. `networking.wakeOnLan.enable` has no equivalent
# nix-darwin pre-check at all, but its own activation script calls the
# same `systemsetup` family with no `|| true` guard under the identical
# `set -e` wrapper -- a documented real-world failure on hardware/drivers
# that report Wake-on-LAN as unsupported (nix-darwin's own option
# docstring: "Battery powered devices may require being connected to
# power."). Never render either option natively -- this generator has no
# mechanism to detect target-hardware capability at generate or apply
# time, so both are downgraded to a manual-report comment instead.
_POWER_HARDWARE_DEPENDENT_NIX_PATHS = frozenset({"power.restartAfterPowerFailure", "networking.wakeOnLan.enable"})


def _coerce_power_native_value(nix_path: str, value: Any) -> Any:
    if nix_path in _POWER_SLEEP_NIX_PATHS:
        try:
            minutes = int(value)
        except (TypeError, ValueError):
            return value
        return "never" if minutes <= 0 else minutes
    return value


def _build_render_context(items: list[_CuratedItem]) -> dict[str, Any]:
    """Apply coercion, group by tier, and shape the Jinja2 render context.

    NATIVE assignments are deduped by `nix_path` -- Nix rejects an attrset
    that assigns the same dotted path twice (e.g. both
    "battery_power.sleep" and "ac_power.sleep" resolve to the same
    "power.sleep.computer" nix-darwin option, which has no per-power-source
    control). Iterating `sorted(native.items())` for the final render list
    keeps output deterministic regardless of dict insertion order.

    MANUAL_REPORT comments get two further, independent dedup passes for the
    same underlying reason (pmset reports some keys under both "AC Power:"
    and "Battery Power:"): a `nix_path`-keyed, first-occurrence-wins dedup
    for the hardware-dependent power/networking settings (whose comment text
    embeds the scanned value, so two different values must still collapse to
    one entry), and a final whole-list `dict.fromkeys()` pass for unmapped
    fields whose destination string never varies by value (so an
    exact-string dedup is sufficient there).
    """
    native: dict[str, Any] = {}
    custom_user_prefs: dict[str, dict[str, Any]] = {}
    custom_system_prefs: dict[str, dict[str, Any]] = {}
    wallpaper_path: str | None = None
    manual_report_comments: list[str] = []
    reported_hardware_dependent_paths: set[str] = set()

    for item in items:
        result = item.result
        metadata = result.metadata or {}

        if result.tier == ClassificationTier.NATIVE:
            if result.nix_path in _POWER_HARDWARE_DEPENDENT_NIX_PATHS:
                # pmset reports some keys (e.g. "autorestart", "womp") under
                # both the "AC Power:" and "Battery Power:" sections even
                # though the underlying setting isn't actually
                # per-power-source -- the same duplication `native`'s
                # dict-write already dedupes for NATIVE paths. Dedupe here
                # too, or a real scan produces two identical manual-report
                # comments for the same nix_path.
                if result.nix_path not in reported_hardware_dependent_paths:
                    reported_hardware_dependent_paths.add(result.nix_path)
                    manual_report_comments.append(
                        f"manual report: {result.nix_path} (scanned value {item.value!r}) not applied -- "
                        "target-hardware support for this setting can't be verified from a source-machine "
                        "scan; setting it on unsupported hardware aborts the entire darwin-rebuild switch. "
                        "Verify with `systemsetup -get...` on the target Mac and set manually if supported."
                    )
            elif result.nix_path is not None:
                value = result.coercion(item.value) if result.coercion else item.value
                value = _coerce_power_native_value(result.nix_path, value)
                native[result.nix_path] = value
        elif result.tier == ClassificationTier.CUSTOM_PREFS:
            if item.domain is None or item.key is None:
                # Every CUSTOM_PREFS item this generator produces is
                # preference-sourced (classify_system_setting/classify_wallpaper
                # never return CUSTOM_PREFS) -- defensive, not expected.
                continue
            bucket = custom_user_prefs if result.destination == "CustomUserPreferences" else custom_system_prefs
            bucket.setdefault(item.domain, {})[item.key] = item.value
        elif result.tier == ClassificationTier.ACTIVATION_SCRIPT:
            if "wallpaper_path" in metadata:
                wallpaper_path = metadata["wallpaper_path"]
            else:
                # This generator only implements the wallpaper case for
                # ACTIVATION_SCRIPT; any other Tier-3 result (e.g. a
                # binary-data plist value) intentionally falls back to a
                # manual-report comment instead of a real activation
                # script, since synthesizing an arbitrary `defaults write`
                # script for binary data is out of this narrow generator's
                # scope.
                manual_report_comments.append(result.destination)
        elif not metadata.get("skipped"):
            manual_report_comments.append(result.destination)

    # A real, confirmed-on-hardware case: pmset reports some keys (e.g.
    # "hibernatemode") under both "AC Power:" and "Battery Power:" with
    # different values, but classify_system_setting()'s MANUAL_REPORT
    # destination string for an unmapped field doesn't include the value --
    # so two source-prefixed keys for the same unmapped field produce two
    # identical comment strings. dict.fromkeys() dedupes exact-duplicate
    # strings while preserving first-occurrence order.
    manual_report_comments = list(dict.fromkeys(manual_report_comments))

    return {
        "native_items": [{"nix_path": path, "value": value} for path, value in sorted(native.items())],
        "custom_user_prefs": custom_user_prefs,
        "custom_system_prefs": custom_system_prefs,
        "wallpaper_path": wallpaper_path,
        "manual_report_comments": manual_report_comments,
    }


def generate_preferences(system_state: SystemState) -> str:
    """Render the curated preferences.nix module from one host's scan.

    Returns rendered Nix source text -- it does not write the file itself;
    `generate_all()` owns file I/O.
    """
    if system_state.preferences is None or system_state.system is None:
        return _EMPTY_MODULE

    items = _collect_preference_items(system_state.preferences.domains)
    items.extend(_collect_power_items(system_state.system.power_settings))

    if system_state.system.wallpaper_path is not None:
        wallpaper_result = classify_wallpaper(system_state.system.wallpaper_path)
        items.append(_CuratedItem(value=system_state.system.wallpaper_path, result=wallpaper_result))

    context = _build_render_context(items)
    return render_template(_TEMPLATE_NAME, context)
