"""Curated macOS preferences generator: dock, Finder, screensaver, trackpad,
keyboard shortcuts, keyboard text replacements, battery/power, and wallpaper.

Narrow by design -- this is not the full 197-option Tier 1 sweep, just the
curated subset the migration MVP targets. See `hack/PROJECT.md`'s "Mapping
Layer Architecture" section for the four-tier classifier this generator
consumes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mac2nix.generators._nix_render import nix_post_activation_script, nix_string, render_template
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
# way to make nix-darwin's own option skip its unconditional check. Step 14
# instead renders each as its own self-guarding activation script that
# probes target support directly (mirroring nix-darwin's own
# modules/system/checks.nix grep-for-"Not supported" pattern) and only
# applies via `systemsetup` if supported, bypassing the native option
# (and its unconditional check) entirely.
_POWER_HARDWARE_DEPENDENT_NIX_PATHS = frozenset({"power.restartAfterPowerFailure", "networking.wakeOnLan.enable"})


def _coerce_hardware_dependent_setting(value: Any) -> str | None:
    """Coerce a scanned pmset boolean-like value (autorestart/womp) to exactly "on" or "off".

    Per security consultation: coerce to a closed set rather than escaping
    an open one -- anything that isn't exactly the scanned pmset literal
    "1" or "0" fails closed to the manual-report path, never passed
    through as a raw scanned string.
    """
    if value == "1":
        return "on"
    if value == "0":
        return "off"
    return None


def _build_hardware_dependent_activation_script(
    probe_flag: str, apply_flag: str, value: str, setting_label: str
) -> str:
    """Build a self-guarding activation-script body for a hardware-dependent power/networking setting.

    Mirrors nix-darwin's own modules/system/checks.nix grep-for-"Not
    supported" probe pattern instead of relying on its unconditional
    native-option check. Unlike wallpaper's AppleScript call, neither
    setting needs `sudo -u ${config.system.primaryUser}` -- `systemsetup`
    operates at the system level and nix-darwin activation already runs as
    root. `value` is already one of exactly "on"/"off" (never a raw
    scanned string) by the time it reaches here; still routed through
    `lib.escapeShellArg` as defense-in-depth against a future coercion bug.

    Returns a bare body expression -- the caller collects these into a list
    for `nix_post_activation_script()`, which is the only function that
    wraps them into the one real `system.activationScripts.postActivation`
    hook nix-darwin actually executes.
    """
    return (
        "let\n"
        f"      settingValue = {nix_string(value)};\n"
        "    in\n"
        "    ''\n"
        f'      if systemsetup {probe_flag} | grep -q "Not supported"; then\n'
        f'        echo "mac2nix: {setting_label} not supported on this hardware, skipped" >&2\n'
        "      else\n"
        f"        systemsetup {apply_flag} ${{lib.escapeShellArg settingValue}}\n"
        "      fi\n"
        "    ''"
    )


def _build_restart_after_power_failure_activation_script(value: str) -> str:
    return _build_hardware_dependent_activation_script(
        "-getRestartPowerFailure", "-setRestartPowerFailure", value, "restart-after-power-failure"
    )


def _build_wake_on_lan_activation_script(value: str) -> str:
    """`-getwakeonnetworkaccess`/`-setwakeonnetworkaccess` are the real `systemsetup`
    flags for Wake-on-LAN -- confirmed against a real `systemsetup -help` on a Tart
    VM. `-get/setRemoteWakeUp` (an earlier, incorrect guess) is not a valid
    `systemsetup` command at all; the tool prints an "is not a valid command"
    error but still exits 0, which is why a real VM switch never surfaced this as
    a failure -- it silently no-op'd instead of erroring or applying anything.
    """
    return _build_hardware_dependent_activation_script(
        "-getwakeonnetworkaccess", "-setwakeonnetworkaccess", value, "wake-on-LAN"
    )


# Step 13's curated-domain audit: of every `[coverage gap]` manual-report
# case reachable from this generator (preference domain/key items always
# route to NATIVE or CUSTOM_PREFS when unmapped, never MANUAL_REPORT -- see
# classify_preference()'s fallthrough -- so `[coverage gap]` only ever
# comes from classify_system_setting()'s no-mapping fallback for pmset
# keys), these three are promotable: no native nix-darwin option exists,
# but unlike restartAfterPowerFailure/wakeOnLan (systemsetup, hard-fails on
# unsupported hardware), `pmset -a <key> <value>` silently no-ops a setting
# that doesn't apply to the current hardware (e.g. `lidwake` on a Mac with
# no lid) rather than erroring -- safe to apply unconditionally, no probe
# needed. [ASSUMPTION: detail] this enumeration is the audit itself, not
# exhaustive -- a real scan may surface more `[coverage gap]` pmset keys;
# these three are the ones this audit could confirm safe without one. Well
# under the plan's own ~5-case scope circuit-breaker.
_PROMOTED_POWER_SETTING_KEYS = frozenset({"hibernatemode", "standby", "lidwake"})


def _coerce_promoted_power_setting_value(value: Any) -> int | None:
    """Coerce a scanned pmset value to a plain non-negative int, or None if it can't be.

    Fails closed like Step 14's power-boolean coercion: anything that
    doesn't cleanly coerce is never passed through as a raw scanned string
    -- the caller falls back to the manual-report path instead.
    """
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        return None
    return coerced if coerced >= 0 else None


def _build_promoted_power_setting_activation_script(pmset_key: str, value: int) -> str:
    """Build a self-contained activation-script body for a promoted `[coverage gap]` pmset setting.

    `pmset_key` is always one of the fixed, module-controlled
    `_PROMOTED_POWER_SETTING_KEYS` literals -- never attacker/scan-derived
    data -- so it's safe to embed directly in the shell command. `value` is
    already a coerced Python int by the time it reaches here (never a raw
    scanned string); still routed through `lib.escapeShellArg` as
    defense-in-depth against a future coercion bug, matching Step 14's
    same discipline.

    Returns a bare body expression -- see
    `_build_hardware_dependent_activation_script()`'s docstring for why.
    """
    return (
        "let\n"
        f"      settingValue = toString {value};\n"
        "    in\n"
        "    ''\n"
        f"      pmset -a {pmset_key} ${{lib.escapeShellArg settingValue}}\n"
        "    ''"
    )


def _handle_manual_report_item(
    item: _CuratedItem, activation_scripts: dict[str, str], manual_report_comments: list[str]
) -> None:
    """Route a MANUAL_REPORT-tier result to a promoted activation script or a plain comment.

    A promoted case (its `field_name` in `_PROMOTED_POWER_SETTING_KEYS`,
    with a cleanly-coercible value) never also appears as a comment --
    promotion here is the only path for that field_name, mirroring the
    same never-appears-in-both-lists mechanism Step 14 uses for
    hardware-dependent settings.

    `activation_scripts` is keyed by an internal dedup identifier only
    (never a real Nix attribute name) -- see `_build_render_context()`'s
    docstring for why there is no longer a per-case Nix key.
    """
    result = item.result
    metadata = result.metadata or {}
    field_name = metadata.get("field_name")

    if field_name in _PROMOTED_POWER_SETTING_KEYS:
        coerced = _coerce_promoted_power_setting_value(item.value)
        if coerced is not None:
            activation_scripts[f"pmset_{field_name}"] = _build_promoted_power_setting_activation_script(
                field_name, coerced
            )
            return

    if not metadata.get("skipped"):
        manual_report_comments.append(result.destination)


# A path whose resolved parent falls here ships identically on every macOS
# install -- portable across machines as an absolute path reference,
# no bundling needed. Anything else is a personal file unique to the
# scanned machine (_prepare_wallpaper_asset() decides whether it's safe to
# bundle it into the generated output instead).
_WALLPAPER_ASSET_ALLOWLIST = frozenset(
    {
        Path("/System/Library/Desktop Pictures"),
        Path("/Library/Desktop Pictures"),
    }
)


def _is_portable_wallpaper_path(path: Path) -> bool:
    """A path anywhere under an allowlisted OS-asset directory is portable.

    macOS ships stock wallpapers in nested subdirectories (e.g.
    "Solid Colors/Black.png", ".wallpapers/Sonoma Horizon/Sonoma Horizon.heic")
    -- an exact-parent-match check would misclassify these as personal files
    and route a genuinely portable OS-shipped wallpaper through the bundling
    path, where it fails every allowlist there too and silently drops the
    wallpaper automation entirely (found by a fresh-context adversarial
    review, confirmed live against real subdirectories on this machine).
    Allowlist entries are resolved too, matching
    `_is_bundleable_wallpaper_location`'s same rationale for a symlinked
    ancestor.
    """
    resolved = path.resolve()
    return any(resolved.is_relative_to(d.resolve()) for d in _WALLPAPER_ASSET_ALLOWLIST)


# Independent from _WALLPAPER_ASSET_ALLOWLIST above: that allowlist decides
# "is this path portable as-is"; this one decides "is bundling THIS
# personal path actually safe" -- a personal file outside both allowlists
# (e.g. under Downloads or an external volume) falls back to manual-report
# instead of bundling. [ASSUMPTION: detail] a starting guess at realistic
# personal-wallpaper locations, not exhaustively researched -- widen if a
# real scan's UAT run shows the bundling path rarely triggers.
def _wallpaper_bundle_source_allowlist() -> tuple[Path, ...]:
    home = Path.home()
    return (home / "Pictures", home / "Library" / "Application Support" / "Dock")


_WALLPAPER_EXTENSION_ALLOWLIST = frozenset({".heic", ".jpg", ".jpeg", ".png", ".tiff"})
_WALLPAPER_MAX_BYTES = 20 * 1024 * 1024

# ISO-BMFF (HEIC/HEIF) brand codes at bytes[8:12] of a "....ftyp<brand>" box.
_HEIC_FTYP_BRANDS = frozenset({b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"})


def _sniff_image_extension(data: bytes) -> str | None:
    """Identify a real image format from magic bytes -- never trust a claimed extension.

    `imghdr` was removed in Python 3.13 (PEP 594); this covers exactly the
    formats in `_WALLPAPER_EXTENSION_ALLOWLIST`, nothing more.
    """
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith((b"II*\x00", b"MM\x00*")):
        return ".tiff"
    if len(data) >= 12 and data[4:8] == b"ftyp" and data[8:12] in _HEIC_FTYP_BRANDS:
        return ".heic"
    return None


def _is_bundleable_wallpaper_location(resolved: Path) -> bool:
    """Path/location checks only -- content checks (size, magic bytes) happen separately.

    `resolved` must already be the fully symlink-resolved real path: a
    symlink inside an allowlisted directory that points outside it must be
    rejected, so the check has to apply to the real target, not the
    pre-symlink path. The allowlist dirs are resolved too, not just
    `resolved` -- otherwise a symlinked tmpdir (or any symlinked component
    of $HOME) compares an already-resolved path against an unresolved one,
    spuriously rejecting a genuinely-allowlisted file.
    """
    if not resolved.is_file():
        return False
    if resolved.suffix.lower() not in _WALLPAPER_EXTENSION_ALLOWLIST:
        return False
    return any(resolved.is_relative_to(d.resolve()) for d in _wallpaper_bundle_source_allowlist())


@dataclass(frozen=True, slots=True)
class WallpaperAsset:
    """A bundled personal wallpaper image awaiting disk write by `generate_all()`.

    `filename` is a bare filename fragment (e.g. "wallpaper.heic"), not a
    full path -- this module has no `hostname` to build
    `hosts/darwin/<hostname>/assets/...` itself; `generate_all()` owns
    joining it under that host's own `assets/` directory and owns all file
    I/O, per this module's existing contract (it performs no I/O itself).
    """

    filename: str
    data: bytes


def _prepare_wallpaper_asset(source_path: Path) -> WallpaperAsset | None:
    """Validate and read a personal wallpaper file for bundling into generated output.

    Fails closed: any validation failure (missing file, wrong location,
    disguised content, oversized) returns None, routing the caller to a
    manual-report fallback instead of bundling. The wallpaper path was
    captured at *scan* time -- by the time `generate` actually runs
    (possibly much later, against a saved --scan-file), the file may no
    longer exist; `resolve(strict=True)`'s FileNotFoundError is caught like
    any other validation failure here, never left to crash `generate` over
    one stale wallpaper reference.
    """
    try:
        resolved = source_path.resolve(strict=True)
    except (OSError, FileNotFoundError):
        return None

    if not _is_bundleable_wallpaper_location(resolved):
        return None

    try:
        if resolved.stat().st_size > _WALLPAPER_MAX_BYTES:
            return None
        data = resolved.read_bytes()
    except OSError:
        return None

    ext = _sniff_image_extension(data)
    return None if ext is None else WallpaperAsset(filename=f"wallpaper{ext}", data=data)


def _build_wallpaper_activation_script(wallpaper_path_nix_expr: str) -> str:
    """Build the wallpaper self-guarding activation-script body.

    `wallpaper_path_nix_expr` is a complete Nix expression for the
    `wallpaperPath` let-binding's right-hand side -- either a `nix_str`-
    quoted absolute path (a portable, OS-shipped wallpaper) or a
    `toString ./assets/<file>` path literal (a bundled personal image,
    resolved relative to the importing module and content-addressed into
    the Nix store). Returns a bare body expression -- see
    `_build_hardware_dependent_activation_script()`'s docstring for why.

    nix-darwin removed {pre,post}UserActivation -- all activation now runs
    as root, so the osascript call (which must talk to the logged-in user's
    WindowServer session) is explicitly run as system.primaryUser. The path
    is passed as an osascript *argument* (argv), never embedded into the
    AppleScript source text itself -- a path containing a literal `"` would
    otherwise terminate the embedded AppleScript string early and allow
    arbitrary command injection via `&`/`do shell script`. A headless/SSH-only
    activation (no WindowServer session for primaryUser -- e.g. a fleet
    member switched over a remote session) would otherwise fail this whole
    activation script under nix-darwin's `set -e`; `|| echo ... >&2` keeps
    that failure non-fatal but still loud, rather than either aborting the
    switch or failing silently.
    """
    set_picture_applescript = (
        'tell application "System Events" to tell every desktop to set picture to POSIX file (item 1 of argv)'
    )
    no_gui_session_fallback = (
        'echo "mac2nix: could not set desktop wallpaper (no GUI session for ${config.system.primaryUser}?)" >&2'
    )
    return (
        "let\n"
        f"      wallpaperPath = {wallpaper_path_nix_expr};\n"
        "    in\n"
        "    ''\n"
        "      sudo -u ${config.system.primaryUser} osascript \\\n"
        "        -e 'on run argv' \\\n"
        f"        -e '  {set_picture_applescript}' \\\n"
        "        -e 'end run' \\\n"
        "        ${lib.escapeShellArg wallpaperPath} \\\n"
        f"        || {no_gui_session_fallback}\n"
        "    ''"
    )


def _coerce_power_native_value(nix_path: str, value: Any) -> Any:
    if nix_path in _POWER_SLEEP_NIX_PATHS:
        try:
            minutes = int(value)
        except (TypeError, ValueError):
            return value
        return "never" if minutes <= 0 else minutes
    return value


def _render_activation_script_item(
    result: ClassificationResult, metadata: dict[str, Any]
) -> tuple[str | None, WallpaperAsset | None, str | None]:
    """Route an ACTIVATION_SCRIPT-tier result to wallpaper handling or a manual-report fallback.

    Returns `(activation_script, asset, manual_report_comment)`.
    `manual_report_comment` is non-None only when the other two are both
    None (the out-of-scope/bundling-failed fallback paths); `activation_script`
    and `asset` can BOTH be non-None together (a successfully bundled personal
    wallpaper returns its activation-script body alongside the asset to
    write), so this is not a strict one-of-three. This generator only
    implements the wallpaper case for ACTIVATION_SCRIPT; any other Tier-3 result (e.g. a
    binary-data plist value) intentionally falls back to a manual-report
    comment instead of a real activation script, since synthesizing an
    arbitrary `defaults write` activation script is out of this narrow
    generator's scope. Tagged `[out of scope]` here, not in
    classify_preference() -- the classifier's own tier assignment for this
    case (ACTIVATION_SCRIPT, automatable in principle) is correct; only
    this generator's own scope decision demotes it to a comment, so the
    "why" is only known at this level.
    """
    if "wallpaper_path" not in metadata:
        return None, None, f"[out of scope] {result.destination}"

    wallpaper_path = Path(metadata["wallpaper_path"])
    if _is_portable_wallpaper_path(wallpaper_path):
        return _build_wallpaper_activation_script(nix_string(str(wallpaper_path))), None, None

    asset = _prepare_wallpaper_asset(wallpaper_path)
    if asset is not None:
        return _build_wallpaper_activation_script(f"toString ./assets/{asset.filename}"), asset, None

    comment = (
        f"[coverage gap] wallpaper: personal image at {wallpaper_path} could not be "
        "bundled (missing, oversized, an unrecognized format, or outside "
        "~/Pictures / ~/Library/Application Support/Dock) -- copy it manually and "
        "reference it from a custom activation script if needed."
    )
    return None, None, comment


def _handle_native_item(
    item: _CuratedItem,
    reported_hardware_dependent_paths: set[str],
    native: dict[str, Any],
    activation_scripts: dict[str, str],
    manual_report_comments: list[str],
) -> None:
    """Route a NATIVE-tier result to a native assignment, a hardware-dependent
    self-guarding activation script, or (if uncoercible) a manual-report comment.

    A hardware-dependent nix_path already reported once is silently
    dropped: pmset reports some keys under both "AC Power:" and "Battery
    Power:" sections even though the underlying setting isn't actually
    per-power-source, so the first occurrence wins, mirroring `native`'s
    own dict-write dedup -- a duplicate activation script for the same
    setting must be prevented exactly like the duplicate comment was.
    """
    result = item.result
    if result.nix_path in _POWER_HARDWARE_DEPENDENT_NIX_PATHS:
        if result.nix_path in reported_hardware_dependent_paths:
            return
        reported_hardware_dependent_paths.add(result.nix_path)
        coerced = _coerce_hardware_dependent_setting(item.value)
        if coerced is None:
            manual_report_comments.append(
                f"[hardware-dependent] manual report: {result.nix_path} (scanned value {item.value!r}) "
                "not applied -- value could not be safely coerced to on/off. Verify with "
                "`systemsetup -get...` on the target Mac and set manually if supported."
            )
            return
        if result.nix_path == "power.restartAfterPowerFailure":
            key, script = "restart_after_power_failure", _build_restart_after_power_failure_activation_script(coerced)
        else:
            key, script = "wake_on_lan", _build_wake_on_lan_activation_script(coerced)
        activation_scripts[key] = script
        return
    if result.nix_path is not None:
        value = result.coercion(item.value) if result.coercion else item.value
        value = _coerce_power_native_value(result.nix_path, value)
        native[result.nix_path] = value


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

    `activation_scripts` is keyed by an internal dedup identifier only
    (never a real Nix attribute name -- nix-darwin's own activation-scripts.nix
    module only ever concatenates a fixed, hardcoded set of named entries
    into the script `darwin-rebuild switch` actually runs; an arbitrary
    custom key like "mac2nixWallpaper" is valid Nix and builds successfully
    but is silently never executed, confirmed via a real Tart-VM switch and
    nix-darwin's own GitHub issue #663). Every body collected here gets
    combined into the one real hook, `system.activationScripts.postActivation`,
    by `nix_post_activation_script()` at the end of this function. Dict-keying
    dedupes the same way `native` does, and iterating
    `sorted(activation_scripts.items())` keeps render order deterministic.
    """
    native: dict[str, Any] = {}
    custom_user_prefs: dict[str, dict[str, Any]] = {}
    custom_system_prefs: dict[str, dict[str, Any]] = {}
    activation_scripts: dict[str, str] = {}
    manual_report_comments: list[str] = []
    reported_hardware_dependent_paths: set[str] = set()
    wallpaper_asset: WallpaperAsset | None = None

    for item in items:
        result = item.result
        metadata = result.metadata or {}

        if result.tier == ClassificationTier.NATIVE:
            _handle_native_item(
                item, reported_hardware_dependent_paths, native, activation_scripts, manual_report_comments
            )
        elif result.tier == ClassificationTier.CUSTOM_PREFS:
            if item.domain is None or item.key is None:
                # Every CUSTOM_PREFS item this generator produces is
                # preference-sourced (classify_system_setting/classify_wallpaper
                # never return CUSTOM_PREFS) -- defensive, not expected.
                continue
            bucket = custom_user_prefs if result.destination == "CustomUserPreferences" else custom_system_prefs
            bucket.setdefault(item.domain, {})[item.key] = item.value
        elif result.tier == ClassificationTier.ACTIVATION_SCRIPT:
            script, asset, comment = _render_activation_script_item(result, metadata)
            if script is not None:
                activation_scripts["wallpaper"] = script
            if asset is not None:
                wallpaper_asset = asset
            if comment is not None:
                manual_report_comments.append(comment)
        else:
            _handle_manual_report_item(item, activation_scripts, manual_report_comments)

    # A real, confirmed-on-hardware case: pmset reports some keys (e.g.
    # "hibernatemode") under both "AC Power:" and "Battery Power:" with
    # different values, but classify_system_setting()'s MANUAL_REPORT
    # destination string for an unmapped field doesn't include the value --
    # so two source-prefixed keys for the same unmapped field produce two
    # identical comment strings. dict.fromkeys() dedupes exact-duplicate
    # strings while preserving first-occurrence order.
    manual_report_comments = list(dict.fromkeys(manual_report_comments))

    post_activation_script = (
        nix_post_activation_script([body for _, body in sorted(activation_scripts.items())])
        if activation_scripts
        else None
    )

    return {
        "native_items": [{"nix_path": path, "value": value} for path, value in sorted(native.items())],
        "custom_user_prefs": custom_user_prefs,
        "custom_system_prefs": custom_system_prefs,
        "post_activation_script": post_activation_script,
        "manual_report_comments": manual_report_comments,
        "wallpaper_asset": wallpaper_asset,
    }


@dataclass(frozen=True, slots=True)
class GeneratePreferencesResult:
    """Result of `generate_preferences()`: rendered Nix source plus an optional
    bundled wallpaper asset.
    """

    rendered: str
    asset: WallpaperAsset | None = None


def generate_preferences(system_state: SystemState) -> GeneratePreferencesResult:
    """Render the curated preferences.nix module from one host's scan.

    Returns rendered Nix source text (plus an optional bundled wallpaper
    asset) -- it does not write anything itself; `generate_all()` owns file
    I/O.
    """
    if system_state.preferences is None or system_state.system is None:
        return GeneratePreferencesResult(rendered=_EMPTY_MODULE)

    items = _collect_preference_items(system_state.preferences.domains)
    items.extend(_collect_power_items(system_state.system.power_settings))

    if system_state.system.wallpaper_path is not None:
        wallpaper_result = classify_wallpaper(system_state.system.wallpaper_path)
        items.append(_CuratedItem(value=system_state.system.wallpaper_path, result=wallpaper_result))

    context = _build_render_context(items)
    asset = context.pop("wallpaper_asset")

    if system_state.system.wallpaper_scan_error is not None:
        context["manual_report_comments"].append(
            f"[coverage gap] wallpaper: {system_state.system.wallpaper_scan_error}"
        )

    rendered = render_template(_TEMPLATE_NAME, context)
    return GeneratePreferencesResult(rendered=rendered, asset=asset)
