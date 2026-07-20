"""Mapping of macOS `defaults` domain/key pairs to typed nix-darwin `system.defaults.*` options.

Source data transcribed from hack/research/feat-research-1746313200-nix-darwin-defaults-mapping.md
(197 typed options across 20 nix-darwin modules, as of that research pass).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class NixOption:
    """A single nix-darwin option mapping for one macOS defaults (domain, key) pair."""

    nix_path: str
    nix_type: str
    coercion: Callable[[Any], Any] | None = None
    conditions: dict[str, Any] | None = None


# ──────────────────────────────────────────────
# Reverse coercion lookup tables + factory
# ──────────────────────────────────────────────
# Pattern 1 (floatWithDeprecationError) and pattern 5 (path-to-string) require no
# python-side transform going scanner-value -> nix-value: coercion=None (identity).
# Pattern 6 (complex struct) is marked non-mappable via `conditions`, not a coercion.
# Patterns 2-4 below need an actual reverse lookup, implemented via a shared factory.

_CONTROLCENTER_BOOL_REVERSE: dict[int, bool] = {18: True, 24: False}

_HITOOLBOX_FN_REVERSE: dict[int, str] = {
    0: "Do Nothing",
    1: "Change Input Source",
    2: "Show Emoji & Symbols",
    3: "Start Dictation",
}

_ICAL_DAY_REVERSE: dict[int, str] = {
    0: "System Setting",
    1: "Sunday",
    2: "Monday",
    3: "Tuesday",
    4: "Wednesday",
    5: "Thursday",
    6: "Friday",
    7: "Saturday",
}

_FINDER_WINDOW_TARGET_REVERSE: dict[str, str] = {
    "PfCm": "Computer",
    "PfVo": "OS volume",
    "PfHm": "Home",
    "PfDe": "Desktop",
    "PfDo": "Documents",
    "PfAF": "Recents",
    "PfID": "iCloud Drive",
    "PfLo": "Other",
}


def _reverse_lookup_factory(table: dict[Any, Any]) -> Callable[[Any], Any]:
    """Build a coercion callable that reverses a scanned value via a lookup table.

    Falls back to the original value when the scanned value isn't in the table
    (e.g. a future macOS release changes the underlying encoding).
    """

    def _reverse(value: Any) -> Any:
        return table.get(value, value)

    return _reverse


# Pattern 2: bool-to-int (controlcenter apply: true->18, false->24)
reverse_controlcenter_bool = _reverse_lookup_factory(_CONTROLCENTER_BOOL_REVERSE)

# Pattern 3: enum-to-int (hitoolbox AppleFnUsageType, iCal first-day-of-week)
reverse_hitoolbox_fn_usage_type = _reverse_lookup_factory(_HITOOLBOX_FN_REVERSE)
reverse_ical_first_day_of_week = _reverse_lookup_factory(_ICAL_DAY_REVERSE)

# Pattern 4: enum-to-string-code (finder NewWindowTarget: PfCm/PfHm/etc.)
reverse_finder_new_window_target = _reverse_lookup_factory(_FINDER_WINDOW_TARGET_REVERSE)


# ──────────────────────────────────────────────
# Raw mapping, grouped by domain for readability/transcription fidelity.
# Flattened into DEFAULTS_TO_NIX below.
# ──────────────────────────────────────────────

_RAW: dict[str, dict[str, NixOption]] = {
    # ── dock (com.apple.dock) — 33 options ──────
    "com.apple.dock": {
        "appswitcher-all-displays": NixOption("system.defaults.dock.appswitcher-all-displays", "bool"),
        "autohide": NixOption("system.defaults.dock.autohide", "bool"),
        "autohide-delay": NixOption("system.defaults.dock.autohide-delay", "float"),
        "autohide-time-modifier": NixOption("system.defaults.dock.autohide-time-modifier", "float"),
        "dashboard-in-overlay": NixOption("system.defaults.dock.dashboard-in-overlay", "bool"),
        "enable-spring-load-actions-on-all-items": NixOption(
            "system.defaults.dock.enable-spring-load-actions-on-all-items", "bool"
        ),
        "expose-animation-duration": NixOption("system.defaults.dock.expose-animation-duration", "float"),
        "expose-group-apps": NixOption("system.defaults.dock.expose-group-apps", "bool"),
        "launchanim": NixOption("system.defaults.dock.launchanim", "bool"),
        "mineffect": NixOption("system.defaults.dock.mineffect", "enum:genie|suck|scale"),
        "minimize-to-application": NixOption("system.defaults.dock.minimize-to-application", "bool"),
        "mouse-over-hilite-stack": NixOption("system.defaults.dock.mouse-over-hilite-stack", "bool"),
        "mru-spaces": NixOption("system.defaults.dock.mru-spaces", "bool"),
        "orientation": NixOption("system.defaults.dock.orientation", "enum:bottom|left|right"),
        # Complex struct pattern (6): not directly mappable, still registered so
        # get_unmapped_keys() doesn't treat these as unmapped. tier_override signals
        # a future classifier to route straight to Tier 2 despite having a nix_path.
        "persistent-apps": NixOption(
            "system.defaults.dock.persistent-apps", "complex", conditions={"tier_override": 2}
        ),
        "persistent-others": NixOption(
            "system.defaults.dock.persistent-others", "complex", conditions={"tier_override": 2}
        ),
        "scroll-to-open": NixOption("system.defaults.dock.scroll-to-open", "bool"),
        "show-process-indicators": NixOption("system.defaults.dock.show-process-indicators", "bool"),
        "show-recents": NixOption("system.defaults.dock.show-recents", "bool"),
        "showAppExposeGestureEnabled": NixOption("system.defaults.dock.showAppExposeGestureEnabled", "bool"),
        "showDesktopGestureEnabled": NixOption("system.defaults.dock.showDesktopGestureEnabled", "bool"),
        "showLaunchpadGestureEnabled": NixOption("system.defaults.dock.showLaunchpadGestureEnabled", "bool"),
        "showMissionControlGestureEnabled": NixOption("system.defaults.dock.showMissionControlGestureEnabled", "bool"),
        "showhidden": NixOption("system.defaults.dock.showhidden", "bool"),
        "slow-motion-allowed": NixOption("system.defaults.dock.slow-motion-allowed", "bool"),
        "static-only": NixOption("system.defaults.dock.static-only", "bool"),
        "tilesize": NixOption("system.defaults.dock.tilesize", "int"),
        "magnification": NixOption("system.defaults.dock.magnification", "bool"),
        "largesize": NixOption("system.defaults.dock.largesize", "bounded_int:16-128"),
        "wvous-tl-corner": NixOption("system.defaults.dock.wvous-tl-corner", "positive_int"),
        "wvous-bl-corner": NixOption("system.defaults.dock.wvous-bl-corner", "positive_int"),
        "wvous-tr-corner": NixOption("system.defaults.dock.wvous-tr-corner", "positive_int"),
        "wvous-br-corner": NixOption("system.defaults.dock.wvous-br-corner", "positive_int"),
    },
    # ── NSGlobalDomain — 53 options ─────────────
    # Also reachable via ".GlobalPreferences" (disk plist domain name) — see DOMAIN_ALIASES.
    "NSGlobalDomain": {
        "AppleShowAllFiles": NixOption("system.defaults.NSGlobalDomain.AppleShowAllFiles", "bool"),
        "AppleEnableMouseSwipeNavigateWithScrolls": NixOption(
            "system.defaults.NSGlobalDomain.AppleEnableMouseSwipeNavigateWithScrolls", "bool"
        ),
        "AppleEnableSwipeNavigateWithScrolls": NixOption(
            "system.defaults.NSGlobalDomain.AppleEnableSwipeNavigateWithScrolls", "bool"
        ),
        "AppleFontSmoothing": NixOption("system.defaults.NSGlobalDomain.AppleFontSmoothing", "enum_int:0|1|2"),
        "AppleInterfaceStyle": NixOption("system.defaults.NSGlobalDomain.AppleInterfaceStyle", "enum:Dark"),
        "AppleIconAppearanceTheme": NixOption(
            "system.defaults.NSGlobalDomain.AppleIconAppearanceTheme",
            "enum:RegularDark|RegularAutomatic|ClearLight|ClearDark|ClearAutomatic|TintedLight|TintedDark|TintedAutomatic",
        ),
        "AppleInterfaceStyleSwitchesAutomatically": NixOption(
            "system.defaults.NSGlobalDomain.AppleInterfaceStyleSwitchesAutomatically", "bool"
        ),
        "AppleKeyboardUIMode": NixOption("system.defaults.NSGlobalDomain.AppleKeyboardUIMode", "enum_int:0|2|3"),
        "ApplePressAndHoldEnabled": NixOption("system.defaults.NSGlobalDomain.ApplePressAndHoldEnabled", "bool"),
        "AppleShowAllExtensions": NixOption("system.defaults.NSGlobalDomain.AppleShowAllExtensions", "bool"),
        "AppleShowScrollBars": NixOption(
            "system.defaults.NSGlobalDomain.AppleShowScrollBars", "enum:WhenScrolling|Automatic|Always"
        ),
        "AppleScrollerPagingBehavior": NixOption("system.defaults.NSGlobalDomain.AppleScrollerPagingBehavior", "bool"),
        "AppleSpacesSwitchOnActivate": NixOption("system.defaults.NSGlobalDomain.AppleSpacesSwitchOnActivate", "bool"),
        "NSAutomaticCapitalizationEnabled": NixOption(
            "system.defaults.NSGlobalDomain.NSAutomaticCapitalizationEnabled", "bool"
        ),
        "NSAutomaticInlinePredictionEnabled": NixOption(
            "system.defaults.NSGlobalDomain.NSAutomaticInlinePredictionEnabled", "bool"
        ),
        "NSAutomaticDashSubstitutionEnabled": NixOption(
            "system.defaults.NSGlobalDomain.NSAutomaticDashSubstitutionEnabled", "bool"
        ),
        "NSAutomaticPeriodSubstitutionEnabled": NixOption(
            "system.defaults.NSGlobalDomain.NSAutomaticPeriodSubstitutionEnabled", "bool"
        ),
        "NSAutomaticQuoteSubstitutionEnabled": NixOption(
            "system.defaults.NSGlobalDomain.NSAutomaticQuoteSubstitutionEnabled", "bool"
        ),
        "NSAutomaticSpellingCorrectionEnabled": NixOption(
            "system.defaults.NSGlobalDomain.NSAutomaticSpellingCorrectionEnabled", "bool"
        ),
        "NSAutomaticWindowAnimationsEnabled": NixOption(
            "system.defaults.NSGlobalDomain.NSAutomaticWindowAnimationsEnabled", "bool"
        ),
        "NSDisableAutomaticTermination": NixOption(
            "system.defaults.NSGlobalDomain.NSDisableAutomaticTermination", "bool"
        ),
        "NSDocumentSaveNewDocumentsToCloud": NixOption(
            "system.defaults.NSGlobalDomain.NSDocumentSaveNewDocumentsToCloud", "bool"
        ),
        "AppleWindowTabbingMode": NixOption(
            "system.defaults.NSGlobalDomain.AppleWindowTabbingMode", "enum:manual|always|fullscreen"
        ),
        "NSNavPanelExpandedStateForSaveMode": NixOption(
            "system.defaults.NSGlobalDomain.NSNavPanelExpandedStateForSaveMode", "bool"
        ),
        "NSNavPanelExpandedStateForSaveMode2": NixOption(
            "system.defaults.NSGlobalDomain.NSNavPanelExpandedStateForSaveMode2", "bool"
        ),
        "NSTableViewDefaultSizeMode": NixOption(
            "system.defaults.NSGlobalDomain.NSTableViewDefaultSizeMode", "enum_int:1|2|3"
        ),
        "NSTextShowsControlCharacters": NixOption(
            "system.defaults.NSGlobalDomain.NSTextShowsControlCharacters", "bool"
        ),
        "NSUseAnimatedFocusRing": NixOption("system.defaults.NSGlobalDomain.NSUseAnimatedFocusRing", "bool"),
        "NSScrollAnimationEnabled": NixOption("system.defaults.NSGlobalDomain.NSScrollAnimationEnabled", "bool"),
        "NSWindowResizeTime": NixOption("system.defaults.NSGlobalDomain.NSWindowResizeTime", "float"),
        "NSWindowShouldDragOnGesture": NixOption("system.defaults.NSGlobalDomain.NSWindowShouldDragOnGesture", "bool"),
        "NSStatusItemSpacing": NixOption("system.defaults.NSGlobalDomain.NSStatusItemSpacing", "int"),
        "NSStatusItemSelectionPadding": NixOption("system.defaults.NSGlobalDomain.NSStatusItemSelectionPadding", "int"),
        "InitialKeyRepeat": NixOption("system.defaults.NSGlobalDomain.InitialKeyRepeat", "int"),
        "KeyRepeat": NixOption("system.defaults.NSGlobalDomain.KeyRepeat", "int"),
        "PMPrintingExpandedStateForPrint": NixOption(
            "system.defaults.NSGlobalDomain.PMPrintingExpandedStateForPrint", "bool"
        ),
        "PMPrintingExpandedStateForPrint2": NixOption(
            "system.defaults.NSGlobalDomain.PMPrintingExpandedStateForPrint2", "bool"
        ),
        "com.apple.keyboard.fnState": NixOption('system.defaults.NSGlobalDomain."com.apple.keyboard.fnState"', "bool"),
        "com.apple.mouse.tapBehavior": NixOption(
            'system.defaults.NSGlobalDomain."com.apple.mouse.tapBehavior"', "enum_int:1"
        ),
        "com.apple.sound.beep.volume": NixOption(
            'system.defaults.NSGlobalDomain."com.apple.sound.beep.volume"', "float"
        ),
        "com.apple.sound.beep.feedback": NixOption(
            'system.defaults.NSGlobalDomain."com.apple.sound.beep.feedback"', "int"
        ),
        "com.apple.trackpad.enableSecondaryClick": NixOption(
            'system.defaults.NSGlobalDomain."com.apple.trackpad.enableSecondaryClick"', "bool"
        ),
        "com.apple.trackpad.trackpadCornerClickBehavior": NixOption(
            'system.defaults.NSGlobalDomain."com.apple.trackpad.trackpadCornerClickBehavior"', "enum_int:1"
        ),
        "com.apple.trackpad.scaling": NixOption('system.defaults.NSGlobalDomain."com.apple.trackpad.scaling"', "float"),
        "com.apple.trackpad.forceClick": NixOption(
            'system.defaults.NSGlobalDomain."com.apple.trackpad.forceClick"', "bool"
        ),
        "com.apple.springing.enabled": NixOption(
            'system.defaults.NSGlobalDomain."com.apple.springing.enabled"', "bool"
        ),
        "com.apple.springing.delay": NixOption('system.defaults.NSGlobalDomain."com.apple.springing.delay"', "float"),
        "com.apple.swipescrolldirection": NixOption(
            'system.defaults.NSGlobalDomain."com.apple.swipescrolldirection"', "bool"
        ),
        "AppleMeasurementUnits": NixOption(
            "system.defaults.NSGlobalDomain.AppleMeasurementUnits", "enum:Centimeters|Inches"
        ),
        "AppleMetricUnits": NixOption("system.defaults.NSGlobalDomain.AppleMetricUnits", "enum_int:0|1"),
        "AppleTemperatureUnit": NixOption(
            "system.defaults.NSGlobalDomain.AppleTemperatureUnit", "enum:Celsius|Fahrenheit"
        ),
        "AppleICUForce24HourTime": NixOption("system.defaults.NSGlobalDomain.AppleICUForce24HourTime", "bool"),
        "_HIHideMenuBar": NixOption("system.defaults.NSGlobalDomain._HIHideMenuBar", "bool"),
    },
    # ── finder (com.apple.finder) — 20 options ──
    "com.apple.finder": {
        "AppleShowAllFiles": NixOption("system.defaults.finder.AppleShowAllFiles", "bool"),
        "ShowStatusBar": NixOption("system.defaults.finder.ShowStatusBar", "bool"),
        "ShowPathbar": NixOption("system.defaults.finder.ShowPathbar", "bool"),
        "FXDefaultSearchScope": NixOption("system.defaults.finder.FXDefaultSearchScope", "str"),
        "FXRemoveOldTrashItems": NixOption("system.defaults.finder.FXRemoveOldTrashItems", "bool"),
        "FXPreferredViewStyle": NixOption("system.defaults.finder.FXPreferredViewStyle", "str"),
        "AppleShowAllExtensions": NixOption("system.defaults.finder.AppleShowAllExtensions", "bool"),
        "CreateDesktop": NixOption("system.defaults.finder.CreateDesktop", "bool"),
        "QuitMenuItem": NixOption("system.defaults.finder.QuitMenuItem", "bool"),
        "ShowExternalHardDrivesOnDesktop": NixOption("system.defaults.finder.ShowExternalHardDrivesOnDesktop", "bool"),
        "ShowHardDrivesOnDesktop": NixOption("system.defaults.finder.ShowHardDrivesOnDesktop", "bool"),
        "ShowMountedServersOnDesktop": NixOption("system.defaults.finder.ShowMountedServersOnDesktop", "bool"),
        "ShowRemovableMediaOnDesktop": NixOption("system.defaults.finder.ShowRemovableMediaOnDesktop", "bool"),
        "_FXEnableColumnAutoSizing": NixOption("system.defaults.finder._FXEnableColumnAutoSizing", "bool"),
        "_FXShowPosixPathInTitle": NixOption("system.defaults.finder._FXShowPosixPathInTitle", "bool"),
        "_FXSortFoldersFirst": NixOption("system.defaults.finder._FXSortFoldersFirst", "bool"),
        "_FXSortFoldersFirstOnDesktop": NixOption("system.defaults.finder._FXSortFoldersFirstOnDesktop", "bool"),
        "FXEnableExtensionChangeWarning": NixOption("system.defaults.finder.FXEnableExtensionChangeWarning", "bool"),
        # Pattern 4: enum-to-string-code — scanner reads the 4-char code, reverse to label.
        "NewWindowTarget": NixOption(
            "system.defaults.finder.NewWindowTarget",
            "enum:Computer|OS volume|Home|Desktop|Documents|Recents|iCloud Drive|Other",
            coercion=reverse_finder_new_window_target,
        ),
        # Only meaningful when NewWindowTarget == "Other" — documented interdependency.
        "NewWindowTargetPath": NixOption(
            "system.defaults.finder.NewWindowTargetPath",
            "str",
            conditions={"requires": {"NewWindowTarget": "Other"}},
        ),
    },
    # ── trackpad (primary domain) — 22 options ──
    # com.apple.driver.AppleBluetoothMultitouch.trackpad writes the same keys to the
    # same nix options — handled via DOMAIN_ALIASES rather than duplicating entries.
    "com.apple.AppleMultitouchTrackpad": {
        "Clicking": NixOption("system.defaults.trackpad.Clicking", "bool"),
        "Dragging": NixOption("system.defaults.trackpad.Dragging", "bool"),
        "TrackpadRightClick": NixOption("system.defaults.trackpad.TrackpadRightClick", "bool"),
        "TrackpadThreeFingerDrag": NixOption("system.defaults.trackpad.TrackpadThreeFingerDrag", "bool"),
        "ActuationStrength": NixOption("system.defaults.trackpad.ActuationStrength", "enum_int:0|1"),
        "FirstClickThreshold": NixOption("system.defaults.trackpad.FirstClickThreshold", "enum_int:0|1|2"),
        "SecondClickThreshold": NixOption("system.defaults.trackpad.SecondClickThreshold", "enum_int:0|1|2"),
        "TrackpadThreeFingerTapGesture": NixOption(
            "system.defaults.trackpad.TrackpadThreeFingerTapGesture", "enum_int:0|2"
        ),
        "ActuateDetents": NixOption("system.defaults.trackpad.ActuateDetents", "bool"),
        "DragLock": NixOption("system.defaults.trackpad.DragLock", "bool"),
        "ForceSuppressed": NixOption("system.defaults.trackpad.ForceSuppressed", "bool"),
        "TrackpadCornerSecondaryClick": NixOption(
            "system.defaults.trackpad.TrackpadCornerSecondaryClick", "enum_int:0|1|2"
        ),
        "TrackpadFourFingerHorizSwipeGesture": NixOption(
            "system.defaults.trackpad.TrackpadFourFingerHorizSwipeGesture", "enum_int:0|2"
        ),
        "TrackpadFourFingerPinchGesture": NixOption(
            "system.defaults.trackpad.TrackpadFourFingerPinchGesture", "enum_int:0|2"
        ),
        "TrackpadFourFingerVertSwipeGesture": NixOption(
            "system.defaults.trackpad.TrackpadFourFingerVertSwipeGesture", "enum_int:0|2"
        ),
        "TrackpadMomentumScroll": NixOption("system.defaults.trackpad.TrackpadMomentumScroll", "bool"),
        "TrackpadPinch": NixOption("system.defaults.trackpad.TrackpadPinch", "bool"),
        "TrackpadRotate": NixOption("system.defaults.trackpad.TrackpadRotate", "bool"),
        "TrackpadThreeFingerHorizSwipeGesture": NixOption(
            "system.defaults.trackpad.TrackpadThreeFingerHorizSwipeGesture", "enum_int:0|1|2"
        ),
        "TrackpadThreeFingerVertSwipeGesture": NixOption(
            "system.defaults.trackpad.TrackpadThreeFingerVertSwipeGesture", "enum_int:0|2"
        ),
        "TrackpadTwoFingerDoubleTapGesture": NixOption(
            "system.defaults.trackpad.TrackpadTwoFingerDoubleTapGesture", "bool"
        ),
        "TrackpadTwoFingerFromRightEdgeSwipeGesture": NixOption(
            "system.defaults.trackpad.TrackpadTwoFingerFromRightEdgeSwipeGesture", "enum_int:0|3"
        ),
    },
    # ── loginwindow (com.apple.loginwindow) — 11 options ──
    "com.apple.loginwindow": {
        "SHOWFULLNAME": NixOption("system.defaults.loginwindow.SHOWFULLNAME", "bool"),
        "autoLoginUser": NixOption("system.defaults.loginwindow.autoLoginUser", "str"),
        "GuestEnabled": NixOption("system.defaults.loginwindow.GuestEnabled", "bool"),
        "LoginwindowText": NixOption("system.defaults.loginwindow.LoginwindowText", "str"),
        "ShutDownDisabled": NixOption("system.defaults.loginwindow.ShutDownDisabled", "bool"),
        "SleepDisabled": NixOption("system.defaults.loginwindow.SleepDisabled", "bool"),
        "RestartDisabled": NixOption("system.defaults.loginwindow.RestartDisabled", "bool"),
        "ShutDownDisabledWhileLoggedIn": NixOption("system.defaults.loginwindow.ShutDownDisabledWhileLoggedIn", "bool"),
        "PowerOffDisabledWhileLoggedIn": NixOption("system.defaults.loginwindow.PowerOffDisabledWhileLoggedIn", "bool"),
        "RestartDisabledWhileLoggedIn": NixOption("system.defaults.loginwindow.RestartDisabledWhileLoggedIn", "bool"),
        "DisableConsoleAccess": NixOption("system.defaults.loginwindow.DisableConsoleAccess", "bool"),
    },
    # ── controlcenter (com.apple.controlcenter) — 7 options ──
    # ByHost domain: scanner may report "com.apple.controlcenter.<hardware-uuid>" — see
    # _strip_byhost_suffix(), used internally by get_nix_option().
    "com.apple.controlcenter": {
        "BatteryShowPercentage": NixOption("system.defaults.controlcenter.BatteryShowPercentage", "bool"),
        # Pattern 2: bool-to-int — scanner reads 18/24, reverse to bool.
        "Sound": NixOption("system.defaults.controlcenter.Sound", "bool", coercion=reverse_controlcenter_bool),
        "Bluetooth": NixOption("system.defaults.controlcenter.Bluetooth", "bool", coercion=reverse_controlcenter_bool),
        "AirDrop": NixOption("system.defaults.controlcenter.AirDrop", "bool", coercion=reverse_controlcenter_bool),
        "Display": NixOption("system.defaults.controlcenter.Display", "bool", coercion=reverse_controlcenter_bool),
        "FocusModes": NixOption(
            "system.defaults.controlcenter.FocusModes", "bool", coercion=reverse_controlcenter_bool
        ),
        "NowPlaying": NixOption(
            "system.defaults.controlcenter.NowPlaying", "bool", coercion=reverse_controlcenter_bool
        ),
    },
    # ── WindowManager (com.apple.WindowManager) — 12 options ──
    "com.apple.WindowManager": {
        "GloballyEnabled": NixOption("system.defaults.WindowManager.GloballyEnabled", "bool"),
        "EnableStandardClickToShowDesktop": NixOption(
            "system.defaults.WindowManager.EnableStandardClickToShowDesktop", "bool"
        ),
        "AutoHide": NixOption("system.defaults.WindowManager.AutoHide", "bool"),
        "AppWindowGroupingBehavior": NixOption("system.defaults.WindowManager.AppWindowGroupingBehavior", "bool"),
        "StandardHideDesktopIcons": NixOption("system.defaults.WindowManager.StandardHideDesktopIcons", "bool"),
        "HideDesktop": NixOption("system.defaults.WindowManager.HideDesktop", "bool"),
        "EnableTilingByEdgeDrag": NixOption("system.defaults.WindowManager.EnableTilingByEdgeDrag", "bool"),
        "EnableTopTilingByEdgeDrag": NixOption("system.defaults.WindowManager.EnableTopTilingByEdgeDrag", "bool"),
        "EnableTilingOptionAccelerator": NixOption(
            "system.defaults.WindowManager.EnableTilingOptionAccelerator", "bool"
        ),
        "EnableTiledWindowMargins": NixOption("system.defaults.WindowManager.EnableTiledWindowMargins", "bool"),
        "StandardHideWidgets": NixOption("system.defaults.WindowManager.StandardHideWidgets", "bool"),
        "StageManagerHideWidgets": NixOption("system.defaults.WindowManager.StageManagerHideWidgets", "bool"),
    },
    # ── ActivityMonitor (com.apple.ActivityMonitor) — 5 options ──
    "com.apple.ActivityMonitor": {
        "ShowCategory": NixOption(
            "system.defaults.ActivityMonitor.ShowCategory", "enum_int:100|101|102|103|104|105|106|107"
        ),
        "IconType": NixOption("system.defaults.ActivityMonitor.IconType", "int"),
        "SortColumn": NixOption("system.defaults.ActivityMonitor.SortColumn", "str"),
        "SortDirection": NixOption("system.defaults.ActivityMonitor.SortDirection", "int"),
        "OpenMainWindow": NixOption("system.defaults.ActivityMonitor.OpenMainWindow", "bool"),
    },
    # ── universalaccess (com.apple.universalaccess) — 5 options ──
    "com.apple.universalaccess": {
        "mouseDriverCursorSize": NixOption("system.defaults.universalaccess.mouseDriverCursorSize", "float"),
        "reduceMotion": NixOption("system.defaults.universalaccess.reduceMotion", "bool"),
        "reduceTransparency": NixOption("system.defaults.universalaccess.reduceTransparency", "bool"),
        "closeViewScrollWheelToggle": NixOption("system.defaults.universalaccess.closeViewScrollWheelToggle", "bool"),
        "closeViewZoomFollowsFocus": NixOption("system.defaults.universalaccess.closeViewZoomFollowsFocus", "bool"),
    },
    # ── iCal (com.apple.iCal) — 3 options ──
    "com.apple.iCal": {
        # Pattern 3: enum-to-int — scanner reads int 0-7, reverse to day-of-week string.
        "first day of week": NixOption(
            'system.defaults.iCal."first day of week"',
            "enum:System Setting|Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday",
            coercion=reverse_ical_first_day_of_week,
        ),
        "CalendarSidebarShown": NixOption("system.defaults.iCal.CalendarSidebarShown", "bool"),
        "TimeZone support enabled": NixOption('system.defaults.iCal."TimeZone support enabled"', "bool"),
    },
    # ── screencapture (com.apple.screencapture) — 7 options ──
    "com.apple.screencapture": {
        "location": NixOption("system.defaults.screencapture.location", "str"),
        "type": NixOption("system.defaults.screencapture.type", "str"),
        "disable-shadow": NixOption("system.defaults.screencapture.disable-shadow", "bool"),
        "include-date": NixOption("system.defaults.screencapture.include-date", "bool"),
        "save-selections": NixOption("system.defaults.screencapture.save-selections", "bool"),
        "show-thumbnail": NixOption("system.defaults.screencapture.show-thumbnail", "bool"),
        "target": NixOption("system.defaults.screencapture.target", "enum:file|clipboard|preview|mail|messages"),
    },
    # ── menuExtraClock (com.apple.menuextra.clock) — 8 options ──
    "com.apple.menuextra.clock": {
        "FlashDateSeparators": NixOption("system.defaults.menuExtraClock.FlashDateSeparators", "bool"),
        "IsAnalog": NixOption("system.defaults.menuExtraClock.IsAnalog", "bool"),
        "Show24Hour": NixOption("system.defaults.menuExtraClock.Show24Hour", "bool"),
        "ShowAMPM": NixOption("system.defaults.menuExtraClock.ShowAMPM", "bool"),
        "ShowDayOfMonth": NixOption("system.defaults.menuExtraClock.ShowDayOfMonth", "bool"),
        "ShowDayOfWeek": NixOption("system.defaults.menuExtraClock.ShowDayOfWeek", "bool"),
        "ShowDate": NixOption("system.defaults.menuExtraClock.ShowDate", "enum_int:0|1|2"),
        "ShowSeconds": NixOption("system.defaults.menuExtraClock.ShowSeconds", "bool"),
    },
    # ── .GlobalPreferences — 2 options ──
    # Distinct from NSGlobalDomain (dot-prefixed domain); aliased both ways in DOMAIN_ALIASES.
    ".GlobalPreferences": {
        # Pattern 5: path-to-string — identity, no python-side transform needed.
        "com.apple.sound.beep.sound": NixOption(
            'system.defaults.".GlobalPreferences"."com.apple.sound.beep.sound"', "path"
        ),
        "com.apple.mouse.scaling": NixOption('system.defaults.".GlobalPreferences"."com.apple.mouse.scaling"', "float"),
    },
    # ── HIToolbox (com.apple.HIToolbox) — 1 option ──
    "com.apple.HIToolbox": {
        # Pattern 3: enum-to-int — scanner reads int 0-3, reverse to label string.
        "AppleFnUsageType": NixOption(
            "system.defaults.hitoolbox.AppleFnUsageType",
            "enum:Do Nothing|Change Input Source|Show Emoji & Symbols|Start Dictation",
            coercion=reverse_hitoolbox_fn_usage_type,
        ),
    },
    # ── screensaver (com.apple.screensaver) — 2 options ──
    "com.apple.screensaver": {
        "askForPassword": NixOption("system.defaults.screensaver.askForPassword", "bool"),
        "askForPasswordDelay": NixOption("system.defaults.screensaver.askForPasswordDelay", "int"),
    },
    # ── spaces (com.apple.spaces) — 1 option ──
    "com.apple.spaces": {
        "spans-displays": NixOption("system.defaults.spaces.spans-displays", "bool"),
    },
    # ── smb (com.apple.smb.server) — 2 options ──
    "com.apple.smb.server": {
        "NetBIOSName": NixOption("system.defaults.smb.NetBIOSName", "str"),
        "ServerDescription": NixOption("system.defaults.smb.ServerDescription", "str"),
    },
    # ── magicmouse (primary domain) — 1 option ──
    # com.apple.driver.AppleMultitouchMouse.mouse writes the same key — see DOMAIN_ALIASES.
    "com.apple.AppleMultitouchMouse": {
        "MouseButtonMode": NixOption("system.defaults.magicmouse.MouseButtonMode", "enum:OneButton|TwoButton"),
    },
    # ── SoftwareUpdate (com.apple.SoftwareUpdate) — 1 option ──
    "com.apple.SoftwareUpdate": {
        "AutomaticallyInstallMacOSUpdates": NixOption(
            "system.defaults.SoftwareUpdate.AutomaticallyInstallMacOSUpdates", "bool"
        ),
    },
    # ── LaunchServices (com.apple.LaunchServices) — 1 option ──
    "com.apple.LaunchServices": {
        "LSQuarantine": NixOption("system.defaults.LaunchServices.LSQuarantine", "bool"),
    },
}


DEFAULTS_TO_NIX: dict[tuple[str, str], NixOption] = {
    (domain, key): option for domain, entries in _RAW.items() for key, option in entries.items()
}


# ──────────────────────────────────────────────
# Domain aliases: a scanned domain name that should also be looked up under a
# different canonical domain name (bidirectional where the alias's key set is
# a strict subset/superset of the canonical domain, e.g. NSGlobalDomain).
# ──────────────────────────────────────────────
DOMAIN_ALIASES: dict[str, str] = {
    # Scanner reads .GlobalPreferences.plist from disk; the cfprefsd fallback reports
    # NSGlobalDomain. Both bidirectional so either lookup falls back to the other.
    "NSGlobalDomain": ".GlobalPreferences",
    ".GlobalPreferences": "NSGlobalDomain",
    # trackpad / magicmouse write the same keys to two domains simultaneously.
    "com.apple.driver.AppleBluetoothMultitouch.trackpad": "com.apple.AppleMultitouchTrackpad",
    "com.apple.driver.AppleMultitouchMouse.mouse": "com.apple.AppleMultitouchMouse",
}


# ByHost preference files are named "<domain>.<hardware-uuid-or-mac-hex>.plist"; the
# scanner derives domain_name from the plist stem, so the suffix survives as part of
# the domain string. Strip a trailing hex/dash segment of 8+ characters to recover
# the canonical domain (e.g. "com.apple.controlcenter.F8DD5F35-...-D6D3").
_BYHOST_SUFFIX_RE = re.compile(r"\.[0-9A-Fa-f-]{8,}$")


def _strip_byhost_suffix(domain: str) -> str:
    return _BYHOST_SUFFIX_RE.sub("", domain)


def get_nix_option(domain: str, key: str) -> NixOption | None:
    """Look up the nix-darwin option for a scanned (domain, key) pair, resolving ByHost suffixes and aliases."""
    resolved = _strip_byhost_suffix(domain)

    option = DEFAULTS_TO_NIX.get((resolved, key))
    if option is not None:
        return option

    alias = DOMAIN_ALIASES.get(resolved)
    if alias is not None:
        return DEFAULTS_TO_NIX.get((alias, key))

    return None


def get_unmapped_keys(domain: str, keys: Iterable[str]) -> list[str]:
    """Return the subset of `keys` that have no nix-darwin mapping for `domain`."""
    return [key for key in keys if get_nix_option(domain, key) is None]
