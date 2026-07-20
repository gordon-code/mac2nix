"""Tests for defaults_to_nix mapping layer."""

from mac2nix.mappings.defaults_to_nix import (
    DEFAULTS_TO_NIX,
    DOMAIN_ALIASES,
    get_nix_option,
    get_unmapped_keys,
)


class TestSpotCheckPerCategory:
    """One representative option per major category, to catch transcription/keying errors."""

    def test_dock(self) -> None:
        option = get_nix_option("com.apple.dock", "autohide")
        assert option is not None
        assert option.nix_path == "system.defaults.dock.autohide"
        assert option.nix_type == "bool"

    def test_nsglobaldomain(self) -> None:
        option = get_nix_option("NSGlobalDomain", "AppleShowAllFiles")
        assert option is not None
        assert option.nix_path == "system.defaults.NSGlobalDomain.AppleShowAllFiles"

    def test_finder(self) -> None:
        option = get_nix_option("com.apple.finder", "ShowPathbar")
        assert option is not None
        assert option.nix_path == "system.defaults.finder.ShowPathbar"

    def test_trackpad(self) -> None:
        option = get_nix_option("com.apple.AppleMultitouchTrackpad", "Clicking")
        assert option is not None
        assert option.nix_path == "system.defaults.trackpad.Clicking"

    def test_loginwindow(self) -> None:
        option = get_nix_option("com.apple.loginwindow", "GuestEnabled")
        assert option is not None
        assert option.nix_path == "system.defaults.loginwindow.GuestEnabled"

    def test_controlcenter(self) -> None:
        option = get_nix_option("com.apple.controlcenter", "BatteryShowPercentage")
        assert option is not None
        assert option.nix_path == "system.defaults.controlcenter.BatteryShowPercentage"

    def test_windowmanager(self) -> None:
        option = get_nix_option("com.apple.WindowManager", "GloballyEnabled")
        assert option is not None
        assert option.nix_path == "system.defaults.WindowManager.GloballyEnabled"

    def test_activitymonitor(self) -> None:
        option = get_nix_option("com.apple.ActivityMonitor", "OpenMainWindow")
        assert option is not None
        assert option.nix_path == "system.defaults.ActivityMonitor.OpenMainWindow"

    def test_universalaccess(self) -> None:
        option = get_nix_option("com.apple.universalaccess", "reduceMotion")
        assert option is not None
        assert option.nix_path == "system.defaults.universalaccess.reduceMotion"

    def test_ical(self) -> None:
        option = get_nix_option("com.apple.iCal", "CalendarSidebarShown")
        assert option is not None
        assert option.nix_path == "system.defaults.iCal.CalendarSidebarShown"

    def test_screencapture(self) -> None:
        option = get_nix_option("com.apple.screencapture", "location")
        assert option is not None
        assert option.nix_path == "system.defaults.screencapture.location"

    def test_menu_extra_clock(self) -> None:
        option = get_nix_option("com.apple.menuextra.clock", "Show24Hour")
        assert option is not None
        assert option.nix_path == "system.defaults.menuExtraClock.Show24Hour"

    def test_global_preferences(self) -> None:
        option = get_nix_option(".GlobalPreferences", "com.apple.mouse.scaling")
        assert option is not None
        assert option.nix_path == 'system.defaults.".GlobalPreferences"."com.apple.mouse.scaling"'

    def test_hitoolbox(self) -> None:
        option = get_nix_option("com.apple.HIToolbox", "AppleFnUsageType")
        assert option is not None
        assert option.nix_path == "system.defaults.hitoolbox.AppleFnUsageType"

    def test_screensaver(self) -> None:
        option = get_nix_option("com.apple.screensaver", "askForPassword")
        assert option is not None
        assert option.nix_path == "system.defaults.screensaver.askForPassword"

    def test_spaces(self) -> None:
        option = get_nix_option("com.apple.spaces", "spans-displays")
        assert option is not None
        assert option.nix_path == "system.defaults.spaces.spans-displays"

    def test_smb(self) -> None:
        option = get_nix_option("com.apple.smb.server", "NetBIOSName")
        assert option is not None
        assert option.nix_path == "system.defaults.smb.NetBIOSName"

    def test_magicmouse(self) -> None:
        option = get_nix_option("com.apple.AppleMultitouchMouse", "MouseButtonMode")
        assert option is not None
        assert option.nix_path == "system.defaults.magicmouse.MouseButtonMode"

    def test_software_update(self) -> None:
        option = get_nix_option("com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates")
        assert option is not None
        assert option.nix_path == "system.defaults.SoftwareUpdate.AutomaticallyInstallMacOSUpdates"

    def test_launch_services(self) -> None:
        option = get_nix_option("com.apple.LaunchServices", "LSQuarantine")
        assert option is not None
        assert option.nix_path == "system.defaults.LaunchServices.LSQuarantine"


class TestCoercionPatterns:
    """One test per each of the 6 documented coercion patterns."""

    def test_pattern1_float_with_deprecation_error_is_identity(self) -> None:
        option = get_nix_option("com.apple.dock", "autohide-delay")
        assert option is not None
        assert option.nix_type == "float"
        assert option.coercion is None

    def test_pattern2_bool_to_int_reversal(self) -> None:
        option = get_nix_option("com.apple.controlcenter", "Sound")
        assert option is not None
        assert option.coercion is not None
        assert option.coercion(18) is True
        assert option.coercion(24) is False

    def test_pattern3_enum_to_int_reversal_hitoolbox(self) -> None:
        option = get_nix_option("com.apple.HIToolbox", "AppleFnUsageType")
        assert option is not None
        assert option.coercion is not None
        assert option.coercion(0) == "Do Nothing"
        assert option.coercion(3) == "Start Dictation"

    def test_pattern3_enum_to_int_reversal_ical(self) -> None:
        option = get_nix_option("com.apple.iCal", "first day of week")
        assert option is not None
        assert option.coercion is not None
        assert option.coercion(0) == "System Setting"
        assert option.coercion(1) == "Sunday"

    def test_pattern4_enum_to_string_code_reversal(self) -> None:
        option = get_nix_option("com.apple.finder", "NewWindowTarget")
        assert option is not None
        assert option.coercion is not None
        assert option.coercion("PfCm") == "Computer"
        assert option.coercion("PfHm") == "Home"

    def test_pattern5_path_to_string_is_identity(self) -> None:
        option = get_nix_option(".GlobalPreferences", "com.apple.sound.beep.sound")
        assert option is not None
        assert option.nix_type == "path"
        assert option.coercion is None

    def test_pattern6_complex_struct_marked_not_directly_mappable(self) -> None:
        option = get_nix_option("com.apple.dock", "persistent-apps")
        assert option is not None
        assert option.nix_type == "complex"
        assert option.coercion is None
        assert option.conditions == {"tier_override": 2}

    def test_unknown_reverse_value_falls_back_to_original(self) -> None:
        option = get_nix_option("com.apple.controlcenter", "Sound")
        assert option is not None
        assert option.coercion is not None
        assert option.coercion(999) == 999


class TestConditions:
    def test_finder_new_window_target_path_requires_other(self) -> None:
        option = get_nix_option("com.apple.finder", "NewWindowTargetPath")
        assert option is not None
        assert option.conditions == {"requires": {"NewWindowTarget": "Other"}}


class TestDomainAliasResolution:
    def test_nsglobaldomain_to_globalpreferences_direct(self) -> None:
        option = get_nix_option("NSGlobalDomain", "AppleShowAllFiles")
        assert option is not None
        assert option.nix_path == "system.defaults.NSGlobalDomain.AppleShowAllFiles"

    def test_globalpreferences_resolves_nsglobaldomain_key_via_alias(self) -> None:
        # Not a direct entry under ".GlobalPreferences" — must fall back via DOMAIN_ALIASES.
        option = get_nix_option(".GlobalPreferences", "AppleShowAllFiles")
        assert option is not None
        assert option.nix_path == "system.defaults.NSGlobalDomain.AppleShowAllFiles"

    def test_nsglobaldomain_resolves_globalpreferences_key_via_alias(self) -> None:
        # Not a direct entry under "NSGlobalDomain" — must fall back via DOMAIN_ALIASES.
        option = get_nix_option("NSGlobalDomain", "com.apple.mouse.scaling")
        assert option is not None
        assert option.nix_path == 'system.defaults.".GlobalPreferences"."com.apple.mouse.scaling"'

    def test_trackpad_bluetooth_domain_aliases_to_primary(self) -> None:
        primary = get_nix_option("com.apple.AppleMultitouchTrackpad", "Clicking")
        aliased = get_nix_option("com.apple.driver.AppleBluetoothMultitouch.trackpad", "Clicking")
        assert primary is not None
        assert aliased == primary

    def test_magicmouse_secondary_domain_aliases_to_primary(self) -> None:
        primary = get_nix_option("com.apple.AppleMultitouchMouse", "MouseButtonMode")
        aliased = get_nix_option("com.apple.driver.AppleMultitouchMouse.mouse", "MouseButtonMode")
        assert primary is not None
        assert aliased == primary

    def test_domain_aliases_dict_contains_expected_entries(self) -> None:
        assert DOMAIN_ALIASES["NSGlobalDomain"] == ".GlobalPreferences"
        assert DOMAIN_ALIASES[".GlobalPreferences"] == "NSGlobalDomain"


class TestByHostSuffixStripping:
    def test_controlcenter_byhost_uuid_suffix_resolves_same_as_bare_domain(self) -> None:
        bare = get_nix_option("com.apple.controlcenter", "Sound")
        byhost = get_nix_option("com.apple.controlcenter.F8DD5F35-6DC1-56D2-9364-C2A0C2C4D6D3", "Sound")
        assert bare is not None
        assert byhost == bare

    def test_controlcenter_byhost_short_hex_suffix_resolves_same_as_bare_domain(self) -> None:
        bare = get_nix_option("com.apple.controlcenter", "BatteryShowPercentage")
        byhost = get_nix_option("com.apple.controlcenter.AABBCCDD", "BatteryShowPercentage")
        assert bare is not None
        assert byhost == bare


class TestGetUnmappedKeys:
    def test_mix_of_mapped_and_unmapped(self) -> None:
        unmapped = get_unmapped_keys("com.apple.dock", ["autohide", "tilesize", "TotallyMadeUpKey", "AnotherFakeKey"])
        assert unmapped == ["TotallyMadeUpKey", "AnotherFakeKey"]

    def test_all_mapped_returns_empty(self) -> None:
        unmapped = get_unmapped_keys("com.apple.dock", ["autohide", "tilesize"])
        assert unmapped == []

    def test_all_unmapped_returns_all(self) -> None:
        unmapped = get_unmapped_keys("com.apple.nonexistent.domain", ["a", "b"])
        assert unmapped == ["a", "b"]

    def test_resolves_aliases_before_reporting_unmapped(self) -> None:
        # AppleShowAllFiles only lives under "NSGlobalDomain" in the raw dict — must not be
        # reported as unmapped when queried via the ".GlobalPreferences" alias.
        unmapped = get_unmapped_keys(".GlobalPreferences", ["AppleShowAllFiles", "NotARealKey"])
        assert unmapped == ["NotARealKey"]


class TestDictIntegrity:
    def test_entry_count_matches_research_doc(self) -> None:
        assert len(DEFAULTS_TO_NIX) == 197

    def test_persistent_apps_and_others_present_not_reported_unmapped(self) -> None:
        unmapped = get_unmapped_keys("com.apple.dock", ["persistent-apps", "persistent-others"])
        assert unmapped == []

    def test_unknown_key_returns_none(self) -> None:
        assert get_nix_option("com.apple.dock", "not-a-real-key") is None

    def test_unknown_domain_returns_none(self) -> None:
        assert get_nix_option("com.apple.not.a.real.domain", "autohide") is None
