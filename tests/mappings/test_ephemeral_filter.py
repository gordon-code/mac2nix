"""Tests for the ephemeral state filter.

Every axis below pairs a case that SHOULD be filtered with a deliberate
near-miss that looks similar but must NOT be filtered — this module exists
specifically to fix defaults2nix's substring-overmatch bugs, so the
near-miss cases are the load-bearing assertions.
"""

from mac2nix.mappings.ephemeral_filter import filter_ephemeral, is_ephemeral


class TestUiStateKeyPatterns:
    def test_ns_window_frame_prefix_is_filtered(self) -> None:
        assert is_ephemeral("NSWindow Frame TerminalWindow", "100 100 800 600 0 0 1440 900") is True

    def test_exact_match_is_filtered(self) -> None:
        assert is_ephemeral("NSNavPanelExpandedSize", True) is True

    def test_frame_suffix_with_window_is_filtered(self) -> None:
        assert is_ephemeral("MainWindowFrame", "100 100 800 600 0 0 1440 900") is True

    def test_contains_pattern_is_filtered(self) -> None:
        assert is_ephemeral("CropRect", "{{0, 0}, {100, 100}}") is True

    def test_unrelated_window_key_is_not_filtered(self) -> None:
        assert is_ephemeral("WindowTabbingMode", "always") is False

    def test_similar_nav_panel_key_is_not_filtered(self) -> None:
        assert is_ephemeral("NSNavPanelStyle", "expanded") is False

    def test_frame_without_window_is_not_filtered(self) -> None:
        assert is_ephemeral("AnimationFrame", 12) is False


class TestTimestampKeySuffix:
    def test_last_used_suffix_is_filtered(self) -> None:
        assert is_ephemeral("SomeAppLastUsed", 5) is True

    def test_checked_at_suffix_is_filtered(self) -> None:
        assert is_ephemeral("LastCheckedAt", 5) is True

    def test_epoch_suffix_is_filtered(self) -> None:
        assert is_ephemeral("UpdateEpoch", 5) is True

    def test_lowercase_camel_checked_at_is_filtered(self) -> None:
        assert is_ephemeral("checkedAt", 5) is True

    def test_autohide_time_modifier_is_not_filtered(self) -> None:
        """The flagship defaults2nix bug: 'time' as a substring, not a suffix word."""
        assert is_ephemeral("autohide-time-modifier", 2) is False

    def test_time_format_is_not_filtered(self) -> None:
        assert is_ephemeral("TimeFormat", "24Hour") is False

    def test_date_format_is_not_filtered(self) -> None:
        assert is_ephemeral("DateFormat", "MM/DD/YYYY") is False

    def test_screen_saver_idle_time_is_not_filtered(self) -> None:
        assert is_ephemeral("ScreenSaverIdleTime", 600) is False

    def test_category_is_not_filtered(self) -> None:
        """Guards against defaults2nix's 'at' substring bug (Category contains 'at')."""
        assert is_ephemeral("Category", "Productivity") is False

    def test_authenticate_is_not_filtered(self) -> None:
        """Guards against defaults2nix's 'when'/'at' substring bugs."""
        assert is_ephemeral("Authenticate", False) is False


class TestTimestampValueRange:
    def test_unix_timestamp_range_is_filtered(self) -> None:
        assert is_ephemeral("RandomCounter", 1_700_000_000) is True

    def test_cfabsolute_time_range_is_filtered(self) -> None:
        assert is_ephemeral("RandomCounter", 500_000_000) is True

    def test_small_int_is_not_filtered(self) -> None:
        assert is_ephemeral("RetryCount", 42) is False

    def test_bool_is_not_treated_as_numeric_timestamp(self) -> None:
        assert is_ephemeral("SomeFlag", True) is False

    def test_out_of_range_large_int_is_not_filtered(self) -> None:
        assert is_ephemeral("FileSizeBytes", 5_000_000_000) is False

    def test_disk_cache_size_in_timestamp_range_is_not_filtered(self) -> None:
        """1GB byte count lands in the Unix timestamp range by coincidence."""
        assert is_ephemeral("DiskCacheSize", 1_073_741_824) is False

    def test_memory_limit_in_timestamp_range_is_not_filtered(self) -> None:
        assert is_ephemeral("MemoryLimit", 1_073_741_824) is False

    def test_opaque_key_with_timestamp_value_is_still_filtered(self) -> None:
        """Keys with no quantity or time-related suffix still rely on value-range detection."""
        assert is_ephemeral("SomeInternalField", 1_700_000_000) is True


class TestDateStringValue:
    def test_date_only_is_filtered(self) -> None:
        assert is_ephemeral("SomeKey", "2026-07-20") is True

    def test_full_datetime_is_filtered(self) -> None:
        assert is_ephemeral("SomeKey", "2026-07-20T11:52:00") is True

    def test_partial_date_is_not_filtered(self) -> None:
        assert is_ephemeral("SomeKey", "2026-07") is False

    def test_digits_only_is_not_filtered(self) -> None:
        assert is_ephemeral("SomeKey", "20260720") is False

    def test_version_string_is_not_filtered(self) -> None:
        assert is_ephemeral("AppVersion", "1.2.3") is False


class TestUuidDetection:
    def test_uuid_whole_key_is_filtered(self) -> None:
        assert is_ephemeral("550e8400-e29b-41d4-a716-446655440000", "value") is True

    def test_uuid_whole_value_is_filtered(self) -> None:
        assert is_ephemeral("SessionID", "550e8400-e29b-41d4-a716-446655440000") is True

    def test_hashed_id_key_is_filtered(self) -> None:
        assert is_ephemeral("_19a3bc4999bddb89e1a44f4b87bdc37c", "value") is True

    def test_uuid_embedded_in_larger_string_is_not_filtered(self) -> None:
        assert is_ephemeral("SessionID-550e8400-e29b-41d4-a716-446655440000-cache", "value") is False

    def test_short_underscore_prefixed_string_is_not_filtered(self) -> None:
        assert is_ephemeral("_1234", "value") is False


class TestBinaryDataSentinel:
    def test_sentinel_format_is_filtered(self) -> None:
        assert is_ephemeral("SomeKey", "<data:128 bytes>") is True

    def test_malformed_sentinel_is_not_filtered(self) -> None:
        assert is_ephemeral("SomeKey", "<data:bytes>") is False

    def test_plain_bytes_description_is_not_filtered(self) -> None:
        assert is_ephemeral("SomeKey", "128 bytes") is False


class TestSparklePrefix:
    def test_su_last_check_time_is_filtered(self) -> None:
        assert is_ephemeral("SULastCheckTime", "2026-07-20") is True

    def test_su_update_relaunch_path_is_filtered(self) -> None:
        assert is_ephemeral("SUUpdateRelaunchPath", "/Applications/App.app") is True

    def test_su_has_launched_before_is_filtered(self) -> None:
        assert is_ephemeral("SUHasLaunchedBefore", True) is True

    def test_enable_automatic_checks_is_not_filtered(self) -> None:
        assert is_ephemeral("SUEnableAutomaticChecks", True) is False

    def test_lowercase_su_prefix_is_not_filtered(self) -> None:
        assert is_ephemeral("SubtitleFont", "Helvetica") is False


class TestUiGeometryValue:
    def test_nsrect_is_filtered(self) -> None:
        assert is_ephemeral("WindowGeometry", "{{0, 0}, {800, 600}}") is True

    def test_nssize_is_filtered(self) -> None:
        assert is_ephemeral("PanelSize", "{800, 600}") is True

    def test_window_frame_floats_is_filtered(self) -> None:
        assert is_ephemeral("SomeGeometry", "100 200 300 400 500 600 700 800") is True

    def test_split_view_frame_is_filtered(self) -> None:
        assert is_ephemeral("SomeSplitView", "0,0,100,100,50,YES") is True

    def test_nssize_with_equals_is_not_filtered(self) -> None:
        assert is_ephemeral("PanelSize", "{width=800, height=600}") is False

    def test_eight_non_float_tokens_is_not_filtered(self) -> None:
        assert is_ephemeral("SomeGeometry", "one two three four five six seven eight") is False

    def test_five_commas_without_yes_no_is_not_filtered(self) -> None:
        assert is_ephemeral("SomeSplitView", "0,0,100,100,50,MAYBE") is False


class TestCacheKeysNotFilteredOnPatternAlone:
    def test_disk_cache_size_with_ordinary_value_is_not_filtered(self) -> None:
        assert is_ephemeral("DiskCacheSize", 52_428_800) is False

    def test_webkit_cache_model_is_not_filtered(self) -> None:
        assert is_ephemeral("WebKitCacheModel", 0) is False

    def test_cache_policy_is_not_filtered(self) -> None:
        assert is_ephemeral("CachePolicy", 1) is False

    def test_cache_key_with_timestamp_like_value_is_filtered(self) -> None:
        """Not a key-pattern rule — this only fires via the general value-range check."""
        assert is_ephemeral("ThumbnailCacheLastPurged", 1_700_000_000) is True


class TestFilterEphemeral:
    def test_mixed_dict_keeps_only_non_ephemeral_entries(self) -> None:
        keys = {
            "NSWindow Frame Main": "100 100 800 600 0 0 1440 900",
            "SULastCheckTime": "2026-07-20",
            "AppVersion": "1.2.3",
            "TimeFormat": "24Hour",
            "RetryCount": 3,
        }

        result = filter_ephemeral(keys)

        assert result == {"AppVersion": "1.2.3", "TimeFormat": "24Hour", "RetryCount": 3}

    def test_empty_dict_returns_empty_dict(self) -> None:
        assert filter_ephemeral({}) == {}
