"""Tests for the curated macOS preferences generator."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from mac2nix.generators.preferences import (
    CURATED_GLOBAL_DOMAIN_KEYS,
    CURATED_WHOLESALE_DOMAINS,
    _build_render_context,
    _collect_power_items,
    _collect_preference_items,
    _CuratedItem,
    generate_preferences,
)
from mac2nix.mappings.classifier import ClassificationResult, ClassificationTier, classify_wallpaper
from mac2nix.models.preferences import PreferencesDomain, PreferencesResult
from mac2nix.models.system import SystemConfig
from mac2nix.models.system_state import SystemState


def _domain(name: str, keys: dict) -> PreferencesDomain:
    return PreferencesDomain(domain_name=name, keys=keys)


def _state(*, preferences: PreferencesResult | None = None, system: SystemConfig | None = None) -> SystemState:
    return SystemState(
        hostname="test-host",
        macos_version="26.0",
        architecture="arm64",
        preferences=preferences,
        system=system,
    )


class TestCuratedDomainAllowlists:
    def test_curated_wholesale_domains_are_the_expected_set(self) -> None:
        assert {
            "com.apple.dock",
            "com.apple.finder",
            "com.apple.screensaver",
            "com.apple.AppleMultitouchTrackpad",
            "com.apple.driver.AppleBluetoothMultitouch.trackpad",
            "com.apple.symbolichotkeys",
        } == CURATED_WHOLESALE_DOMAINS

    def test_curated_global_domain_keys_are_the_expected_set(self) -> None:
        assert {
            "NSUserDictionaryReplacementItems",
            "KeyRepeat",
            "InitialKeyRepeat",
            "ApplePressAndHoldEnabled",
            "com.apple.trackpad.scaling",
            "com.apple.trackpad.forceClick",
            "com.apple.swipescrolldirection",
        } == CURATED_GLOBAL_DOMAIN_KEYS


class TestCuratedFiltering:
    def test_curated_filtering(self) -> None:
        domains = [
            _domain("com.apple.dock", {"tilesize": 48, "autohide": True}),
            _domain("com.apple.Safari", {"HomePage": "https://example.com"}),
        ]
        items = _collect_preference_items(domains)

        assert len(items) == 2
        assert {i.key for i in items} == {"tilesize", "autohide"}
        for item in items:
            assert item.domain == "com.apple.dock"
            assert item.value == domains[0].keys[item.key]

    def test_global_domain_only_curated_keys_are_classified(self) -> None:
        domains = [_domain("NSGlobalDomain", {"KeyRepeat": 2, "AppleInterfaceStyle": "Dark"})]
        items = _collect_preference_items(domains)

        assert len(items) == 1
        assert items[0].key == "KeyRepeat"
        assert items[0].value == 2

    def test_global_preferences_alias_is_also_treated_as_global(self) -> None:
        domains = [_domain(".GlobalPreferences", {"KeyRepeat": 2, "AppleInterfaceStyle": "Dark"})]
        items = _collect_preference_items(domains)

        assert len(items) == 1
        assert items[0].key == "KeyRepeat"

    def test_uncurated_domain_is_skipped_entirely(self) -> None:
        domains = [_domain("com.apple.Safari", {"HomePage": "https://example.com"})]
        assert _collect_preference_items(domains) == []


class TestPowerItems:
    def test_prefixed_power_key_is_stripped_before_classification(self) -> None:
        items = _collect_power_items({"ac_power.sleep": "0", "battery_power.displaysleep": "2"})
        native = {item.result.nix_path: item.value for item in items if item.result.tier == ClassificationTier.NATIVE}
        assert native == {"power.sleep.computer": "0", "power.sleep.display": "2"}

    def test_unmapped_power_key_routes_to_manual_report(self) -> None:
        items = _collect_power_items({"ac_power.hibernatemode": "3"})
        assert items[0].result.tier == ClassificationTier.MANUAL_REPORT


class TestBuildRenderContext:
    def test_native_dedupes_by_nix_path(self) -> None:
        """Two power sources mapping to the same nix option must not double-assign it."""
        items = _collect_power_items({"ac_power.sleep": "0", "battery_power.sleep": "1"})
        context = _build_render_context(items)
        matching = [i for i in context["native_items"] if i["nix_path"] == "power.sleep.computer"]
        assert len(matching) == 1

    def test_power_sleep_zero_coerces_to_never_not_integer_zero(self) -> None:
        """nix-darwin's power.sleep.* type is `null | positive-int | "never"` --
        confirmed via a real `nix build` failure: the integer 0 isn't itself a
        valid positive integer, and a raw scanned "0" string is neither.
        """
        items = _collect_power_items({"ac_power.sleep": "0"})
        context = _build_render_context(items)
        (item,) = [i for i in context["native_items"] if i["nix_path"] == "power.sleep.computer"]
        assert item["value"] == "never"

    def test_power_sleep_nonzero_coerces_to_int(self) -> None:
        items = _collect_power_items({"ac_power.displaysleep": "10"})
        context = _build_render_context(items)
        (item,) = [i for i in context["native_items"] if i["nix_path"] == "power.sleep.display"]
        assert item["value"] == 10
        assert isinstance(item["value"], int)

    def test_power_boolean_setting_coerces_from_raw_string(self) -> None:
        items = _collect_power_items({"ac_power.autorestart": "0", "ac_power.womp": "1"})
        context = _build_render_context(items)
        by_path = {i["nix_path"]: i["value"] for i in context["native_items"]}
        assert by_path["power.restartAfterPowerFailure"] is False
        assert by_path["networking.wakeOnLan.enable"] is True

    def test_custom_prefs_grouped_by_domain_and_key(self) -> None:
        domains = [_domain("com.apple.symbolichotkeys", {"AppleSymbolicHotKeys": {"32": {"enabled": 0}}})]
        items = _collect_preference_items(domains)
        context = _build_render_context(items)
        assert context["custom_user_prefs"] == {
            "com.apple.symbolichotkeys": {"AppleSymbolicHotKeys": {"32": {"enabled": 0}}}
        }

    def test_tier_override_custom_prefs_uses_item_domain_key_not_metadata(self) -> None:
        """dock's persistent-apps/persistent-others hit the tier_override CUSTOM_PREFS
        path, whose metadata has no domain/key -- _build_render_context must source
        them from the _CuratedItem itself, not result.metadata.
        """
        domains = [_domain("com.apple.dock", {"persistent-apps": [{"tile-data": {}}]})]
        items = _collect_preference_items(domains)
        assert items[0].result.tier == ClassificationTier.CUSTOM_PREFS
        assert "domain" not in (items[0].result.metadata or {})

        context = _build_render_context(items)
        assert context["custom_user_prefs"] == {"com.apple.dock": {"persistent-apps": [{"tile-data": {}}]}}

    def test_skipped_manual_report_is_dropped_not_rendered(self) -> None:
        result = ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination="skipped: ephemeral UI/runtime state, not reproducible config",
            metadata={"skipped": True, "reason": "ephemeral"},
        )
        context = _build_render_context([_CuratedItem(value="x", result=result)])
        assert context["manual_report_comments"] == []

    def test_non_skipped_manual_report_is_rendered_as_comment(self) -> None:
        result = ClassificationResult(
            tier=ClassificationTier.MANUAL_REPORT,
            destination="manual report: no nix-darwin option for X",
            metadata={"field_name": "X", "value": 1},
        )
        context = _build_render_context([_CuratedItem(value=1, result=result)])
        assert context["manual_report_comments"] == ["manual report: no nix-darwin option for X"]

    def test_wallpaper_activation_script_extracted_from_metadata(self) -> None:
        result = classify_wallpaper(Path("/System/Library/Desktop Pictures/The Cliffs.heic"))
        context = _build_render_context([_CuratedItem(value=Path("/x"), result=result)])
        assert context["wallpaper_path"] == "/System/Library/Desktop Pictures/The Cliffs.heic"


class TestGeneratePreferences:
    def test_missing_preferences_domain_returns_empty_module_fallback(self) -> None:
        state = _state(preferences=None, system=SystemConfig(hostname="h"))
        assert generate_preferences(state) == (
            "# preferences/system domain not scanned -- nothing to generate\n{ config, lib, pkgs, ... }:\n{\n}\n"
        )

    def test_missing_system_domain_returns_empty_module_fallback(self) -> None:
        state = _state(preferences=PreferencesResult(domains=[]), system=None)
        assert generate_preferences(state) == (
            "# preferences/system domain not scanned -- nothing to generate\n{ config, lib, pkgs, ... }:\n{\n}\n"
        )

    def test_render(self) -> None:
        domains = [
            _domain("com.apple.finder", {"NewWindowTarget": "PfHm"}),
            _domain("com.apple.symbolichotkeys", {"AppleSymbolicHotKeys": {"32": {"enabled": 0}}}),
        ]
        system = SystemConfig(
            hostname="h",
            power_settings={},
            wallpaper_path=Path("/System/Library/Desktop Pictures/The Cliffs.heic"),
        )
        state = _state(preferences=PreferencesResult(domains=domains), system=system)

        rendered = generate_preferences(state)

        # NATIVE: coerced value ("Home"), not the raw scanned code ("PfHm").
        assert 'system.defaults.finder.NewWindowTarget = lib.mkDefault "Home";' in rendered
        assert "PfHm" not in rendered

        # CUSTOM_PREFS: nested under CustomUserPreferences.
        assert "system.defaults.CustomUserPreferences" in rendered
        assert "AppleSymbolicHotKeys" in rendered

        # ACTIVATION_SCRIPT: wallpaper.
        assert "system.activationScripts.postActivation.text" in rendered
        assert "The Cliffs.heic" in rendered
        assert "lib.escapeShellArg" in rendered

    def test_skipped_ephemeral_key_produces_no_manual_report_comment(self) -> None:
        # A key/value shaped to trip is_ephemeral()'s UI-state detection.
        domains = [_domain("com.apple.finder", {"NSWindowFrame": "0 0 100 100 0 0 1920 1080"})]
        system = SystemConfig(hostname="h", power_settings={})
        state = _state(preferences=PreferencesResult(domains=domains), system=system)

        rendered = generate_preferences(state)
        assert "not automated" not in rendered

    def test_newline_in_sensitive_key_cannot_inject_nix_syntax_via_manual_report_comment(self) -> None:
        """A real, previously-exploitable bug: a plist key is fully attacker-writable
        (`defaults write <domain> <key> ...` needs no privilege), and a newline in a
        key routed to MANUAL_REPORT would otherwise break out of the rendered
        `# not automated: ...` single-line Nix comment.
        """
        malicious_key = 'x_TOKEN\n  }; system.activationScripts.pwned.text = "pwned"; { y'
        domains = [_domain("com.apple.dock", {malicious_key: "irrelevant"})]
        system = SystemConfig(hostname="h", power_settings={})
        state = _state(preferences=PreferencesResult(domains=domains), system=system)

        rendered = generate_preferences(state)

        assert "\n  }; system.activationScripts.pwned" not in rendered
        assert "pwned" not in rendered  # the redacted key never appears in output at all
        for line in rendered.splitlines():
            assert line.count("#") <= 1 or line.strip().startswith("#")

    def test_custom_system_preferences_bucket_is_reachable_and_renders(self) -> None:
        """A system-scoped plist for a curated domain is real, not speculative -- the
        preferences scanner globs `/Library/Preferences/*.plist` unfiltered, so any
        curated domain name can legitimately appear there on a real Mac.
        """
        domain = PreferencesDomain(
            domain_name="com.apple.screensaver",
            source_path=Path("/Library/Preferences/com.apple.screensaver.plist"),
            keys={"someUnmappedKey": "value"},
        )
        system = SystemConfig(hostname="h", power_settings={})
        state = _state(preferences=PreferencesResult(domains=[domain]), system=system)

        rendered = generate_preferences(state)

        assert "system.defaults.CustomSystemPreferences" in rendered
        assert "someUnmappedKey" in rendered
        assert "system.defaults.CustomUserPreferences" not in rendered


@pytest.fixture
def require_nix_instantiate() -> None:
    if shutil.which("nix-instantiate") is None:
        pytest.skip("nix-instantiate not on PATH")


@pytest.mark.nix
def test_render_is_valid_nix(require_nix_instantiate: None, tmp_path: Path) -> None:
    domains = [
        _domain("com.apple.dock", {"tilesize": 48}),
        _domain("com.apple.finder", {"NewWindowTarget": "PfHm"}),
        _domain("com.apple.symbolichotkeys", {"AppleSymbolicHotKeys": {"32": {"enabled": 0}}}),
    ]
    system = SystemConfig(
        hostname="h",
        power_settings={"ac_power.sleep": "0"},
        wallpaper_path=Path("/System/Library/Desktop Pictures/The Cliffs.heic"),
    )
    state = _state(preferences=PreferencesResult(domains=domains), system=system)

    rendered = generate_preferences(state)
    module_path = tmp_path / "preferences.nix"
    module_path.write_text(rendered)

    result = subprocess.run(  # noqa: S603
        ["nix-instantiate", "--parse", str(module_path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.nix
def test_empty_module_fallback_is_valid_nix(require_nix_instantiate: None, tmp_path: Path) -> None:
    state = _state(preferences=None, system=None)
    rendered = generate_preferences(state)
    module_path = tmp_path / "preferences.nix"
    module_path.write_text(rendered)

    result = subprocess.run(  # noqa: S603
        ["nix-instantiate", "--parse", str(module_path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.nix
def test_custom_system_preferences_block_is_valid_nix(require_nix_instantiate: None, tmp_path: Path) -> None:
    domain = PreferencesDomain(
        domain_name="com.apple.screensaver",
        source_path=Path("/Library/Preferences/com.apple.screensaver.plist"),
        keys={"someUnmappedKey": "value"},
    )
    system = SystemConfig(hostname="h", power_settings={})
    state = _state(preferences=PreferencesResult(domains=[domain]), system=system)

    rendered = generate_preferences(state)
    module_path = tmp_path / "preferences.nix"
    module_path.write_text(rendered)

    result = subprocess.run(  # noqa: S603
        ["nix-instantiate", "--parse", str(module_path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.nix
def test_newline_in_key_does_not_break_nix_syntax(require_nix_instantiate: None, tmp_path: Path) -> None:
    malicious_key = 'x_TOKEN\n  }; system.activationScripts.pwned.text = "pwned"; { y'
    domains = [_domain("com.apple.dock", {malicious_key: "irrelevant"})]
    system = SystemConfig(hostname="h", power_settings={})
    state = _state(preferences=PreferencesResult(domains=domains), system=system)

    rendered = generate_preferences(state)
    module_path = tmp_path / "preferences.nix"
    module_path.write_text(rendered)

    result = subprocess.run(  # noqa: S603
        ["nix-instantiate", "--parse", str(module_path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
