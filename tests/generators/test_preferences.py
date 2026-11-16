"""Tests for the curated macOS preferences generator."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from mac2nix.generators.preferences import (
    CURATED_GLOBAL_DOMAIN_KEYS,
    CURATED_WHOLESALE_DOMAINS,
    WallpaperAsset,
    _build_render_context,
    _collect_power_items,
    _collect_preference_items,
    _CuratedItem,
    _prepare_wallpaper_asset,
    generate_preferences,
)
from mac2nix.mappings.classifier import ClassificationResult, ClassificationTier, classify_wallpaper
from mac2nix.models.preferences import PreferencesDomain, PreferencesResult
from mac2nix.models.system import SystemConfig
from mac2nix.models.system_state import SystemState
from tests._generate_helpers import assert_activation_script_neutralizes_shell_metacharacters


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

    def test_unmapped_field_from_two_power_sources_produces_one_manual_report_comment(self) -> None:
        """Confirmed on real hardware via `pmset -g custom`: an unmapped key like
        'ttyskeepawake' can appear under both "AC Power:" and "Battery Power:"
        with DIFFERENT values, but classify_system_setting()'s MANUAL_REPORT
        destination string for an unmapped field never includes the value --
        two source-prefixed keys must still produce exactly one comment, not two
        identical duplicates. Uses a field NOT in `_PROMOTED_POWER_SETTING_KEYS`
        (Step 13) -- a promoted field is covered by its own dedicated test class.
        """
        items = _collect_power_items({"ac_power.ttyskeepawake": "3", "battery_power.ttyskeepawake": "0"})
        context = _build_render_context(items)
        matching = [c for c in context["manual_report_comments"] if "ttyskeepawake" in c]
        assert len(matching) == 1

    @pytest.mark.parametrize(
        "domains",
        [
            pytest.param(
                [_domain("NSGlobalDomain", {"KeyRepeat": 2}), _domain(".GlobalPreferences", {"KeyRepeat": 6})],
                id="nsglobaldomain-first",
            ),
            pytest.param(
                [_domain(".GlobalPreferences", {"KeyRepeat": 6}), _domain("NSGlobalDomain", {"KeyRepeat": 2})],
                id="globalpreferences-first",
            ),
        ],
    )
    def test_global_domain_alias_conflict_nsglobaldomain_wins_deterministically(
        self, domains: list[PreferencesDomain]
    ) -> None:
        """Both 'NSGlobalDomain' and '.GlobalPreferences' are guaranteed to appear as
        domain_name in the same real scan: PreferencesScanner._discover_cfprefsd_domains()
        only skips a cfprefsd domain already in `seen`, and `seen` is populated from
        on-disk plist file *stems* -- ".GlobalPreferences.plist"'s stem never matches the
        literal string "NSGlobalDomain" that `defaults domains` reports, so any Mac with
        a `.GlobalPreferences.plist` (virtually all of them) produces both. When they
        disagree, NSGlobalDomain (cfprefsd, live) must win over .GlobalPreferences
        (on-disk) -- Apple's own documentation states cfprefsd's in-memory cache is
        authoritative and the on-disk plist is only asynchronously, eventually
        reconciled with it. This must hold regardless of scan/list order -- parametrized
        both ways to prove it's not an incidental artifact of iteration order.
        """
        items = _collect_preference_items(domains)
        context = _build_render_context(items)

        matching = [i for i in context["native_items"] if i["nix_path"] == "system.defaults.NSGlobalDomain.KeyRepeat"]
        assert len(matching) == 1
        assert matching[0]["value"] == 2

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

    @pytest.mark.parametrize(
        "power_settings",
        [pytest.param({"ac_power.autorestart": "0", "ac_power.womp": "1"}, id="typical-values")],
    )
    def test_hardware_dependent_activation_renders_script_not_native(self, power_settings: dict[str, str]) -> None:
        """Confirmed via a real `nix_vm` integration-test failure: nix-darwin's own
        modules/system/checks.nix aborts the ENTIRE `darwin-rebuild switch` whenever
        `power.restartAfterPowerFailure` is set at all (true OR false) on hardware that
        doesn't support it, and `networking.wakeOnLan.enable` carries the same
        unsupported-hardware risk with no nix-darwin guard at all. Neither can be
        safely rendered as a plain native assignment -- both must route to
        `context["post_activation_script"]` (Step 14's self-guarding probe-then-apply
        scripts, combined into the one real `postActivation` hook nix-darwin
        actually executes) instead of `context["native_items"]`.
        """
        items = _collect_power_items(power_settings)
        context = _build_render_context(items)
        native_paths = {i["nix_path"] for i in context["native_items"]}
        assert "power.restartAfterPowerFailure" not in native_paths
        assert "networking.wakeOnLan.enable" not in native_paths
        assert context["post_activation_script"] is not None
        assert "restart-after-power-failure" in context["post_activation_script"]
        assert "wake-on-LAN" in context["post_activation_script"]
        assert context["manual_report_comments"] == []

    def test_hardware_dependent_activation_uncoercible_value_falls_back(self) -> None:
        """A value that isn't cleanly "0"/"1" fails closed (Step 14): never passed
        through as a raw scanned string, routed to manual-report instead of an
        activation script.
        """
        items = _collect_power_items({"ac_power.autorestart": "", "ac_power.womp": "some-future-value"})
        context = _build_render_context(items)

        assert context["post_activation_script"] is None
        assert any("power.restartAfterPowerFailure" in c for c in context["manual_report_comments"])
        assert any("networking.wakeOnLan.enable" in c for c in context["manual_report_comments"])
        assert all(c.startswith("[hardware-dependent] ") for c in context["manual_report_comments"])

    def test_hardware_dependent_activation_dedupes_across_power_sources(self) -> None:
        """pmset reports `autorestart`/`womp` under both the "AC Power:" and
        "Battery Power:" sections even though the underlying setting isn't
        actually per-power-source -- two source-prefixed keys resolving to the
        same nix_path must produce exactly one activation script entry, not two,
        mirroring the dedup NATIVE items already get via dict-write. Uses
        DIFFERING values across sources (confirmed real via `pmset -g custom` on
        real hardware, which reports different autorestart/womp values per
        section) to prove the nix_path-keyed dedup mechanism applies before
        either value is even coerced -- the first-encountered source wins.
        """
        items = _collect_power_items(
            {
                "ac_power.autorestart": "0",
                "battery_power.autorestart": "1",
                "ac_power.womp": "1",
                "battery_power.womp": "0",
            }
        )
        context = _build_render_context(items)
        combined = context["post_activation_script"]
        assert combined is not None
        assert combined.count("restart-after-power-failure not supported") == 1
        assert combined.count("wake-on-LAN not supported") == 1

    @pytest.mark.nix
    def test_hardware_dependent_activation_renders_valid_nix(
        self, require_nix_instantiate: None, tmp_path: Path
    ) -> None:
        """Step 9's adversarial-escaping helper needs an injectable string value --
        these settings have none, since `_coerce_hardware_dependent_setting` only
        ever accepts exactly "on"/"off" (see
        test_hardware_dependent_activation_uncoercible_value_falls_back for the
        fail-closed proof). A real `nix-instantiate --parse` check is the
        meaningful equivalent here, matching Step 13's promoted-case tests.
        """
        items = _collect_power_items({"ac_power.autorestart": "0", "ac_power.womp": "1"})
        context = _build_render_context(items)
        assert context["post_activation_script"] is not None

        module_source = "{ config, lib, pkgs, ... }:\n{\n  " + context["post_activation_script"] + "\n}\n"
        module_path = tmp_path / "fixture.nix"
        module_path.write_text(module_source)

        result = subprocess.run(  # noqa: S603
            ["nix-instantiate", "--parse", str(module_path)],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr

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
        assert context["post_activation_script"] is not None
        assert "system.activationScripts.postActivation.text" in context["post_activation_script"]
        assert "The Cliffs.heic" in context["post_activation_script"]

    def test_binary_data_activation_script_without_wallpaper_falls_back_to_manual_report(self) -> None:
        """classify_preference's binary-sentinel precheck routes a `<data:N bytes>` value to
        ACTIVATION_SCRIPT with metadata {command_type, domain, key, value_type, value} -- no
        "wallpaper_path" key. _build_render_context's ACTIVATION_SCRIPT branch only extracts
        wallpaper_path; this generator has no support for rendering an arbitrary `defaults
        write` activation script, so any other ACTIVATION_SCRIPT item must fall back to a
        manual-report comment instead of being silently dropped.
        """
        domains = [_domain("com.apple.dock", {"some-binary-pref": "<data:16 bytes>"})]
        items = _collect_preference_items(domains)
        assert items[0].result.tier == ClassificationTier.ACTIVATION_SCRIPT
        assert "wallpaper_path" not in (items[0].result.metadata or {})

        context = _build_render_context(items)
        assert context["manual_report_comments"] == [
            "[out of scope] activationScripts: defaults write for com.apple.dock some-binary-pref (binary data)"
        ]
        assert context["post_activation_script"] is None


_JPEG_MAGIC = b"\xff\xd8\xff\xe0" + b"\x00" * 50
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
_TIFF_LE_MAGIC = b"II*\x00" + b"\x00" * 50
_TIFF_BE_MAGIC = b"MM\x00*" + b"\x00" * 50
_HEIC_MAGIC = b"\x00\x00\x00\x18ftypheic" + b"\x00" * 50
_TEXT_DISGUISED_AS_JPEG = b"this is plain text padded out to look like a real file, not a jpeg"


class TestWallpaperPortability:
    def test_os_asset_path_renders_absolute_path_unchanged(self) -> None:
        result = classify_wallpaper(Path("/System/Library/Desktop Pictures/The Cliffs.heic"))
        context = _build_render_context([_CuratedItem(value=Path("/x"), result=result)])

        assert context["post_activation_script"] is not None
        assert '"/System/Library/Desktop Pictures/The Cliffs.heic"' in context["post_activation_script"]
        assert context["wallpaper_asset"] is None

    def test_os_asset_path_in_nested_subdirectory_is_still_portable(self) -> None:
        """macOS ships stock wallpapers in nested subdirectories (e.g. "Solid
        Colors/Black.png", ".wallpapers/Sonoma Horizon/Sonoma Horizon.heic") --
        an exact-parent-match allowlist check would misclassify these as personal
        files, routing a genuinely portable OS-shipped wallpaper through the
        bundling path, where it fails every bundling allowlist too and silently
        drops wallpaper automation entirely (found by a fresh-context adversarial
        review, confirmed live against real subdirectories on the reviewing
        machine).
        """
        result = classify_wallpaper(Path("/System/Library/Desktop Pictures/Solid Colors/Black.png"))
        context = _build_render_context([_CuratedItem(value=Path("/x"), result=result)])

        assert context["post_activation_script"] is not None
        assert '"/System/Library/Desktop Pictures/Solid Colors/Black.png"' in context["post_activation_script"]
        assert context["wallpaper_asset"] is None
        assert context["manual_report_comments"] == []

    @pytest.mark.nix
    def test_os_asset_path_adversarial_value_stays_quoted(self, tmp_path: Path) -> None:
        """The wallpaper path is scanned (untrusted) data reaching a shell command via
        `_build_wallpaper_activation_script` -- per `assert_activation_script_neutralizes_shell_metacharacters`'s
        own docstring, it must be verified through that helper like every other
        activation-script code path built from untrusted data. This was missing: the
        only existing adversarial-injection test for the shared `nix_post_activation_script`
        renderer used a synthetic body, never the real classify_wallpaper() ->
        _build_render_context() pipeline.
        """
        # No literal '/' in the marker -- unlike a generic string value, a wallpaper
        # path is a filesystem path, so a '/' would just describe a different
        # directory rather than exercise injection into the shell/Nix layers below.
        marker = 'inject`ed $(id) ; "quoted"\nnewline'
        adversarial_path = Path(f"/System/Library/Desktop Pictures/{marker}.heic")
        result = classify_wallpaper(adversarial_path)
        context = _build_render_context([_CuratedItem(value=adversarial_path, result=result)])

        assert context["post_activation_script"] is not None
        assert_activation_script_neutralizes_shell_metacharacters(
            context["post_activation_script"], str(adversarial_path), tmp_path
        )

    def test_personal_path_routes_to_bundling_path(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        pictures = home / "Pictures"
        pictures.mkdir(parents=True)
        source = pictures / "sunset.jpg"
        source.write_bytes(_JPEG_MAGIC)

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = classify_wallpaper(source)
            context = _build_render_context([_CuratedItem(value=source, result=result)])

        assert context["wallpaper_asset"] == WallpaperAsset(filename="wallpaper.jpg", data=_JPEG_MAGIC)
        assert context["post_activation_script"] is not None
        assert "toString ./assets/wallpaper.jpg" in context["post_activation_script"]

    def test_personal_path_outside_bundle_allowlist_falls_back_to_manual_report(self, tmp_path: Path) -> None:
        """A personal path outside both bundling allowlist directories (e.g. Downloads)
        must fall back to a manual-report comment, not silently drop the wallpaper.
        """
        home = tmp_path / "home"
        downloads = home / "Downloads"
        downloads.mkdir(parents=True)
        source = downloads / "sunset.jpg"
        source.write_bytes(_JPEG_MAGIC)

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = classify_wallpaper(source)
            context = _build_render_context([_CuratedItem(value=source, result=result)])

        assert context["wallpaper_asset"] is None
        assert context["post_activation_script"] is None
        assert any("[coverage gap] wallpaper" in c for c in context["manual_report_comments"])

    def test_wallpaper_scan_error_produces_manual_report_comment(self) -> None:
        system = SystemConfig(
            hostname="h", power_settings={}, wallpaper_scan_error="could not read desktoppicture.db (corrupt)"
        )
        state = _state(preferences=PreferencesResult(domains=[]), system=system)

        generated = generate_preferences(state)

        assert "[coverage gap] wallpaper: could not read desktoppicture.db (corrupt)" in generated.rendered


class TestPrepareWallpaperAsset:
    def _home_with_pictures(self, tmp_path: Path) -> Path:
        home = tmp_path / "home"
        (home / "Pictures").mkdir(parents=True)
        return home

    def test_valid_image_bundles_with_fixed_destination_name(self, tmp_path: Path) -> None:
        home = self._home_with_pictures(tmp_path)
        source = home / "Pictures" / "my-photo.jpg"
        source.write_bytes(_JPEG_MAGIC)

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = _prepare_wallpaper_asset(source)

        assert result == WallpaperAsset(filename="wallpaper.jpg", data=_JPEG_MAGIC)

    def test_extension_lying_about_content_is_rejected(self, tmp_path: Path) -> None:
        home = self._home_with_pictures(tmp_path)
        source = home / "Pictures" / "fake.jpg"
        source.write_bytes(_TEXT_DISGUISED_AS_JPEG)

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = _prepare_wallpaper_asset(source)

        assert result is None

    def test_oversized_file_is_rejected(self, tmp_path: Path) -> None:
        home = self._home_with_pictures(tmp_path)
        source = home / "Pictures" / "huge.jpg"
        source.write_bytes(_JPEG_MAGIC + b"\x00" * (20 * 1024 * 1024))

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = _prepare_wallpaper_asset(source)

        assert result is None

    def test_path_outside_allowlist_is_rejected(self, tmp_path: Path) -> None:
        home = tmp_path / "home"
        downloads = home / "Downloads"
        downloads.mkdir(parents=True)
        source = downloads / "sunset.jpg"
        source.write_bytes(_JPEG_MAGIC)

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = _prepare_wallpaper_asset(source)

        assert result is None

    def test_symlink_inside_allowlist_pointing_outside_is_rejected(self, tmp_path: Path) -> None:
        """A symlink physically located inside ~/Pictures but pointing outside it must
        still be rejected -- the check applies to the resolved real target, not the
        pre-symlink path the symlink itself sits at.
        """
        home = self._home_with_pictures(tmp_path)
        outside_target = tmp_path / "outside" / "real.jpg"
        outside_target.parent.mkdir(parents=True)
        outside_target.write_bytes(_JPEG_MAGIC)
        symlink_source = home / "Pictures" / "sneaky.jpg"
        symlink_source.symlink_to(outside_target)

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = _prepare_wallpaper_asset(symlink_source)

        assert result is None

    def test_deleted_file_falls_back_gracefully_not_uncaught_error(self, tmp_path: Path) -> None:
        """The wallpaper path is captured at scan time -- by the time `generate` runs
        (possibly against a saved --scan-file, much later), the file may be gone.
        """
        home = self._home_with_pictures(tmp_path)
        source = home / "Pictures" / "gone.jpg"

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = _prepare_wallpaper_asset(source)

        assert result is None

    @pytest.mark.parametrize(
        ("filename", "magic", "expected_ext"),
        [
            pytest.param("photo.png", _PNG_MAGIC, ".png", id="png"),
            pytest.param("photo.tiff", _TIFF_LE_MAGIC, ".tiff", id="tiff-little-endian"),
            pytest.param("photo.tiff", _TIFF_BE_MAGIC, ".tiff", id="tiff-big-endian"),
            pytest.param("photo.heic", _HEIC_MAGIC, ".heic", id="heic"),
        ],
    )
    def test_every_allowlisted_format_is_recognized_by_magic_bytes(
        self, tmp_path: Path, filename: str, magic: bytes, expected_ext: str
    ) -> None:
        """`_sniff_image_extension` has a distinct branch per format in
        `_WALLPAPER_EXTENSION_ALLOWLIST` -- every prior test in this class only ever
        used JPEG magic bytes, leaving the PNG/TIFF(x2)/HEIC branches dead as far as
        tests could tell.
        """
        home = self._home_with_pictures(tmp_path)
        source = home / "Pictures" / filename
        source.write_bytes(magic)

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = _prepare_wallpaper_asset(source)

        assert result == WallpaperAsset(filename=f"wallpaper{expected_ext}", data=magic)

    def test_heic_ftyp_box_shorter_than_length_guard_is_rejected(self, tmp_path: Path) -> None:
        """`_sniff_image_extension`'s HEIC branch guards with `len(data) >= 12` before
        indexing `data[8:12]` -- a file too short to contain a full ftyp brand must be
        rejected, not raise an IndexError-adjacent slicing bug.
        """
        home = self._home_with_pictures(tmp_path)
        source = home / "Pictures" / "truncated.heic"
        source.write_bytes(b"\x00\x00\x00\x18ftyphe")  # 10 bytes, brand field cut short

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = _prepare_wallpaper_asset(source)

        assert result is None

    def test_uppercase_extension_still_bundles(self, tmp_path: Path) -> None:
        """`_is_bundleable_wallpaper_location` deliberately lowercases the suffix
        before the allowlist check -- prove a `.JPG`-suffixed file (a real macOS
        filename case, not hypothetical) still bundles rather than silently failing
        an exact-case string comparison.
        """
        home = self._home_with_pictures(tmp_path)
        source = home / "Pictures" / "photo.JPG"
        source.write_bytes(_JPEG_MAGIC)

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = _prepare_wallpaper_asset(source)

        assert result == WallpaperAsset(filename="wallpaper.jpg", data=_JPEG_MAGIC)

    def test_second_allowlist_directory_also_bundles(self, tmp_path: Path) -> None:
        """`_wallpaper_bundle_source_allowlist()` returns two directories -- every
        other test in this class only ever placed its fixture under `~/Pictures`,
        leaving `~/Library/Application Support/Dock` untested.
        """
        home = tmp_path / "home"
        dock_dir = home / "Library" / "Application Support" / "Dock"
        dock_dir.mkdir(parents=True)
        source = dock_dir / "sunset.jpg"
        source.write_bytes(_JPEG_MAGIC)

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = _prepare_wallpaper_asset(source)

        assert result == WallpaperAsset(filename="wallpaper.jpg", data=_JPEG_MAGIC)


class TestActivationScriptPromotion:
    """Step 13's audit: `[coverage gap]` pmset keys with no native nix-darwin
    option, promotable because `pmset -a` (unlike `systemsetup`) silently
    no-ops on hardware where a setting doesn't apply rather than
    hard-failing -- no capability probe needed.
    """

    @pytest.mark.parametrize("field_name", ["hibernatemode", "standby", "lidwake"])
    def test_activation_script_promotion_renders_script_not_comment(self, field_name: str) -> None:
        items = _collect_power_items({f"ac_power.{field_name}": "1"})
        context = _build_render_context(items)

        assert context["post_activation_script"] is not None
        assert f"pmset -a {field_name}" in context["post_activation_script"]
        assert not any(field_name in c for c in context["manual_report_comments"])

    def test_activation_script_promotion_non_promoted_case_still_renders_as_comment(self) -> None:
        """A `[coverage gap]` field NOT in `_PROMOTED_POWER_SETTING_KEYS` (no safe CLI
        path confirmed by this audit) must stay a comment, not be force-fit into an
        activation script.
        """
        items = _collect_power_items({"ac_power.gpuswitch": "2"})
        context = _build_render_context(items)

        assert context["post_activation_script"] is None
        assert any("[coverage gap]" in c and "gpuswitch" in c for c in context["manual_report_comments"])

    @pytest.mark.parametrize("field_name", ["hibernatemode", "standby", "lidwake"])
    def test_activation_script_promotion_uncoercible_value_falls_back(self, field_name: str) -> None:
        """Fails closed like Step 14's power-boolean coercion: a value that doesn't
        cleanly coerce to a non-negative int is never passed through raw.
        """
        items = _collect_power_items({f"ac_power.{field_name}": "not-a-number"})
        context = _build_render_context(items)

        assert context["post_activation_script"] is None
        assert any(field_name in c for c in context["manual_report_comments"])

    @pytest.mark.parametrize("field_name", ["hibernatemode", "standby", "lidwake"])
    def test_activation_script_promotion_negative_value_falls_back(self, field_name: str) -> None:
        """`_coerce_promoted_power_setting_value` requires a *non-negative* int -- a
        value like "-1" parses cleanly via `int()` (so the `except (TypeError,
        ValueError)` branch alone would miss it) and must still be rejected by the
        `coerced >= 0` guard, not passed through raw.
        """
        items = _collect_power_items({f"ac_power.{field_name}": "-1"})
        context = _build_render_context(items)

        assert context["post_activation_script"] is None
        assert any(field_name in c for c in context["manual_report_comments"])

    @pytest.mark.nix
    @pytest.mark.parametrize("field_name", ["hibernatemode", "standby", "lidwake"])
    def test_activation_script_promotion_renders_valid_nix(
        self, field_name: str, require_nix_instantiate: None, tmp_path: Path
    ) -> None:
        """Step 9's adversarial-escaping helper needs an injectable string value to
        assert against -- these settings have no such value, since
        `_coerce_promoted_power_setting_value` only ever accepts a non-negative int
        (see test_activation_script_promotion_uncoercible_value_falls_back for the
        fail-closed proof) and `pmset_key` is always one of the fixed,
        module-controlled `_PROMOTED_POWER_SETTING_KEYS` literals, never scanned
        data. A real `nix-instantiate --parse` check is the meaningful equivalent
        here.
        """
        items = _collect_power_items({f"ac_power.{field_name}": "1"})
        context = _build_render_context(items)
        script = context["post_activation_script"]
        assert script is not None

        module_source = f"{{ config, lib, pkgs, ... }}:\n{{\n  {script}\n}}\n"
        module_path = tmp_path / "fixture.nix"
        module_path.write_text(module_source)

        result = subprocess.run(  # noqa: S603
            ["nix-instantiate", "--parse", str(module_path)],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr


class TestGeneratePreferences:
    def test_missing_preferences_domain_returns_empty_module_fallback(self) -> None:
        state = _state(preferences=None, system=SystemConfig(hostname="h"))
        assert generate_preferences(state).rendered == (
            "# preferences/system domain not scanned -- nothing to generate\n{ config, lib, pkgs, ... }:\n{\n}\n"
        )

    def test_missing_system_domain_returns_empty_module_fallback(self) -> None:
        state = _state(preferences=PreferencesResult(domains=[]), system=None)
        assert generate_preferences(state).rendered == (
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

        rendered = generate_preferences(state).rendered

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

        # A headless/SSH-only activation (no WindowServer session for
        # primaryUser) must not abort the whole activation under
        # nix-darwin's `set -e` -- the osascript call has a non-fatal,
        # loud fallback.
        assert "|| echo" in rendered
        assert "no GUI session" in rendered

    def test_skipped_ephemeral_key_produces_no_manual_report_comment(self) -> None:
        # A key/value shaped to trip is_ephemeral()'s UI-state detection.
        domains = [_domain("com.apple.finder", {"NSWindowFrame": "0 0 100 100 0 0 1920 1080"})]
        system = SystemConfig(hostname="h", power_settings={})
        state = _state(preferences=PreferencesResult(domains=domains), system=system)

        rendered = generate_preferences(state).rendered
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

        rendered = generate_preferences(state).rendered

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

        rendered = generate_preferences(state).rendered

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
        power_settings={"ac_power.sleep": "0", "ac_power.autorestart": "0", "ac_power.womp": "1"},
        wallpaper_path=Path("/System/Library/Desktop Pictures/The Cliffs.heic"),
    )
    state = _state(preferences=PreferencesResult(domains=domains), system=system)

    rendered = generate_preferences(state).rendered
    module_path = tmp_path / "preferences.nix"
    module_path.write_text(rendered)

    # The two hardware-dependent settings now render as self-guarding
    # activation scripts (Step 14) -- confirm they actually rendered (not
    # silently dropped) before the nix-instantiate check below, so this
    # test would fail loudly if that branch stopped firing rather than
    # just passing trivially on empty activation-script output.
    assert "restart-after-power-failure" in rendered
    assert "wake-on-LAN" in rendered

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
    rendered = generate_preferences(state).rendered
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

    rendered = generate_preferences(state).rendered
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

    rendered = generate_preferences(state).rendered
    module_path = tmp_path / "preferences.nix"
    module_path.write_text(rendered)

    result = subprocess.run(  # noqa: S603
        ["nix-instantiate", "--parse", str(module_path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
