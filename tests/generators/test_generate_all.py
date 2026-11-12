"""Tests for generate_all() -- the preferences-scoped foundation of the `generate` orchestrator."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from mac2nix.generators import GenerateError, generate_all
from mac2nix.models.preferences import PreferencesDomain, PreferencesResult
from mac2nix.models.system import SystemConfig
from mac2nix.models.system_state import SystemState
from tests._generate_helpers import _register_fake_host


def _state(*, preferences: PreferencesResult | None, system: SystemConfig | None) -> SystemState:
    return SystemState(hostname="h", macos_version="26.0", architecture="arm64", preferences=preferences, system=system)


def _full_state() -> SystemState:
    domains = [PreferencesDomain(domain_name="com.apple.dock", keys={"tilesize": 48})]
    return _state(preferences=PreferencesResult(domains=domains), system=SystemConfig(hostname="h"))


def _state_with_wallpaper(wallpaper_path: Path) -> SystemState:
    domains = [PreferencesDomain(domain_name="com.apple.dock", keys={"tilesize": 48})]
    system = SystemConfig(hostname="h", wallpaper_path=wallpaper_path)
    return _state(preferences=PreferencesResult(domains=domains), system=system)


_JPEG_MAGIC = b"\xff\xd8\xff\xe0" + b"\x00" * 50


class TestGenerateAll:
    def test_writes_preferences_and_updates_imports(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        host_dir = _register_fake_host(output_dir, "myhost")

        # Hand-added content outside the sentinel markers must survive regeneration.
        config_path = host_dir / "configuration.nix"
        hand_added = 'system.stateVersion = 7;\n  networking.hostName = "myhost";'
        config_path.write_text(config_path.read_text().replace("system.stateVersion = 7;", hand_added))

        result = generate_all(_full_state(), output_dir, "myhost", {"preferences"})

        assert result.ran == {"preferences"}
        assert result.skipped == {}
        assert result.unrecognized == frozenset()
        assert result.homebrew_audit_manifest is None

        assert (host_dir / "preferences.nix").exists()
        rendered_config = config_path.read_text()
        assert "./preferences.nix" in rendered_config
        assert 'networking.hostName = "myhost";' in rendered_config

    def test_missing_system_domain_skips_preferences(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        _register_fake_host(output_dir, "myhost")
        domains = [PreferencesDomain(domain_name="com.apple.dock", keys={"tilesize": 48})]
        state = _state(preferences=PreferencesResult(domains=domains), system=None)

        result = generate_all(state, output_dir, "myhost", {"preferences"})

        assert result.ran == set()
        assert result.skipped == {"preferences": "not scanned"}

    def test_repeatable_generate_keeps_file_in_imports_with_empty_domains(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        host_dir = _register_fake_host(output_dir, "myhost")

        generate_all(_full_state(), output_dir, "myhost", {"preferences"})
        assert (host_dir / "preferences.nix").exists()

        result = generate_all(_full_state(), output_dir, "myhost", set())

        assert result.ran == set()
        assert result.skipped == {}
        config_content = (host_dir / "configuration.nix").read_text()
        assert "./preferences.nix" in config_content

    def test_unregistered_host_raises_and_writes_nothing(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        output_dir.mkdir(parents=True)

        with pytest.raises(GenerateError):
            generate_all(_full_state(), output_dir, "ghost-host", {"preferences"})

        assert not (output_dir / "hosts" / "darwin" / "ghost-host").exists()

    def test_unrecognized_domain_returns_without_raising(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        _register_fake_host(output_dir, "myhost")

        result = generate_all(_full_state(), output_dir, "myhost", {"bogus"})

        assert result.ran == set()
        assert result.skipped == {}
        assert result.unrecognized == frozenset({"bogus"})
        assert result.homebrew_audit_manifest is None

    def test_hand_edited_imports_section_warns_but_still_overwrites(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        output_dir = tmp_path / "repo"
        host_dir = _register_fake_host(output_dir, "myhost")

        generate_all(_full_state(), output_dir, "myhost", {"preferences"})

        # Simulate a hand-edit of the generated-imports section.
        config_path = host_dir / "configuration.nix"
        content = config_path.read_text()
        hand_edited = content.replace(
            "imports = [ ./preferences.nix ];", "imports = [ ./preferences.nix ./hand-added.nix ];"
        )
        config_path.write_text(hand_edited)

        with caplog.at_level(logging.WARNING):
            generate_all(_full_state(), output_dir, "myhost", {"preferences"})

        assert any("hand-edit" in record.message for record in caplog.records)
        # Still overwrites -- the hand-added import doesn't survive.
        assert "hand-added.nix" not in config_path.read_text()

    def test_missing_sentinel_markers_raise_clear_generate_error(self, tmp_path: Path) -> None:
        """A stripped/corrupted sentinel pair must raise a purpose-written
        GenerateError, not a raw, unhelpful `ValueError: substring not found`.
        """
        output_dir = tmp_path / "repo"
        host_dir = _register_fake_host(output_dir, "myhost")
        config_path = host_dir / "configuration.nix"
        stripped = config_path.read_text().replace(
            "  # MAC2NIX:GENERATE:BEGIN -- generated by `mac2nix generate`; do not edit by hand\n"
            "  # MAC2NIX:GENERATE:END\n",
            "",
        )
        config_path.write_text(stripped)

        with pytest.raises(GenerateError, match="sentinel"):
            generate_all(_full_state(), output_dir, "myhost", {"preferences"})

        # generate_all()'s documented partial-failure guarantee: a domain
        # generator that already ran and wrote its file before the later
        # sentinel-parsing failure must have that file survive on disk.
        assert (host_dir / "preferences.nix").exists()

    def test_missing_configuration_nix_raises_clear_generate_error(self, tmp_path: Path) -> None:
        """A registered host whose configuration.nix was deleted must raise a
        purpose-written GenerateError, not a raw `FileNotFoundError`.
        """
        output_dir = tmp_path / "repo"
        host_dir = _register_fake_host(output_dir, "myhost")
        config_path = host_dir / "configuration.nix"
        config_path.unlink()

        with pytest.raises(GenerateError, match="is missing or is not a regular file"):
            generate_all(_full_state(), output_dir, "myhost", {"preferences"})

        # generate_all()'s documented partial-failure guarantee: a domain
        # generator that already ran and wrote its file before the later
        # missing-configuration.nix failure must have that file survive on disk.
        assert (host_dir / "preferences.nix").exists()

    def test_configuration_nix_replaced_with_directory_raises_clear_generate_error(self, tmp_path: Path) -> None:
        """A registered host whose configuration.nix was replaced with a directory
        must raise the same purpose-written GenerateError, not a raw
        `IsADirectoryError` -- `is_file()` is False for both this and the
        deleted-file case, so both must be guarded identically.
        """
        output_dir = tmp_path / "repo"
        host_dir = _register_fake_host(output_dir, "myhost")
        config_path = host_dir / "configuration.nix"
        config_path.unlink()
        config_path.mkdir()

        with pytest.raises(GenerateError, match="is missing or is not a regular file"):
            generate_all(_full_state(), output_dir, "myhost", {"preferences"})

        assert (host_dir / "preferences.nix").exists()

    def test_corrupt_meta_file_handled_gracefully(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """A hand-corrupted `.mac2nix-meta.json` must not crash generate_all() or
        spuriously warn -- mirrors test_scaffold.py's
        test_corrupt_state_file_handled_gracefully for add_host()'s analogous
        `.mac2nix-state.json` mechanism.
        """
        output_dir = tmp_path / "repo"
        host_dir = _register_fake_host(output_dir, "myhost")

        generate_all(_full_state(), output_dir, "myhost", {"preferences"})

        (host_dir / ".mac2nix-meta.json").write_text("{not valid json")

        with caplog.at_level(logging.WARNING):
            result = generate_all(_full_state(), output_dir, "myhost", {"preferences"})

        assert not caplog.records
        assert result.ran == {"preferences"}
        assert result.skipped == {}
        assert (host_dir / "preferences.nix").exists()


class TestGenerateAllWallpaperAsset:
    def _bundleable_wallpaper_source(self, tmp_path: Path) -> tuple[Path, Path]:
        home = tmp_path / "home"
        (home / "Pictures").mkdir(parents=True)
        source = home / "Pictures" / "sunset.jpg"
        source.write_bytes(_JPEG_MAGIC)
        return home, source

    def test_writes_bundled_wallpaper_asset_alongside_preferences(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        host_dir = _register_fake_host(output_dir, "myhost")
        home, source = self._bundleable_wallpaper_source(tmp_path)

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = generate_all(_state_with_wallpaper(source), output_dir, "myhost", {"preferences"})

        assert result.ran == {"preferences"}
        asset_path = host_dir / "assets" / "wallpaper.jpg"
        assert asset_path.is_file()
        assert asset_path.read_bytes() == _JPEG_MAGIC
        assert "toString ./assets/wallpaper.jpg" in (host_dir / "preferences.nix").read_text()

    def test_second_generate_with_unchanged_wallpaper_does_not_rewrite_asset(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        host_dir = _register_fake_host(output_dir, "myhost")
        home, source = self._bundleable_wallpaper_source(tmp_path)

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            generate_all(_state_with_wallpaper(source), output_dir, "myhost", {"preferences"})
            asset_path = host_dir / "assets" / "wallpaper.jpg"
            mtime_before = asset_path.stat().st_mtime_ns

            generate_all(_state_with_wallpaper(source), output_dir, "myhost", {"preferences"})

        assert asset_path.stat().st_mtime_ns == mtime_before

    def test_hand_edited_asset_warns_but_still_overwrites(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        output_dir = tmp_path / "repo"
        host_dir = _register_fake_host(output_dir, "myhost")
        home, source = self._bundleable_wallpaper_source(tmp_path)

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            generate_all(_state_with_wallpaper(source), output_dir, "myhost", {"preferences"})
            asset_path = host_dir / "assets" / "wallpaper.jpg"
            asset_path.write_bytes(b"hand-edited content")

            with caplog.at_level(logging.WARNING):
                generate_all(_state_with_wallpaper(source), output_dir, "myhost", {"preferences"})

        assert any("hand-edit" in record.message for record in caplog.records)
        assert asset_path.read_bytes() == _JPEG_MAGIC

    def test_corrupt_meta_file_still_writes_asset(self, tmp_path: Path) -> None:
        """`_write_wallpaper_asset`'s `_read_host_meta` exception path (`meta = None`
        on a corrupt/unreadable `.mac2nix-meta.json`) is only reached when a wallpaper
        asset actually needs writing -- `test_corrupt_meta_file_handled_gracefully`
        (this module) covers the exception path in isolation but never with a
        wallpaper present, so the `meta = None` fallback inside this specific function
        was untested. The asset write itself must still succeed even though the
        hash-tracking/hand-edit-warning half of the function can't run without meta.
        """
        output_dir = tmp_path / "repo"
        host_dir = _register_fake_host(output_dir, "myhost")
        home, source = self._bundleable_wallpaper_source(tmp_path)
        (host_dir / ".mac2nix-meta.json").write_text("{not valid json")

        with patch("mac2nix.generators.preferences.Path.home", return_value=home):
            result = generate_all(_state_with_wallpaper(source), output_dir, "myhost", {"preferences"})

        assert result.ran == {"preferences"}
        asset_path = host_dir / "assets" / "wallpaper.jpg"
        assert asset_path.is_file()
        assert asset_path.read_bytes() == _JPEG_MAGIC
