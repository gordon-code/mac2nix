"""Tests for preferences models."""

from pathlib import Path

from mac2nix.models import PreferencesDomain, PreferencesResult


class TestPreferencesDomain:
    def test_domain_with_various_value_types(self):
        domain = PreferencesDomain(
            domain_name="com.apple.dock",
            source_path=Path("~/Library/Preferences/com.apple.dock.plist"),
            keys={
                "autohide": True,
                "tilesize": 48,
                "magnification-size": 64.0,
                "orientation": "bottom",
                "persistent-apps": ["Safari", "Terminal"],
                "window-settings": {"alpha": 0.9},
            },
        )
        assert domain.domain_name == "com.apple.dock"
        assert domain.keys["autohide"] is True
        assert domain.keys["tilesize"] == 48
        assert domain.keys["magnification-size"] == 64.0
        assert domain.keys["orientation"] == "bottom"
        assert domain.keys["persistent-apps"] == ["Safari", "Terminal"]
        assert domain.keys["window-settings"] == {"alpha": 0.9}


class TestPreferencesResult:
    def test_multiple_domains(self):
        result = PreferencesResult(
            domains=[
                PreferencesDomain(
                    domain_name="com.apple.dock",
                    source_path=Path("~/Library/Preferences/com.apple.dock.plist"),
                    keys={"autohide": True},
                ),
                PreferencesDomain(
                    domain_name="com.apple.finder",
                    source_path=Path("~/Library/Preferences/com.apple.finder.plist"),
                    keys={"ShowPathbar": True, "ShowStatusBar": False},
                ),
            ]
        )
        assert len(result.domains) == 2
        assert result.domains[0].domain_name == "com.apple.dock"
        assert result.domains[1].domain_name == "com.apple.finder"

    def test_json_roundtrip(self):
        original = PreferencesResult(
            domains=[
                PreferencesDomain(
                    domain_name="com.apple.dock",
                    source_path=Path("~/Library/Preferences/com.apple.dock.plist"),
                    keys={"autohide": True, "tilesize": 48},
                ),
            ]
        )
        json_str = original.model_dump_json()
        restored = PreferencesResult.model_validate_json(json_str)
        assert restored.domains[0].domain_name == "com.apple.dock"
        assert restored.domains[0].keys["autohide"] is True
        assert restored.domains[0].keys["tilesize"] == 48
