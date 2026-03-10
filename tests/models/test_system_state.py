"""Tests for SystemState model."""

import json
from datetime import UTC, datetime
from pathlib import Path

from mac2nix.models import (
    BrewFormula,
    HomebrewState,
    LibraryAuditResult,
    PreferencesDomain,
    PreferencesResult,
    SystemState,
)


class TestSystemState:
    def test_minimal_creation(self):
        state = SystemState(
            hostname="test-mac",
            macos_version="15.3",
            architecture="arm64",
        )
        assert state.hostname == "test-mac"
        assert state.macos_version == "15.3"
        assert state.architecture == "arm64"
        assert state.scan_timestamp is not None

    def test_optional_domains_default_none(self):
        state = SystemState(
            hostname="test-mac",
            macos_version="15.3",
            architecture="arm64",
        )
        assert state.preferences is None
        assert state.applications is None
        assert state.homebrew is None

    def test_serialization_roundtrip(self):
        original = SystemState(
            hostname="test-mac",
            scan_timestamp=datetime(2026, 3, 5, 12, 0, 0, tzinfo=UTC),
            macos_version="15.3",
            architecture="arm64",
        )
        json_str = original.to_json()
        restored = SystemState.from_json(json_str)
        assert restored.hostname == original.hostname
        assert restored.macos_version == original.macos_version
        assert restored.architecture == original.architecture
        assert restored.scan_timestamp == original.scan_timestamp

    def test_to_json_writes_file(self, tmp_path):
        state = SystemState(
            hostname="test-mac",
            scan_timestamp=datetime(2026, 3, 5, 12, 0, 0, tzinfo=UTC),
            macos_version="15.3",
            architecture="arm64",
        )
        output = tmp_path / "state.json"
        state.to_json(output)
        assert output.exists()
        loaded = json.loads(output.read_text())
        assert loaded["hostname"] == "test-mac"

    def test_from_json_file(self, tmp_path):
        state = SystemState(
            hostname="file-test",
            scan_timestamp=datetime(2026, 3, 5, 12, 0, 0, tzinfo=UTC),
            macos_version="15.3",
            architecture="x86_64",
        )
        path = tmp_path / "state.json"
        state.to_json(path)
        restored = SystemState.from_json(path)
        assert restored.hostname == "file-test"
        assert restored.architecture == "x86_64"

    def test_with_domain_data(self):
        prefs = PreferencesResult(
            domains=[
                PreferencesDomain(
                    domain_name="com.apple.dock",
                    source_path=Path("~/Library/Preferences/com.apple.dock.plist"),
                    keys={"autohide": True},
                ),
            ]
        )
        brew = HomebrewState(
            formulae=[BrewFormula(name="git"), BrewFormula(name="ripgrep")],
        )
        state = SystemState(
            hostname="test-mac",
            macos_version="15.3",
            architecture="arm64",
            preferences=prefs,
            homebrew=brew,
        )
        json_str = state.to_json()
        restored = SystemState.from_json(json_str)
        assert restored.preferences is not None
        assert len(restored.preferences.domains) == 1
        assert restored.preferences.domains[0].domain_name == "com.apple.dock"
        assert restored.homebrew is not None
        assert len(restored.homebrew.formulae) == 2

    def test_library_audit_field(self):
        state = SystemState(
            hostname="test-mac",
            macos_version="15.3",
            architecture="arm64",
            library_audit=LibraryAuditResult(
                spelling_words=["nix", "darwin"],
                keyboard_layouts=["US"],
            ),
        )
        assert state.library_audit is not None
        assert state.library_audit.spelling_words == ["nix", "darwin"]

    def test_library_audit_default_none(self):
        state = SystemState(
            hostname="test-mac",
            macos_version="15.3",
            architecture="arm64",
        )
        assert state.library_audit is None
