"""Tests for generate_all() -- the preferences-scoped foundation of the `generate` orchestrator."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from mac2nix.generators import GenerateError, generate_all
from mac2nix.generators.scaffold import _read_template, _render_placeholders
from mac2nix.models.preferences import PreferencesDomain, PreferencesResult
from mac2nix.models.system import SystemConfig
from mac2nix.models.system_state import SystemState


def _register_fake_host(output_dir: Path, hostname: str, username: str = "testuser") -> Path:
    """Build a minimal, real-template-backed registered host without real age-keygen/sops.

    generate_all() only reads/writes configuration.nix and .mac2nix-meta.json
    -- it never touches secrets/flake.nix, so a full add_host() isn't needed
    for these unit tests.
    """
    host_dir = output_dir / "hosts" / "darwin" / hostname
    host_dir.mkdir(parents=True)
    template = _read_template("hosts", "darwin", "configuration.nix")
    (host_dir / "configuration.nix").write_text(_render_placeholders(template, hostname, username))
    meta = {"hostname": hostname, "username": username, "system": "aarch64-darwin", "age_public_key": "age1fake"}
    (host_dir / ".mac2nix-meta.json").write_text(json.dumps(meta))
    return host_dir


def _state(*, preferences: PreferencesResult | None, system: SystemConfig | None) -> SystemState:
    return SystemState(hostname="h", macos_version="26.0", architecture="arm64", preferences=preferences, system=system)


def _full_state() -> SystemState:
    domains = [PreferencesDomain(domain_name="com.apple.dock", keys={"tilesize": 48})]
    return _state(preferences=PreferencesResult(domains=domains), system=SystemConfig(hostname="h"))


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
