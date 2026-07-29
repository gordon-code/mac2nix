"""Tests for the app_config_registry mapping."""

from mac2nix.mappings.app_config_registry import (
    APP_CONFIG_REGISTRY,
    AppConfigInfo,
    get_app_config,
)
from mac2nix.models.files import ConfigFileType


class TestGetAppConfig:
    def test_known_bundle_id(self) -> None:
        info = get_app_config("com.apple.Safari")
        assert info is not None
        assert info.file_type == ConfigFileType.DATABASE
        assert info.scannable is False

    def test_unknown_bundle_id_returns_none(self) -> None:
        assert get_app_config("com.example.NotARealApp") is None

    def test_case_sensitive_lookup(self) -> None:
        assert get_app_config("com.apple.safari") is None


class TestAppConfigRegistry:
    def test_registry_has_minimum_entries(self) -> None:
        assert len(APP_CONFIG_REGISTRY) >= 20

    def test_all_entries_are_app_config_info(self) -> None:
        for info in APP_CONFIG_REGISTRY.values():
            assert isinstance(info, AppConfigInfo)
            assert len(info.config_paths) > 0

    def test_safari_history_is_database_and_not_scannable(self) -> None:
        info = APP_CONFIG_REGISTRY["com.apple.Safari"]
        assert info.file_type == ConfigFileType.DATABASE
        assert info.scannable is False
        assert info.config_paths == ("~/Library/Safari/History.db",)

    def test_vscode_settings_are_json_and_scannable(self) -> None:
        info = APP_CONFIG_REGISTRY["com.microsoft.VSCode"]
        assert info.file_type == ConfigFileType.JSON
        assert info.scannable is True
        assert "~/Library/Application Support/Code/User/settings.json" in info.config_paths

    def test_spotify_prefs_are_conf(self) -> None:
        info = APP_CONFIG_REGISTRY["com.spotify.client"]
        assert info.file_type == ConfigFileType.CONF
        assert info.scannable is True

    def test_at_least_one_database_entry_not_scannable(self) -> None:
        database_entries = [info for info in APP_CONFIG_REGISTRY.values() if info.file_type == ConfigFileType.DATABASE]
        assert len(database_entries) >= 1
        assert all(not info.scannable for info in database_entries)

    def test_docker_settings_are_json(self) -> None:
        info = APP_CONFIG_REGISTRY["com.docker.docker"]
        assert info.file_type == ConfigFileType.JSON
        assert info.config_paths == ("~/Library/Group Containers/group.com.docker/settings.json",)

    def test_notes_default_to_none(self) -> None:
        info = AppConfigInfo(config_paths=("~/foo",), file_type=ConfigFileType.UNKNOWN)
        assert info.notes is None
        assert info.scannable is True
