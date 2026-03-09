"""Tests for app config scanner."""

from pathlib import Path
from unittest.mock import patch

from mac2nix.models.files import AppConfigResult, ConfigFileType
from mac2nix.scanners.app_config import AppConfigScanner


def _setup_app_support(tmp_path: Path) -> Path:
    app_support = tmp_path / "Library" / "Application Support"
    app_support.mkdir(parents=True)
    return app_support


class TestAppConfigScanner:
    def test_name_property(self) -> None:
        assert AppConfigScanner().name == "app_config"

    def test_json_config(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "MyApp"
        app_dir.mkdir()
        (app_dir / "settings.json").write_text('{"key": "value"}')

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert len(result.entries) == 1
        assert result.entries[0].file_type == ConfigFileType.JSON
        assert result.entries[0].app_name == "MyApp"
        assert result.entries[0].scannable is True

    def test_plist_config(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "SomeApp"
        app_dir.mkdir()
        (app_dir / "config.plist").write_text("<plist></plist>")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert result.entries[0].file_type == ConfigFileType.PLIST
        assert result.entries[0].scannable is True

    def test_database_not_scannable(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "DBApp"
        app_dir.mkdir()
        (app_dir / "data.sqlite").write_bytes(b"SQLite format 3\x00")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert result.entries[0].file_type == ConfigFileType.DATABASE
        assert result.entries[0].scannable is False

    def test_unknown_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "OtherApp"
        app_dir.mkdir()
        (app_dir / "data.xyz").write_text("unknown format")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert result.entries[0].file_type == ConfigFileType.UNKNOWN

    def test_conf_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "ConfApp"
        app_dir.mkdir()
        (app_dir / "app.conf").write_text("[section]\nkey=value")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert result.entries[0].file_type == ConfigFileType.CONF

    def test_content_hash_computed(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "HashApp"
        app_dir.mkdir()
        (app_dir / "config.json").write_text('{"a": 1}')

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert result.entries[0].content_hash is not None
        assert len(result.entries[0].content_hash) == 16

    def test_empty_app_support(self, tmp_path: Path) -> None:
        _setup_app_support(tmp_path)

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert result.entries == []

    def test_database_hash_skipped(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "DBApp"
        app_dir.mkdir()
        (app_dir / "data.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert len(result.entries) == 1
        assert result.entries[0].file_type == ConfigFileType.DATABASE
        assert result.entries[0].scannable is False
        assert result.entries[0].content_hash is None

    def test_group_containers(self, tmp_path: Path) -> None:
        group_containers = tmp_path / "Library" / "Group Containers"
        group_containers.mkdir(parents=True)
        app_dir = group_containers / "group.com.example.app"
        app_dir.mkdir()
        (app_dir / "settings.json").write_text('{"key": "value"}')

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert len(result.entries) == 1
        assert result.entries[0].app_name == "group.com.example.app"
        assert result.entries[0].file_type == ConfigFileType.JSON

    def test_large_file_skipped(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "BigApp"
        app_dir.mkdir()
        large_file = app_dir / "huge.json"
        large_file.write_text("x")

        with (
            patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path),
            patch("mac2nix.scanners.app_config._MAX_FILE_SIZE", 0),
        ):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert result.entries == []

    def test_returns_app_config_result(self, tmp_path: Path) -> None:
        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
