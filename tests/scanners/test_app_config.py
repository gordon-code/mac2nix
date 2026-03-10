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

    def test_yaml_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "YamlApp"
        app_dir.mkdir()
        (app_dir / "config.yaml").write_text("key: value")
        (app_dir / "settings.yml").write_text("other: true")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert len(result.entries) == 2
        assert all(e.file_type == ConfigFileType.YAML for e in result.entries)

    def test_xml_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "XmlApp"
        app_dir.mkdir()
        (app_dir / "config.xml").write_text("<config/>")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert len(result.entries) == 1
        assert result.entries[0].file_type == ConfigFileType.XML

    def test_returns_app_config_result(self, tmp_path: Path) -> None:
        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)

    def test_containers_app_support(self, tmp_path: Path) -> None:
        _setup_app_support(tmp_path)
        container = tmp_path / "Library" / "Containers" / "com.test.app" / "Data" / "Library" / "Application Support"
        container.mkdir(parents=True)
        app_dir = container / "TestApp"
        app_dir.mkdir()
        (app_dir / "config.json").write_text('{"key": "value"}')

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert len(result.entries) == 1
        assert result.entries[0].app_name == "TestApp"

    def test_skip_dirs_pruned(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "MyApp"
        app_dir.mkdir()
        (app_dir / "settings.json").write_text("{}")
        cache_dir = app_dir / "Caches"
        cache_dir.mkdir()
        (cache_dir / "cached.json").write_text("{}")
        git_dir = app_dir / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("[core]")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        paths = {str(e.path) for e in result.entries}
        assert any("settings.json" in p for p in paths)
        assert not any("Caches" in p for p in paths)
        assert not any(".git" in p for p in paths)

    def test_large_file_skipped(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "BigApp"
        app_dir.mkdir()
        (app_dir / "small.json").write_text("{}")
        big_file = app_dir / "huge.json"
        # Write just over 10MB
        big_file.write_bytes(b"x" * (10 * 1024 * 1024 + 1))

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert len(result.entries) == 1
        assert result.entries[0].path.name == "small.json"

    def test_max_files_per_app_cap(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "ManyFilesApp"
        app_dir.mkdir()
        # Create 501 files to hit the cap (500)
        for i in range(501):
            (app_dir / f"file{i:04d}.json").write_text("{}")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        app_entries = [e for e in result.entries if e.app_name == "ManyFilesApp"]
        assert len(app_entries) == 500

    def test_toml_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "TomlApp"
        app_dir.mkdir()
        (app_dir / "config.toml").write_text("[section]\nkey = 'value'")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert result.entries[0].file_type == ConfigFileType.TOML

    def test_ini_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "IniApp"
        app_dir.mkdir()
        (app_dir / "config.ini").write_text("[section]\nkey=value")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert result.entries[0].file_type == ConfigFileType.CONF

    def test_cfg_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "CfgApp"
        app_dir.mkdir()
        (app_dir / "app.cfg").write_text("key=value")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert result.entries[0].file_type == ConfigFileType.CONF

    def test_sqlite3_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "Sqlite3App"
        app_dir.mkdir()
        (app_dir / "data.sqlite3").write_bytes(b"SQLite format 3\x00")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert result.entries[0].file_type == ConfigFileType.DATABASE
        assert result.entries[0].scannable is False

    def test_nested_config_files(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "Chrome"
        profile = app_dir / "Default"
        profile.mkdir(parents=True)
        (profile / "Preferences").write_text('{"key": "value"}')
        (app_dir / "Local State").write_text('{"other": true}')

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert len(result.entries) == 2

    def test_modified_time_set(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "TimeApp"
        app_dir.mkdir()
        (app_dir / "config.json").write_text("{}")

        with patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path):
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
        assert result.entries[0].modified_time is not None

    def test_permission_denied_containers(self, tmp_path: Path) -> None:
        _setup_app_support(tmp_path)
        containers = tmp_path / "Library" / "Containers"
        containers.mkdir(parents=True)

        with (
            patch("mac2nix.scanners.app_config.Path.home", return_value=tmp_path),
            patch("pathlib.Path.iterdir", side_effect=PermissionError("denied")),
        ):
            # Should not crash — gracefully handles permission error
            result = AppConfigScanner().scan()

        assert isinstance(result, AppConfigResult)
