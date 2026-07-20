"""Tests for library scanner."""

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mac2nix.models.files import ConfigFileType, LibraryResult
from mac2nix.scanners._utils import redact_sensitive_keys
from mac2nix.scanners.library_scanner import (
    _COVERED_DIRS,
    _SENSITIVE_VALUE_RE,
    _TRANSIENT_DIRS,
    LibraryScanner,
)


def _setup_app_support(tmp_path: Path) -> Path:
    app_support = tmp_path / "Library" / "Application Support"
    app_support.mkdir(parents=True)
    return app_support


class TestLibraryScanner:
    def test_name_property(self) -> None:
        assert LibraryScanner().name == "library"

    # --- App config tests (via scan()) ---

    def test_json_config(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "MyApp"
        app_dir.mkdir()
        (app_dir / "settings.json").write_text('{"key": "value"}')

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert len(result.app_configs) == 1
        assert result.app_configs[0].file_type == ConfigFileType.JSON
        assert result.app_configs[0].app_name == "MyApp"
        assert result.app_configs[0].scannable is True

    def test_plist_config(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "SomeApp"
        app_dir.mkdir()
        (app_dir / "config.plist").write_text("<plist></plist>")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.app_configs[0].file_type == ConfigFileType.PLIST
        assert result.app_configs[0].scannable is True

    def test_database_not_scannable(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "DBApp"
        app_dir.mkdir()
        (app_dir / "data.sqlite").write_bytes(b"SQLite format 3\x00")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.app_configs[0].file_type == ConfigFileType.DATABASE
        assert result.app_configs[0].scannable is False

    def test_unknown_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "OtherApp"
        app_dir.mkdir()
        (app_dir / "data.xyz").write_text("unknown format")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.app_configs[0].file_type == ConfigFileType.UNKNOWN

    def test_conf_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "ConfApp"
        app_dir.mkdir()
        (app_dir / "app.conf").write_text("[section]\nkey=value")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.app_configs[0].file_type == ConfigFileType.CONF

    def test_content_hash_computed(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "HashApp"
        app_dir.mkdir()
        (app_dir / "config.json").write_text('{"a": 1}')

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.app_configs[0].content_hash is not None
        assert len(result.app_configs[0].content_hash) == 16

    def test_empty_app_support(self, tmp_path: Path) -> None:
        _setup_app_support(tmp_path)

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.app_configs == []

    def test_database_hash_skipped(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "DBApp"
        app_dir.mkdir()
        (app_dir / "data.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert len(result.app_configs) == 1
        assert result.app_configs[0].file_type == ConfigFileType.DATABASE
        assert result.app_configs[0].scannable is False
        assert result.app_configs[0].content_hash is None

    def test_group_containers(self, tmp_path: Path) -> None:
        group_containers = tmp_path / "Library" / "Group Containers"
        group_containers.mkdir(parents=True)
        app_dir = group_containers / "group.com.example.app"
        app_dir.mkdir()
        (app_dir / "settings.json").write_text('{"key": "value"}')

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert len(result.app_configs) == 1
        assert result.app_configs[0].app_name == "group.com.example.app"
        assert result.app_configs[0].file_type == ConfigFileType.JSON

    def test_yaml_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "YamlApp"
        app_dir.mkdir()
        (app_dir / "config.yaml").write_text("key: value")
        (app_dir / "settings.yml").write_text("other: true")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert len(result.app_configs) == 2
        assert all(e.file_type == ConfigFileType.YAML for e in result.app_configs)

    def test_xml_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "XmlApp"
        app_dir.mkdir()
        (app_dir / "config.xml").write_text("<config/>")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert len(result.app_configs) == 1
        assert result.app_configs[0].file_type == ConfigFileType.XML

    def test_returns_library_result(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)

    def test_containers_app_support(self, tmp_path: Path) -> None:
        _setup_app_support(tmp_path)
        container = tmp_path / "Library" / "Containers" / "com.test.app" / "Data" / "Library" / "Application Support"
        container.mkdir(parents=True)
        app_dir = container / "TestApp"
        app_dir.mkdir()
        (app_dir / "config.json").write_text('{"key": "value"}')

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert len(result.app_configs) == 1
        assert result.app_configs[0].app_name == "TestApp"

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

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        paths = {str(e.path) for e in result.app_configs}
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

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert len(result.app_configs) == 1
        assert result.app_configs[0].path.name == "small.json"

    def test_processes_all_files_no_cap(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "ManyFilesApp"
        app_dir.mkdir()
        for i in range(501):
            (app_dir / f"file{i:04d}.json").write_text("{}")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        app_entries = [e for e in result.app_configs if e.app_name == "ManyFilesApp"]
        assert len(app_entries) == 501

    def test_skips_non_config_dirs(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "TestApp"
        app_dir.mkdir()
        (app_dir / "config.json").write_text("{}")
        for skip_name in ["node_modules", ".git", "Caches"]:
            skip_dir = app_dir / skip_name
            skip_dir.mkdir()
            (skip_dir / "junk.json").write_text("{}")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        app_entries = [e for e in result.app_configs if e.app_name == "TestApp"]
        paths = {str(e.path) for e in app_entries}
        assert any("config.json" in p for p in paths)
        assert not any("junk.json" in p for p in paths)

    def test_toml_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "TomlApp"
        app_dir.mkdir()
        (app_dir / "config.toml").write_text("[section]\nkey = 'value'")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.app_configs[0].file_type == ConfigFileType.TOML

    def test_ini_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "IniApp"
        app_dir.mkdir()
        (app_dir / "config.ini").write_text("[section]\nkey=value")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.app_configs[0].file_type == ConfigFileType.CONF

    def test_cfg_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "CfgApp"
        app_dir.mkdir()
        (app_dir / "app.cfg").write_text("key=value")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.app_configs[0].file_type == ConfigFileType.CONF

    def test_sqlite3_extension(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "Sqlite3App"
        app_dir.mkdir()
        (app_dir / "data.sqlite3").write_bytes(b"SQLite format 3\x00")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.app_configs[0].file_type == ConfigFileType.DATABASE
        assert result.app_configs[0].scannable is False

    def test_nested_config_files(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "Chrome"
        profile = app_dir / "Default"
        profile.mkdir(parents=True)
        (profile / "Preferences").write_text('{"key": "value"}')
        (app_dir / "Local State").write_text('{"other": true}')

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert len(result.app_configs) == 2

    def test_modified_time_set(self, tmp_path: Path) -> None:
        app_support = _setup_app_support(tmp_path)
        app_dir = app_support / "TimeApp"
        app_dir.mkdir()
        (app_dir / "config.json").write_text("{}")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.app_configs[0].modified_time is not None

    def test_permission_denied_containers(self, tmp_path: Path) -> None:
        _setup_app_support(tmp_path)
        containers = tmp_path / "Library" / "Containers"
        containers.mkdir(parents=True)

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch("pathlib.Path.iterdir", side_effect=PermissionError("denied")),
        ):
            # Should not crash — gracefully handles permission error
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)

    # --- Library audit tests ---

    def test_audit_directories_covered(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        prefs = lib / "Preferences"
        prefs.mkdir()
        (prefs / "com.apple.finder.plist").write_bytes(b"data")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        pref_dir = next(d for d in result.directories if d.name == "Preferences")
        assert pref_dir.covered_by_scanner == "preferences"
        assert pref_dir.has_user_content is False

    def test_audit_directories_uncovered(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        custom = lib / "CustomDir"
        custom.mkdir()
        (custom / "file.txt").write_text("hello")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        custom_dir = next(d for d in result.directories if d.name == "CustomDir")
        assert custom_dir.covered_by_scanner is None
        assert custom_dir.has_user_content is True

    def test_audit_directories_transient_not_user_content(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        caches = lib / "Caches"
        caches.mkdir()
        (caches / "something.cache").write_bytes(b"data")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        cache_dir = next(d for d in result.directories if d.name == "Caches")
        assert cache_dir.covered_by_scanner is None
        assert cache_dir.has_user_content is False

    def test_dir_stats(self, tmp_path: Path) -> None:
        (tmp_path / "file1.txt").write_text("hello")
        (tmp_path / "file2.txt").write_text("world!")

        file_count, total_size, newest_mod = LibraryScanner._dir_stats(tmp_path)

        assert file_count == 2
        assert total_size is not None
        assert total_size > 0
        assert newest_mod is not None

    def test_dir_stats_permission_denied(self, tmp_path: Path) -> None:
        protected = tmp_path / "protected"
        protected.mkdir()

        with patch.object(Path, "iterdir", side_effect=PermissionError("denied")):
            file_count, total_size, newest_mod = LibraryScanner._dir_stats(protected)

        assert file_count is None
        assert total_size is None
        assert newest_mod is None

    def test_classify_file_plist(self, tmp_path: Path) -> None:
        plist_file = tmp_path / "test.plist"
        plist_file.write_bytes(b"data")

        with (
            patch("mac2nix.scanners.library_scanner.read_plist_safe", return_value={"key": "value"}),
            patch("mac2nix.scanners.library_scanner.hash_file", return_value="abc123"),
        ):
            entry = LibraryScanner()._classify_file(plist_file)

        assert entry is not None
        assert entry.file_type == "plist"
        assert entry.migration_strategy == "plist_capture"
        assert entry.plist_content == {"key": "value"}

    def test_classify_file_text(self, tmp_path: Path) -> None:
        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("some text content")

        with patch("mac2nix.scanners.library_scanner.hash_file", return_value="def456"):
            entry = LibraryScanner()._classify_file(txt_file)

        assert entry is not None
        assert entry.file_type == "txt"
        assert entry.migration_strategy == "text_capture"
        assert entry.text_content == "some text content"

    def test_classify_file_text_too_large(self, tmp_path: Path) -> None:
        large_file = tmp_path / "big.txt"
        large_file.write_text("x" * 70000)

        with patch("mac2nix.scanners.library_scanner.hash_file", return_value="abc"):
            entry = LibraryScanner()._classify_file(large_file)

        assert entry is not None
        assert entry.migration_strategy == "hash_only"
        assert entry.text_content is None

    def test_classify_file_bundle_extension(self, tmp_path: Path) -> None:
        bundle = tmp_path / "plugin.component"
        bundle.write_bytes(b"data")

        with patch("mac2nix.scanners.library_scanner.hash_file", return_value="hash"):
            entry = LibraryScanner()._classify_file(bundle)

        assert entry is not None
        assert entry.migration_strategy == "bundle"

    def test_classify_file_unknown(self, tmp_path: Path) -> None:
        binary_file = tmp_path / "data.bin"
        binary_file.write_bytes(b"\x00\x01\x02")

        entry = LibraryScanner()._classify_file(binary_file)

        assert entry is not None
        assert entry.migration_strategy == "metadata_only"
        assert entry.content_hash is None

    def test_key_bindings(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        kb_dir = lib / "KeyBindings"
        kb_dir.mkdir(parents=True)
        kb_file = kb_dir / "DefaultKeyBinding.dict"
        kb_file.write_bytes(b"dummy")

        with patch(
            "mac2nix.scanners.library_scanner.read_plist_safe",
            return_value={"^w": "deleteWordBackward:", "~f": "moveWordForward:"},
        ):
            result = LibraryScanner()._scan_key_bindings(lib)

        assert len(result) == 2
        keys = {e.key for e in result}
        assert "^w" in keys
        assert "~f" in keys

    def test_key_bindings_no_file(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        result = LibraryScanner()._scan_key_bindings(lib)
        assert result == []

    def test_spelling_words(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        spelling = lib / "Spelling"
        spelling.mkdir(parents=True)
        local_dict = spelling / "LocalDictionary"
        local_dict.write_text("nix\ndarwin\nhomebrew\n")
        (spelling / "en_US").write_text("")

        words, dicts = LibraryScanner()._scan_spelling(lib)

        assert words == ["nix", "darwin", "homebrew"]
        assert "en_US" in dicts

    def test_spelling_no_dir(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        words, dicts = LibraryScanner()._scan_spelling(lib)
        assert words == []
        assert dicts == []

    def test_scan_workflows(self, tmp_path: Path) -> None:
        wf_dir = tmp_path / "Services"
        wf = wf_dir / "MyService.workflow"
        contents = wf / "Contents"
        contents.mkdir(parents=True)
        info = contents / "Info.plist"
        info.write_bytes(b"dummy")

        with patch(
            "mac2nix.scanners.library_scanner.read_plist_safe",
            return_value={"CFBundleIdentifier": "com.example.myservice"},
        ):
            result = LibraryScanner()._scan_workflows(wf_dir)

        assert len(result) == 1
        assert result[0].name == "MyService"
        assert result[0].identifier == "com.example.myservice"

    def test_scan_workflows_no_dir(self, tmp_path: Path) -> None:
        result = LibraryScanner()._scan_workflows(tmp_path / "nonexistent")
        assert result == []

    def test_scan_bundles_in_dir(self, tmp_path: Path) -> None:
        im_dir = tmp_path / "Input Methods"
        bundle = im_dir / "MyInput.app"
        contents = bundle / "Contents"
        contents.mkdir(parents=True)
        info = contents / "Info.plist"
        info.write_bytes(b"dummy")

        with patch(
            "mac2nix.scanners.library_scanner.read_plist_safe",
            return_value={
                "CFBundleIdentifier": "com.example.input",
                "CFBundleShortVersionString": "1.0",
            },
        ):
            result = LibraryScanner()._scan_bundles_in_dir(im_dir)

        assert len(result) == 1
        assert result[0].bundle_id == "com.example.input"
        assert result[0].version == "1.0"

    def test_scan_bundles_no_dir(self) -> None:
        result = LibraryScanner()._scan_bundles_in_dir(Path("/nonexistent"))
        assert result == []

    def test_list_files_by_extension(self, tmp_path: Path) -> None:
        (tmp_path / "layout1.keylayout").write_text("xml")
        (tmp_path / "layout2.keylayout").write_text("xml")
        (tmp_path / "other.txt").write_text("ignored")

        result = LibraryScanner._list_files_by_extension(tmp_path, ".keylayout")

        assert len(result) == 2
        assert "layout1.keylayout" in result
        assert "layout2.keylayout" in result

    def test_list_files_by_extension_no_dir(self) -> None:
        result = LibraryScanner._list_files_by_extension(Path("/nonexistent"), ".icc")
        assert result == []

    def test_scan_scripts_with_applescript(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        scripts = lib / "Scripts"
        scripts.mkdir(parents=True)
        scpt = scripts / "hello.scpt"
        scpt.write_bytes(b"compiled")
        sh = scripts / "cleanup.sh"
        sh.write_text("#!/bin/bash\necho cleanup")

        with patch(
            "mac2nix.scanners.library_scanner.run_command",
            return_value=MagicMock(returncode=0, stdout='display dialog "Hello"'),
        ):
            result = LibraryScanner()._scan_scripts(lib)

        assert len(result) == 2
        script_names = [s.split(":")[0] if ":" in s else s for s in result]
        assert "cleanup.sh" in script_names
        assert "hello.scpt" in script_names

    def test_scan_scripts_applescript_decompile_fails(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        scripts = lib / "Scripts"
        scripts.mkdir(parents=True)
        scpt = scripts / "broken.scpt"
        scpt.write_bytes(b"compiled")

        with patch("mac2nix.scanners.library_scanner.run_command", return_value=None):
            result = LibraryScanner()._scan_scripts(lib)

        assert result == ["broken.scpt"]

    def test_scan_scripts_no_dir(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        result = LibraryScanner()._scan_scripts(lib)
        assert result == []

    def test_text_replacements(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        ks_dir = lib / "KeyboardServices"
        ks_dir.mkdir(parents=True)
        db_path = ks_dir / "TextReplacements.db"
        db_path.write_bytes(b"dummy")

        mock_rows = [("omw", "On my way!"), ("addr", "123 Main St")]
        mock_cursor = type("MockCursor", (), {"fetchall": lambda _self: mock_rows})()
        mock_conn = type(
            "MockConn",
            (),
            {
                "execute": lambda _self, _query: mock_cursor,
                "close": lambda _self: None,
            },
        )()

        with patch("mac2nix.scanners.library_scanner.sqlite3.connect", return_value=mock_conn):
            result = LibraryScanner()._scan_text_replacements(lib)

        assert len(result) == 2
        assert result[0] == {"shortcut": "omw", "phrase": "On my way!"}

    def test_text_replacements_no_db(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        result = LibraryScanner()._scan_text_replacements(lib)
        assert result == []

    def test_capture_uncovered_dir_walks_all_files(self, tmp_path: Path) -> None:
        for i in range(210):
            (tmp_path / f"file{i:03d}.txt").write_text(f"content {i}")

        with (
            patch("mac2nix.scanners.library_scanner.hash_file", return_value="hash"),
            patch("mac2nix.scanners.library_scanner.read_plist_safe", return_value=None),
        ):
            files, _workflows, _bundles = LibraryScanner()._capture_uncovered_dir(tmp_path)

        assert len(files) == 210

    def test_capture_uncovered_dir_skips_non_config_dirs(self, tmp_path: Path) -> None:
        config_dir = tmp_path / "real_config"
        config_dir.mkdir()
        (config_dir / "settings.json").write_text("{}")

        for skip_name in ["node_modules", ".git", "Caches", "DerivedData"]:
            skip_dir = tmp_path / skip_name
            skip_dir.mkdir()
            (skip_dir / "junk.txt").write_text("should be skipped")

        with (
            patch("mac2nix.scanners.library_scanner.hash_file", return_value="hash"),
            patch("mac2nix.scanners.library_scanner.read_plist_safe", return_value=None),
        ):
            files, _workflows, _bundles = LibraryScanner()._capture_uncovered_dir(tmp_path)

        paths = {str(f.path) for f in files}
        assert any("settings.json" in p for p in paths)
        assert not any("junk.txt" in p for p in paths)

    def test_uncovered_files_collected(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        custom = lib / "CustomStuff"
        custom.mkdir()
        (custom / "config.json").write_text('{"key": "value"}')

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
            patch("mac2nix.scanners.library_scanner.hash_file", return_value="hash"),
            patch("mac2nix.scanners.library_scanner.read_plist_safe", return_value=None),
        ):
            result = LibraryScanner().scan()

        assert len(result.uncovered_files) >= 1
        json_file = next(f for f in result.uncovered_files if "config.json" in str(f.path))
        assert json_file.file_type == "json"

    def test_workflows_from_services_dir(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        services = lib / "Services"
        wf = services / "Convert.workflow"
        contents = wf / "Contents"
        contents.mkdir(parents=True)
        (contents / "Info.plist").write_bytes(b"dummy")

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
            patch(
                "mac2nix.scanners.library_scanner.read_plist_safe",
                return_value={"CFBundleIdentifier": "com.example.convert"},
            ),
        ):
            result = LibraryScanner().scan()

        assert any(w.name == "Convert" for w in result.workflows)

    def test_empty_library(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()

        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.directories == []
        assert result.uncovered_files == []

    def test_no_library_dir(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.library_scanner.Path.home", return_value=tmp_path),
            patch.object(LibraryScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryScanner().scan()

        assert isinstance(result, LibraryResult)
        assert result.directories == []


class TestRedactSensitiveKeys:
    def test_redacts_api_key(self) -> None:
        data = {"API_KEY": "secret123", "name": "test"}
        redact_sensitive_keys(data)

        redacted = "***REDACTED***"
        assert data["API_KEY"] == redacted
        assert data["name"] == "test"

    def test_redacts_nested_dict(self) -> None:
        data = {"config": {"DB_PASSWORD": "secret", "host": "localhost"}}
        redact_sensitive_keys(data)

        redacted = "***REDACTED***"
        assert data["config"]["DB_PASSWORD"] == redacted
        assert data["config"]["host"] == "localhost"

    def test_redacts_in_list(self) -> None:
        data = {"items": [{"ACCESS_TOKEN": "token123"}, {"normal": "value"}]}
        redact_sensitive_keys(data)

        redacted = "***REDACTED***"
        assert data["items"][0]["ACCESS_TOKEN"] == redacted
        assert data["items"][1]["normal"] == "value"

    def test_case_insensitive_match(self) -> None:
        data = {"my_auth_header": "Bearer xyz"}
        redact_sensitive_keys(data)

        redacted = "***REDACTED***"
        assert data["my_auth_header"] == redacted

    def test_no_sensitive_keys(self) -> None:
        data = {"name": "test", "count": 42}
        redact_sensitive_keys(data)
        assert data == {"name": "test", "count": 42}


class TestCoveredDirsMapping:
    def test_known_covered_dirs(self) -> None:
        assert _COVERED_DIRS["Preferences"] == "preferences"
        assert _COVERED_DIRS["Application Support"] == "library"
        assert _COVERED_DIRS["LaunchAgents"] == "launch_agents"
        assert _COVERED_DIRS["Fonts"] == "fonts"

    def test_transient_dirs(self) -> None:
        assert "Caches" in _TRANSIENT_DIRS
        assert "Logs" in _TRANSIENT_DIRS
        assert "Saved Application State" in _TRANSIENT_DIRS


class TestScanAudioPlugins:
    def test_finds_component_bundles(self, tmp_path: Path) -> None:
        components = tmp_path / "Components"
        components.mkdir()
        plugin = components / "MyPlugin.component"
        plugin.mkdir()
        info = plugin / "Contents" / "Info.plist"
        info.parent.mkdir()
        info.write_bytes(b"dummy")

        with patch(
            "mac2nix.scanners.library_scanner.read_plist_safe",
            return_value={"CFBundleIdentifier": "com.test.plugin", "CFBundleShortVersionString": "1.0"},
        ):
            result = LibraryScanner()._scan_audio_plugins(tmp_path)

        assert len(result) == 1
        assert result[0].name == "MyPlugin.component"
        assert result[0].bundle_id == "com.test.plugin"

    def test_skips_non_bundle_dirs(self, tmp_path: Path) -> None:
        components = tmp_path / "Components"
        components.mkdir()
        regular_dir = components / "NotABundle"
        regular_dir.mkdir()

        result = LibraryScanner()._scan_audio_plugins(tmp_path)
        assert result == []

    def test_empty_audio_dir(self, tmp_path: Path) -> None:
        result = LibraryScanner()._scan_audio_plugins(tmp_path / "nonexistent")
        assert result == []


class TestTextReplacementsCorrupted:
    def test_corrupted_db_returns_empty(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        ks_dir = lib / "KeyboardServices"
        ks_dir.mkdir(parents=True)
        db_path = ks_dir / "TextReplacements.db"
        db_path.write_bytes(b"not a sqlite database")

        with patch(
            "mac2nix.scanners.library_scanner.sqlite3.connect",
            side_effect=sqlite3.OperationalError("not a database"),
        ):
            result = LibraryScanner()._scan_text_replacements(lib)

        assert result == []

    def test_null_rows_filtered(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        ks_dir = lib / "KeyboardServices"
        ks_dir.mkdir(parents=True)
        db_path = ks_dir / "TextReplacements.db"
        db_path.write_bytes(b"dummy")

        mock_rows = [("omw", "On my way!"), (None, "no shortcut"), ("notext", None), (None, None)]
        mock_cursor = type("MockCursor", (), {"fetchall": lambda _self: mock_rows})()
        mock_conn = type(
            "MockConn",
            (),
            {
                "execute": lambda _self, _query: mock_cursor,
                "close": lambda _self: None,
            },
        )()

        with patch("mac2nix.scanners.library_scanner.sqlite3.connect", return_value=mock_conn):
            result = LibraryScanner()._scan_text_replacements(lib)

        assert len(result) == 1
        assert result[0] == {"shortcut": "omw", "phrase": "On my way!"}


class TestCaptureUncoveredDirEdgeCases:
    def test_processes_all_files_no_dir_cap(self, tmp_path: Path) -> None:
        for i in range(1050):
            (tmp_path / f"file{i:04d}.txt").write_text(f"content {i}")

        with (
            patch("mac2nix.scanners.library_scanner.hash_file", return_value="hash"),
            patch("mac2nix.scanners.library_scanner.read_plist_safe", return_value=None),
        ):
            files, _workflows, _bundles = LibraryScanner()._capture_uncovered_dir(tmp_path)

        assert len(files) == 1050

    def test_workflow_bundles_discovered(self, tmp_path: Path) -> None:
        wf = tmp_path / "MyAction.workflow"
        contents = wf / "Contents"
        contents.mkdir(parents=True)
        (contents / "Info.plist").write_bytes(b"dummy")

        with patch(
            "mac2nix.scanners.library_scanner.read_plist_safe",
            return_value={"CFBundleIdentifier": "com.example.action"},
        ):
            _files, workflows, _bundles = LibraryScanner()._capture_uncovered_dir(tmp_path)

        assert len(workflows) == 1
        assert workflows[0].name == "MyAction"
        assert workflows[0].identifier == "com.example.action"

    def test_bundle_dirs_discovered(self, tmp_path: Path) -> None:
        plugin = tmp_path / "MyPlugin.component"
        plugin_contents = plugin / "Contents"
        plugin_contents.mkdir(parents=True)
        (plugin_contents / "Info.plist").write_bytes(b"dummy")

        with patch(
            "mac2nix.scanners.library_scanner.read_plist_safe",
            return_value={"CFBundleIdentifier": "com.example.plugin", "CFBundleShortVersionString": "2.0"},
        ):
            _files, _workflows, bundles = LibraryScanner()._capture_uncovered_dir(tmp_path)

        assert len(bundles) == 1
        assert bundles[0].name == "MyPlugin.component"
        assert bundles[0].bundle_id == "com.example.plugin"
        assert bundles[0].bundle_type == "component"


class TestClassifyFileEdgeCases:
    def test_plist_returns_non_dict(self, tmp_path: Path) -> None:
        plist_file = tmp_path / "list.plist"
        plist_file.write_bytes(b"data")

        with (
            patch("mac2nix.scanners.library_scanner.read_plist_safe", return_value=["item1", "item2"]),
            patch("mac2nix.scanners.library_scanner.hash_file", return_value="abc123"),
        ):
            entry = LibraryScanner()._classify_file(plist_file)

        assert entry is not None
        assert entry.migration_strategy == "hash_only"
        assert entry.plist_content is None
        assert entry.content_hash == "abc123"

    def test_classify_file_non_config_extension_returns_none(self, tmp_path: Path) -> None:
        py_file = tmp_path / "script.py"
        py_file.write_text("print('hello')")

        assert LibraryScanner()._classify_file(py_file) is None

    def test_classify_file_redacts_sensitive_text(self, tmp_path: Path) -> None:
        conf_file = tmp_path / "app.conf"
        conf_file.write_text("host = localhost\npassword = secret123\nport = 8080\n")

        with patch("mac2nix.scanners.library_scanner.hash_file", return_value="hash"):
            entry = LibraryScanner()._classify_file(conf_file)

        assert entry is not None
        assert entry.text_content is not None
        assert "secret123" not in entry.text_content
        assert "***REDACTED***" in entry.text_content
        assert "localhost" in entry.text_content
        assert "8080" in entry.text_content


class TestSensitiveValueRedaction:
    """Test _SENSITIVE_VALUE_RE directly — no file I/O."""

    @pytest.mark.parametrize(
        ("line", "secret"),
        [
            # Bare standalone keys
            ("password = secret123", "secret123"),
            ("secret = mysecret", "mysecret"),
            ("token = ghp_abc", "ghp_abc"),
            ("passwd = hunter2", "hunter2"),
            # Compound keys with underscore
            ("db_password = xxx", "xxx"),
            ("api_key: sk-abc", "sk-abc"),
            ("SECRET_KEY = xxx", "xxx"),
            ("AUTH_TOKEN: ghp_xxx", "ghp_xxx"),
            # Compound keys with hyphen/dot
            ("access-token = xxx", "xxx"),
            ("auth.token: xxx", "xxx"),
            ("private-key = xxx", "xxx"),
            # No-space separators
            ("TOKEN=ghp_realtoken", "ghp_realtoken"),
            # JSON quoted keys
            ('"password": "secret123"', '"secret123"'),
            ('"api_key": "sk-abc"', '"sk-abc"'),
            # Indented (YAML)
            ("  password: secret123", "secret123"),
            ("  db_password: xxx", "xxx"),
        ],
        ids=lambda v: v[:25] if isinstance(v, str) else v,
    )
    def test_redacts_sensitive_values(self, line: str, secret: str) -> None:
        result = _SENSITIVE_VALUE_RE.sub(r"\1***REDACTED***", line)
        assert secret not in result
        assert "***REDACTED***" in result

    @pytest.mark.parametrize(
        ("line", "preserved_value"),
        [
            ("monkey = banana", "banana"),
            ("turkey = bird", "bird"),
            ("keyboard = us", "us"),
            ("author = John", "John"),
            ("hockey_score = 3", "3"),
            ("donkey_kong = mario", "mario"),
            ("host = localhost", "localhost"),
            ("port = 8080", "8080"),
            ("name = Alice", "Alice"),
        ],
        ids=lambda v: v[:25] if isinstance(v, str) else v,
    )
    def test_preserves_non_sensitive_values(self, line: str, preserved_value: str) -> None:
        result = _SENSITIVE_VALUE_RE.sub(r"\1***REDACTED***", line)
        assert result == line
        assert preserved_value in result


class TestKeyBindingsEdgeCases:
    def test_non_string_dict_actions_filtered(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        kb_dir = lib / "KeyBindings"
        kb_dir.mkdir(parents=True)
        (kb_dir / "DefaultKeyBinding.dict").write_bytes(b"dummy")

        with patch(
            "mac2nix.scanners.library_scanner.read_plist_safe",
            return_value={
                "^w": "deleteWordBackward:",
                "^x": 42,
                "^y": ["a", "b"],
                "^z": {"moveRight:": "moveWordRight:"},
            },
        ):
            result = LibraryScanner()._scan_key_bindings(lib)

        assert len(result) == 2
        keys = {e.key for e in result}
        assert "^w" in keys
        assert "^z" in keys
        assert "^x" not in keys
        assert "^y" not in keys


class TestScanSystemLibrary:
    def test_discovers_kext_bundles(self, tmp_path: Path) -> None:
        extensions = tmp_path / "Extensions"
        kext = extensions / "MyDriver.kext"
        kext_contents = kext / "Contents"
        kext_contents.mkdir(parents=True)
        (kext_contents / "Info.plist").write_bytes(b"dummy")

        with (
            patch("mac2nix.scanners.library_scanner.Path", wraps=Path) as mock_path,
            patch(
                "mac2nix.scanners.library_scanner.read_plist_safe",
                return_value={"CFBundleIdentifier": "com.example.driver", "CFBundleShortVersionString": "1.0"},
            ),
        ):
            mock_path.side_effect = lambda p: tmp_path if p == "/Library" else Path(p)
            scanner = LibraryScanner()
            # Directly call with our tmp_path standing in for /Library
            result = scanner._scan_bundles_in_dir(extensions)

        # At minimum, verify the bundle parsing works
        # (full _scan_system_library integration is hard to mock cleanly)
        assert len(result) == 1
        assert result[0].bundle_id == "com.example.driver"

    def test_discovers_audio_plugins(self, tmp_path: Path) -> None:
        components = tmp_path / "Components"
        components.mkdir()
        vst = components / "Synth.vst"
        vst_contents = vst / "Contents"
        vst_contents.mkdir(parents=True)
        (vst_contents / "Info.plist").write_bytes(b"dummy")

        with patch(
            "mac2nix.scanners.library_scanner.read_plist_safe",
            return_value={"CFBundleIdentifier": "com.example.synth"},
        ):
            result = LibraryScanner()._scan_audio_plugins(tmp_path)

        assert len(result) == 1
        assert result[0].bundle_id == "com.example.synth"
        assert result[0].bundle_type == "vst"

    def test_parse_bundle_fallback_info_plist(self, tmp_path: Path) -> None:
        bundle = tmp_path / "MyBundle.plugin"
        bundle.mkdir()
        # Info.plist at root level (no Contents/ dir)
        (bundle / "Info.plist").write_bytes(b"dummy")

        with patch(
            "mac2nix.scanners.library_scanner.read_plist_safe",
            return_value={"CFBundleIdentifier": "com.example.root"},
        ):
            result = LibraryScanner._parse_bundle(bundle)

        assert result.bundle_id == "com.example.root"

    def test_parse_bundle_no_info_plist(self, tmp_path: Path) -> None:
        bundle = tmp_path / "Empty.plugin"
        bundle.mkdir()

        result = LibraryScanner._parse_bundle(bundle)

        assert result.name == "Empty.plugin"
        assert result.bundle_id is None
        assert result.version is None
        assert result.bundle_type == "plugin"

    def test_parse_bundle_no_suffix(self, tmp_path: Path) -> None:
        bundle = tmp_path / "WeirdBundle"
        bundle.mkdir()

        result = LibraryScanner._parse_bundle(bundle)

        assert result.name == "WeirdBundle"
        assert result.bundle_type is None


class TestSymlinkSafety:
    def test_dir_stats_skips_symlinks(self, tmp_path: Path) -> None:
        (tmp_path / "real_file.txt").write_text("hello")
        (tmp_path / "link").symlink_to(tmp_path / "real_file.txt")

        file_count, _total_size, _ = LibraryScanner._dir_stats(tmp_path)

        # Symlink should be skipped — only real_file counted
        assert file_count == 1

    def test_scan_bundles_in_dir_skips_symlinks(self, tmp_path: Path) -> None:
        real_bundle = tmp_path / "Real.app"
        real_bundle.mkdir()
        (tmp_path / "Linked.app").symlink_to(real_bundle)

        result = LibraryScanner()._scan_bundles_in_dir(tmp_path)

        names = [b.name for b in result]
        assert "Real.app" in names
        assert "Linked.app" not in names


class TestScanAppDirEdgeCases:
    def test_scan_app_dir_skips_non_config_extensions(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "MyApp"
        app_dir.mkdir()
        (app_dir / "config.json").write_text('{"key": "value"}')
        (app_dir / "module.py").write_text("print('hello')")

        entries = LibraryScanner()._scan_app_dir(app_dir)

        paths = [e.path.name for e in entries]
        assert "config.json" in paths
        assert "module.py" not in paths

    def test_scan_app_dir_skips_noindex_dirs(self, tmp_path: Path) -> None:
        app_dir = tmp_path / "MyApp"
        app_dir.mkdir()
        noindex_dir = app_dir / "foo.noindex"
        noindex_dir.mkdir()
        (noindex_dir / "settings.json").write_text('{"hidden": true}')

        entries = LibraryScanner()._scan_app_dir(app_dir)

        paths = [str(e.path) for e in entries]
        assert not any("foo.noindex" in p for p in paths)
