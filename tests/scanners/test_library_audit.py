"""Tests for library audit scanner."""

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

from mac2nix.models.files import LibraryAuditResult
from mac2nix.scanners.library_audit import (
    _COVERED_DIRS,
    _TRANSIENT_DIRS,
    LibraryAuditScanner,
    _redact_sensitive_keys,
)


class TestLibraryAuditScanner:
    def test_name_property(self) -> None:
        assert LibraryAuditScanner().name == "library_audit"

    def test_returns_library_audit_result(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        with (
            patch("mac2nix.scanners.library_audit.Path.home", return_value=tmp_path),
            patch.object(LibraryAuditScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryAuditScanner().scan()

        assert isinstance(result, LibraryAuditResult)

    def test_audit_directories_covered(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        prefs = lib / "Preferences"
        prefs.mkdir()
        (prefs / "com.apple.finder.plist").write_bytes(b"data")

        with (
            patch("mac2nix.scanners.library_audit.Path.home", return_value=tmp_path),
            patch.object(LibraryAuditScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryAuditScanner().scan()

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
            patch("mac2nix.scanners.library_audit.Path.home", return_value=tmp_path),
            patch.object(LibraryAuditScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryAuditScanner().scan()

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
            patch("mac2nix.scanners.library_audit.Path.home", return_value=tmp_path),
            patch.object(LibraryAuditScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryAuditScanner().scan()

        cache_dir = next(d for d in result.directories if d.name == "Caches")
        assert cache_dir.covered_by_scanner is None
        assert cache_dir.has_user_content is False

    def test_dir_stats(self, tmp_path: Path) -> None:
        (tmp_path / "file1.txt").write_text("hello")
        (tmp_path / "file2.txt").write_text("world!")

        file_count, total_size, newest_mod = LibraryAuditScanner._dir_stats(tmp_path)

        assert file_count == 2
        assert total_size is not None
        assert total_size > 0
        assert newest_mod is not None

    def test_dir_stats_permission_denied(self, tmp_path: Path) -> None:
        protected = tmp_path / "protected"
        protected.mkdir()

        with patch.object(Path, "iterdir", side_effect=PermissionError("denied")):
            file_count, total_size, newest_mod = LibraryAuditScanner._dir_stats(protected)

        assert file_count is None
        assert total_size is None
        assert newest_mod is None

    def test_classify_file_plist(self, tmp_path: Path) -> None:
        plist_file = tmp_path / "test.plist"
        plist_file.write_bytes(b"data")

        with (
            patch("mac2nix.scanners.library_audit.read_plist_safe", return_value={"key": "value"}),
            patch("mac2nix.scanners.library_audit.hash_file", return_value="abc123"),
        ):
            entry = LibraryAuditScanner()._classify_file(plist_file)

        assert entry is not None
        assert entry.file_type == "plist"
        assert entry.migration_strategy == "plist_capture"
        assert entry.plist_content == {"key": "value"}

    def test_classify_file_text(self, tmp_path: Path) -> None:
        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("some text content")

        with patch("mac2nix.scanners.library_audit.hash_file", return_value="def456"):
            entry = LibraryAuditScanner()._classify_file(txt_file)

        assert entry is not None
        assert entry.file_type == "txt"
        assert entry.migration_strategy == "text_capture"
        assert entry.text_content == "some text content"

    def test_classify_file_text_too_large(self, tmp_path: Path) -> None:
        large_file = tmp_path / "big.txt"
        large_file.write_text("x" * 70000)

        with patch("mac2nix.scanners.library_audit.hash_file", return_value="abc"):
            entry = LibraryAuditScanner()._classify_file(large_file)

        assert entry is not None
        assert entry.migration_strategy == "hash_only"
        assert entry.text_content is None

    def test_classify_file_bundle_extension(self, tmp_path: Path) -> None:
        bundle = tmp_path / "plugin.component"
        bundle.write_bytes(b"data")

        with patch("mac2nix.scanners.library_audit.hash_file", return_value="hash"):
            entry = LibraryAuditScanner()._classify_file(bundle)

        assert entry is not None
        assert entry.migration_strategy == "bundle"

    def test_classify_file_unknown(self, tmp_path: Path) -> None:
        binary_file = tmp_path / "data.bin"
        binary_file.write_bytes(b"\x00\x01\x02")

        with patch("mac2nix.scanners.library_audit.hash_file", return_value="hash"):
            entry = LibraryAuditScanner()._classify_file(binary_file)

        assert entry is not None
        assert entry.migration_strategy == "hash_only"

    def test_key_bindings(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        kb_dir = lib / "KeyBindings"
        kb_dir.mkdir(parents=True)
        kb_file = kb_dir / "DefaultKeyBinding.dict"
        kb_file.write_bytes(b"dummy")

        with patch(
            "mac2nix.scanners.library_audit.read_plist_safe",
            return_value={"^w": "deleteWordBackward:", "~f": "moveWordForward:"},
        ):
            result = LibraryAuditScanner()._scan_key_bindings(lib)

        assert len(result) == 2
        keys = {e.key for e in result}
        assert "^w" in keys
        assert "~f" in keys

    def test_key_bindings_no_file(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        result = LibraryAuditScanner()._scan_key_bindings(lib)
        assert result == []

    def test_spelling_words(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        spelling = lib / "Spelling"
        spelling.mkdir(parents=True)
        local_dict = spelling / "LocalDictionary"
        local_dict.write_text("nix\ndarwin\nhomebrew\n")
        (spelling / "en_US").write_text("")

        words, dicts = LibraryAuditScanner()._scan_spelling(lib)

        assert words == ["nix", "darwin", "homebrew"]
        assert "en_US" in dicts

    def test_spelling_no_dir(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        words, dicts = LibraryAuditScanner()._scan_spelling(lib)
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
            "mac2nix.scanners.library_audit.read_plist_safe",
            return_value={"CFBundleIdentifier": "com.example.myservice"},
        ):
            result = LibraryAuditScanner()._scan_workflows(wf_dir)

        assert len(result) == 1
        assert result[0].name == "MyService"
        assert result[0].identifier == "com.example.myservice"

    def test_scan_workflows_no_dir(self, tmp_path: Path) -> None:
        result = LibraryAuditScanner()._scan_workflows(tmp_path / "nonexistent")
        assert result == []

    def test_scan_bundles_in_dir(self, tmp_path: Path) -> None:
        im_dir = tmp_path / "Input Methods"
        bundle = im_dir / "MyInput.app"
        contents = bundle / "Contents"
        contents.mkdir(parents=True)
        info = contents / "Info.plist"
        info.write_bytes(b"dummy")

        with patch(
            "mac2nix.scanners.library_audit.read_plist_safe",
            return_value={
                "CFBundleIdentifier": "com.example.input",
                "CFBundleShortVersionString": "1.0",
            },
        ):
            result = LibraryAuditScanner()._scan_bundles_in_dir(im_dir)

        assert len(result) == 1
        assert result[0].bundle_id == "com.example.input"
        assert result[0].version == "1.0"

    def test_scan_bundles_no_dir(self) -> None:
        result = LibraryAuditScanner()._scan_bundles_in_dir(Path("/nonexistent"))
        assert result == []

    def test_scan_file_hashes(self, tmp_path: Path) -> None:
        (tmp_path / "layout1.keylayout").write_text("xml")
        (tmp_path / "layout2.keylayout").write_text("xml")
        (tmp_path / "other.txt").write_text("ignored")

        result = LibraryAuditScanner._scan_file_hashes(tmp_path, ".keylayout")

        assert len(result) == 2
        assert "layout1.keylayout" in result
        assert "layout2.keylayout" in result

    def test_scan_file_hashes_no_dir(self) -> None:
        result = LibraryAuditScanner._scan_file_hashes(Path("/nonexistent"), ".icc")
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
            "mac2nix.scanners.library_audit.run_command",
            return_value=MagicMock(returncode=0, stdout='display dialog "Hello"'),
        ):
            result = LibraryAuditScanner()._scan_scripts(lib)

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

        with patch("mac2nix.scanners.library_audit.run_command", return_value=None):
            result = LibraryAuditScanner()._scan_scripts(lib)

        assert result == ["broken.scpt"]

    def test_scan_scripts_no_dir(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        result = LibraryAuditScanner()._scan_scripts(lib)
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

        with patch("mac2nix.scanners.library_audit.sqlite3.connect", return_value=mock_conn):
            result = LibraryAuditScanner()._scan_text_replacements(lib)

        assert len(result) == 2
        assert result[0] == {"shortcut": "omw", "phrase": "On my way!"}

    def test_text_replacements_no_db(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        result = LibraryAuditScanner()._scan_text_replacements(lib)
        assert result == []

    def test_capture_uncovered_dir_capped(self, tmp_path: Path) -> None:
        for i in range(210):
            (tmp_path / f"file{i:03d}.txt").write_text(f"content {i}")

        with (
            patch("mac2nix.scanners.library_audit.hash_file", return_value="hash"),
            patch("mac2nix.scanners.library_audit.read_plist_safe", return_value=None),
        ):
            files, _workflows = LibraryAuditScanner()._capture_uncovered_dir(tmp_path)

        assert len(files) <= 200

    def test_uncovered_files_collected(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()
        custom = lib / "CustomStuff"
        custom.mkdir()
        (custom / "config.json").write_text('{"key": "value"}')

        with (
            patch("mac2nix.scanners.library_audit.Path.home", return_value=tmp_path),
            patch.object(LibraryAuditScanner, "_scan_system_library", return_value=[]),
            patch("mac2nix.scanners.library_audit.hash_file", return_value="hash"),
            patch("mac2nix.scanners.library_audit.read_plist_safe", return_value=None),
        ):
            result = LibraryAuditScanner().scan()

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
            patch("mac2nix.scanners.library_audit.Path.home", return_value=tmp_path),
            patch.object(LibraryAuditScanner, "_scan_system_library", return_value=[]),
            patch(
                "mac2nix.scanners.library_audit.read_plist_safe",
                return_value={"CFBundleIdentifier": "com.example.convert"},
            ),
        ):
            result = LibraryAuditScanner().scan()

        assert any(w.name == "Convert" for w in result.workflows)

    def test_empty_library(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        lib.mkdir()

        with (
            patch("mac2nix.scanners.library_audit.Path.home", return_value=tmp_path),
            patch.object(LibraryAuditScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryAuditScanner().scan()

        assert isinstance(result, LibraryAuditResult)
        assert result.directories == []
        assert result.uncovered_files == []

    def test_no_library_dir(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.library_audit.Path.home", return_value=tmp_path),
            patch.object(LibraryAuditScanner, "_scan_system_library", return_value=[]),
        ):
            result = LibraryAuditScanner().scan()

        assert isinstance(result, LibraryAuditResult)
        assert result.directories == []


class TestRedactSensitiveKeys:
    def test_redacts_api_key(self) -> None:
        data = {"API_KEY": "secret123", "name": "test"}
        _redact_sensitive_keys(data)

        redacted = "***REDACTED***"
        assert data["API_KEY"] == redacted
        assert data["name"] == "test"

    def test_redacts_nested_dict(self) -> None:
        data = {"config": {"DB_PASSWORD": "secret", "host": "localhost"}}
        _redact_sensitive_keys(data)

        redacted = "***REDACTED***"
        assert data["config"]["DB_PASSWORD"] == redacted
        assert data["config"]["host"] == "localhost"

    def test_redacts_in_list(self) -> None:
        data = {"items": [{"ACCESS_TOKEN": "token123"}, {"normal": "value"}]}
        _redact_sensitive_keys(data)

        redacted = "***REDACTED***"
        assert data["items"][0]["ACCESS_TOKEN"] == redacted
        assert data["items"][1]["normal"] == "value"

    def test_case_insensitive_match(self) -> None:
        data = {"my_auth_header": "Bearer xyz"}
        _redact_sensitive_keys(data)

        redacted = "***REDACTED***"
        assert data["my_auth_header"] == redacted

    def test_no_sensitive_keys(self) -> None:
        data = {"name": "test", "count": 42}
        _redact_sensitive_keys(data)
        assert data == {"name": "test", "count": 42}


class TestCoveredDirsMapping:
    def test_known_covered_dirs(self) -> None:
        assert _COVERED_DIRS["Preferences"] == "preferences"
        assert _COVERED_DIRS["Application Support"] == "app_config"
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
            "mac2nix.scanners.library_audit.read_plist_safe",
            return_value={"CFBundleIdentifier": "com.test.plugin", "CFBundleShortVersionString": "1.0"},
        ):
            result = LibraryAuditScanner()._scan_audio_plugins(tmp_path)

        assert len(result) == 1
        assert result[0].name == "MyPlugin.component"
        assert result[0].bundle_id == "com.test.plugin"

    def test_skips_non_bundle_dirs(self, tmp_path: Path) -> None:
        components = tmp_path / "Components"
        components.mkdir()
        regular_dir = components / "NotABundle"
        regular_dir.mkdir()

        result = LibraryAuditScanner()._scan_audio_plugins(tmp_path)
        assert result == []

    def test_empty_audio_dir(self, tmp_path: Path) -> None:
        result = LibraryAuditScanner()._scan_audio_plugins(tmp_path / "nonexistent")
        assert result == []


class TestTextReplacementsCorrupted:
    def test_corrupted_db_returns_empty(self, tmp_path: Path) -> None:
        lib = tmp_path / "Library"
        ks_dir = lib / "KeyboardServices"
        ks_dir.mkdir(parents=True)
        db_path = ks_dir / "TextReplacements.db"
        db_path.write_bytes(b"not a sqlite database")

        with patch(
            "mac2nix.scanners.library_audit.sqlite3.connect",
            side_effect=sqlite3.OperationalError("not a database"),
        ):
            result = LibraryAuditScanner()._scan_text_replacements(lib)

        assert result == []
