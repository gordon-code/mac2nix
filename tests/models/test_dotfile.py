"""Tests for dotfile, app config entry, and font models."""

from pathlib import Path

from mac2nix.models.files import (
    AppConfigEntry,
    ConfigFileType,
    DotfileEntry,
    DotfileManager,
    DotfilesResult,
    FontEntry,
    FontSource,
    FontsResult,
)


class TestDotfileEntry:
    def test_with_symlink_target(self):
        entry = DotfileEntry(
            path=Path("~/.zshrc"),
            symlink_target=Path("~/dotfiles/zshrc"),
            managed_by=DotfileManager.STOW,
        )
        assert entry.symlink_target == Path("~/dotfiles/zshrc")
        assert entry.managed_by == DotfileManager.STOW

    def test_managed_by_enum_values(self):
        for manager in DotfileManager:
            entry = DotfileEntry(path=Path("~/.bashrc"), managed_by=manager)
            assert entry.managed_by == manager
        assert DotfileManager.GIT == "git"
        assert DotfileManager.STOW == "stow"
        assert DotfileManager.MANUAL == "manual"
        assert DotfileManager.UNKNOWN == "unknown"

    def test_defaults(self):
        entry = DotfileEntry(path=Path("~/.vimrc"))
        assert entry.content_hash is None
        assert entry.managed_by == DotfileManager.UNKNOWN
        assert entry.symlink_target is None


class TestDotfilesResult:
    def test_with_entries(self):
        entries = [
            DotfileEntry(path=Path("~/.zshrc"), managed_by=DotfileManager.GIT),
            DotfileEntry(path=Path("~/.gitconfig"), managed_by=DotfileManager.MANUAL),
        ]
        result = DotfilesResult(entries=entries)
        assert len(result.entries) == 2
        assert result.entries[0].managed_by == DotfileManager.GIT

    def test_json_roundtrip(self):
        original = DotfilesResult(
            entries=[
                DotfileEntry(
                    path=Path("~/.zshrc"),
                    content_hash="abc123",
                    managed_by=DotfileManager.STOW,
                    symlink_target=Path("~/dotfiles/zshrc"),
                ),
            ],
        )
        json_str = original.model_dump_json()
        restored = DotfilesResult.model_validate_json(json_str)
        assert restored.entries[0].path == Path("~/.zshrc")
        assert restored.entries[0].content_hash == "abc123"
        assert restored.entries[0].symlink_target == Path("~/dotfiles/zshrc")


class TestAppConfigEntry:
    def test_database_not_scannable(self):
        entry = AppConfigEntry(
            app_name="Safari",
            app_bundle_id="com.apple.Safari",
            path=Path("~/Library/Safari/History.db"),
            file_type=ConfigFileType.DATABASE,
            scannable=False,
        )
        assert entry.scannable is False
        assert entry.file_type == ConfigFileType.DATABASE

    def test_defaults(self):
        entry = AppConfigEntry(
            app_name="iTerm2",
            path=Path("~/Library/Preferences/com.googlecode.iterm2.plist"),
        )
        assert entry.app_bundle_id is None
        assert entry.file_type == ConfigFileType.UNKNOWN
        assert entry.content_hash is None
        assert entry.scannable is True


class TestFontEntry:
    def test_user_source(self):
        entry = FontEntry(
            name="FiraCode-Regular.ttf",
            path=Path("~/Library/Fonts/FiraCode-Regular.ttf"),
            source=FontSource.USER,
        )
        assert entry.source == FontSource.USER
        assert entry.name == "FiraCode-Regular.ttf"

    def test_system_source(self):
        entry = FontEntry(
            name="Helvetica.ttc",
            path=Path("/Library/Fonts/Helvetica.ttc"),
            source=FontSource.SYSTEM,
        )
        assert entry.source == FontSource.SYSTEM


class TestFontsResult:
    def test_with_entries(self):
        entries = [
            FontEntry(
                name="FiraCode-Regular.ttf",
                path=Path("~/Library/Fonts/FiraCode-Regular.ttf"),
                source=FontSource.USER,
            ),
            FontEntry(
                name="Helvetica.ttc",
                path=Path("/Library/Fonts/Helvetica.ttc"),
                source=FontSource.SYSTEM,
            ),
        ]
        result = FontsResult(entries=entries)
        assert len(result.entries) == 2

    def test_json_roundtrip(self):
        original = FontsResult(
            entries=[
                FontEntry(
                    name="JetBrainsMono.ttf",
                    path=Path("~/Library/Fonts/JetBrainsMono.ttf"),
                    source=FontSource.USER,
                ),
            ],
        )
        json_str = original.model_dump_json()
        restored = FontsResult.model_validate_json(json_str)
        assert restored.entries[0].name == "JetBrainsMono.ttf"
        assert restored.entries[0].source == FontSource.USER
