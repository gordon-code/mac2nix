"""Tests for fonts scanner."""

from pathlib import Path
from unittest.mock import patch

from mac2nix.models.files import FontSource, FontsResult
from mac2nix.scanners.fonts import FontsScanner


class TestFontsScanner:
    def test_name_property(self) -> None:
        assert FontsScanner().name == "fonts"

    def test_user_fonts(self, tmp_path: Path) -> None:
        font_dir = tmp_path / "user_fonts"
        font_dir.mkdir()
        (font_dir / "Hack.ttf").write_bytes(b"\x00\x01\x00\x00")
        (font_dir / "Fira.otf").write_bytes(b"\x4f\x54\x54\x4f")

        with patch(
            "mac2nix.scanners.fonts._FONT_DIRS",
            [(font_dir, FontSource.USER)],
        ):
            result = FontsScanner().scan()

        assert isinstance(result, FontsResult)
        assert len(result.entries) == 2
        names = {e.name for e in result.entries}
        assert "Hack" in names
        assert "Fira" in names
        assert all(e.source == FontSource.USER for e in result.entries)

    def test_system_fonts(self, tmp_path: Path) -> None:
        font_dir = tmp_path / "system_fonts"
        font_dir.mkdir()
        (font_dir / "Arial.ttc").write_bytes(b"\x74\x74\x63\x66")

        with patch(
            "mac2nix.scanners.fonts._FONT_DIRS",
            [(font_dir, FontSource.SYSTEM)],
        ):
            result = FontsScanner().scan()

        assert isinstance(result, FontsResult)
        assert len(result.entries) == 1
        assert result.entries[0].source == FontSource.SYSTEM

    def test_non_font_files_excluded(self, tmp_path: Path) -> None:
        font_dir = tmp_path / "fonts"
        font_dir.mkdir()
        (font_dir / "readme.txt").write_text("Not a font")
        (font_dir / "license.pdf").write_bytes(b"%PDF")
        (font_dir / "Mono.ttf").write_bytes(b"\x00\x01\x00\x00")

        with patch(
            "mac2nix.scanners.fonts._FONT_DIRS",
            [(font_dir, FontSource.USER)],
        ):
            result = FontsScanner().scan()

        assert isinstance(result, FontsResult)
        assert len(result.entries) == 1
        assert result.entries[0].name == "Mono"

    def test_woff_extensions(self, tmp_path: Path) -> None:
        font_dir = tmp_path / "fonts"
        font_dir.mkdir()
        (font_dir / "Web.woff").write_bytes(b"wOFF")
        (font_dir / "Web2.woff2").write_bytes(b"wOF2")

        with patch(
            "mac2nix.scanners.fonts._FONT_DIRS",
            [(font_dir, FontSource.USER)],
        ):
            result = FontsScanner().scan()

        assert isinstance(result, FontsResult)
        assert len(result.entries) == 2

    def test_empty_dirs(self, tmp_path: Path) -> None:
        font_dir = tmp_path / "fonts"
        font_dir.mkdir()

        with patch(
            "mac2nix.scanners.fonts._FONT_DIRS",
            [(font_dir, FontSource.USER)],
        ):
            result = FontsScanner().scan()

        assert isinstance(result, FontsResult)
        assert result.entries == []

    def test_nonexistent_dir(self) -> None:
        with patch(
            "mac2nix.scanners.fonts._FONT_DIRS",
            [(Path("/nonexistent/fonts"), FontSource.USER)],
        ):
            result = FontsScanner().scan()

        assert isinstance(result, FontsResult)
        assert result.entries == []

    def test_returns_fonts_result(self) -> None:
        with patch("mac2nix.scanners.fonts._FONT_DIRS", []):
            result = FontsScanner().scan()

        assert isinstance(result, FontsResult)
