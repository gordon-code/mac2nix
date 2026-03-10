"""Fonts scanner — discovers installed user and system fonts."""

from __future__ import annotations

import logging
from pathlib import Path

from mac2nix.models.files import FontCollection, FontEntry, FontSource, FontsResult
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_FONT_DIRS: list[tuple[Path, FontSource]] = [
    (Path.home() / "Library" / "Fonts", FontSource.USER),
    (Path("/Library/Fonts"), FontSource.SYSTEM),
]

_FONT_EXTENSIONS = frozenset({".ttf", ".otf", ".ttc", ".woff", ".woff2"})


@register("fonts")
class FontsScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "fonts"

    def scan(self) -> FontsResult:
        entries: list[FontEntry] = []

        for font_dir, source in _FONT_DIRS:
            if not font_dir.exists():
                continue
            try:
                children = sorted(font_dir.iterdir())
            except PermissionError:
                logger.warning("Permission denied reading font directory: %s", font_dir)
                continue
            for font_path in children:
                if font_path.is_file() and font_path.suffix.lower() in _FONT_EXTENSIONS:
                    entries.append(
                        FontEntry(
                            name=font_path.stem,
                            path=font_path,
                            source=source,
                        )
                    )

        collections = self._get_font_collections()
        return FontsResult(entries=entries, collections=collections)

    def _get_font_collections(self) -> list[FontCollection]:
        """Scan ~/Library/FontCollections/ for font collection files."""
        collections_dir = Path.home() / "Library" / "FontCollections"
        if not collections_dir.is_dir():
            return []
        collections: list[FontCollection] = []
        try:
            for path in sorted(collections_dir.iterdir()):
                if path.is_file() and path.suffix.lower() == ".collection":
                    collections.append(FontCollection(name=path.stem, path=path))
        except PermissionError:
            logger.warning("Permission denied reading font collections: %s", collections_dir)
        return collections
