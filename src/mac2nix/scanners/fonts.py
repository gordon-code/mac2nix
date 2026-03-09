"""Fonts scanner — discovers installed user and system fonts."""

from __future__ import annotations

import logging
from pathlib import Path

from mac2nix.models.files import FontEntry, FontSource, FontsResult
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

        return FontsResult(entries=entries)
