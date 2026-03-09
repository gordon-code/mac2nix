"""Dotfiles scanner — discovers dotfile configuration files and their managers."""

from __future__ import annotations

import logging
from pathlib import Path

from mac2nix.models.files import DotfileEntry, DotfileManager, DotfilesResult
from mac2nix.scanners._utils import hash_file
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_KNOWN_DOTFILES = [
    ".zshrc",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".gitconfig",
    ".gitignore_global",
    ".ssh/config",
    ".hushlogin",
    ".vimrc",
    ".tmux.conf",
    ".editorconfig",
]

_SCAN_DIRS = [
    ".config",
    ".local/share",
]


@register("dotfiles")
class DotfilesScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "dotfiles"

    def scan(self) -> DotfilesResult:
        home = Path.home()
        entries: list[DotfileEntry] = []

        # Known dotfiles
        for dotfile in _KNOWN_DOTFILES:
            path = home / dotfile
            if path.exists():
                entry = self._make_entry(path, home)
                if entry is not None:
                    entries.append(entry)

        # Scan directories (first-level entries only)
        for scan_dir in _SCAN_DIRS:
            dir_path = home / scan_dir
            if not dir_path.is_dir():
                continue
            try:
                children = sorted(dir_path.iterdir())
            except PermissionError:
                logger.warning("Permission denied reading directory: %s", dir_path)
                continue
            for child in children:
                if child.is_file():
                    entry = self._make_entry(child, home)
                    if entry is not None:
                        entries.append(entry)

        return DotfilesResult(entries=entries)

    def _make_entry(self, path: Path, home: Path) -> DotfileEntry | None:
        symlink_target: Path | None = None
        managed_by = DotfileManager.MANUAL

        try:
            if path.is_symlink():
                raw_target = path.readlink()
                # Resolve relative targets against parent directory
                symlink_target = raw_target if raw_target.is_absolute() else (path.parent / raw_target).resolve()
                managed_by = self._detect_manager(symlink_target, home)
        except OSError as exc:
            logger.warning("Error reading symlink %s: %s", path, exc)
            managed_by = DotfileManager.UNKNOWN

        content_hash = hash_file(path)

        return DotfileEntry(
            path=path,
            content_hash=content_hash,
            managed_by=managed_by,
            symlink_target=symlink_target,
        )

    def _detect_manager(self, target: Path, home: Path) -> DotfileManager:
        # Check for GNU Stow
        try:
            stow_ignore = target.parent / ".stow-local-ignore"
            if stow_ignore.exists():
                return DotfileManager.STOW
            # Check if 'stow' appears in parent chain
            for parent in target.parents:
                if "stow" in parent.name.lower():
                    return DotfileManager.STOW
        except OSError:
            pass

        # Check for git-managed dotfiles
        for dotfiles_dir in [home / ".dotfiles", home / "dotfiles"]:
            if dotfiles_dir.is_dir() and (dotfiles_dir / ".git").exists() and target.is_relative_to(dotfiles_dir):
                return DotfileManager.GIT

        return DotfileManager.UNKNOWN
