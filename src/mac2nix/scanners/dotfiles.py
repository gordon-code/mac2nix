"""Dotfiles scanner — discovers dotfile configuration files and their managers."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from mac2nix.models.files import DotfileEntry, DotfileManager, DotfilesResult
from mac2nix.scanners._utils import hash_file
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_EXCLUDED_DOTFILES = frozenset({
    ".Trash",
    ".cache",
    ".DS_Store",
    ".CFUserTextEncoding",
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".node_repl_history",
    ".psql_history",
    ".sqlite_history",
    ".lesshst",
    ".wget-hsts",
})

_SCAN_DIRS = [
    ".config",
    ".local/share",
    ".local/state",
]

_SENSITIVE_DIRS = frozenset({
    ".ssh",
    ".gnupg",
    ".aws",
    ".docker",
    ".kube",
    ".azure",
})

_SENSITIVE_DIR_PATHS = frozenset({
    ".config/gcloud",
})

_SENSITIVE_FILES = frozenset({
    ".netrc",
    ".npmrc",
    ".pypirc",
})

_SENSITIVE_FILE_PATHS = frozenset({
    ".gem/credentials",
    ".config/gh/hosts.yml",
    ".config/hub",
})


@register("dotfiles")
class DotfilesScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "dotfiles"

    def scan(self) -> DotfilesResult:
        home = Path.home()
        entries: list[DotfileEntry] = []

        self._discover_home_dotfiles(home, entries)

        # Scan XDG directories (first-level entries only)
        for dir_path in self._get_xdg_scan_dirs(home):
            self._scan_directory_children(dir_path, home, entries)

        # Apply global manager as fallback for UNKNOWN entries
        global_mgr = self._detect_global_manager(home)
        if global_mgr is not None:
            for entry in entries:
                if entry.managed_by == DotfileManager.UNKNOWN:
                    entry.managed_by = global_mgr

        return DotfilesResult(entries=entries)

    def _discover_home_dotfiles(self, home: Path, entries: list[DotfileEntry]) -> None:
        """Discover all ~/.*  files and directories."""
        try:
            for child in sorted(home.iterdir()):
                if not child.name.startswith("."):
                    continue
                if child.name in _EXCLUDED_DOTFILES:
                    continue
                self._classify_and_append(child, home, entries)
        except PermissionError:
            logger.warning("Permission denied reading home directory: %s", home)

    def _scan_directory_children(self, dir_path: Path, home: Path, entries: list[DotfileEntry]) -> None:
        """Scan first-level children of a directory."""
        if not dir_path.is_dir():
            return
        try:
            children = sorted(dir_path.iterdir())
        except PermissionError:
            logger.warning("Permission denied reading directory: %s", dir_path)
            return
        for child in children:
            self._classify_and_append(child, home, entries)

    def _classify_and_append(self, child: Path, home: Path, entries: list[DotfileEntry]) -> None:
        """Classify a path as file or directory and append the entry."""
        if child.is_dir():
            entry = self._make_dir_entry(child)
        elif child.is_file() or child.is_symlink():
            entry = self._make_entry(child, home)
        else:
            return
        if entry is not None:
            entries.append(entry)

    @staticmethod
    def _get_xdg_scan_dirs(home: Path) -> list[Path]:
        """Get XDG-based directories to scan, honoring env overrides."""
        dirs: list[Path] = []
        for env_var, default_rel in [
            ("XDG_CONFIG_HOME", ".config"),
            ("XDG_DATA_HOME", ".local/share"),
            ("XDG_STATE_HOME", ".local/state"),
        ]:
            env_val = os.environ.get(env_var)
            candidate = Path(env_val) if env_val else home / default_rel
            if candidate.is_dir():
                dirs.append(candidate)
        return dirs

    def _make_dir_entry(self, path: Path) -> DotfileEntry | None:
        """Create a DotfileEntry for a directory."""
        file_count: int | None = None
        try:
            file_count = len(list(path.iterdir()))
        except PermissionError:
            logger.debug("Permission denied counting files in: %s", path)

        sensitive = self._is_sensitive_path(path)

        return DotfileEntry(
            path=path,
            is_directory=True,
            file_count=file_count,
            sensitive=sensitive,
        )

    def _make_entry(self, path: Path, home: Path) -> DotfileEntry | None:
        symlink_target: Path | None = None
        managed_by = DotfileManager.MANUAL
        sensitive = self._is_sensitive_path(path)

        try:
            if path.is_symlink():
                raw_target = path.readlink()
                # Resolve relative targets against parent directory
                symlink_target = raw_target if raw_target.is_absolute() else (path.parent / raw_target).resolve()
                managed_by = self._detect_manager(symlink_target, home)
        except OSError as exc:
            logger.warning("Error reading symlink %s: %s", path, exc)
            managed_by = DotfileManager.UNKNOWN

        content_hash = None if sensitive else hash_file(path)

        return DotfileEntry(
            path=path,
            content_hash=content_hash,
            managed_by=managed_by,
            symlink_target=symlink_target,
            sensitive=sensitive,
        )

    @staticmethod
    def _is_sensitive_path(path: Path) -> bool:
        """Check if a path is a known sensitive directory or file."""
        name = path.name
        if name in _SENSITIVE_DIRS or name in _SENSITIVE_FILES:
            return True
        # Check relative paths for nested sensitive locations
        try:
            home = Path.home()
            rel = path.relative_to(home)
            rel_str = str(rel)
            return rel_str in _SENSITIVE_DIR_PATHS or rel_str in _SENSITIVE_FILE_PATHS
        except ValueError:
            return False

    def _detect_manager(self, target: Path, home: Path) -> DotfileManager:
        # Check for GNU Stow
        if self._is_stow_managed(target):
            return DotfileManager.STOW

        # Check for chezmoi
        chezmoi_dir = home / ".local" / "share" / "chezmoi"
        if chezmoi_dir.is_dir() and target.is_relative_to(chezmoi_dir):
            return DotfileManager.CHEZMOI

        # Check for yadm
        for yadm_dir in [home / ".local" / "share" / "yadm", home / ".config" / "yadm"]:
            if yadm_dir.is_dir() and target.is_relative_to(yadm_dir):
                return DotfileManager.YADM

        # Check for home-manager
        for hm_path in [home / ".config" / "home-manager", home / ".config" / "nixpkgs" / "home.nix"]:
            if hm_path.exists() and target.is_relative_to(hm_path.parent if hm_path.is_file() else hm_path):
                return DotfileManager.HOME_MANAGER

        # Check for git-managed dotfiles
        for dotfiles_dir in [home / ".dotfiles", home / "dotfiles"]:
            if dotfiles_dir.is_dir() and (dotfiles_dir / ".git").exists() and target.is_relative_to(dotfiles_dir):
                return DotfileManager.GIT

        return DotfileManager.UNKNOWN

    @staticmethod
    def _detect_global_manager(home: Path) -> DotfileManager | None:
        """Detect if a global dotfile manager is in use (non-symlink detection)."""
        try:
            if (home / ".local" / "share" / "chezmoi").is_dir() or (home / ".chezmoiroot").is_file():
                return DotfileManager.CHEZMOI
            if (home / ".local" / "share" / "yadm").is_dir() or (home / ".config" / "yadm").is_dir():
                return DotfileManager.YADM
            if (home / ".config" / "home-manager").is_dir() or (home / ".config" / "nixpkgs" / "home.nix").is_file():
                return DotfileManager.HOME_MANAGER
            if (home / ".rcrc").is_file():
                return DotfileManager.RCM
        except PermissionError:
            logger.debug("Permission denied detecting global dotfile manager")
        return None

    @staticmethod
    def _is_stow_managed(target: Path) -> bool:
        """Check if a symlink target is managed by GNU Stow."""
        try:
            if (target.parent / ".stow-local-ignore").exists():
                return True
            return any("stow" in parent.name.lower() for parent in target.parents)
        except OSError:
            return False
