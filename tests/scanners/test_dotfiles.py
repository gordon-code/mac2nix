"""Tests for dotfiles scanner."""

from pathlib import Path
from unittest.mock import patch

from mac2nix.models.files import DotfileManager, DotfilesResult
from mac2nix.scanners.dotfiles import DotfilesScanner


class TestDotfilesScanner:
    def test_name_property(self) -> None:
        assert DotfilesScanner().name == "dotfiles"

    def test_plain_file(self, tmp_path: Path) -> None:
        (tmp_path / ".zshrc").write_text("export PATH=/usr/bin")

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch("mac2nix.scanners.dotfiles._SCAN_DIRS", []),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        zshrc = next(e for e in result.entries if e.path.name == ".zshrc")
        assert zshrc.managed_by == DotfileManager.MANUAL
        assert zshrc.content_hash is not None
        assert len(zshrc.content_hash) == 16
        assert zshrc.symlink_target is None

    def test_symlink_file(self, tmp_path: Path) -> None:
        target = tmp_path / "dotfiles_repo" / ".vimrc"
        target.parent.mkdir()
        target.write_text("set number")
        link = tmp_path / ".vimrc"
        link.symlink_to(target)

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch("mac2nix.scanners.dotfiles._SCAN_DIRS", []),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        vimrc = next(e for e in result.entries if e.path.name == ".vimrc")
        assert vimrc.symlink_target is not None
        assert vimrc.managed_by == DotfileManager.UNKNOWN

    def test_stow_managed(self, tmp_path: Path) -> None:
        stow_dir = tmp_path / "stow_packages" / "vim"
        stow_dir.mkdir(parents=True)
        target = stow_dir / ".vimrc"
        target.write_text("set number")
        (stow_dir / ".stow-local-ignore").touch()
        link = tmp_path / ".vimrc"
        link.symlink_to(target)

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch("mac2nix.scanners.dotfiles._SCAN_DIRS", []),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        vimrc = next(e for e in result.entries if e.path.name == ".vimrc")
        assert vimrc.managed_by == DotfileManager.STOW

    def test_git_managed(self, tmp_path: Path) -> None:
        dotfiles_repo = tmp_path / ".dotfiles"
        dotfiles_repo.mkdir()
        (dotfiles_repo / ".git").mkdir()
        target = dotfiles_repo / ".bashrc"
        target.write_text("alias ll='ls -la'")
        link = tmp_path / ".bashrc"
        link.symlink_to(target)

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch("mac2nix.scanners.dotfiles._SCAN_DIRS", []),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        bashrc = next(e for e in result.entries if e.path.name == ".bashrc")
        assert bashrc.managed_by == DotfileManager.GIT

    def test_missing_optional(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch("mac2nix.scanners.dotfiles._SCAN_DIRS", []),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        assert result.entries == []

    def test_scan_dirs(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".config"
        config_dir.mkdir()
        (config_dir / "starship.toml").write_text("format = '$all'")

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch("mac2nix.scanners.dotfiles._SCAN_DIRS", [".config"]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        assert any(e.path.name == "starship.toml" for e in result.entries)

    def test_hash_file_permission_denied(self, tmp_path: Path) -> None:
        (tmp_path / ".gitconfig").write_text("[user]\nname = Test")

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch("mac2nix.scanners.dotfiles._SCAN_DIRS", []),
            patch("mac2nix.scanners.dotfiles.hash_file", return_value=None),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        gitconfig = next(e for e in result.entries if e.path.name == ".gitconfig")
        assert gitconfig.content_hash is None

    def test_returns_dotfiles_result(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch("mac2nix.scanners.dotfiles._SCAN_DIRS", []),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
