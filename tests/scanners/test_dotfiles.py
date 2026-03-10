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
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
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
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
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
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
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
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        bashrc = next(e for e in result.entries if e.path.name == ".bashrc")
        assert bashrc.managed_by == DotfileManager.GIT

    def test_missing_optional(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        assert result.entries == []

    def test_xdg_scan_dirs(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".config"
        config_dir.mkdir()
        (config_dir / "starship.toml").write_text("format = '$all'")

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[config_dir]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        assert any(e.path.name == "starship.toml" for e in result.entries)

    def test_hash_file_permission_denied(self, tmp_path: Path) -> None:
        (tmp_path / ".gitconfig").write_text("[user]\nname = Test")

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
            patch("mac2nix.scanners.dotfiles.hash_file", return_value=None),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        gitconfig = next(e for e in result.entries if e.path.name == ".gitconfig")
        assert gitconfig.content_hash is None

    def test_stow_parent_name_detection(self, tmp_path: Path) -> None:
        stow_dir = tmp_path / "mystow" / "vim"
        stow_dir.mkdir(parents=True)
        target = stow_dir / ".vimrc"
        target.write_text("set number")
        link = tmp_path / ".vimrc"
        link.symlink_to(target)

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        vimrc = next(e for e in result.entries if e.path.name == ".vimrc")
        assert vimrc.managed_by == DotfileManager.STOW

    def test_returns_dotfiles_result(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)

    def test_discovers_directories(self, tmp_path: Path) -> None:
        (tmp_path / ".config").mkdir()
        (tmp_path / ".config" / "somefile").write_text("x")
        (tmp_path / ".zshrc").write_text("# zsh")

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        dir_entry = next(e for e in result.entries if e.path.name == ".config")
        assert dir_entry.is_directory is True
        assert dir_entry.file_count == 1

    def test_excluded_dotfiles_skipped(self, tmp_path: Path) -> None:
        (tmp_path / ".DS_Store").write_bytes(b"\x00")
        (tmp_path / ".Trash").mkdir()
        (tmp_path / ".zshrc").write_text("# zsh")

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        names = {e.path.name for e in result.entries}
        assert ".DS_Store" not in names
        assert ".Trash" not in names
        assert ".zshrc" in names

    def test_sensitive_dir_flagged(self, tmp_path: Path) -> None:
        (tmp_path / ".ssh").mkdir()
        (tmp_path / ".ssh" / "id_rsa").write_text("key")
        (tmp_path / ".gnupg").mkdir()

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        ssh = next(e for e in result.entries if e.path.name == ".ssh")
        assert ssh.sensitive is True
        assert ssh.is_directory is True
        gnupg = next(e for e in result.entries if e.path.name == ".gnupg")
        assert gnupg.sensitive is True

    def test_sensitive_file_flagged(self, tmp_path: Path) -> None:
        (tmp_path / ".netrc").write_text("machine example.com login user password pass")

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        netrc = next(e for e in result.entries if e.path.name == ".netrc")
        assert netrc.sensitive is True
        assert netrc.content_hash is None  # hash skipped for sensitive files

    def test_sensitive_nested_path(self, tmp_path: Path) -> None:
        gcloud = tmp_path / ".config" / "gcloud"
        gcloud.mkdir(parents=True)

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[tmp_path / ".config"]),
        ):
            result = DotfilesScanner().scan()

        gcloud_entry = next(
            (e for e in result.entries if e.path.name == "gcloud"),
            None,
        )
        assert gcloud_entry is not None
        assert gcloud_entry.sensitive is True

    def test_xdg_env_override(self, tmp_path: Path) -> None:
        custom_config = tmp_path / "custom_config"
        custom_config.mkdir()
        (custom_config / "starship.toml").write_text("format = '$all'")

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.dict("os.environ", {"XDG_CONFIG_HOME": str(custom_config)}),
        ):
            dirs = DotfilesScanner._get_xdg_scan_dirs(tmp_path)

        assert custom_config in dirs

    def test_xdg_default_dirs(self, tmp_path: Path) -> None:
        (tmp_path / ".config").mkdir()
        (tmp_path / ".local" / "share").mkdir(parents=True)

        with patch.dict("os.environ", {}, clear=True):
            dirs = DotfilesScanner._get_xdg_scan_dirs(tmp_path)

        expected_names = {str(tmp_path / ".config"), str(tmp_path / ".local" / "share")}
        actual_names = {str(d) for d in dirs}
        assert expected_names.issubset(actual_names)

    def test_permission_denied_home(self, tmp_path: Path) -> None:
        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
            patch("pathlib.Path.iterdir", side_effect=PermissionError("denied")),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        assert result.entries == []

    def test_permission_denied_xdg_dir(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".config"
        config_dir.mkdir()

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[config_dir]),
        ):
            # Make config dir unreadable after scanner sees it exists
            config_dir.chmod(0o000)
            try:
                result = DotfilesScanner().scan()
            finally:
                config_dir.chmod(0o755)

        assert isinstance(result, DotfilesResult)

    def test_non_dotfile_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "regular_file").write_text("not a dotfile")
        (tmp_path / ".actual_dotfile").write_text("dotfile")

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        names = {e.path.name for e in result.entries}
        assert "regular_file" not in names
        assert ".actual_dotfile" in names

    def test_chezmoi_managed(self, tmp_path: Path) -> None:
        chezmoi_dir = tmp_path / ".local" / "share" / "chezmoi"
        chezmoi_dir.mkdir(parents=True)
        target = chezmoi_dir / ".bashrc"
        target.write_text("alias ll='ls -la'")
        link = tmp_path / ".bashrc"
        link.symlink_to(target)

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        bashrc = next(e for e in result.entries if e.path.name == ".bashrc")
        assert bashrc.managed_by == DotfileManager.CHEZMOI

    def test_yadm_managed(self, tmp_path: Path) -> None:
        yadm_dir = tmp_path / ".local" / "share" / "yadm"
        yadm_dir.mkdir(parents=True)
        target = yadm_dir / ".vimrc"
        target.write_text("set number")
        link = tmp_path / ".vimrc"
        link.symlink_to(target)

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        vimrc = next(e for e in result.entries if e.path.name == ".vimrc")
        assert vimrc.managed_by == DotfileManager.YADM

    def test_home_manager_managed(self, tmp_path: Path) -> None:
        hm_dir = tmp_path / ".config" / "home-manager"
        hm_dir.mkdir(parents=True)
        target = hm_dir / ".gitconfig"
        target.write_text("[user]\nname = Test")
        link = tmp_path / ".gitconfig"
        link.symlink_to(target)

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        gitconfig = next(e for e in result.entries if e.path.name == ".gitconfig")
        assert gitconfig.managed_by == DotfileManager.HOME_MANAGER

    def test_rcm_global_manager(self, tmp_path: Path) -> None:
        (tmp_path / ".rcrc").write_text("DOTFILES_DIRS=~/.dotfiles")
        target = tmp_path / "some_repo" / ".zshrc"
        target.parent.mkdir()
        target.write_text("# zsh")
        link = tmp_path / ".zshrc"
        link.symlink_to(target)

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        zshrc = next(e for e in result.entries if e.path.name == ".zshrc")
        # RCM is detected globally, applied as fallback to UNKNOWN entries
        assert zshrc.managed_by == DotfileManager.RCM

    def test_chezmoi_global_manager(self, tmp_path: Path) -> None:
        (tmp_path / ".chezmoiroot").write_text("home")
        (tmp_path / ".bashrc").write_text("# bash")

        with (
            patch("mac2nix.scanners.dotfiles.Path.home", return_value=tmp_path),
            patch.object(DotfilesScanner, "_get_xdg_scan_dirs", return_value=[]),
        ):
            result = DotfilesScanner().scan()

        assert isinstance(result, DotfilesResult)
        # Plain files get MANUAL, not affected by global manager
        bashrc = next(e for e in result.entries if e.path.name == ".bashrc")
        assert bashrc.managed_by == DotfileManager.MANUAL
