"""Tests for dotfile_to_hm mapping."""

from pathlib import Path
from unittest.mock import patch

from mac2nix.mappings.dotfile_to_hm import DOTFILE_TO_HM, get_hm_program


class TestDotfileToHm:
    def test_shell_category(self) -> None:
        assert DOTFILE_TO_HM["~/.zshrc"] == "programs.zsh"
        assert DOTFILE_TO_HM["~/.config/fish/config.fish"] == "programs.fish"

    def test_git_vcs_category(self) -> None:
        assert DOTFILE_TO_HM["~/.gitconfig"] == "programs.git"
        assert DOTFILE_TO_HM["~/.config/gh/config.yml"] == "programs.gh"

    def test_ssh_gpg_security_category(self) -> None:
        assert DOTFILE_TO_HM["~/.ssh/config"] == "programs.ssh"
        assert DOTFILE_TO_HM["~/.gnupg/gpg.conf"] == "programs.gpg"

    def test_terminal_emulators_category(self) -> None:
        assert DOTFILE_TO_HM["~/.config/alacritty/alacritty.toml"] == "programs.alacritty"
        assert DOTFILE_TO_HM["~/.config/kitty/kitty.conf"] == "programs.kitty"

    def test_editors_category(self) -> None:
        assert DOTFILE_TO_HM["~/.config/nvim/init.lua"] == "programs.neovim"
        assert DOTFILE_TO_HM["~/.vimrc"] == "programs.vim"

    def test_cli_tools_category(self) -> None:
        assert DOTFILE_TO_HM["~/.config/starship.toml"] == "programs.starship"
        assert DOTFILE_TO_HM["~/.config/tmux/tmux.conf"] == "programs.tmux"

    def test_programming_languages_category(self) -> None:
        assert DOTFILE_TO_HM["~/.cargo/config.toml"] == "programs.cargo"
        assert DOTFILE_TO_HM["~/.npmrc"] == "programs.npm"

    def test_devops_cloud_category(self) -> None:
        assert DOTFILE_TO_HM["~/.docker/config.json"] == "programs.docker-cli"
        assert DOTFILE_TO_HM["~/.aws/config"] == "programs.awscli"

    def test_browsers_category(self) -> None:
        assert DOTFILE_TO_HM["~/.mozilla/firefox"] == "programs.firefox"
        assert DOTFILE_TO_HM["~/.config/qutebrowser/config.py"] == "programs.qutebrowser"

    def test_media_category(self) -> None:
        assert DOTFILE_TO_HM["~/.config/mpv/mpv.conf"] == "programs.mpv"
        assert DOTFILE_TO_HM["~/.config/mpv/input.conf"] == "programs.mpv"

    def test_xdg_and_legacy_paths_resolve_to_same_module(self) -> None:
        assert get_hm_program("~/.tmux.conf") == get_hm_program("~/.config/tmux/tmux.conf")
        assert get_hm_program("~/.gitconfig") == get_hm_program("~/.config/git/config")
        assert get_hm_program("~/.npmrc") == get_hm_program("~/.config/npm/npmrc")

    def test_home_relative_and_absolute_paths_resolve_identically(self, tmp_path: Path) -> None:
        with patch("mac2nix.mappings.dotfile_to_hm.Path.home", return_value=tmp_path):
            relative_result = get_hm_program("~/.zshrc")
            absolute_result = get_hm_program(tmp_path / ".zshrc")
            absolute_str_result = get_hm_program(str(tmp_path / ".zshrc"))

        assert relative_result == "programs.zsh"
        assert absolute_result == "programs.zsh"
        assert absolute_str_result == "programs.zsh"

    def test_macos_library_application_support_path(self) -> None:
        assert get_hm_program("~/Library/Application Support/lazygit/config.yml") == "programs.lazygit"
        assert get_hm_program("~/Library/Application Support/Code/User/settings.json") == "programs.vscode"

    def test_trailing_slash_is_stripped(self) -> None:
        assert get_hm_program("~/.config/fish/functions/") == "programs.fish"
        assert get_hm_program("~/.password-store/") == "programs.password-store"

    def test_unrecognized_path_returns_none(self) -> None:
        assert get_hm_program("~/.config/does-not-exist/config.toml") is None
        assert get_hm_program("/some/unrelated/path") is None
