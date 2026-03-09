"""Tests for shell scanner."""

from pathlib import Path
from unittest.mock import patch

from mac2nix.models.services import ShellConfig
from mac2nix.scanners.shell import ShellScanner


def _patch_shell(shell_path: str):
    """Patch _get_login_shell to return a specific shell path."""
    return patch.object(ShellScanner, "_get_login_shell", return_value=shell_path)


class TestShellScanner:
    def test_name_property(self) -> None:
        assert ShellScanner().name == "shell"

    def test_detects_fish(self, tmp_path: Path) -> None:
        config_fish = tmp_path / ".config" / "fish"
        config_fish.mkdir(parents=True)
        (config_fish / "config.fish").write_text("# fish config")

        with (
            _patch_shell("/opt/homebrew/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert result.shell_type == "fish"

    def test_detects_zsh(self, tmp_path: Path) -> None:
        (tmp_path / ".zshrc").write_text("# zsh config")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert result.shell_type == "zsh"

    def test_zsh_alias_extraction(self, tmp_path: Path) -> None:
        (tmp_path / ".zshrc").write_text("alias ll='ls -la'\nalias gs='git status'\n")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert "ll" in result.aliases
        assert result.aliases["ll"] == "ls -la"

    def test_fish_path_extraction(self, tmp_path: Path) -> None:
        config_fish = tmp_path / ".config" / "fish"
        config_fish.mkdir(parents=True)
        (config_fish / "config.fish").write_text("fish_add_path /opt/homebrew/bin\nfish_add_path ~/.local/bin\n")

        with (
            _patch_shell("/usr/local/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert "/opt/homebrew/bin" in result.path_components

    def test_export_env_vars(self, tmp_path: Path) -> None:
        (tmp_path / ".zshrc").write_text("export EDITOR=vim\nexport GOPATH=/home/user/go\n")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert result.env_vars.get("EDITOR") == "vim"

    def test_fish_set_export(self, tmp_path: Path) -> None:
        config_fish = tmp_path / ".config" / "fish"
        config_fish.mkdir(parents=True)
        (config_fish / "config.fish").write_text("set -gx EDITOR nvim\n")

        with (
            _patch_shell("/usr/local/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert result.env_vars.get("EDITOR") == "nvim"

    def test_fish_functions_dir(self, tmp_path: Path) -> None:
        config_fish = tmp_path / ".config" / "fish"
        config_fish.mkdir(parents=True)
        (config_fish / "config.fish").write_text("# config")
        func_dir = config_fish / "functions"
        func_dir.mkdir()
        (func_dir / "fish_prompt.fish").write_text("function fish_prompt; end")
        (func_dir / "my_func.fish").write_text("function my_func; end")

        with (
            _patch_shell("/opt/homebrew/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert "fish_prompt" in result.functions
        assert "my_func" in result.functions

    def test_missing_rc_file(self, tmp_path: Path) -> None:
        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert result.rc_files == []

    def test_unknown_shell_defaults_to_zsh(self, tmp_path: Path) -> None:
        with (
            _patch_shell("/usr/local/bin/nu"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert result.shell_type == "zsh"

    def test_sensitive_posix_vars_filtered(self, tmp_path: Path) -> None:
        (tmp_path / ".zshrc").write_text(
            "export API_KEY=secret123\nexport GH_TOKEN=ghp_abc\nexport DB_PASSWORD=hunter2\nexport EDITOR=vim\n"
        )

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert "API_KEY" not in result.env_vars
        assert "GH_TOKEN" not in result.env_vars
        assert "DB_PASSWORD" not in result.env_vars
        assert result.env_vars.get("EDITOR") == "vim"

    def test_sensitive_fish_vars_filtered(self, tmp_path: Path) -> None:
        config_fish = tmp_path / ".config" / "fish"
        config_fish.mkdir(parents=True)
        (config_fish / "config.fish").write_text(
            "set -gx API_KEY secret123\nset -gx AWS_SECRET_ACCESS_KEY abc\nset -gx EDITOR nvim\n"
        )

        with (
            _patch_shell("/usr/local/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert "API_KEY" not in result.env_vars
        assert "AWS_SECRET_ACCESS_KEY" not in result.env_vars
        assert result.env_vars.get("EDITOR") == "nvim"

    def test_posix_function_detection(self, tmp_path: Path) -> None:
        (tmp_path / ".zshrc").write_text("my_func() {\n  echo hello\n}\n")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert "my_func" in result.functions

    def test_dscl_login_shell_detection(self, cmd_result) -> None:
        with patch(
            "mac2nix.scanners.shell.run_command",
            return_value=cmd_result("UserShell: /opt/homebrew/bin/fish\n"),
        ):
            shell = ShellScanner._get_login_shell()

        assert shell == "/opt/homebrew/bin/fish"

    def test_dscl_fallback_to_env(self) -> None:
        with (
            patch("mac2nix.scanners.shell.run_command", return_value=None),
            patch.dict("os.environ", {"SHELL": "/bin/bash"}),
        ):
            shell = ShellScanner._get_login_shell()

        assert shell == "/bin/bash"

    def test_returns_shell_config(self, tmp_path: Path) -> None:
        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
