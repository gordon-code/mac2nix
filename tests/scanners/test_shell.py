"""Tests for shell scanner."""

import os
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

    def test_fish_conf_d(self, tmp_path: Path) -> None:
        conf_d = tmp_path / ".config" / "fish" / "conf.d"
        conf_d.mkdir(parents=True)
        (conf_d / "abbr.fish").write_text("abbr -a g git")
        (conf_d / "path.fish").write_text("fish_add_path /opt/bin")
        (tmp_path / ".config" / "fish" / "config.fish").write_text("# config")

        with (
            _patch_shell("/opt/homebrew/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert len(result.conf_d_files) == 2
        names = {f.name for f in result.conf_d_files}
        assert "abbr.fish" in names
        assert "path.fish" in names

    def test_fish_completions(self, tmp_path: Path) -> None:
        comp_dir = tmp_path / ".config" / "fish" / "completions"
        comp_dir.mkdir(parents=True)
        (comp_dir / "git.fish").write_text("complete -c git")
        (comp_dir / "docker.fish").write_text("complete -c docker")
        (tmp_path / ".config" / "fish" / "config.fish").write_text("# config")

        with (
            _patch_shell("/opt/homebrew/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert len(result.completion_files) == 2

    def test_zsh_conf_d(self, tmp_path: Path) -> None:
        zsh_dir = tmp_path / ".zsh"
        zsh_dir.mkdir()
        (zsh_dir / "aliases.zsh").write_text("alias ll='ls -la'")
        (zsh_dir / "exports.zsh").write_text("export EDITOR=vim")
        (tmp_path / ".zshrc").write_text("# zsh")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert len(result.conf_d_files) == 2

    def test_zsh_completions(self, tmp_path: Path) -> None:
        comp_dir = tmp_path / ".zsh" / "completions"
        comp_dir.mkdir(parents=True)
        (comp_dir / "_git").write_text("#compdef git")
        (tmp_path / ".zshrc").write_text("# zsh")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert len(result.completion_files) == 1

    def test_posix_source_detection(self, tmp_path: Path) -> None:
        sourced = tmp_path / ".shell_aliases"
        sourced.write_text("alias g='git'")
        (tmp_path / ".zshrc").write_text(f"source {sourced}\n")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert len(result.sourced_files) == 1
        assert result.sourced_files[0].name == ".shell_aliases"

    def test_fish_source_detection(self, tmp_path: Path) -> None:
        fish_dir = tmp_path / ".config" / "fish"
        fish_dir.mkdir(parents=True)
        sourced = fish_dir / "extras.fish"
        sourced.write_text("set -gx EXTRA true")
        (fish_dir / "config.fish").write_text(f"source {sourced}\n")

        with (
            _patch_shell("/opt/homebrew/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert len(result.sourced_files) == 1

    def test_source_tilde_expansion(self, tmp_path: Path) -> None:
        sourced = tmp_path / ".my_aliases"
        sourced.write_text("alias ll='ls -la'")
        (tmp_path / ".zshrc").write_text("source ~/.my_aliases\n")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert len(result.sourced_files) == 1

    def test_source_nonexistent_ignored(self, tmp_path: Path) -> None:
        (tmp_path / ".zshrc").write_text("source /nonexistent/file\n")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert result.sourced_files == []

    def test_source_no_infinite_loop(self, tmp_path: Path) -> None:
        rc = tmp_path / ".zshrc"
        # Source itself — should not loop
        rc.write_text(f"source {rc}\n")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        # .zshrc is the rc file itself, already in seen_files — not in sourced_files
        assert len(result.sourced_files) == 0

    def test_posix_path_export(self, tmp_path: Path) -> None:
        (tmp_path / ".zshrc").write_text("export PATH=/usr/local/bin:/opt/bin:$PATH\n")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert "/usr/local/bin" in result.path_components
        assert "/opt/bin" in result.path_components
        assert "$PATH" not in result.path_components

    def test_comments_and_blanks_skipped(self, tmp_path: Path) -> None:
        (tmp_path / ".zshrc").write_text("# comment\n\n  \nalias ll='ls -la'\n# another comment\n")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert len(result.aliases) == 1

    def test_multiple_rc_files(self, tmp_path: Path) -> None:
        (tmp_path / ".zshrc").write_text("alias a='b'\n")
        (tmp_path / ".zprofile").write_text("export EDITOR=vim\n")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert len(result.rc_files) == 2
        assert "a" in result.aliases
        assert result.env_vars.get("EDITOR") == "vim"

    def test_fish_alias_extraction(self, tmp_path: Path) -> None:
        fish_dir = tmp_path / ".config" / "fish"
        fish_dir.mkdir(parents=True)
        (fish_dir / "config.fish").write_text("alias g git\nalias ll 'ls -la'\n")

        with (
            _patch_shell("/opt/homebrew/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert "g" in result.aliases
        assert result.aliases["g"] == "git"

    def test_bash_detection(self, tmp_path: Path) -> None:
        (tmp_path / ".bashrc").write_text("alias ll='ls -la'\n")

        with (
            _patch_shell("/bin/bash"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert result.shell_type == "bash"
        assert "ll" in result.aliases

    def test_oh_my_fish_detection(self, tmp_path: Path) -> None:
        fish_dir = tmp_path / ".config" / "fish"
        fish_dir.mkdir(parents=True)
        (fish_dir / "config.fish").write_text("# config")
        omf_dir = fish_dir / "omf"
        omf_dir.mkdir()
        pkg_dir = omf_dir / "pkg"
        pkg_dir.mkdir()
        (pkg_dir / "z").mkdir()
        theme_file = omf_dir / "theme"
        theme_file.write_text("bobthefish\n")

        with (
            _patch_shell("/opt/homebrew/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        omf = next(f for f in result.frameworks if f.name == "oh-my-fish")
        assert "z" in omf.plugins
        assert omf.theme == "bobthefish"

    def test_fisher_detection(self, tmp_path: Path) -> None:
        fish_dir = tmp_path / ".config" / "fish"
        fish_dir.mkdir(parents=True)
        (fish_dir / "config.fish").write_text("# config")
        (fish_dir / "fish_plugins").write_text("jorgebucaran/fisher\npatrickf1/fzf.fish\n")

        with (
            _patch_shell("/opt/homebrew/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        fisher = next(f for f in result.frameworks if f.name == "fisher")
        assert "jorgebucaran/fisher" in fisher.plugins
        assert "patrickf1/fzf.fish" in fisher.plugins

    def test_oh_my_zsh_detection(self, tmp_path: Path) -> None:
        omz_dir = tmp_path / ".oh-my-zsh"
        omz_dir.mkdir()
        custom_plugins = omz_dir / "custom" / "plugins"
        custom_plugins.mkdir(parents=True)
        (custom_plugins / "zsh-autosuggestions").mkdir()
        (tmp_path / ".zshrc").write_text("# zsh")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        omz = next(f for f in result.frameworks if f.name == "oh-my-zsh")
        assert "zsh-autosuggestions" in omz.plugins

    def test_prezto_detection(self, tmp_path: Path) -> None:
        (tmp_path / ".zprezto").mkdir()
        (tmp_path / ".zshrc").write_text("# zsh")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        prezto = next(f for f in result.frameworks if f.name == "prezto")
        assert prezto.path == tmp_path / ".zprezto"

    def test_starship_detection(self, tmp_path: Path) -> None:
        (tmp_path / ".config").mkdir()
        (tmp_path / ".config" / "starship.toml").write_text("format = '$all'")
        (tmp_path / ".zshrc").write_text("# zsh")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        starship = next(f for f in result.frameworks if f.name == "starship")
        assert starship.path is not None

    def test_starship_xdg_detection(self, tmp_path: Path) -> None:
        custom_config = tmp_path / "custom_xdg"
        custom_config.mkdir()
        (custom_config / "starship.toml").write_text("format = '$all'")
        (tmp_path / ".zshrc").write_text("# zsh")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
            patch.dict(os.environ, {"XDG_CONFIG_HOME": str(custom_config)}),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert any(f.name == "starship" for f in result.frameworks)

    def test_eval_detection_posix(self, tmp_path: Path) -> None:
        (tmp_path / ".zshrc").write_text('eval "$(starship init zsh)"\n')

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert len(result.dynamic_commands) >= 1
        assert any("starship" in cmd for cmd in result.dynamic_commands)

    def test_eval_detection_fish(self, tmp_path: Path) -> None:
        fish_dir = tmp_path / ".config" / "fish"
        fish_dir.mkdir(parents=True)
        (fish_dir / "config.fish").write_text("eval (starship init fish)\n")

        with (
            _patch_shell("/opt/homebrew/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert len(result.dynamic_commands) >= 1

    def test_fish_xdg_config_home(self, tmp_path: Path) -> None:
        custom_xdg = tmp_path / "custom_config"
        fish_dir = custom_xdg / "fish"
        fish_dir.mkdir(parents=True)
        (fish_dir / "config.fish").write_text("set -gx EDITOR nvim\n")

        with (
            _patch_shell("/opt/homebrew/bin/fish"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
            patch.dict(os.environ, {"XDG_CONFIG_HOME": str(custom_xdg)}),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert result.shell_type == "fish"
        assert result.env_vars.get("EDITOR") == "nvim"
        assert any(f.name == "config.fish" for f in result.rc_files)

    def test_no_frameworks(self, tmp_path: Path) -> None:
        (tmp_path / ".zshrc").write_text("alias ll='ls -la'\n")

        with (
            _patch_shell("/bin/zsh"),
            patch("mac2nix.scanners.shell.Path.home", return_value=tmp_path),
        ):
            result = ShellScanner().scan()

        assert isinstance(result, ShellConfig)
        assert result.frameworks == []
