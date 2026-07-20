"""Tests for app_to_hm mapping."""

from mac2nix.mappings.app_to_hm import APP_TO_HM_MODULE, HMModuleInfo, get_hm_module


class TestAppToHm:
    def test_git_module(self) -> None:
        info = APP_TO_HM_MODULE["git"]
        assert info.module_path == "programs.git"
        assert "~/.config/git/config" in info.config_paths

    def test_ssh_module(self) -> None:
        info = APP_TO_HM_MODULE["ssh"]
        assert info.module_path == "programs.ssh"
        assert info.config_paths == ("~/.ssh/config",)

    def test_fish_module(self) -> None:
        info = APP_TO_HM_MODULE["fish"]
        assert info.module_path == "programs.fish"
        assert "~/.config/fish/config.fish" in info.config_paths

    def test_zsh_module(self) -> None:
        info = APP_TO_HM_MODULE["zsh"]
        assert info.module_path == "programs.zsh"
        assert "~/.zshrc" in info.config_paths

    def test_darwin_aware_vscode_module(self) -> None:
        info = APP_TO_HM_MODULE["vscode"]
        assert info.module_path == "programs.vscode"
        assert info.config_paths == ("~/.config/Code/User/settings.json",)
        assert info.darwin_config_paths == ("~/Library/Application Support/Code/User/settings.json",)
        assert info.extensions_cmd == "code --list-extensions"

    def test_darwin_aware_k9s_lazygit_go_modules(self) -> None:
        assert APP_TO_HM_MODULE["k9s"].darwin_config_paths == ("~/Library/Application Support/k9s/",)
        assert APP_TO_HM_MODULE["lazygit"].darwin_config_paths == ("~/Library/Application Support/lazygit/",)
        assert APP_TO_HM_MODULE["go"].darwin_config_paths == ("~/Library/Application Support/go/env",)

    def test_darwin_only_rectangle_module(self) -> None:
        info = APP_TO_HM_MODULE["rectangle"]
        assert info.module_path == "programs.rectangle"
        assert info.config_paths == ()
        assert info.darwin_config_paths == ("~/Library/Preferences/com.knollsoft.Rectangle.plist",)

    def test_inject_only_shell_integration_modules(self) -> None:
        for name in ("fzf", "zoxide", "jq", "pyenv"):
            info = APP_TO_HM_MODULE[name]
            assert info.inject_only is True
            assert info.config_paths == ()

    def test_non_inject_only_module_defaults_false(self) -> None:
        assert APP_TO_HM_MODULE["git"].inject_only is False

    def test_get_hm_module_case_insensitive(self) -> None:
        assert get_hm_module("Git") == APP_TO_HM_MODULE["git"]
        assert get_hm_module("VSCODE") == APP_TO_HM_MODULE["vscode"]
        assert get_hm_module("Fzf") == APP_TO_HM_MODULE["fzf"]

    def test_get_hm_module_unrecognized_returns_none(self) -> None:
        assert get_hm_module("does-not-exist") is None
        assert get_hm_module("") is None

    def test_hm_module_info_defaults(self) -> None:
        info = HMModuleInfo(module_path="programs.example")
        assert info.config_paths == ()
        assert info.darwin_config_paths == ()
        assert info.extensions_cmd is None
        assert info.inject_only is False
