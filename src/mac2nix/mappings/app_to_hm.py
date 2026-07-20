"""Application/tool to home-manager program module mapping."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HMModuleInfo:
    """Metadata describing a home-manager ``programs.*`` module for a detected app or tool."""

    module_path: str
    config_paths: tuple[str, ...] = ()
    darwin_config_paths: tuple[str, ...] = ()
    extensions_cmd: str | None = None
    inject_only: bool = False


APP_TO_HM_MODULE: dict[str, HMModuleInfo] = {
    # Version Control / SSH / GPG
    "git": HMModuleInfo(
        module_path="programs.git",
        config_paths=("~/.config/git/config", "~/.config/git/ignore", "~/.config/git/attributes"),
    ),
    "ssh": HMModuleInfo(module_path="programs.ssh", config_paths=("~/.ssh/config",)),
    "gpg": HMModuleInfo(
        module_path="programs.gpg",
        config_paths=("~/.gnupg/gpg.conf", "~/.gnupg/scdaemon.conf", "~/.gnupg/dirmngr.conf"),
    ),
    "gh": HMModuleInfo(
        module_path="programs.gh",
        config_paths=("~/.config/gh/config.yml",),
        extensions_cmd="gh extension list",
    ),
    # Shells
    "fish": HMModuleInfo(
        module_path="programs.fish",
        config_paths=("~/.config/fish/config.fish", "~/.config/fish/functions/", "~/.config/fish/completions/"),
    ),
    "zsh": HMModuleInfo(module_path="programs.zsh", config_paths=("~/.zshrc", "~/.zshenv", "~/.zprofile")),
    "bash": HMModuleInfo(module_path="programs.bash", config_paths=("~/.bashrc", "~/.bash_profile", "~/.profile")),
    # Terminal multiplexers / emulators
    "tmux": HMModuleInfo(module_path="programs.tmux", config_paths=("~/.config/tmux/tmux.conf",)),
    "alacritty": HMModuleInfo(module_path="programs.alacritty", config_paths=("~/.config/alacritty/alacritty.toml",)),
    "kitty": HMModuleInfo(module_path="programs.kitty", config_paths=("~/.config/kitty/kitty.conf",)),
    "ghostty": HMModuleInfo(module_path="programs.ghostty", config_paths=("~/.config/ghostty/config",)),
    "wezterm": HMModuleInfo(module_path="programs.wezterm", config_paths=("~/.config/wezterm/wezterm.lua",)),
    # Editors
    "neovim": HMModuleInfo(
        module_path="programs.neovim",
        config_paths=("~/.config/nvim/init.lua", "~/.local/share/nvim/site/pack/hm/"),
    ),
    "vim": HMModuleInfo(module_path="programs.vim"),
    "vscode": HMModuleInfo(
        module_path="programs.vscode",
        config_paths=("~/.config/Code/User/settings.json",),
        darwin_config_paths=("~/Library/Application Support/Code/User/settings.json",),
        extensions_cmd="code --list-extensions",
    ),
    "helix": HMModuleInfo(
        module_path="programs.helix",
        config_paths=("~/.config/helix/config.toml", "~/.config/helix/languages.toml"),
    ),
    "zed": HMModuleInfo(module_path="programs.zed-editor", config_paths=("~/.config/zed/settings.json",)),
    # Browsers
    "firefox": HMModuleInfo(
        module_path="programs.firefox",
        config_paths=("~/.mozilla/firefox/",),
        darwin_config_paths=("~/Library/Application Support/Firefox/",),
    ),
    # Prompt / shell integration CLI tools
    "starship": HMModuleInfo(module_path="programs.starship", config_paths=("~/.config/starship.toml",)),
    "direnv": HMModuleInfo(module_path="programs.direnv", config_paths=("~/.config/direnv/direnv.toml",)),
    "fzf": HMModuleInfo(module_path="programs.fzf", inject_only=True),
    "bat": HMModuleInfo(module_path="programs.bat", config_paths=("~/.config/bat/config",)),
    "eza": HMModuleInfo(module_path="programs.eza", config_paths=("~/.config/eza/theme.yml",)),
    "fd": HMModuleInfo(module_path="programs.fd", config_paths=("~/.config/fd/ignore",)),
    "ripgrep": HMModuleInfo(module_path="programs.ripgrep", config_paths=("~/.config/ripgrep/ripgreprc",)),
    "jq": HMModuleInfo(module_path="programs.jq", inject_only=True),
    "htop": HMModuleInfo(module_path="programs.htop", config_paths=("~/.config/htop/htoprc",)),
    "btop": HMModuleInfo(module_path="programs.btop", config_paths=("~/.config/btop/btop.conf",)),
    "zoxide": HMModuleInfo(module_path="programs.zoxide", inject_only=True),
    "atuin": HMModuleInfo(module_path="programs.atuin", config_paths=("~/.config/atuin/config.toml",)),
    "readline": HMModuleInfo(module_path="programs.readline", config_paths=("~/.inputrc",)),
    "yt-dlp": HMModuleInfo(module_path="programs.yt-dlp", config_paths=("~/.config/yt-dlp/config",)),
    "mpv": HMModuleInfo(
        module_path="programs.mpv", config_paths=("~/.config/mpv/mpv.conf", "~/.config/mpv/input.conf")
    ),
    "mcfly": HMModuleInfo(module_path="programs.mcfly", inject_only=True),
    "autojump": HMModuleInfo(module_path="programs.autojump", inject_only=True),
    "pazi": HMModuleInfo(module_path="programs.pazi", inject_only=True),
    "carapace": HMModuleInfo(module_path="programs.carapace", inject_only=True),
    "keychain": HMModuleInfo(module_path="programs.keychain", inject_only=True),
    "pay-respects": HMModuleInfo(module_path="programs.pay-respects", inject_only=True),
    "nnn": HMModuleInfo(module_path="programs.nnn", inject_only=True),
    # DevOps / Cloud
    "k9s": HMModuleInfo(
        module_path="programs.k9s",
        config_paths=("~/.config/k9s/config.yaml",),
        darwin_config_paths=("~/Library/Application Support/k9s/",),
    ),
    "lazygit": HMModuleInfo(
        module_path="programs.lazygit",
        config_paths=("~/.config/lazygit/config.yml",),
        darwin_config_paths=("~/Library/Application Support/lazygit/",),
    ),
    "docker": HMModuleInfo(module_path="programs.docker-cli", config_paths=("~/.docker/config.json",)),
    "aws": HMModuleInfo(module_path="programs.awscli", config_paths=("~/.aws/config", "~/.aws/credentials")),
    # Programming languages / build tools
    "go": HMModuleInfo(
        module_path="programs.go",
        config_paths=("~/.config/go/env",),
        darwin_config_paths=("~/Library/Application Support/go/env",),
    ),
    "java": HMModuleInfo(module_path="programs.java", inject_only=True),
    "cargo": HMModuleInfo(module_path="programs.cargo", config_paths=("~/.cargo/config.toml",)),
    "npm": HMModuleInfo(module_path="programs.npm", config_paths=("~/.npmrc",)),
    "pyenv": HMModuleInfo(module_path="programs.pyenv", inject_only=True),
    "rbenv": HMModuleInfo(module_path="programs.rbenv", config_paths=("~/.rbenv/plugins/",)),
    "mise": HMModuleInfo(module_path="programs.mise", config_paths=("~/.config/mise/config.toml",)),
    # macOS-only window/status managers
    "rectangle": HMModuleInfo(
        module_path="programs.rectangle",
        darwin_config_paths=("~/Library/Preferences/com.knollsoft.Rectangle.plist",),
    ),
    "aerospace": HMModuleInfo(module_path="programs.aerospace", config_paths=("~/.config/aerospace/aerospace.toml",)),
    "sketchybar": HMModuleInfo(module_path="programs.sketchybar", config_paths=("~/.config/sketchybar/sketchybarrc",)),
}


def get_hm_module(app_name: str) -> HMModuleInfo | None:
    """Look up the home-manager module info for an app/tool name, or None if unmapped."""
    return APP_TO_HM_MODULE.get(app_name.lower())
