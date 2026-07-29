"""Dotfile path to home-manager program module mapping."""

from __future__ import annotations

from pathlib import Path

DOTFILE_TO_HM: dict[str, str] = {
    # Shell Config Files
    "~/.bashrc": "programs.bash",
    "~/.bash_profile": "programs.bash",
    "~/.profile": "programs.bash",
    "~/.bash_logout": "programs.bash",
    "~/.config/fish/config.fish": "programs.fish",
    "~/.config/fish/functions": "programs.fish",
    "~/.config/fish/completions": "programs.fish",
    "~/.config/fish/conf.d": "programs.fish",
    "~/.zshrc": "programs.zsh",
    "~/.zshenv": "programs.zsh",
    "~/.zprofile": "programs.zsh",
    "~/.zlogin": "programs.zsh",
    "~/.zlogout": "programs.zsh",
    "~/.inputrc": "programs.readline",
    "~/.config/nushell/config.nu": "programs.nushell",
    "~/.config/nushell/env.nu": "programs.nushell",
    # Git / VCS
    "~/.gitconfig": "programs.git",
    "~/.config/git/config": "programs.git",
    "~/.config/git/ignore": "programs.git",
    "~/.config/git/attributes": "programs.git",
    "~/.config/gh/config.yml": "programs.gh",
    "~/.config/lazygit/config.yml": "programs.lazygit",
    "~/Library/Application Support/lazygit/config.yml": "programs.lazygit",
    "~/.hgrc": "programs.mercurial",
    "~/.config/jj/config.toml": "programs.jujutsu",
    # SSH / GPG / Security
    "~/.ssh/config": "programs.ssh",
    "~/.gnupg/gpg.conf": "programs.gpg",
    "~/.gnupg/scdaemon.conf": "programs.gpg",
    "~/.gnupg/dirmngr.conf": "programs.gpg",
    "~/.password-store": "programs.password-store",
    # Terminal Emulators
    "~/.config/alacritty/alacritty.toml": "programs.alacritty",
    "~/.config/kitty/kitty.conf": "programs.kitty",
    "~/.config/kitty/diff.conf": "programs.kitty",
    "~/.config/kitty/macos-launch-services-cmdline": "programs.kitty",
    "~/.config/ghostty/config": "programs.ghostty",
    "~/.config/ghostty/themes": "programs.ghostty",
    "~/.config/wezterm/wezterm.lua": "programs.wezterm",
    "~/.config/wezterm/colors": "programs.wezterm",
    # Editors
    "~/.config/nvim/init.lua": "programs.neovim",
    "~/.config/nvim/init.vim": "programs.neovim",
    "~/.config/nvim/coc-settings.json": "programs.neovim",
    "~/.vimrc": "programs.vim",
    "~/.config/helix/config.toml": "programs.helix",
    "~/.config/helix/languages.toml": "programs.helix",
    "~/Library/Application Support/Code/User/settings.json": "programs.vscode",
    "~/Library/Application Support/Code/User/keybindings.json": "programs.vscode",
    "~/.config/Code/User/settings.json": "programs.vscode",
    "~/.emacs.d/init.el": "programs.emacs",
    "~/.config/emacs/init.el": "programs.emacs",
    "~/.config/kak/kakrc": "programs.kakoune",
    "~/.config/zed/settings.json": "programs.zed-editor",
    "~/.config/micro/settings.json": "programs.micro",
    # CLI Tools
    "~/.config/starship.toml": "programs.starship",
    "~/.config/direnv/direnv.toml": "programs.direnv",
    "~/.config/direnv/direnvrc": "programs.direnv",
    "~/.config/bat/config": "programs.bat",
    "~/.config/eza/theme.yml": "programs.eza",
    "~/.config/fd/ignore": "programs.fd",
    "~/.config/ripgrep/ripgreprc": "programs.ripgrep",
    "~/.config/htop/htoprc": "programs.htop",
    "~/.config/btop/btop.conf": "programs.btop",
    "~/.config/atuin/config.toml": "programs.atuin",
    "~/.config/tmux/tmux.conf": "programs.tmux",
    "~/.tmux.conf": "programs.tmux",
    "~/.config/zellij/config.kdl": "programs.zellij",
    "~/.config/bottom/bottom.toml": "programs.bottom",
    "~/.config/yt-dlp/config": "programs.yt-dlp",
    "~/.config/broot/conf.toml": "programs.broot",
    "~/.config/lf/lfrc": "programs.lf",
    "~/.config/yazi/yazi.toml": "programs.yazi",
    "~/.config/ranger/rc.conf": "programs.ranger",
    "~/.screenrc": "programs.screen",
    "~/.tmate.conf": "programs.tmate",
    "~/.lesskey": "programs.less",
    "~/.config/pandoc/defaults.yaml": "programs.pandoc",
    # Programming Languages
    "~/Library/Application Support/go/env": "programs.go",
    "~/.config/go/env": "programs.go",
    "~/.cargo/config.toml": "programs.cargo",
    "~/.npmrc": "programs.npm",
    "~/.config/npm/npmrc": "programs.npm",
    "~/.config/mise/config.toml": "programs.mise",
    "~/.config/pypoetry/config.toml": "programs.poetry",
    "~/.config/uv/uv.toml": "programs.uv",
    "~/.config/ruff/ruff.toml": "programs.ruff",
    "~/.gradle/gradle.properties": "programs.gradle",
    "~/.config/bun/bunfig.toml": "programs.bun",
    # DevOps / Cloud
    "~/Library/Application Support/k9s/config.yaml": "programs.k9s",
    "~/.config/k9s/config.yaml": "programs.k9s",
    "~/.docker/config.json": "programs.docker-cli",
    "~/.config/docker/config.json": "programs.docker-cli",
    "~/.aws/config": "programs.awscli",
    "~/.aws/credentials": "programs.awscli",
    "~/.config/borgmatic/config.yaml": "programs.borgmatic",
    # Browsers
    "~/Library/Application Support/Firefox": "programs.firefox",
    "~/.mozilla/firefox": "programs.firefox",
    "~/Library/Application Support/Chromium": "programs.chromium",
    "~/.config/chromium": "programs.chromium",
    "~/.config/qutebrowser/config.py": "programs.qutebrowser",
    # Media
    "~/.config/mpv/mpv.conf": "programs.mpv",
    "~/.config/mpv/input.conf": "programs.mpv",
    "~/.config/mpv/scripts": "programs.mpv",
}


def _normalize_path(dotfile_path: str | Path) -> str:
    """Normalize a dotfile path to a ``~``-relative, slash-stripped string for lookup."""
    raw = str(dotfile_path).rstrip("/")
    home = str(Path.home())
    if raw == home:
        return "~"
    if raw.startswith(home + "/"):
        return "~" + raw[len(home) :]
    return raw


def get_hm_program(dotfile_path: str | Path) -> str | None:
    """Look up the home-manager program module for a dotfile path, or None if unmapped."""
    return DOTFILE_TO_HM.get(_normalize_path(dotfile_path))
