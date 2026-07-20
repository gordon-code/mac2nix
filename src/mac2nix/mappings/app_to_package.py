"""macOS application bundle to nix-darwin installation channel mapping."""

from __future__ import annotations

import re
from dataclasses import dataclass

_VERSION_SUFFIX_RE = re.compile(r"\s+\d+(\.\d+)*$")
_WHITESPACE_RE = re.compile(r"\s+")

_NAME_OVERRIDES: dict[str, str] = {
    "zoom.us": "zoom",
    "iterm": "iterm2",
    "linear": "linear-linear",
    "ice": "jordanbaird-ice",
    "github desktop": "github",
    "parallels desktop": "parallels",
    "alttab": "alt-tab",
    "hidden bar": "hiddenbar",
}


@dataclass(frozen=True, slots=True)
class AppClassification:
    source: str
    package_name: str
    nix_alternative: str | None = None


def normalize_app_name(name: str) -> str:
    """Normalize a raw app bundle name into the lookup key used by APP_TO_PACKAGE."""
    normalized = name.strip()
    if normalized.lower().endswith(".app"):
        normalized = normalized[: -len(".app")]
    normalized = _VERSION_SUFFIX_RE.sub("", normalized).strip().lower()
    if normalized in _NAME_OVERRIDES:
        return _NAME_OVERRIDES[normalized]
    return _WHITESPACE_RE.sub("-", normalized)


def classify_app(name: str) -> AppClassification | None:
    """Classify an app bundle name into its nix-darwin installation channel, or None if unrecognized."""
    return APP_TO_PACKAGE.get(normalize_app_name(name))


APP_TO_PACKAGE: dict[str, AppClassification] = {
    # nixpkgs (Darwin-confirmed)
    "firefox": AppClassification("nixpkgs", "firefox"),
    "alacritty": AppClassification("nixpkgs", "alacritty"),
    "kitty": AppClassification("nixpkgs", "kitty"),
    "wezterm": AppClassification("nixpkgs", "wezterm"),
    "vlc": AppClassification("nixpkgs", "vlc"),
    "emacs": AppClassification("nixpkgs", "emacs"),
    "iina": AppClassification("nixpkgs", "iina"),
    "ghostty": AppClassification("nixpkgs", "ghostty-bin"),
    "obs": AppClassification("nixpkgs", "obs-studio"),
    "handbrake": AppClassification("nixpkgs", "handbrake"),
    "neovide": AppClassification("nixpkgs", "neovide"),
    "qutebrowser": AppClassification("nixpkgs", "qutebrowser"),
    "utm": AppClassification("nixpkgs", "utm"),
    "karabiner-elements": AppClassification("nixpkgs", "karabiner-elements"),
    "monitorcontrol": AppClassification("nixpkgs", "monitorcontrol"),
    # cask (Homebrew cask only)
    "google-chrome": AppClassification("cask", "google-chrome"),
    "visual-studio-code": AppClassification("cask", "visual-studio-code"),
    "cursor": AppClassification("cask", "cursor"),
    "slack": AppClassification("cask", "slack"),
    "discord": AppClassification("cask", "discord", nix_alternative="discord"),
    "zoom": AppClassification("cask", "zoom"),
    "microsoft-teams": AppClassification("cask", "microsoft-teams"),
    "telegram": AppClassification("cask", "telegram"),
    "1password": AppClassification("cask", "1password"),
    "alfred": AppClassification("cask", "alfred"),
    "raycast": AppClassification("cask", "raycast"),
    "rectangle": AppClassification("cask", "rectangle"),
    "bettertouchtool": AppClassification("cask", "bettertouchtool"),
    "docker": AppClassification("cask", "docker"),
    "postman": AppClassification("cask", "postman"),
    "tableplus": AppClassification("cask", "tableplus"),
    "github": AppClassification("cask", "github"),
    "spotify": AppClassification("cask", "spotify"),
    "dropbox": AppClassification("cask", "dropbox"),
    "google-drive": AppClassification("cask", "google-drive"),
    "onedrive": AppClassification("cask", "onedrive"),
    "notion": AppClassification("cask", "notion"),
    "obsidian": AppClassification("cask", "obsidian", nix_alternative="obsidian"),
    "logseq": AppClassification("cask", "logseq"),
    "arc": AppClassification("cask", "arc"),
    "brave-browser": AppClassification("cask", "brave-browser"),
    "microsoft-edge": AppClassification("cask", "microsoft-edge"),
    "warp": AppClassification("cask", "warp"),
    "iterm2": AppClassification("cask", "iterm2"),
    "sublime-text": AppClassification("cask", "sublime-text"),
    "tower": AppClassification("cask", "tower"),
    "fork": AppClassification("cask", "fork"),
    "appcleaner": AppClassification("cask", "appcleaner"),
    "the-unarchiver": AppClassification("cask", "the-unarchiver"),
    "bartender": AppClassification("cask", "bartender"),
    "cleanmymac": AppClassification("cask", "cleanmymac"),
    "stats": AppClassification("cask", "stats"),
    "parallels": AppClassification("cask", "parallels"),
    "vmware-fusion": AppClassification("cask", "vmware-fusion"),
    "hyper": AppClassification("cask", "hyper"),
    "jetbrains-toolbox": AppClassification("cask", "jetbrains-toolbox"),
    "android-studio": AppClassification("cask", "android-studio"),
    "signal": AppClassification("cask", "signal", nix_alternative="signal-desktop"),
    "keepassxc": AppClassification("cask", "keepassxc", nix_alternative="keepassxc"),
    "gitkraken": AppClassification("cask", "gitkraken"),
    "sublime-merge": AppClassification("cask", "sublime-merge"),
    "sourcetree": AppClassification("cask", "sourcetree"),
    "proxyman": AppClassification("cask", "proxyman"),
    "charles": AppClassification("cask", "charles"),
    "dash": AppClassification("cask", "dash"),
    "transmit": AppClassification("cask", "transmit"),
    "hammerspoon": AppClassification("cask", "hammerspoon"),
    "amethyst": AppClassification("cask", "amethyst"),
    "bitwarden": AppClassification("cask", "bitwarden"),
    "alt-tab": AppClassification("cask", "alt-tab"),
    "hiddenbar": AppClassification("cask", "hiddenbar"),
    "keepingyouawake": AppClassification("cask", "keepingyouawake"),
    # appstore (Mac App Store exclusive)
    "xcode": AppClassification("appstore", "Xcode"),
    "bear": AppClassification("appstore", "Bear"),
    "magnet": AppClassification("appstore", "Magnet"),
    "fantastical": AppClassification("appstore", "Fantastical"),
    "things": AppClassification("appstore", "Things"),
    "pixelmator-pro": AppClassification("appstore", "Pixelmator Pro"),
    "amphetamine": AppClassification("appstore", "Amphetamine"),
    "pages": AppClassification("appstore", "Pages"),
    "numbers": AppClassification("appstore", "Numbers"),
    "keynote": AppClassification("appstore", "Keynote"),
    # system (bundled with macOS, no installation channel)
    "safari": AppClassification("system", "n/a"),
    "mail": AppClassification("system", "n/a"),
    "calendar": AppClassification("system", "n/a"),
    "notes": AppClassification("system", "n/a"),
    "reminders": AppClassification("system", "n/a"),
    "maps": AppClassification("system", "n/a"),
    "photos": AppClassification("system", "n/a"),
    "messages": AppClassification("system", "n/a"),
    "facetime": AppClassification("system", "n/a"),
    "music": AppClassification("system", "n/a"),
    "tv": AppClassification("system", "n/a"),
    "podcasts": AppClassification("system", "n/a"),
    "news": AppClassification("system", "n/a"),
    "stocks": AppClassification("system", "n/a"),
    "books": AppClassification("system", "n/a"),
    "preview": AppClassification("system", "n/a"),
    "terminal": AppClassification("system", "n/a"),
    "activity-monitor": AppClassification("system", "n/a"),
    "disk-utility": AppClassification("system", "n/a"),
    "keychain-access": AppClassification("system", "n/a"),
    "system-preferences": AppClassification("system", "n/a"),
    "system-settings": AppClassification("system", "n/a"),
    "finder": AppClassification("system", "n/a"),
    "textedit": AppClassification("system", "n/a"),
    "quicktime-player": AppClassification("system", "n/a"),
    "screenshot": AppClassification("system", "n/a"),
    "font-book": AppClassification("system", "n/a"),
    "calculator": AppClassification("system", "n/a"),
    "dictionary": AppClassification("system", "n/a"),
    "chess": AppClassification("system", "n/a"),
    "siri": AppClassification("system", "n/a"),
    "home": AppClassification("system", "n/a"),
    "shortcuts": AppClassification("system", "n/a"),
    "freeform": AppClassification("system", "n/a"),
    "weather": AppClassification("system", "n/a"),
    "clock": AppClassification("system", "n/a"),
    "contacts": AppClassification("system", "n/a"),
    "find-my": AppClassification("system", "n/a"),
    "automator": AppClassification("system", "n/a"),
    "imovie": AppClassification("system", "n/a"),
    "garageband": AppClassification("system", "n/a"),
}
