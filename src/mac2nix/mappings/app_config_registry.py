"""Registry of well-known macOS app configuration file locations.

Used by the four-tier classifier to determine whether an app's Application
Support (or equivalent) directory contents are further analyzable, or are
opaque binary/database blobs that should be flagged for manual review.
"""

from __future__ import annotations

from dataclasses import dataclass

from mac2nix.models.files import ConfigFileType


@dataclass(frozen=True, slots=True)
class AppConfigInfo:
    config_paths: list[str]
    file_type: ConfigFileType
    scannable: bool = True
    notes: str | None = None


APP_CONFIG_REGISTRY: dict[str, AppConfigInfo] = {
    "com.apple.Safari": AppConfigInfo(
        config_paths=["~/Library/Safari/History.db"],
        file_type=ConfigFileType.DATABASE,
        scannable=False,
        notes="Browsing history database; bookmarks stored separately in ~/Library/Safari/Bookmarks.plist",
    ),
    "com.apple.mail": AppConfigInfo(
        config_paths=["~/Library/Mail"],
        file_type=ConfigFileType.DATABASE,
        scannable=False,
        notes="Versioned V*/MailData/Envelope Index sqlite database; not directly editable config",
    ),
    "com.google.Chrome": AppConfigInfo(
        config_paths=["~/Library/Application Support/Google/Chrome/Default/Preferences"],
        file_type=ConfigFileType.JSON,
        scannable=True,
        notes="Large single-file JSON blob; consider extracting only user-relevant keys",
    ),
    "com.brave.Browser": AppConfigInfo(
        config_paths=["~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Preferences"],
        file_type=ConfigFileType.JSON,
        scannable=True,
        notes="Chromium-based; same structure as Chrome's Preferences file",
    ),
    "org.mozilla.firefox": AppConfigInfo(
        config_paths=["~/Library/Application Support/Firefox/Profiles"],
        file_type=ConfigFileType.CONF,
        scannable=False,
        notes="prefs.js uses JS call syntax (user_pref(...)), not simple key=value; "
        "profile directory names require profiles.ini resolution",
    ),
    "org.mozilla.thunderbird": AppConfigInfo(
        config_paths=["~/Library/Thunderbird/Profiles"],
        file_type=ConfigFileType.CONF,
        scannable=False,
        notes="Same prefs.js/profiles.ini structure as Firefox",
    ),
    "com.microsoft.VSCode": AppConfigInfo(
        config_paths=[
            "~/Library/Application Support/Code/User/settings.json",
            "~/Library/Application Support/Code/User/keybindings.json",
        ],
        file_type=ConfigFileType.JSON,
        scannable=True,
    ),
    "com.sublimetext.4": AppConfigInfo(
        config_paths=["~/Library/Application Support/Sublime Text/Packages/User/Preferences.sublime-settings"],
        file_type=ConfigFileType.JSON,
        scannable=True,
        notes=".sublime-settings extension but JSON-with-comments format",
    ),
    "com.jetbrains.intellij": AppConfigInfo(
        config_paths=["~/Library/Application Support/JetBrains"],
        file_type=ConfigFileType.XML,
        scannable=True,
        notes="Versioned per-release subdirectories (e.g. IntelliJIdea2026.1/options/*.xml)",
    ),
    "com.jetbrains.pycharm": AppConfigInfo(
        config_paths=["~/Library/Application Support/JetBrains"],
        file_type=ConfigFileType.XML,
        scannable=True,
        notes="Same JetBrains versioned-subdirectory scheme as IntelliJ IDEA",
    ),
    "com.jetbrains.WebStorm": AppConfigInfo(
        config_paths=["~/Library/Application Support/JetBrains"],
        file_type=ConfigFileType.XML,
        scannable=True,
        notes="Same JetBrains versioned-subdirectory scheme as IntelliJ IDEA",
    ),
    "com.github.GitHubClient": AppConfigInfo(
        config_paths=["~/Library/Application Support/GitHub Desktop"],
        file_type=ConfigFileType.JSON,
        scannable=True,
        notes="Electron app config; exact filename unverified, flagged for manual review",
    ),
    "com.spotify.client": AppConfigInfo(
        config_paths=["~/Library/Application Support/Spotify/prefs"],
        file_type=ConfigFileType.CONF,
        scannable=True,
        notes="key=value pairs despite no file extension",
    ),
    "com.1password.1password": AppConfigInfo(
        config_paths=["~/Library/Group Containers/2BUA8C4S2C.com.1password/Library/Application Support/1Password/Data"],
        file_type=ConfigFileType.DATABASE,
        scannable=False,
        notes="Encrypted vault data, not human-editable config",
    ),
    "com.bitwarden.desktop": AppConfigInfo(
        config_paths=["~/Library/Application Support/Bitwarden/data.json"],
        file_type=ConfigFileType.DATABASE,
        scannable=False,
        notes="Encrypted vault export despite .json extension",
    ),
    "com.tinyspeck.slackmacgap": AppConfigInfo(
        config_paths=["~/Library/Application Support/Slack/storage"],
        file_type=ConfigFileType.DATABASE,
        scannable=False,
        notes="LevelDB-backed local storage, not directly parseable",
    ),
    "com.hnc.Discord": AppConfigInfo(
        config_paths=["~/Library/Application Support/discord/settings.json"],
        file_type=ConfigFileType.JSON,
        scannable=True,
        notes="Message/user cache stored separately in LevelDB (not scannable)",
    ),
    "com.docker.docker": AppConfigInfo(
        config_paths=["~/Library/Group Containers/group.com.docker/settings.json"],
        file_type=ConfigFileType.JSON,
        scannable=True,
    ),
    "md.obsidian": AppConfigInfo(
        config_paths=["~/Library/Application Support/obsidian/obsidian.json"],
        file_type=ConfigFileType.JSON,
        scannable=True,
        notes="Global app config; per-vault settings live in each vault's .obsidian/ folder, not under ~/Library",
    ),
    "com.raycast.macos": AppConfigInfo(
        config_paths=["~/Library/Application Support/com.raycast.macos"],
        file_type=ConfigFileType.DATABASE,
        scannable=False,
        notes="Settings and extension state stored in sqlite databases",
    ),
    "com.googlecode.iterm2": AppConfigInfo(
        config_paths=["~/Library/Application Support/iTerm2/DynamicProfiles"],
        file_type=ConfigFileType.JSON,
        scannable=True,
        notes="Dynamic profile JSON files; core preferences stored separately in "
        "~/Library/Preferences/com.googlecode.iterm2.plist (see preferences scanner)",
    ),
    "org.videolan.vlc": AppConfigInfo(
        config_paths=["~/Library/Preferences/org.videolan.vlc/vlcrc"],
        file_type=ConfigFileType.CONF,
        scannable=True,
        notes="INI-style key=value config despite being under ~/Library/Preferences",
    ),
    "us.zoom.xos": AppConfigInfo(
        config_paths=["~/Library/Application Support/zoom.us/data/zoomus.enc.db"],
        file_type=ConfigFileType.DATABASE,
        scannable=False,
        notes="Encrypted local settings db; user-visible preferences duplicated in "
        "~/Library/Preferences/us.zoom.xos.plist",
    ),
    "com.culturedcode.ThingsMac": AppConfigInfo(
        config_paths=["~/Library/Group Containers/JLMPQHK86H.com.culturedcode.ThingsMac"],
        file_type=ConfigFileType.DATABASE,
        scannable=False,
        notes="Things Database.thingsdatabase sqlite store",
    ),
    "com.postmanlabs.mac": AppConfigInfo(
        config_paths=["~/Library/Application Support/Postman"],
        file_type=ConfigFileType.DATABASE,
        scannable=False,
        notes="Mostly cloud-synced; local storage format unverified, flagged for manual review",
    ),
    "org.qbittorrent.qBittorrent": AppConfigInfo(
        config_paths=["~/Library/Preferences/qBittorrent/qBittorrent.ini"],
        file_type=ConfigFileType.CONF,
        scannable=True,
    ),
    "com.microsoft.rdc.macos": AppConfigInfo(
        config_paths=[
            "~/Library/Containers/com.microsoft.rdc.macos/Data/Library/Application Support/Microsoft Remote Desktop"
        ],
        file_type=ConfigFileType.DATABASE,
        scannable=False,
        notes="Connection list stored in a Core Data sqlite store, not directly editable",
    ),
}


def get_app_config(bundle_id: str) -> AppConfigInfo | None:
    return APP_CONFIG_REGISTRY.get(bundle_id)
