"""Tests for app_to_package mapping."""

from mac2nix.mappings.app_to_package import APP_TO_PACKAGE, classify_app, normalize_app_name


class TestNormalizeAppName:
    def test_strips_app_suffix_and_lowercases(self) -> None:
        assert normalize_app_name("Firefox.app") == "firefox"

    def test_hyphenates_spaces(self) -> None:
        assert normalize_app_name("Google Chrome.app") == "google-chrome"

    def test_zoom_us_bundle_gotcha(self) -> None:
        assert normalize_app_name("zoom.us.app") == "zoom"

    def test_iterm_bundle_gotcha(self) -> None:
        assert normalize_app_name("iTerm.app") == "iterm2"

    def test_brave_browser_gotcha(self) -> None:
        assert normalize_app_name("Brave Browser.app") == "brave-browser"

    def test_github_desktop_gotcha(self) -> None:
        assert normalize_app_name("GitHub Desktop.app") == "github"

    def test_linear_gotcha(self) -> None:
        assert normalize_app_name("Linear.app") == "linear-linear"
        classification = classify_app("Linear.app")
        assert classification is not None
        assert classification.source == "cask"
        assert classification.package_name == "linear-linear"

    def test_ice_gotcha(self) -> None:
        assert normalize_app_name("Ice.app") == "jordanbaird-ice"
        classification = classify_app("Ice.app")
        assert classification is not None
        assert classification.source == "cask"
        assert classification.package_name == "jordanbaird-ice"

    def test_parallels_desktop_gotcha(self) -> None:
        assert normalize_app_name("Parallels Desktop.app") == "parallels"

    def test_alttab_gotcha(self) -> None:
        assert normalize_app_name("AltTab.app") == "alt-tab"

    def test_hidden_bar_gotcha(self) -> None:
        assert normalize_app_name("Hidden Bar.app") == "hiddenbar"

    def test_strips_trailing_version_number(self) -> None:
        assert normalize_app_name("1Password 7.app") == "1password"
        assert normalize_app_name("Transmit 5.app") == "transmit"

    def test_leading_digit_in_name_is_preserved(self) -> None:
        assert normalize_app_name("1Password.app") == "1password"

    def test_double_space_collapses_to_single_hyphen(self) -> None:
        assert normalize_app_name("Google  Chrome.app") == "google-chrome"

    def test_tab_whitespace_is_treated_as_space(self) -> None:
        assert normalize_app_name("Fire\tfox.app") == "fire-fox"

    def test_newline_whitespace_is_treated_as_space(self) -> None:
        assert normalize_app_name("Fire\nfox.app") == "fire-fox"


class TestClassifyAppNixpkgs:
    def test_firefox(self) -> None:
        result = classify_app("Firefox.app")
        assert result is not None
        assert result.source == "nixpkgs"
        assert result.package_name == "firefox"

    def test_alacritty(self) -> None:
        result = classify_app("Alacritty.app")
        assert result is not None
        assert result.source == "nixpkgs"

    def test_karabiner_elements(self) -> None:
        result = classify_app("Karabiner-Elements.app")
        assert result is not None
        assert result.source == "nixpkgs"
        assert result.package_name == "karabiner-elements"


class TestClassifyAppCask:
    def test_slack(self) -> None:
        result = classify_app("Slack.app")
        assert result is not None
        assert result.source == "cask"
        assert result.package_name == "slack"
        assert result.nix_alternative is None

    def test_notion(self) -> None:
        result = classify_app("Notion.app")
        assert result is not None
        assert result.source == "cask"

    def test_iterm_via_bundle_name(self) -> None:
        result = classify_app("iTerm.app")
        assert result is not None
        assert result.source == "cask"
        assert result.package_name == "iterm2"

    def test_discord_has_nix_alternative(self) -> None:
        result = classify_app("Discord.app")
        assert result is not None
        assert result.source == "cask"
        assert result.nix_alternative == "discord"

    def test_obsidian_has_nix_alternative(self) -> None:
        result = classify_app("Obsidian.app")
        assert result is not None
        assert result.nix_alternative == "obsidian"

    def test_signal_has_nix_alternative(self) -> None:
        result = classify_app("Signal.app")
        assert result is not None
        assert result.nix_alternative == "signal-desktop"


class TestClassifyAppAppstore:
    def test_xcode(self) -> None:
        result = classify_app("Xcode.app")
        assert result is not None
        assert result.source == "appstore"
        assert result.package_name == "Xcode"

    def test_bear(self) -> None:
        result = classify_app("Bear.app")
        assert result is not None
        assert result.source == "appstore"

    def test_pages(self) -> None:
        result = classify_app("Pages.app")
        assert result is not None
        assert result.source == "appstore"


class TestClassifyAppSystem:
    def test_safari(self) -> None:
        result = classify_app("Safari.app")
        assert result is not None
        assert result.source == "system"

    def test_finder(self) -> None:
        result = classify_app("Finder.app")
        assert result is not None
        assert result.source == "system"

    def test_terminal(self) -> None:
        result = classify_app("Terminal.app")
        assert result is not None
        assert result.source == "system"


class TestClassifyAppCaseInsensitivity:
    def test_uppercase_bundle_name(self) -> None:
        assert classify_app("FIREFOX.APP") == classify_app("Firefox.app")

    def test_mixed_case_bundle_name(self) -> None:
        assert classify_app("sLaCk.aPp") == classify_app("Slack.app")


class TestClassifyAppUnrecognized:
    def test_unknown_app_returns_none(self) -> None:
        assert classify_app("SomeRandomEnterpriseApp.app") is None

    def test_empty_string_returns_none(self) -> None:
        assert classify_app("") is None


class TestAppToPackageCoverage:
    def test_has_at_least_115_entries(self) -> None:
        assert len(APP_TO_PACKAGE) >= 115

    def test_all_sources_represented(self) -> None:
        sources = {classification.source for classification in APP_TO_PACKAGE.values()}
        assert sources == {"nixpkgs", "cask", "appstore", "system"}
