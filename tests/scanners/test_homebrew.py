"""Tests for Homebrew scanner."""

from unittest.mock import patch

from mac2nix.models.application import HomebrewState
from mac2nix.scanners.homebrew import HomebrewScanner

_BREWFILE = """\
tap "homebrew/core"
tap "homebrew/cask"
brew "git"
brew "ripgrep"
cask "firefox"
cask "iterm2"
mas "Keynote", id: 409183694
mas "Numbers", id: 409203825
"""

_VERSIONS = """\
git 2.44.0
ripgrep 14.1.0
firefox 124.0
"""


class TestHomebrewScanner:
    def test_name_property(self) -> None:
        assert HomebrewScanner().name == "homebrew"

    def test_is_available_brew_present(self) -> None:
        with patch("mac2nix.scanners.homebrew.shutil.which", return_value="/opt/homebrew/bin/brew"):
            assert HomebrewScanner().is_available() is True

    def test_is_available_brew_absent(self) -> None:
        with patch("mac2nix.scanners.homebrew.shutil.which", return_value=None):
            assert HomebrewScanner().is_available() is False

    def test_parses_taps(self, cmd_result) -> None:
        with patch(
            "mac2nix.scanners.homebrew.run_command",
            side_effect=[cmd_result(_BREWFILE), cmd_result(_VERSIONS)],
        ):
            result = HomebrewScanner().scan()

        assert isinstance(result, HomebrewState)
        assert "homebrew/core" in result.taps
        assert "homebrew/cask" in result.taps

    def test_parses_formulae(self, cmd_result) -> None:
        with patch(
            "mac2nix.scanners.homebrew.run_command",
            side_effect=[cmd_result(_BREWFILE), cmd_result(_VERSIONS)],
        ):
            result = HomebrewScanner().scan()

        assert isinstance(result, HomebrewState)
        formula_names = [f.name for f in result.formulae]
        assert "git" in formula_names
        assert "ripgrep" in formula_names

    def test_parses_casks(self, cmd_result) -> None:
        with patch(
            "mac2nix.scanners.homebrew.run_command",
            side_effect=[cmd_result(_BREWFILE), cmd_result(_VERSIONS)],
        ):
            result = HomebrewScanner().scan()

        assert isinstance(result, HomebrewState)
        cask_names = [c.name for c in result.casks]
        assert "firefox" in cask_names
        assert "iterm2" in cask_names

    def test_parses_mas_apps(self, cmd_result) -> None:
        with patch(
            "mac2nix.scanners.homebrew.run_command",
            side_effect=[cmd_result(_BREWFILE), cmd_result(_VERSIONS)],
        ):
            result = HomebrewScanner().scan()

        assert isinstance(result, HomebrewState)
        assert len(result.mas_apps) == 2
        assert result.mas_apps[0].name == "Keynote"
        assert result.mas_apps[0].app_id == 409183694

    def test_version_enrichment(self, cmd_result) -> None:
        with patch(
            "mac2nix.scanners.homebrew.run_command",
            side_effect=[cmd_result(_BREWFILE), cmd_result(_VERSIONS)],
        ):
            result = HomebrewScanner().scan()

        assert isinstance(result, HomebrewState)
        git_formula = next(f for f in result.formulae if f.name == "git")
        assert git_formula.version == "2.44.0"
        firefox_cask = next(c for c in result.casks if c.name == "firefox")
        assert firefox_cask.version == "124.0"

    def test_brew_command_fails(self) -> None:
        with patch(
            "mac2nix.scanners.homebrew.run_command",
            return_value=None,
        ):
            result = HomebrewScanner().scan()

        assert isinstance(result, HomebrewState)
        assert result.taps == []
        assert result.formulae == []
        assert result.casks == []

    def test_skips_comments_and_blanks(self, cmd_result) -> None:
        brewfile = '# Comment line\n\ntap "homebrew/core"\n'
        with patch(
            "mac2nix.scanners.homebrew.run_command",
            side_effect=[cmd_result(brewfile), cmd_result("")],
        ):
            result = HomebrewScanner().scan()

        assert isinstance(result, HomebrewState)
        assert result.taps == ["homebrew/core"]
