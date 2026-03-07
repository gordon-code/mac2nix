"""Tests for application and homebrew models."""

from pathlib import Path

from mac2nix.models import (
    AppSource,
    BrewCask,
    BrewFormula,
    HomebrewState,
    InstalledApp,
    MasApp,
)


class TestInstalledApp:
    def test_appstore_app(self):
        app = InstalledApp(
            name="Xcode",
            bundle_id="com.apple.dt.Xcode",
            path=Path("/Applications/Xcode.app"),
            version="16.2",
            source=AppSource.APPSTORE,
        )
        assert app.name == "Xcode"
        assert app.source == AppSource.APPSTORE
        assert app.bundle_id == "com.apple.dt.Xcode"

    def test_cask_app(self):
        app = InstalledApp(
            name="Firefox",
            bundle_id="org.mozilla.firefox",
            path=Path("/Applications/Firefox.app"),
            version="135.0",
            source=AppSource.CASK,
        )
        assert app.source == AppSource.CASK

    def test_manual_app_minimal(self):
        app = InstalledApp(
            name="CustomTool",
            path=Path("/Applications/CustomTool.app"),
            source=AppSource.MANUAL,
        )
        assert app.source == AppSource.MANUAL
        assert app.bundle_id is None
        assert app.version is None


class TestHomebrewState:
    def test_full_state(self):
        state = HomebrewState(
            taps=["homebrew/core", "homebrew/cask"],
            formulae=[
                BrewFormula(name="git", version="2.47.0"),
                BrewFormula(name="ripgrep"),
            ],
            casks=[
                BrewCask(name="firefox", version="135.0"),
            ],
            mas_apps=[
                MasApp(name="Xcode", app_id=497799835, version="16.2"),
            ],
        )
        assert len(state.taps) == 2
        assert len(state.formulae) == 2
        assert state.formulae[0].name == "git"
        assert state.formulae[1].version is None
        assert state.casks[0].name == "firefox"
        assert state.mas_apps[0].app_id == 497799835

    def test_empty_defaults(self):
        state = HomebrewState()
        assert state.taps == []
        assert state.formulae == []
        assert state.casks == []
        assert state.mas_apps == []

    def test_json_roundtrip(self):
        original = HomebrewState(
            taps=["homebrew/core"],
            formulae=[BrewFormula(name="git", version="2.47.0")],
            casks=[BrewCask(name="firefox")],
            mas_apps=[MasApp(name="Xcode", app_id=497799835)],
        )
        json_str = original.model_dump_json()
        restored = HomebrewState.model_validate_json(json_str)
        assert restored.taps == ["homebrew/core"]
        assert restored.formulae[0].name == "git"
        assert restored.formulae[0].version == "2.47.0"
        assert restored.casks[0].name == "firefox"
        assert restored.mas_apps[0].app_id == 497799835
