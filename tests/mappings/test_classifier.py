"""Tests for the four-tier setting classifier."""

from pathlib import Path

from mac2nix.mappings.classifier import (
    ClassificationTier,
    classify_app,
    classify_app_config,
    classify_brew_formula,
    classify_dotfile,
    classify_font,
    classify_launch_agent,
    classify_network_setting,
    classify_preference,
    classify_security_setting,
    classify_shell_setting,
    classify_system_setting,
)
from mac2nix.models.application import AppSource, BrewFormula, InstalledApp
from mac2nix.models.files import DotfileEntry, DotfileManager, FontEntry, FontSource
from mac2nix.models.preferences import PreferencesDomain
from mac2nix.models.services import LaunchAgentEntry, LaunchAgentSource, ShellConfig, ShellFramework


def _domain(name: str, keys: dict, *, source_path: Path | None = None, source: str = "disk") -> PreferencesDomain:
    return PreferencesDomain(domain_name=name, source_path=source_path, source=source, keys=keys)


class TestClassifyPreferenceNativeTier:
    def test_known_defaults_key_routes_to_tier_1(self) -> None:
        domain = _domain(
            "com.apple.dock", {"autohide": True}, source_path=Path.home() / "Library/Preferences/com.apple.dock.plist"
        )
        result = classify_preference(domain, "autohide", True)
        assert result.tier == ClassificationTier.NATIVE
        assert result.nix_path == "system.defaults.dock.autohide"
        assert result.destination == "system.defaults.dock.autohide"

    def test_coercion_is_carried_through_from_nix_option(self) -> None:
        domain = _domain("com.apple.controlcenter", {"Sound": 18})
        result = classify_preference(domain, "Sound", 18)
        assert result.tier == ClassificationTier.NATIVE
        assert result.coercion is not None
        assert result.coercion(18) is True
        assert result.coercion(24) is False


class TestClassifyPreferenceTierOverride:
    def test_dock_persistent_apps_routes_to_tier_override_not_native(self) -> None:
        domain = _domain(
            "com.apple.dock",
            {"persistent-apps": []},
            source_path=Path.home() / "Library/Preferences/com.apple.dock.plist",
        )
        result = classify_preference(domain, "persistent-apps", [{"tile-data": {}}])
        assert result.tier == ClassificationTier.CUSTOM_PREFS
        assert result.destination == "CustomUserPreferences"
        assert result.nix_path is None
        assert result.metadata is not None
        assert result.metadata["native_nix_path_available"] == "system.defaults.dock.persistent-apps"


class TestClassifyPreferenceUnmappedKey:
    def test_unmapped_key_in_user_domain_routes_to_custom_user_preferences(self) -> None:
        domain = _domain(
            "com.example.someapp",
            {"SomeSetting": "value"},
            source_path=Path.home() / "Library/Preferences/com.example.someapp.plist",
        )
        result = classify_preference(domain, "SomeSetting", "value")
        assert result.tier == ClassificationTier.CUSTOM_PREFS
        assert result.destination == "CustomUserPreferences"

    def test_unmapped_key_in_system_domain_routes_to_custom_system_preferences(self) -> None:
        domain = _domain(
            "com.apple.loginwindow",
            {"SomeUnknownKey": 1},
            source_path=Path("/Library/Preferences/com.apple.loginwindow.plist"),
        )
        result = classify_preference(domain, "SomeUnknownKey", 1)
        assert result.tier == ClassificationTier.CUSTOM_PREFS
        assert result.destination == "CustomSystemPreferences"

    def test_cfprefsd_domain_with_no_source_path_defaults_to_user_preferences(self) -> None:
        domain = _domain("com.example.cfprefsdonly", {"Key": 1}, source_path=None, source="cfprefsd")
        result = classify_preference(domain, "Key", 1)
        assert result.tier == ClassificationTier.CUSTOM_PREFS
        assert result.destination == "CustomUserPreferences"


class TestClassifyPreferenceSensitiveKeyRedaction:
    def test_key_matching_sensitive_pattern_routes_to_manual_report_redacted(self) -> None:
        domain = _domain("com.example.someapp", {"API_TOKEN": "sk-live-abc123"})
        result = classify_preference(domain, "API_TOKEN", "sk-live-abc123")
        assert result.tier == ClassificationTier.MANUAL_REPORT
        assert result.metadata is not None
        assert result.metadata["potentially_sensitive"] is True
        assert result.metadata["value"] == "***REDACTED***"

    def test_sensitive_match_takes_priority_over_native_mapping(self) -> None:
        """A sensitive-looking key must never leak into Tier 1/2/3 even if otherwise mappable."""
        domain = _domain("com.apple.dock", {"autohide_TOKEN": True})
        result = classify_preference(domain, "autohide_TOKEN", True)
        assert result.tier == ClassificationTier.MANUAL_REPORT
        assert result.metadata is not None
        assert result.metadata["value"] == "***REDACTED***"

    def test_non_sensitive_key_is_not_redacted(self) -> None:
        domain = _domain("com.example.someapp", {"autohide": True})
        result = classify_preference(domain, "autohide", True)
        assert (
            result.tier != ClassificationTier.MANUAL_REPORT
            or (result.metadata or {}).get("potentially_sensitive") is not True
        )


class TestClassifyPreferenceBinarySentinel:
    def test_binary_sentinel_routes_to_activation_script_not_dropped(self) -> None:
        domain = _domain("com.example.someapp", {"IconData": "<data:128 bytes>"})
        result = classify_preference(domain, "IconData", "<data:128 bytes>")
        assert result.tier == ClassificationTier.ACTIVATION_SCRIPT
        assert result.metadata is not None
        assert result.metadata["command_type"] == "defaults_write"
        assert result.metadata["value"] == "<data:128 bytes>"

    def test_binary_sentinel_metadata_has_no_shell_command_string(self) -> None:
        """SEC-2: metadata must be structured, never a pre-built shell command."""
        domain = _domain("com.example.someapp", {"IconData": "<data:128 bytes>"})
        result = classify_preference(domain, "IconData", "<data:128 bytes>")
        assert result.metadata is not None
        assert set(result.metadata) == {"command_type", "domain", "key", "value_type", "value"}

    def test_malformed_sentinel_like_string_is_not_treated_as_binary(self) -> None:
        domain = _domain("com.example.someapp", {"Description": "128 bytes"})
        result = classify_preference(domain, "Description", "128 bytes")
        assert result.tier != ClassificationTier.ACTIVATION_SCRIPT


class TestClassifyPreferenceEphemeralSkip:
    def test_ephemeral_value_is_skipped_not_reported(self) -> None:
        domain = _domain("com.example.someapp", {"NSWindow Frame Main": "100 100 800 600 0 0 1440 900"})
        result = classify_preference(domain, "NSWindow Frame Main", "100 100 800 600 0 0 1440 900")
        assert result.tier == ClassificationTier.MANUAL_REPORT
        assert result.metadata is not None
        assert result.metadata["skipped"] is True

    def test_ephemeral_check_runs_before_defaults_lookup(self) -> None:
        """A key that would otherwise look ephemeral must not sneak past into Tier 1."""
        domain = _domain("com.example.someapp", {"SULastCheckTime": "2026-07-20"})
        result = classify_preference(domain, "SULastCheckTime", "2026-07-20")
        assert result.tier == ClassificationTier.MANUAL_REPORT
        assert (result.metadata or {}).get("skipped") is True


class TestClassifyPreferenceAlfSpecialCase:
    def test_globalstate_routes_to_application_firewall_enable(self) -> None:
        domain = _domain(
            "com.apple.alf", {"globalstate": 1}, source_path=Path("/Library/Preferences/com.apple.alf.plist")
        )
        result = classify_preference(domain, "globalstate", 1)
        assert result.tier == ClassificationTier.NATIVE
        assert result.nix_path == "networking.applicationFirewall.enable"

    def test_stealthenabled_routes_to_stealth_mode_option(self) -> None:
        domain = _domain(
            "com.apple.alf", {"stealthenabled": 1}, source_path=Path("/Library/Preferences/com.apple.alf.plist")
        )
        result = classify_preference(domain, "stealthenabled", 1)
        assert result.tier == ClassificationTier.NATIVE
        assert result.nix_path == "networking.applicationFirewall.enableStealthMode"

    def test_unaliased_alf_key_falls_back_to_custom_system_preferences(self) -> None:
        domain = _domain(
            "com.apple.alf", {"loggingenabled": 1}, source_path=Path("/Library/Preferences/com.apple.alf.plist")
        )
        result = classify_preference(domain, "loggingenabled", 1)
        assert result.tier == ClassificationTier.CUSTOM_PREFS
        assert result.destination == "CustomSystemPreferences"

    def test_alf_destination_never_mentions_removed_system_defaults_alf_module(self) -> None:
        domain = _domain("com.apple.alf", {"globalstate": 1})
        result = classify_preference(domain, "globalstate", 1)
        assert "system.defaults.alf" not in result.destination


class TestClassifyLaunchAgent:
    def _entry(self, label: str, source: LaunchAgentSource, raw_plist: dict | None = None) -> LaunchAgentEntry:
        return LaunchAgentEntry(label=label, source=source, raw_plist=raw_plist or {})

    def test_known_service_label_routes_to_native_tier(self) -> None:
        entry = self._entry("com.tailscale.tailscaled", LaunchAgentSource.DAEMON)
        result = classify_launch_agent(entry)
        assert result.tier == ClassificationTier.NATIVE
        assert result.nix_path == "services.tailscale"

    def test_unmatched_user_agent_routes_to_custom_prefs_generic_passthrough(self) -> None:
        entry = self._entry("com.example.myagent", LaunchAgentSource.USER)
        result = classify_launch_agent(entry)
        assert result.tier == ClassificationTier.CUSTOM_PREFS
        assert "launchd.user.agents" in result.destination

    def test_unmatched_daemon_routes_to_activation_script_tier(self) -> None:
        entry = self._entry("com.example.mydaemon", LaunchAgentSource.DAEMON)
        result = classify_launch_agent(entry)
        assert result.tier == ClassificationTier.ACTIVATION_SCRIPT
        assert "launchd.daemons" in result.destination

    def test_login_item_has_no_nix_darwin_equivalent(self) -> None:
        entry = self._entry("com.example.loginhelper", LaunchAgentSource.LOGIN_ITEM)
        result = classify_launch_agent(entry)
        assert result.tier == ClassificationTier.MANUAL_REPORT

    def test_droppable_keys_are_stripped_from_raw_plist_metadata(self) -> None:
        entry = self._entry(
            "com.example.myagent",
            LaunchAgentSource.USER,
            raw_plist={"Label": "com.example.myagent", "LegacyTimers": True, "RunAtLoad": True},
        )
        result = classify_launch_agent(entry)
        assert result.metadata is not None
        cleaned = result.metadata["raw_plist"]
        assert "LegacyTimers" not in cleaned
        assert cleaned["RunAtLoad"] is True

    def test_nested_raw_plist_values_are_deep_copied_not_shared_with_source(self) -> None:
        """A shallow copy would leave nested dicts/lists shared with entry.raw_plist,
        so mutating the classifier's output would silently corrupt the scanned source data.
        """
        entry = self._entry(
            "com.example.myagent",
            LaunchAgentSource.USER,
            raw_plist={
                "Label": "com.example.myagent",
                "KeepAlive": {"SuccessfulExit": False},
                "StartCalendarInterval": [{"Hour": 9}],
            },
        )
        result = classify_launch_agent(entry)
        assert result.metadata is not None
        cleaned = result.metadata["raw_plist"]
        assert cleaned["KeepAlive"] is not entry.raw_plist["KeepAlive"]
        assert cleaned["StartCalendarInterval"] is not entry.raw_plist["StartCalendarInterval"]

        cleaned["KeepAlive"]["SuccessfulExit"] = True
        cleaned["StartCalendarInterval"][0]["Hour"] = 17
        assert entry.raw_plist["KeepAlive"]["SuccessfulExit"] is False
        assert entry.raw_plist["StartCalendarInterval"][0]["Hour"] == 9


class TestClassifyApp:
    def test_nixpkgs_app_routes_to_native_system_packages(self) -> None:
        app = InstalledApp(name="Firefox", path=Path("/Applications/Firefox.app"), source=AppSource.MANUAL)
        result = classify_app(app)
        assert result.tier == ClassificationTier.NATIVE
        assert result.nix_path == "pkgs.firefox"

    def test_cask_app_routes_to_homebrew_casks(self) -> None:
        app = InstalledApp(name="Slack", path=Path("/Applications/Slack.app"), source=AppSource.MANUAL)
        result = classify_app(app)
        assert result.tier == ClassificationTier.NATIVE
        assert result.destination == "homebrew.casks"

    def test_appstore_app_routes_to_mas_apps(self) -> None:
        app = InstalledApp(name="Xcode", path=Path("/Applications/Xcode.app"), source=AppSource.APPSTORE)
        result = classify_app(app)
        assert result.tier == ClassificationTier.NATIVE
        assert result.destination == "homebrew.masApps"

    def test_system_app_needs_no_action(self) -> None:
        app = InstalledApp(name="Safari", path=Path("/Applications/Safari.app"), source=AppSource.MANUAL)
        result = classify_app(app)
        assert result.tier == ClassificationTier.MANUAL_REPORT

    def test_unrecognized_app_routes_to_manual_report(self) -> None:
        app = InstalledApp(
            name="SomeObscureInternalTool",
            path=Path("/Applications/SomeObscureInternalTool.app"),
            source=AppSource.MANUAL,
        )
        result = classify_app(app)
        assert result.tier == ClassificationTier.MANUAL_REPORT


class TestClassifyAppConfig:
    def test_scannable_config_routes_to_custom_prefs(self) -> None:
        result = classify_app_config("com.microsoft.VSCode")
        assert result.tier == ClassificationTier.CUSTOM_PREFS
        assert result.metadata is not None
        assert result.metadata["bundle_id"] == "com.microsoft.VSCode"
        assert "~/Library/Application Support/Code/User/settings.json" in result.metadata["config_paths"]

    def test_non_scannable_config_routes_to_manual_report(self) -> None:
        result = classify_app_config("com.apple.Safari")
        assert result.tier == ClassificationTier.MANUAL_REPORT
        assert result.metadata is not None
        assert result.metadata["bundle_id"] == "com.apple.Safari"
        assert "not scannable" in result.destination

    def test_unrecognized_bundle_id_routes_to_manual_report(self) -> None:
        result = classify_app_config("com.example.SomeUnknownApp")
        assert result.tier == ClassificationTier.MANUAL_REPORT
        assert result.metadata == {"bundle_id": "com.example.SomeUnknownApp"}


class TestClassifyDotfile:
    def test_known_dotfile_routes_to_home_manager_program(self) -> None:
        entry = DotfileEntry(path=Path.home() / ".zshrc", managed_by=DotfileManager.MANUAL)
        result = classify_dotfile(entry)
        assert result.tier == ClassificationTier.NATIVE
        assert result.nix_path == "programs.zsh"

    def test_unknown_dotfile_routes_to_manual_report(self) -> None:
        entry = DotfileEntry(path=Path.home() / ".some-totally-unknown-rc", managed_by=DotfileManager.UNKNOWN)
        result = classify_dotfile(entry)
        assert result.tier == ClassificationTier.MANUAL_REPORT


class TestClassifyBrewFormula:
    def test_version_manager_formula_is_flagged_redundant(self) -> None:
        formula = BrewFormula(name="pyenv")
        result = classify_brew_formula(formula)
        assert result.tier == ClassificationTier.MANUAL_REPORT
        assert result.metadata is not None
        assert result.metadata["unnecessary_in_nix"] is True

    def test_no_nixpkgs_equivalent_formula_routes_to_manual_report(self) -> None:
        formula = BrewFormula(name="cocoapods")
        result = classify_brew_formula(formula)
        assert result.tier == ClassificationTier.MANUAL_REPORT
        assert result.metadata is not None
        assert result.metadata.get("unnecessary_in_nix") is None

    def test_mapped_formula_routes_to_native_with_nixpkgs_attr(self) -> None:
        formula = BrewFormula(name="node")
        result = classify_brew_formula(formula)
        assert result.tier == ClassificationTier.NATIVE
        assert result.nix_path == "pkgs.nodejs"

    def test_formula_with_hm_module_gets_metadata_hint(self) -> None:
        formula = BrewFormula(name="git")
        result = classify_brew_formula(formula)
        assert result.tier == ClassificationTier.NATIVE
        assert result.metadata is not None
        assert result.metadata["hm_module_available"] == "programs.git"


class TestClassifyFont:
    def test_known_font_routes_to_native_fonts_packages(self) -> None:
        entry = FontEntry(
            name="Fira Code", path=Path.home() / "Library/Fonts/FiraCode-Regular.ttf", source=FontSource.USER
        )
        result = classify_font(entry)
        assert result.tier == ClassificationTier.NATIVE
        assert result.nix_path == "pkgs.fira-code"

    def test_apple_system_font_routes_to_manual_report(self) -> None:
        entry = FontEntry(name="Menlo", path=Path("/Library/Fonts/Menlo.ttc"), source=FontSource.SYSTEM)
        result = classify_font(entry)
        assert result.tier == ClassificationTier.MANUAL_REPORT


class TestClassifySystemSetting:
    def test_known_pmset_key_routes_to_native(self) -> None:
        result = classify_system_setting("displaysleep", "10")
        assert result.tier == ClassificationTier.NATIVE
        assert result.nix_path == "power.sleep.display"

    def test_unmapped_field_routes_to_manual_report(self) -> None:
        result = classify_system_setting("icloud", {"signed_in": True})
        assert result.tier == ClassificationTier.MANUAL_REPORT

    def test_timezone_routes_to_native_time_timezone(self) -> None:
        result = classify_system_setting("timezone", "America/New_York")
        assert result.tier == ClassificationTier.NATIVE
        assert result.nix_path == "time.timeZone"


class TestClassifySecuritySetting:
    def test_known_security_field_routes_to_native(self) -> None:
        result = classify_security_setting("firewall_enabled", True)
        assert result.tier == ClassificationTier.NATIVE
        assert result.nix_path == "networking.applicationFirewall.enable"

    def test_unmapped_security_field_routes_to_manual_report(self) -> None:
        result = classify_security_setting("filevault_enabled", True)
        assert result.tier == ClassificationTier.MANUAL_REPORT

    def test_sip_and_gatekeeper_are_always_manual(self) -> None:
        assert classify_security_setting("sip_enabled", True).tier == ClassificationTier.MANUAL_REPORT
        assert classify_security_setting("gatekeeper_enabled", True).tier == ClassificationTier.MANUAL_REPORT


class TestClassifyNetworkSetting:
    def test_known_network_field_routes_to_native(self) -> None:
        result = classify_network_setting("computer_name", "MyMac")
        assert result.tier == ClassificationTier.NATIVE
        assert result.nix_path == "networking.computerName"

    def test_unmapped_network_field_routes_to_manual_report(self) -> None:
        result = classify_network_setting("proxy_settings", {})
        assert result.tier == ClassificationTier.MANUAL_REPORT


class TestClassifyShellSetting:
    def test_known_shell_type_routes_to_native(self) -> None:
        config = ShellConfig(shell_type="fish")
        results = classify_shell_setting(config)
        assert len(results) == 1
        assert results[0].tier == ClassificationTier.NATIVE
        assert results[0].nix_path == "programs.fish.enable"

    def test_unknown_shell_type_routes_to_manual_report(self) -> None:
        config = ShellConfig(shell_type="csh")
        results = classify_shell_setting(config)
        assert len(results) == 1
        assert results[0].tier == ClassificationTier.MANUAL_REPORT

    def test_aliases_env_vars_and_path_components_each_produce_a_native_result(self) -> None:
        config = ShellConfig(
            shell_type="fish",
            aliases={"ll": "ls -la"},
            env_vars={"EDITOR": "nvim"},
            path_components=["/opt/homebrew/bin"],
        )
        results = classify_shell_setting(config)
        assert len(results) == 4
        by_destination = {result.destination: result for result in results}
        assert by_destination["environment.shellAliases"].tier == ClassificationTier.NATIVE
        assert by_destination["environment.shellAliases"].metadata == {"aliases": {"ll": "ls -la"}}
        assert by_destination["environment.variables"].tier == ClassificationTier.NATIVE
        assert by_destination["environment.variables"].metadata == {"env_vars": {"EDITOR": "nvim"}}
        assert by_destination["environment.systemPath"].tier == ClassificationTier.NATIVE
        assert by_destination["environment.systemPath"].metadata == {"path_components": ["/opt/homebrew/bin"]}

    def test_empty_aliases_env_vars_and_path_components_produce_no_extra_results(self) -> None:
        config = ShellConfig(shell_type="zsh")
        results = classify_shell_setting(config)
        assert len(results) == 1

    def test_frameworks_and_dynamic_commands_route_to_manual_report(self) -> None:
        config = ShellConfig(
            shell_type="zsh",
            frameworks=[ShellFramework(name="oh-my-zsh")],
            dynamic_commands=["eval $(starship init zsh)"],
        )
        results = classify_shell_setting(config)
        assert len(results) == 3
        manual_results = [result for result in results if result.tier == ClassificationTier.MANUAL_REPORT]
        assert len(manual_results) == 2
        assert any("framework" in result.destination for result in manual_results)
        assert any("dynamic" in result.destination.lower() for result in manual_results)


class TestClassifyShellSettingSensitiveRedaction:
    def test_alias_with_embedded_secret_token_in_body_is_redacted(self) -> None:
        config = ShellConfig(
            shell_type="zsh", aliases={"awsprod": "AWS_SECRET_ACCESS_KEY=AKIAabc123 aws --profile prod"}
        )
        results = classify_shell_setting(config)
        aliases_result = next(r for r in results if r.destination == "environment.shellAliases")
        assert aliases_result.metadata is not None
        assert aliases_result.metadata["aliases"]["awsprod"] == "***REDACTED***"
        assert aliases_result.metadata["potentially_sensitive_entries_redacted"] is True

    def test_alias_with_sensitive_looking_name_is_redacted(self) -> None:
        config = ShellConfig(shell_type="zsh", aliases={"show_api_token": "cat ~/.myapp/config"})
        results = classify_shell_setting(config)
        aliases_result = next(r for r in results if r.destination == "environment.shellAliases")
        assert aliases_result.metadata is not None
        assert aliases_result.metadata["aliases"]["show_api_token"] == "***REDACTED***"

    def test_non_sensitive_alias_is_not_redacted(self) -> None:
        config = ShellConfig(shell_type="zsh", aliases={"ll": "ls -la"})
        results = classify_shell_setting(config)
        aliases_result = next(r for r in results if r.destination == "environment.shellAliases")
        assert aliases_result.metadata == {"aliases": {"ll": "ls -la"}}

    def test_env_var_with_sensitive_looking_value_is_redacted_even_with_innocuous_name(self) -> None:
        config = ShellConfig(shell_type="zsh", env_vars={"MY_APP_CONFIG": "AWS_SECRET_ACCESS_KEY=AKIAabc123"})
        results = classify_shell_setting(config)
        env_result = next(r for r in results if r.destination == "environment.variables")
        assert env_result.metadata is not None
        assert env_result.metadata["env_vars"]["MY_APP_CONFIG"] == "***REDACTED***"
        assert env_result.metadata["potentially_sensitive_entries_redacted"] is True

    def test_env_var_with_sensitive_looking_name_is_redacted(self) -> None:
        config = ShellConfig(shell_type="zsh", env_vars={"GITHUB_TOKEN": "ghp_abc123"})
        results = classify_shell_setting(config)
        env_result = next(r for r in results if r.destination == "environment.variables")
        assert env_result.metadata is not None
        assert env_result.metadata["env_vars"]["GITHUB_TOKEN"] == "***REDACTED***"

    def test_non_sensitive_env_var_is_not_redacted(self) -> None:
        config = ShellConfig(shell_type="zsh", env_vars={"EDITOR": "nvim"})
        results = classify_shell_setting(config)
        env_result = next(r for r in results if r.destination == "environment.variables")
        assert env_result.metadata == {"env_vars": {"EDITOR": "nvim"}}

    def test_dynamic_command_with_embedded_api_key_is_redacted(self) -> None:
        config = ShellConfig(shell_type="zsh", dynamic_commands=["eval $(some-cli --api_key=abc123 init)"])
        results = classify_shell_setting(config)
        dynamic_result = next(r for r in results if "dynamic" in r.destination.lower())
        assert dynamic_result.metadata is not None
        assert dynamic_result.metadata["dynamic_commands"] == ["***REDACTED***"]
        assert dynamic_result.metadata["potentially_sensitive_entries_redacted"] is True

    def test_non_sensitive_dynamic_command_is_not_redacted(self) -> None:
        config = ShellConfig(shell_type="zsh", dynamic_commands=["eval $(starship init zsh)"])
        results = classify_shell_setting(config)
        dynamic_result = next(r for r in results if "dynamic" in r.destination.lower())
        assert dynamic_result.metadata == {"dynamic_commands": ["eval $(starship init zsh)"]}

    def test_path_components_are_never_redacted(self) -> None:
        config = ShellConfig(shell_type="zsh", path_components=["/opt/homebrew/bin"])
        results = classify_shell_setting(config)
        path_result = next(r for r in results if r.destination == "environment.systemPath")
        assert path_result.metadata == {"path_components": ["/opt/homebrew/bin"]}
