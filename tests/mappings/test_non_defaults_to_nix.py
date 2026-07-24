"""Tests for non_defaults_to_nix mapping."""

import pytest

from mac2nix.mappings import non_defaults_to_nix
from mac2nix.mappings.non_defaults_to_nix import (
    ENVIRONMENT_MAP,
    LAUNCHD_KEYS_TO_DROP,
    LAUNCHD_LABEL_TO_SERVICE,
    NETWORKING_MAP,
    SECURITY_MAP,
    SHELL_PROGRAM_MAP,
    TIMEZONE_NIX_OPTION,
    _normalize_font_name,
    get_font_nixpkgs,
    get_launchd_service,
    get_power_nix_option,
    get_shell_program,
    is_launchd_key_droppable,
)


class TestNormalizeFontName:
    def test_strips_weight_suffix(self) -> None:
        assert _normalize_font_name("JetBrainsMono-Regular") == "jetbrainsmono"
        assert _normalize_font_name("IBMPlexMono-BoldItalic") == "ibmplexmono"

    def test_strips_nerd_font_suffix_and_appends_canonical_marker(self) -> None:
        assert _normalize_font_name("FiraCodeNerdFont-Regular") == "firacodenf"
        assert _normalize_font_name("MesloLGS NF") == "meslolgsnf"

    def test_base_font_and_nerd_variant_do_not_collide(self) -> None:
        base = _normalize_font_name("FiraCode-Regular")
        nerd = _normalize_font_name("FiraCodeNerdFont-Regular")
        assert base == "firacode"
        assert nerd == "firacodenf"
        assert base != nerd

    def test_extension_is_stripped(self) -> None:
        assert _normalize_font_name("Hack-Bold.ttf") == "hack"

    def test_separators_and_case_are_normalized(self) -> None:
        assert _normalize_font_name("source_code_pro") == _normalize_font_name("Source Code Pro")


class TestGetFontNixpkgs:
    def test_known_developer_font(self) -> None:
        assert get_font_nixpkgs("Fira Code") == "pkgs.fira-code"

    def test_known_nerd_font_variant_uses_new_nerd_fonts_namespace(self) -> None:
        assert get_font_nixpkgs("JetBrainsMonoNerdFont-Regular") == "pkgs.nerd-fonts.jetbrains-mono"

    def test_apple_system_font_returns_none_explicitly(self) -> None:
        assert get_font_nixpkgs("Menlo") is None
        assert get_font_nixpkgs("SF Pro") is None

    def test_unrecognized_font_returns_none(self) -> None:
        assert get_font_nixpkgs("SomeRandomFontNobodyHasHeardOf") is None


class TestLaunchdLabelToService:
    def test_exact_label_match(self) -> None:
        assert get_launchd_service("org.nixos.nix-daemon") == "services.nix-daemon"
        assert get_launchd_service("com.tailscale.tailscaled") == "services.tailscale"

    def test_prefix_glob_pattern_match(self) -> None:
        assert get_launchd_service("org.pqrs.karabiner.karabiner_console_user_server") == "services.karabiner-elements"

    def test_wildcard_substring_pattern_match(self) -> None:
        assert get_launchd_service("com.koekeishiya.yabai") == "services.yabai"
        assert get_launchd_service("com.koekeishiya.skhd") == "services.skhd"

    def test_unmatched_label_returns_none(self) -> None:
        assert get_launchd_service("com.example.totally-unknown-service") is None

    def test_all_patterns_are_registered(self) -> None:
        assert len(LAUNCHD_LABEL_TO_SERVICE) >= 25

    def test_first_matching_pattern_wins_when_patterns_overlap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """LAUNCHD_LABEL_TO_SERVICE's own comment states specific patterns must be listed
        before broad wildcards so the more precise match is tried first. No pair of
        patterns in the production table currently overlaps in a way that would expose an
        ordering bug, so this locks in get_launchd_service's underlying iteration-order
        semantics directly, independent of the current (accidentally non-conflicting) data.
        """
        monkeypatch.setattr(
            non_defaults_to_nix,
            "LAUNCHD_LABEL_TO_SERVICE",
            [
                ("com.example.specific.exact", "services.specific"),
                ("*example*", "services.broad-fallback"),
            ],
        )
        assert get_launchd_service("com.example.specific.exact") == "services.specific"
        assert get_launchd_service("com.example.other") == "services.broad-fallback"

        monkeypatch.setattr(
            non_defaults_to_nix,
            "LAUNCHD_LABEL_TO_SERVICE",
            [
                ("*example*", "services.broad-fallback"),
                ("com.example.specific.exact", "services.specific"),
            ],
        )
        assert get_launchd_service("com.example.specific.exact") == "services.broad-fallback"


class TestLaunchdKeysToDrop:
    def test_known_unmappable_keys_are_droppable(self) -> None:
        assert is_launchd_key_droppable("LegacyTimers") is True
        assert is_launchd_key_droppable("AssociatedBundleIdentifiers") is True
        assert is_launchd_key_droppable("BundleProgram") is True

    def test_mappable_keys_are_not_droppable(self) -> None:
        assert is_launchd_key_droppable("RunAtLoad") is False
        assert is_launchd_key_droppable("ProgramArguments") is False

    def test_drop_set_contains_all_documented_keys(self) -> None:
        expected = frozenset(
            {
                "LegacyTimers",
                "AssociatedBundleIdentifiers",
                "EnablePressuredExit",
                "BundleProgram",
                "MaterializeDatalessFiles",
                "LimitLoadToHardware",
                "LimitLoadFromHardware",
            }
        )
        assert expected == LAUNCHD_KEYS_TO_DROP


class TestPowerSettingMap:
    def test_known_pmset_keys(self) -> None:
        assert get_power_nix_option("displaysleep") == "power.sleep.display"
        assert get_power_nix_option("sleep") == "power.sleep.computer"
        assert get_power_nix_option("disksleep") == "power.sleep.harddisk"
        assert get_power_nix_option("autorestart") == "power.restartAfterPowerFailure"

    def test_wake_on_lan_routes_to_networking(self) -> None:
        assert get_power_nix_option("womp") == "networking.wakeOnLan.enable"

    def test_unmappable_pmset_key_returns_none(self) -> None:
        assert get_power_nix_option("hibernatemode") is None
        assert get_power_nix_option("standby") is None


class TestShellProgramMap:
    def test_known_shells(self) -> None:
        assert get_shell_program("zsh") == "programs.zsh.enable"
        assert get_shell_program("bash") == "programs.bash.enable"
        assert get_shell_program("fish") == "programs.fish.enable"

    def test_tmux_multiplexer(self) -> None:
        assert get_shell_program("tmux") == "programs.tmux.enable"

    def test_unknown_shell_returns_none(self) -> None:
        assert get_shell_program("csh") is None


class TestNetworkingMap:
    def test_contains_expected_fields(self) -> None:
        assert NETWORKING_MAP["hostname"] == "networking.hostName"
        assert NETWORKING_MAP["computer_name"] == "networking.computerName"
        assert NETWORKING_MAP["local_hostname"] == "networking.localHostName"
        assert NETWORKING_MAP["dns_servers"] == "networking.dns"
        assert NETWORKING_MAP["search_domains"] == "networking.search"
        assert NETWORKING_MAP["known_network_services"] == "networking.knownNetworkServices"


class TestSecurityMap:
    def test_touch_id_and_certificates(self) -> None:
        assert SECURITY_MAP["touch_id_sudo"] == "security.pam.services.sudo_local.touchIdAuth"
        assert SECURITY_MAP["custom_certificates"] == "security.pki.certificates"

    def test_firewall_fields_route_through_application_firewall(self) -> None:
        assert SECURITY_MAP["firewall_enabled"] == "networking.applicationFirewall.enable"
        assert SECURITY_MAP["firewall_stealth_mode"] == "networking.applicationFirewall.enableStealthMode"
        assert SECURITY_MAP["firewall_block_all_incoming"] == "networking.applicationFirewall.blockAllIncoming"
        for option in SECURITY_MAP.values():
            if "firewall" in option.lower():
                assert option.startswith("networking.applicationFirewall.")
                assert "alf" not in option.lower()


class TestEnvironmentMap:
    def test_contains_expected_fields(self) -> None:
        assert ENVIRONMENT_MAP["aliases"] == "environment.shellAliases"
        assert ENVIRONMENT_MAP["env_vars"] == "environment.variables"
        assert ENVIRONMENT_MAP["path_components"] == "environment.systemPath"


class TestTimezoneOption:
    def test_timezone_option_path(self) -> None:
        assert TIMEZONE_NIX_OPTION == "time.timeZone"


class TestShellProgramMapContents:
    def test_all_documented_shells_present(self) -> None:
        assert set(SHELL_PROGRAM_MAP) == {"zsh", "bash", "fish", "tmux"}
