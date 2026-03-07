"""Tests for Phase 2 models: launch_agent, shell, network, security, system, display, audio, cron."""

from __future__ import annotations

from pathlib import Path

from mac2nix.models.hardware import AudioConfig, AudioDevice, DisplayConfig, Monitor
from mac2nix.models.services import (
    CronEntry,
    LaunchAgentEntry,
    LaunchAgentSource,
    LaunchAgentsResult,
    ScheduledTasks,
    ShellConfig,
)
from mac2nix.models.system import NetworkConfig, NetworkInterface, SecurityState, SystemConfig


class TestLaunchAgent:
    def test_entry_user_source(self) -> None:
        entry = LaunchAgentEntry(
            label="com.example.agent",
            program="/usr/bin/example",
            source=LaunchAgentSource.USER,
        )
        assert entry.label == "com.example.agent"
        assert entry.source == LaunchAgentSource.USER
        assert entry.run_at_load is False

    def test_entry_system_source(self) -> None:
        entry = LaunchAgentEntry(
            label="com.apple.agent",
            source=LaunchAgentSource.SYSTEM,
            run_at_load=True,
        )
        assert entry.source == LaunchAgentSource.SYSTEM
        assert entry.run_at_load is True

    def test_entry_daemon_source(self) -> None:
        entry = LaunchAgentEntry(
            label="com.example.daemon",
            source=LaunchAgentSource.DAEMON,
            program_arguments=["/usr/bin/daemon", "--flag"],
        )
        assert entry.source == LaunchAgentSource.DAEMON
        assert len(entry.program_arguments) == 2

    def test_entry_login_item_source(self) -> None:
        entry = LaunchAgentEntry(
            label="com.example.login",
            source=LaunchAgentSource.LOGIN_ITEM,
            plist_path=Path("/Library/LaunchAgents/com.example.plist"),
        )
        assert entry.source == LaunchAgentSource.LOGIN_ITEM
        assert entry.plist_path is not None

    def test_result_multiple_entries(self) -> None:
        entries = [
            LaunchAgentEntry(label="a", source=LaunchAgentSource.USER),
            LaunchAgentEntry(label="b", source=LaunchAgentSource.DAEMON),
            LaunchAgentEntry(label="c", source=LaunchAgentSource.SYSTEM),
        ]
        result = LaunchAgentsResult(entries=entries)
        assert len(result.entries) == 3


class TestShellConfig:
    def test_with_aliases_and_env_vars(self) -> None:
        config = ShellConfig(
            shell_type="fish",
            rc_files=[Path("~/.config/fish/config.fish")],
            path_components=["/opt/homebrew/bin", "/usr/local/bin"],
            aliases={"ll": "ls -la", "gs": "git status"},
            functions=["fish_prompt"],
            env_vars={"EDITOR": "nvim", "LANG": "en_US.UTF-8"},
        )
        assert config.shell_type == "fish"
        assert len(config.aliases) == 2
        assert config.env_vars["EDITOR"] == "nvim"
        assert len(config.path_components) == 2


class TestNetworkConfig:
    def test_with_interfaces_and_dns(self) -> None:
        iface = NetworkInterface(
            name="Wi-Fi",
            hardware_port="Wi-Fi",
            device="en0",
            ip_address="192.168.1.100",
        )
        config = NetworkConfig(
            interfaces=[iface],
            dns_servers=["8.8.8.8", "8.8.4.4"],
            search_domains=["local"],
            wifi_networks=["HomeNetwork"],
        )
        assert len(config.interfaces) == 1
        assert config.interfaces[0].ip_address == "192.168.1.100"
        assert len(config.dns_servers) == 2
        assert config.wifi_networks == ["HomeNetwork"]


class TestSecurityState:
    def test_with_tcc_summary(self) -> None:
        state = SecurityState(
            filevault_enabled=True,
            sip_enabled=True,
            firewall_enabled=False,
            gatekeeper_enabled=True,
            tcc_summary={
                "kTCCServiceAccessibility": ["iTerm2", "Hammerspoon"],
                "kTCCServiceCamera": ["zoom.us"],
            },
        )
        assert state.filevault_enabled is True
        assert state.firewall_enabled is False
        assert len(state.tcc_summary["kTCCServiceAccessibility"]) == 2


class TestSystemConfig:
    def test_with_power_settings(self) -> None:
        config = SystemConfig(
            hostname="macbook",
            timezone="America/New_York",
            locale="en_US.UTF-8",
            power_settings={
                "displaysleep": "10",
                "disksleep": "10",
                "sleep": "0",
            },
            spotlight_indexing=True,
        )
        assert config.hostname == "macbook"
        assert config.timezone == "America/New_York"
        assert config.power_settings["sleep"] == "0"


class TestDisplayConfig:
    def test_multiple_monitors(self) -> None:
        monitors = [
            Monitor(
                name="Built-in Retina Display",
                resolution="3456x2234",
                scaling=2.0,
                retina=True,
                arrangement_position="primary",
            ),
            Monitor(
                name="LG UltraFine",
                resolution="5120x2880",
                scaling=2.0,
                retina=True,
                arrangement_position="right",
            ),
        ]
        config = DisplayConfig(monitors=monitors)
        assert len(config.monitors) == 2
        assert config.monitors[0].retina is True
        assert config.monitors[1].arrangement_position == "right"


class TestAudioConfig:
    def test_with_devices(self) -> None:
        config = AudioConfig(
            input_devices=[
                AudioDevice(name="MacBook Pro Microphone", uid="BuiltInMic"),
            ],
            output_devices=[
                AudioDevice(name="MacBook Pro Speakers", uid="BuiltInSpeaker"),
                AudioDevice(name="AirPods Pro", uid="airpods-uuid"),
            ],
            default_input="MacBook Pro Microphone",
            default_output="AirPods Pro",
            alert_volume=0.75,
        )
        assert len(config.output_devices) == 2
        assert config.default_output == "AirPods Pro"
        assert config.alert_volume == 0.75


class TestScheduledTasks:
    def test_with_cron_entries(self) -> None:
        tasks = ScheduledTasks(
            cron_entries=[
                CronEntry(schedule="0 * * * *", command="/usr/bin/backup", user="root"),
                CronEntry(schedule="*/5 * * * *", command="echo hello"),
            ],
            launchd_scheduled=["com.apple.periodic-daily"],
        )
        assert len(tasks.cron_entries) == 2
        assert tasks.cron_entries[0].user == "root"
        assert tasks.cron_entries[1].user is None
        assert len(tasks.launchd_scheduled) == 1


class TestJsonRoundtrip:
    def test_shell_config_roundtrip(self) -> None:
        config = ShellConfig(
            shell_type="zsh",
            aliases={"ll": "ls -la"},
            env_vars={"HOME": "/Users/test"},
        )
        json_str = config.model_dump_json()
        restored = ShellConfig.model_validate_json(json_str)
        assert restored.shell_type == config.shell_type
        assert restored.aliases == config.aliases

    def test_network_config_roundtrip(self) -> None:
        config = NetworkConfig(
            interfaces=[NetworkInterface(name="en0", ip_address="10.0.0.1")],
            dns_servers=["1.1.1.1"],
        )
        json_str = config.model_dump_json()
        restored = NetworkConfig.model_validate_json(json_str)
        assert len(restored.interfaces) == 1
        assert restored.interfaces[0].ip_address == "10.0.0.1"

    def test_launch_agents_result_roundtrip(self) -> None:
        result = LaunchAgentsResult(
            entries=[
                LaunchAgentEntry(
                    label="com.test.agent",
                    source=LaunchAgentSource.USER,
                    run_at_load=True,
                ),
            ],
        )
        json_str = result.model_dump_json()
        restored = LaunchAgentsResult.model_validate_json(json_str)
        assert len(restored.entries) == 1
        assert restored.entries[0].source == LaunchAgentSource.USER

    def test_audio_config_roundtrip(self) -> None:
        config = AudioConfig(
            input_devices=[AudioDevice(name="Mic", uid="mic-1")],
            default_input="Mic",
            alert_volume=0.5,
        )
        json_str = config.model_dump_json()
        restored = AudioConfig.model_validate_json(json_str)
        assert restored.default_input == "Mic"
        assert restored.alert_volume == 0.5
