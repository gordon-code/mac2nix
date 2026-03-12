"""Tests for Phase 2 models: launch_agent, shell, network, security, system, display, audio, cron."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from mac2nix.models.application import BinarySource, BrewService, PathBinary
from mac2nix.models.files import (
    BundleEntry,
    DotfileEntry,
    DotfileManager,
    FontCollection,
    LibraryAuditResult,
    LibraryFileEntry,
    WorkflowEntry,
)
from mac2nix.models.hardware import AudioConfig, AudioDevice, DisplayConfig, Monitor, NightShiftConfig
from mac2nix.models.services import (
    CronEntry,
    LaunchAgentEntry,
    LaunchAgentSource,
    LaunchAgentsResult,
    LaunchdScheduledJob,
    ScheduledTasks,
    ShellConfig,
    ShellFramework,
)
from mac2nix.models.system import (
    FirewallAppRule,
    ICloudState,
    NetworkConfig,
    NetworkInterface,
    PrinterInfo,
    SecurityState,
    SystemConfig,
    SystemExtension,
    TimeMachineConfig,
    VpnProfile,
)


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
    def test_security_state_fields(self) -> None:
        state = SecurityState(
            filevault_enabled=True,
            sip_enabled=True,
            firewall_enabled=False,
            gatekeeper_enabled=True,
        )
        assert state.filevault_enabled is True
        assert state.firewall_enabled is False
        assert state.gatekeeper_enabled is True


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
            launchd_scheduled=[
                LaunchdScheduledJob(label="com.apple.periodic-daily"),
            ],
        )
        assert len(tasks.cron_entries) == 2
        assert tasks.cron_entries[0].user == "root"
        assert tasks.cron_entries[1].user is None
        assert len(tasks.launchd_scheduled) == 1
        assert tasks.launchd_scheduled[0].label == "com.apple.periodic-daily"


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


class TestBinarySource:
    def test_enum_values(self) -> None:
        assert BinarySource.ASDF == "asdf"
        assert BinarySource.BREW == "brew"
        assert BinarySource.CARGO == "cargo"
        assert BinarySource.CONDA == "conda"
        assert BinarySource.GEM == "gem"
        assert BinarySource.GO == "go"
        assert BinarySource.JENV == "jenv"
        assert BinarySource.MACPORTS == "macports"
        assert BinarySource.MANUAL == "manual"
        assert BinarySource.MISE == "mise"
        assert BinarySource.NIX == "nix"
        assert BinarySource.NPM == "npm"
        assert BinarySource.NVM == "nvm"
        assert BinarySource.PIPX == "pipx"
        assert BinarySource.PYENV == "pyenv"
        assert BinarySource.RBENV == "rbenv"
        assert BinarySource.SDKMAN == "sdkman"
        assert BinarySource.SYSTEM == "system"

    def test_is_str(self) -> None:
        assert isinstance(BinarySource.BREW, str)


class TestPathBinary:
    def test_construction(self) -> None:
        binary = PathBinary(
            name="rg",
            path=Path("/opt/homebrew/bin/rg"),
            source=BinarySource.BREW,
            version="14.1.0",
        )
        assert binary.name == "rg"
        assert binary.path == Path("/opt/homebrew/bin/rg")
        assert binary.source == BinarySource.BREW
        assert binary.version == "14.1.0"

    def test_version_optional(self) -> None:
        binary = PathBinary(
            name="ls",
            path=Path("/bin/ls"),
            source=BinarySource.SYSTEM,
        )
        assert binary.version is None


class TestBrewService:
    def test_construction(self) -> None:
        svc = BrewService(
            name="postgresql@16",
            status="started",
            user="wgordon",
            plist_path=Path("~/Library/LaunchAgents/homebrew.mxcl.postgresql@16.plist"),
        )
        assert svc.name == "postgresql@16"
        assert svc.status == "started"
        assert svc.user == "wgordon"
        assert svc.plist_path is not None

    def test_optional_defaults(self) -> None:
        svc = BrewService(name="redis", status="none")
        assert svc.user is None
        assert svc.plist_path is None


class TestLaunchdScheduledJob:
    def test_calendar_trigger(self) -> None:
        job = LaunchdScheduledJob(
            label="com.apple.periodic-daily",
            schedule=[{"Hour": 3, "Minute": 15}],
            program="/usr/libexec/periodic-wrapper",
            trigger_type="calendar",
        )
        assert job.label == "com.apple.periodic-daily"
        assert job.schedule == [{"Hour": 3, "Minute": 15}]
        assert job.trigger_type == "calendar"

    def test_interval_trigger(self) -> None:
        job = LaunchdScheduledJob(
            label="com.test.interval",
            start_interval=300,
            trigger_type="interval",
        )
        assert job.start_interval == 300
        assert job.trigger_type == "interval"

    def test_watch_paths_trigger(self) -> None:
        job = LaunchdScheduledJob(
            label="com.test.watcher",
            watch_paths=["/var/log/system.log"],
            trigger_type="watch_paths",
        )
        assert job.watch_paths == ["/var/log/system.log"]

    def test_defaults(self) -> None:
        job = LaunchdScheduledJob(label="com.test.minimal")
        assert job.schedule == []
        assert job.program is None
        assert job.program_arguments == []
        assert job.watch_paths == []
        assert job.queue_directories == []
        assert job.start_interval is None
        assert job.trigger_type == "calendar"


class TestLibraryAuditResult:
    def test_all_defaults_empty(self) -> None:
        result = LibraryAuditResult()
        assert result.bundles == []
        assert result.directories == []
        assert result.uncovered_files == []
        assert result.workflows == []
        assert result.key_bindings == []
        assert result.spelling_words == []
        assert result.spelling_dictionaries == []
        assert result.input_methods == []
        assert result.keyboard_layouts == []
        assert result.color_profiles == []
        assert result.compositions == []
        assert result.scripts == []
        assert result.text_replacements == []
        assert result.system_bundles == []

    def test_with_populated_fields(self) -> None:
        result = LibraryAuditResult(
            bundles=[BundleEntry(name="Test.bundle", path=Path("/Library/Bundles/Test.bundle"))],
            spelling_words=["nix", "darwin"],
            keyboard_layouts=["US", "Dvorak"],
            text_replacements=[{"shortcut": "omw", "phrase": "On my way!"}],
        )
        assert len(result.bundles) == 1
        assert result.spelling_words == ["nix", "darwin"]
        assert len(result.text_replacements) == 1


class TestBundleEntry:
    def test_construction(self) -> None:
        entry = BundleEntry(
            name="Test.bundle",
            path=Path("/Library/Bundles/Test.bundle"),
            bundle_id="com.test.bundle",
            version="1.0",
            bundle_type="BNDL",
        )
        assert entry.name == "Test.bundle"
        assert entry.bundle_id == "com.test.bundle"
        assert entry.bundle_type == "BNDL"

    def test_optional_defaults(self) -> None:
        entry = BundleEntry(name="Minimal.bundle", path=Path("/Library/Bundles/Minimal.bundle"))
        assert entry.bundle_id is None
        assert entry.version is None
        assert entry.bundle_type is None


class TestLibraryFileEntry:
    def test_with_plist_content(self) -> None:
        entry = LibraryFileEntry(
            path=Path("~/Library/SomeFile.plist"),
            file_type="plist",
            plist_content={"key": "value"},
        )
        assert entry.plist_content == {"key": "value"}
        assert entry.text_content is None

    def test_with_text_content(self) -> None:
        entry = LibraryFileEntry(
            path=Path("~/Library/SomeFile.conf"),
            file_type="conf",
            text_content="setting=value",
        )
        assert entry.text_content == "setting=value"
        assert entry.plist_content is None

    def test_optional_defaults(self) -> None:
        entry = LibraryFileEntry(path=Path("~/Library/unknown"))
        assert entry.file_type is None
        assert entry.content_hash is None
        assert entry.plist_content is None
        assert entry.text_content is None
        assert entry.migration_strategy is None
        assert entry.size_bytes is None


class TestWorkflowEntry:
    def test_construction(self) -> None:
        entry = WorkflowEntry(
            name="My Workflow",
            path=Path("~/Library/Services/My Workflow.workflow"),
            identifier="com.apple.Automator.MyWorkflow",
            workflow_definition={"actions": [{"type": "shell"}]},
        )
        assert entry.name == "My Workflow"
        assert entry.identifier == "com.apple.Automator.MyWorkflow"
        assert entry.workflow_definition is not None

    def test_optional_defaults(self) -> None:
        entry = WorkflowEntry(name="Basic", path=Path("/Users/test/Library/Services/basic.workflow"))
        assert entry.identifier is None
        assert entry.workflow_definition is None


class TestVpnProfile:
    def test_construction(self) -> None:
        vpn = VpnProfile(
            name="Work VPN",
            protocol="IKEv2",
            status="connected",
            remote_address="vpn.example.com",
        )
        assert vpn.name == "Work VPN"
        assert vpn.protocol == "IKEv2"
        assert vpn.status == "connected"
        assert vpn.remote_address == "vpn.example.com"

    def test_optional_defaults(self) -> None:
        vpn = VpnProfile(name="Test VPN")
        assert vpn.protocol is None
        assert vpn.status is None
        assert vpn.remote_address is None


class TestFirewallAppRule:
    def test_allowed(self) -> None:
        rule = FirewallAppRule(app_path="/Applications/Safari.app", allowed=True)
        assert rule.app_path == "/Applications/Safari.app"
        assert rule.allowed is True

    def test_blocked(self) -> None:
        rule = FirewallAppRule(app_path="/Applications/Suspicious.app", allowed=False)
        assert rule.allowed is False


class TestTimeMachineConfig:
    def test_configured(self) -> None:
        tm = TimeMachineConfig(
            configured=True,
            destination_name="Backup Drive",
            destination_id="ABC-123",
            latest_backup=datetime(2026, 3, 9, 10, 0, 0, tzinfo=UTC),
        )
        assert tm.configured is True
        assert tm.destination_name == "Backup Drive"
        assert tm.latest_backup is not None

    def test_defaults(self) -> None:
        tm = TimeMachineConfig()
        assert tm.configured is False
        assert tm.destination_name is None
        assert tm.destination_id is None
        assert tm.latest_backup is None


class TestPrinterInfo:
    def test_default_printer(self) -> None:
        printer = PrinterInfo(
            name="HP LaserJet",
            is_default=True,
            options={"duplex": "DuplexNoTumble"},
        )
        assert printer.name == "HP LaserJet"
        assert printer.is_default is True
        assert printer.options["duplex"] == "DuplexNoTumble"

    def test_defaults(self) -> None:
        printer = PrinterInfo(name="Generic")
        assert printer.is_default is False
        assert printer.options == {}


class TestNightShiftConfig:
    def test_enabled_with_schedule(self) -> None:
        ns = NightShiftConfig(enabled=True, schedule="sunset_to_sunrise")
        assert ns.enabled is True
        assert ns.schedule == "sunset_to_sunrise"

    def test_defaults(self) -> None:
        ns = NightShiftConfig()
        assert ns.enabled is None
        assert ns.schedule is None


class TestShellFramework:
    def test_construction(self) -> None:
        fw = ShellFramework(
            name="oh-my-zsh",
            path=Path("~/.oh-my-zsh"),
            plugins=["git", "docker", "kubectl"],
            theme="powerlevel10k",
        )
        assert fw.name == "oh-my-zsh"
        assert fw.path == Path("~/.oh-my-zsh")
        assert len(fw.plugins) == 3
        assert fw.theme == "powerlevel10k"

    def test_defaults(self) -> None:
        fw = ShellFramework(name="fisher", path=Path("~/.config/fish/functions"))
        assert fw.plugins == []
        assert fw.theme is None


class TestFontCollection:
    def test_construction(self) -> None:
        fc = FontCollection(
            name="Programming Fonts",
            path=Path("~/Library/FontCollections/Programming.collection"),
        )
        assert fc.name == "Programming Fonts"
        assert fc.path == Path("~/Library/FontCollections/Programming.collection")


class TestDotfileEntryNewFields:
    def test_new_fields_defaults(self) -> None:
        entry = DotfileEntry(path=Path("~/.gitconfig"))
        assert entry.content_hash is None
        assert entry.managed_by == DotfileManager.UNKNOWN
        assert entry.symlink_target is None
        assert entry.is_directory is False
        assert entry.file_count is None
        assert entry.sensitive is False

    def test_with_symlink(self) -> None:
        entry = DotfileEntry(
            path=Path("~/.gitconfig"),
            symlink_target=Path("~/.dotfiles/.gitconfig"),
            managed_by=DotfileManager.STOW,
        )
        assert entry.symlink_target == Path("~/.dotfiles/.gitconfig")
        assert entry.managed_by == DotfileManager.STOW

    def test_sensitive_directory(self) -> None:
        entry = DotfileEntry(
            path=Path("~/.ssh"),
            is_directory=True,
            file_count=5,
            sensitive=True,
        )
        assert entry.is_directory is True
        assert entry.file_count == 5
        assert entry.sensitive is True


class TestDotfileManagerEnum:
    def test_new_values(self) -> None:
        assert DotfileManager.CHEZMOI == "chezmoi"
        assert DotfileManager.YADM == "yadm"
        assert DotfileManager.HOME_MANAGER == "home_manager"
        assert DotfileManager.RCM == "rcm"

    def test_all_values(self) -> None:
        expected = {"git", "stow", "chezmoi", "yadm", "home_manager", "rcm", "manual", "unknown"}
        actual = {m.value for m in DotfileManager}
        assert actual == expected


class TestLaunchAgentEntryNewFields:
    def test_new_fields_all_have_defaults(self) -> None:
        entry = LaunchAgentEntry(label="com.test.agent", source=LaunchAgentSource.USER)
        assert entry.raw_plist == {}
        assert entry.working_directory is None
        assert entry.environment_variables is None
        assert entry.keep_alive is None
        assert entry.start_interval is None
        assert entry.start_calendar_interval is None
        assert entry.watch_paths == []
        assert entry.queue_directories == []
        assert entry.stdout_path is None
        assert entry.stderr_path is None
        assert entry.throttle_interval is None
        assert entry.process_type is None
        assert entry.nice is None
        assert entry.user_name is None
        assert entry.group_name is None

    def test_with_calendar_interval(self) -> None:
        entry = LaunchAgentEntry(
            label="com.test.scheduled",
            source=LaunchAgentSource.USER,
            start_calendar_interval={"Hour": 3, "Minute": 15},
        )
        assert entry.start_calendar_interval == {"Hour": 3, "Minute": 15}

    def test_with_keep_alive_dict(self) -> None:
        entry = LaunchAgentEntry(
            label="com.test.keepalive",
            source=LaunchAgentSource.DAEMON,
            keep_alive={"SuccessfulExit": False},
        )
        assert entry.keep_alive == {"SuccessfulExit": False}


class TestShellConfigNewFields:
    def test_new_list_fields_default_empty(self) -> None:
        config = ShellConfig(shell_type="zsh")
        assert config.conf_d_files == []
        assert config.completion_files == []
        assert config.sourced_files == []
        assert config.frameworks == []
        assert config.dynamic_commands == []

    def test_with_frameworks(self) -> None:
        config = ShellConfig(
            shell_type="zsh",
            frameworks=[
                ShellFramework(name="oh-my-zsh", path=Path("~/.oh-my-zsh"), plugins=["git"]),
            ],
        )
        assert len(config.frameworks) == 1
        assert config.frameworks[0].name == "oh-my-zsh"


class TestSystemConfigNewFields:
    def test_new_optional_fields(self) -> None:
        config = SystemConfig(hostname="macbook")
        assert config.macos_version is None
        assert config.macos_build is None
        assert config.macos_product_name is None
        assert config.hardware_model is None
        assert config.hardware_chip is None
        assert config.hardware_memory is None
        assert config.hardware_serial is None
        assert config.time_machine is None
        assert config.software_update == {}
        assert config.sleep_settings == {}
        assert config.login_window == {}
        assert config.startup_chime is None
        assert config.local_hostname is None
        assert config.dns_hostname is None
        assert config.network_time_enabled is None
        assert config.network_time_server is None
        assert config.printers == []
        assert config.remote_login is None
        assert config.screen_sharing is None
        assert config.file_sharing is None

    def test_with_time_machine(self) -> None:
        config = SystemConfig(
            hostname="macbook",
            time_machine=TimeMachineConfig(configured=True, destination_name="Backup"),
        )
        assert config.time_machine is not None
        assert config.time_machine.configured is True

    def test_with_printers(self) -> None:
        config = SystemConfig(
            hostname="macbook",
            printers=[PrinterInfo(name="HP LaserJet", is_default=True)],
        )
        assert len(config.printers) == 1
        assert config.printers[0].is_default is True


class TestNetworkConfigNewFields:
    def test_with_vpn_profiles(self) -> None:
        config = NetworkConfig(
            vpn_profiles=[
                VpnProfile(name="Work VPN", protocol="IKEv2"),
                VpnProfile(name="Personal VPN", protocol="WireGuard"),
            ],
        )
        assert len(config.vpn_profiles) == 2
        assert config.vpn_profiles[0].name == "Work VPN"

    def test_new_fields_defaults(self) -> None:
        config = NetworkConfig()
        assert config.vpn_profiles == []
        assert config.proxy_bypass_domains == []
        assert config.locations == []
        assert config.current_location is None


class TestSecurityStateNewFields:
    def test_new_fields_defaults(self) -> None:
        state = SecurityState()
        assert state.firewall_stealth_mode is None
        assert state.firewall_app_rules == []
        assert state.firewall_block_all_incoming is None
        assert state.touch_id_sudo is None
        assert state.custom_certificates == []

    def test_with_firewall_rules(self) -> None:
        state = SecurityState(
            firewall_enabled=True,
            firewall_stealth_mode=True,
            firewall_block_all_incoming=False,
            firewall_app_rules=[
                FirewallAppRule(app_path="/Applications/Safari.app", allowed=True),
            ],
        )
        assert state.firewall_stealth_mode is True
        assert len(state.firewall_app_rules) == 1

    def test_with_touch_id_and_certs(self) -> None:
        state = SecurityState(
            touch_id_sudo=True,
            custom_certificates=["Enterprise Root CA"],
        )
        assert state.touch_id_sudo is True
        assert state.custom_certificates == ["Enterprise Root CA"]


class TestAudioConfigNewFields:
    def test_volume_and_mute_fields(self) -> None:
        config = AudioConfig(
            output_volume=75,
            input_volume=80,
            output_muted=False,
        )
        assert config.output_volume == 75
        assert config.input_volume == 80
        assert config.output_muted is False

    def test_volume_defaults(self) -> None:
        config = AudioConfig()
        assert config.output_volume is None
        assert config.input_volume is None
        assert config.output_muted is None


class TestMonitorNewFields:
    def test_with_refresh_rate_and_color_profile(self) -> None:
        monitor = Monitor(
            name="Built-in Retina Display",
            resolution="3456x2234",
            refresh_rate="120Hz",
            color_profile="sRGB IEC61966-2.1",
        )
        assert monitor.refresh_rate == "120Hz"
        assert monitor.color_profile == "sRGB IEC61966-2.1"

    def test_new_fields_defaults(self) -> None:
        monitor = Monitor(name="Generic")
        assert monitor.refresh_rate is None
        assert monitor.color_profile is None


class TestDisplayConfigNewFields:
    def test_with_night_shift(self) -> None:
        config = DisplayConfig(
            night_shift=NightShiftConfig(enabled=True, schedule="sunset_to_sunrise"),
            true_tone_enabled=True,
        )
        assert config.night_shift is not None
        assert config.night_shift.enabled is True
        assert config.true_tone_enabled is True

    def test_defaults(self) -> None:
        config = DisplayConfig()
        assert config.night_shift is None
        assert config.true_tone_enabled is None


class TestScheduledTasksCronEnv:
    def test_cron_env(self) -> None:
        tasks = ScheduledTasks(
            cron_env={"SHELL": "/bin/bash", "PATH": "/usr/bin:/bin"},
        )
        assert tasks.cron_env["SHELL"] == "/bin/bash"

    def test_cron_env_default(self) -> None:
        tasks = ScheduledTasks()
        assert tasks.cron_env == {}


class TestSystemExtension:
    def test_construction(self) -> None:
        ext = SystemExtension(
            identifier="com.crowdstrike.falcon.Agent",
            team_id="X9E956P446",
            version="6.50.16306",
            state="activated_enabled",
        )
        assert ext.identifier == "com.crowdstrike.falcon.Agent"
        assert ext.team_id == "X9E956P446"
        assert ext.version == "6.50.16306"
        assert ext.state == "activated_enabled"

    def test_defaults(self) -> None:
        ext = SystemExtension(identifier="com.example.ext")
        assert ext.team_id is None
        assert ext.version is None
        assert ext.state is None

    def test_roundtrip(self) -> None:
        ext = SystemExtension(
            identifier="com.apple.DriverKit",
            version="1.0",
            state="activated_enabled",
        )
        json_str = ext.model_dump_json()
        restored = SystemExtension.model_validate_json(json_str)
        assert restored.identifier == ext.identifier
        assert restored.state == ext.state


class TestICloudState:
    def test_defaults(self) -> None:
        state = ICloudState()
        assert state.signed_in is False
        assert state.desktop_sync is False
        assert state.documents_sync is False

    def test_with_sync_enabled(self) -> None:
        state = ICloudState(
            signed_in=True,
            desktop_sync=True,
            documents_sync=True,
        )
        assert state.signed_in is True
        assert state.desktop_sync is True
        assert state.documents_sync is True

    def test_roundtrip(self) -> None:
        state = ICloudState(signed_in=True, desktop_sync=True)
        json_str = state.model_dump_json()
        restored = ICloudState.model_validate_json(json_str)
        assert restored.signed_in is True
        assert restored.desktop_sync is True
        assert restored.documents_sync is False


class TestSystemConfigNewFieldsRosetta:
    def test_new_fields_defaults(self) -> None:
        config = SystemConfig(hostname="macbook")
        assert config.rosetta_installed is None
        assert config.system_extensions == []
        assert config.icloud.signed_in is False
        assert config.mdm_enrolled is None

    def test_with_rosetta_and_extensions(self) -> None:
        config = SystemConfig(
            hostname="macbook",
            rosetta_installed=True,
            system_extensions=[
                SystemExtension(identifier="com.crowdstrike.falcon.Agent"),
            ],
            mdm_enrolled=False,
        )
        assert config.rosetta_installed is True
        assert len(config.system_extensions) == 1
        assert config.mdm_enrolled is False

    def test_with_icloud(self) -> None:
        config = SystemConfig(
            hostname="macbook",
            icloud=ICloudState(signed_in=True, desktop_sync=True),
        )
        assert config.icloud.signed_in is True
        assert config.icloud.desktop_sync is True
