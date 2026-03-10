"""Tests for launch agents scanner."""

from pathlib import Path
from unittest.mock import patch

from mac2nix.models.services import LaunchAgentSource, LaunchAgentsResult
from mac2nix.scanners.launch_agents import LaunchAgentsScanner

_BTM_OUTPUT = """\
========================
 Records for UID 501 : AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
========================

 ServiceManagement migrated: true

 Items:

 #1:
                 UUID: 11111111-1111-1111-1111-111111111111
                 Name: Dropbox
       Developer Name: Dropbox, Inc.
                 Type: login item (0x4)
                Flags: [  ] (0)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: 4.com.getdropbox.dropbox.helper
                  URL: Contents/Library/LoginItems/DropboxHelper.app
           Generation: 1
    Bundle Identifier: com.getdropbox.dropbox.helper
    Parent Identifier: 2.com.getdropbox.dropbox

 #2:
                 UUID: 22222222-2222-2222-2222-222222222222
                 Name: Alfred
       Developer Name: Running with Crayons Ltd
                 Type: login item (0x4)
                Flags: [  ] (0)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: 4.com.runningwithcrayons.Alfred
    Bundle Identifier: com.runningwithcrayons.Alfred

 #3:
                 UUID: 33333333-3333-3333-3333-333333333333
                 Name: nix-store
       Developer Name: Determinate Systems
                 Type: legacy daemon (0x10010)
                Flags: [ legacy ] (0x1)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: 16.systems.determinate.nix-store
"""


class TestLaunchAgentsScanner:
    def test_name_property(self) -> None:
        assert LaunchAgentsScanner().name == "launch_agents"

    def test_user_launch_agent(self) -> None:
        plist_path = Path("/Users/test/Library/LaunchAgents/com.test.agent.plist")
        plist_data = {
            "Label": "com.test.agent",
            "Program": "/usr/bin/test",
            "ProgramArguments": ["/usr/bin/test", "--flag"],
            "RunAtLoad": True,
        }

        with (
            patch(
                "mac2nix.scanners.launch_agents.read_launchd_plists",
                return_value=[(plist_path, "user", plist_data)],
            ),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = LaunchAgentsScanner().scan()

        assert isinstance(result, LaunchAgentsResult)
        assert len(result.entries) == 1
        entry = result.entries[0]
        assert entry.label == "com.test.agent"
        assert entry.program == "/usr/bin/test"
        assert entry.program_arguments == ["/usr/bin/test", "--flag"]
        assert entry.run_at_load is True
        assert entry.source == LaunchAgentSource.USER

    def test_daemon(self) -> None:
        plist_path = Path("/Library/LaunchDaemons/com.test.daemon.plist")
        plist_data = {"Label": "com.test.daemon", "Program": "/sbin/daemon"}

        with (
            patch(
                "mac2nix.scanners.launch_agents.read_launchd_plists",
                return_value=[(plist_path, "daemon", plist_data)],
            ),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = LaunchAgentsScanner().scan()

        assert isinstance(result, LaunchAgentsResult)
        assert result.entries[0].source == LaunchAgentSource.DAEMON

    def test_btm_login_items(self, cmd_result) -> None:
        with (
            patch("mac2nix.scanners.launch_agents.read_launchd_plists", return_value=[]),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=cmd_result(_BTM_OUTPUT)),
            patch("mac2nix.scanners.launch_agents.os.getuid", return_value=501),
        ):
            result = LaunchAgentsScanner().scan()

        assert isinstance(result, LaunchAgentsResult)
        login_entries = [e for e in result.entries if e.source == LaunchAgentSource.LOGIN_ITEM]
        assert len(login_entries) == 2
        labels = {e.label for e in login_entries}
        assert "Dropbox" in labels
        assert "Alfred" in labels

    def test_btm_skips_non_login_items(self, cmd_result) -> None:
        with (
            patch("mac2nix.scanners.launch_agents.read_launchd_plists", return_value=[]),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=cmd_result(_BTM_OUTPUT)),
            patch("mac2nix.scanners.launch_agents.os.getuid", return_value=501),
        ):
            result = LaunchAgentsScanner().scan()

        login_entries = [e for e in result.entries if e.source == LaunchAgentSource.LOGIN_ITEM]
        # nix-store is a "legacy daemon", not a "login item" — should be excluded
        labels = {e.label for e in login_entries}
        assert "nix-store" not in labels

    def test_btm_wrong_uid_returns_empty(self, cmd_result) -> None:
        with (
            patch("mac2nix.scanners.launch_agents.read_launchd_plists", return_value=[]),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=cmd_result(_BTM_OUTPUT)),
            patch("mac2nix.scanners.launch_agents.os.getuid", return_value=999),
        ):
            result = LaunchAgentsScanner().scan()

        assert isinstance(result, LaunchAgentsResult)
        login_entries = [e for e in result.entries if e.source == LaunchAgentSource.LOGIN_ITEM]
        assert login_entries == []

    def test_btm_null_name_uses_bundle_id(self, cmd_result) -> None:
        btm_text = """\
========================
 Records for UID 501 : AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
========================

 Items:

 #1:
                 UUID: 44444444-4444-4444-4444-444444444444
                 Name: (null)
                 Type: login item (0x4)
           Identifier: 4.com.example.helper
    Bundle Identifier: com.example.helper
"""

        with (
            patch("mac2nix.scanners.launch_agents.read_launchd_plists", return_value=[]),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=cmd_result(btm_text)),
            patch("mac2nix.scanners.launch_agents.os.getuid", return_value=501),
        ):
            result = LaunchAgentsScanner().scan()

        login_entries = [e for e in result.entries if e.source == LaunchAgentSource.LOGIN_ITEM]
        assert len(login_entries) == 1
        assert login_entries[0].label == "com.example.helper"

    def test_sfltool_unavailable(self) -> None:
        with (
            patch("mac2nix.scanners.launch_agents.read_launchd_plists", return_value=[]),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = LaunchAgentsScanner().scan()

        assert isinstance(result, LaunchAgentsResult)
        assert result.entries == []

    def test_plist_missing_label_skipped(self) -> None:
        plist_path = Path("/Users/test/Library/LaunchAgents/nolabel.plist")
        plist_data = {"Program": "/usr/bin/test"}  # No Label key

        with (
            patch(
                "mac2nix.scanners.launch_agents.read_launchd_plists",
                return_value=[(plist_path, "user", plist_data)],
            ),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = LaunchAgentsScanner().scan()

        assert isinstance(result, LaunchAgentsResult)
        assert result.entries == []

    def test_returns_launch_agents_result(self) -> None:
        with (
            patch("mac2nix.scanners.launch_agents.read_launchd_plists", return_value=[]),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = LaunchAgentsScanner().scan()

        assert isinstance(result, LaunchAgentsResult)

    def test_full_plist_fields_extracted(self) -> None:
        plist_path = Path("/Users/test/Library/LaunchAgents/com.test.full.plist")
        plist_data = {
            "Label": "com.test.full",
            "Program": "/usr/bin/test",
            "ProgramArguments": ["/usr/bin/test", "--verbose"],
            "RunAtLoad": True,
            "WorkingDirectory": "/var/run/test",
            "EnvironmentVariables": {"HOME": "/Users/test", "LANG": "en_US.UTF-8"},
            "KeepAlive": {"SuccessfulExit": False},
            "StartInterval": 3600,
            "StartCalendarInterval": {"Hour": 5, "Minute": 0},
            "WatchPaths": ["/var/log/system.log"],
            "QueueDirectories": ["/var/spool/test"],
            "StandardOutPath": "/var/log/test.out.log",
            "StandardErrorPath": "/var/log/test.err.log",
            "ThrottleInterval": 10,
            "ProcessType": "Background",
            "Nice": 5,
            "UserName": "root",
            "GroupName": "wheel",
        }

        with (
            patch(
                "mac2nix.scanners.launch_agents.read_launchd_plists",
                return_value=[(plist_path, "user", plist_data)],
            ),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = LaunchAgentsScanner().scan()

        assert isinstance(result, LaunchAgentsResult)
        assert len(result.entries) == 1
        entry = result.entries[0]
        assert entry.working_directory == "/var/run/test"
        assert entry.environment_variables == {"HOME": "/Users/test", "LANG": "en_US.UTF-8"}
        assert entry.keep_alive == {"SuccessfulExit": False}
        assert entry.start_interval == 3600
        assert entry.start_calendar_interval == {"Hour": 5, "Minute": 0}
        assert entry.watch_paths == ["/var/log/system.log"]
        assert entry.queue_directories == ["/var/spool/test"]
        assert entry.stdout_path == "/var/log/test.out.log"
        assert entry.stderr_path == "/var/log/test.err.log"
        assert entry.throttle_interval == 10
        assert entry.process_type == "Background"
        assert entry.nice == 5
        assert entry.user_name == "root"
        assert entry.group_name == "wheel"

    def test_sensitive_env_vars_redacted(self) -> None:
        plist_path = Path("/Users/test/Library/LaunchAgents/com.test.secrets.plist")
        redacted = "***REDACTED***"
        plist_data = {
            "Label": "com.test.secrets",
            "EnvironmentVariables": {
                "HOME": "/Users/test",
                "API_KEY": "super_secret_123",
                "GH_TOKEN": "ghp_abc",
                "DB_PASSWORD": "hunter2",
                "NORMAL_VAR": "safe_value",
                "MY_AUTH_HEADER": "Bearer abc",
            },
        }

        with (
            patch(
                "mac2nix.scanners.launch_agents.read_launchd_plists",
                return_value=[(plist_path, "user", plist_data)],
            ),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = LaunchAgentsScanner().scan()

        entry = result.entries[0]
        assert entry.environment_variables["HOME"] == "/Users/test"
        assert entry.environment_variables["NORMAL_VAR"] == "safe_value"
        assert entry.environment_variables["API_KEY"] == redacted
        assert entry.environment_variables["GH_TOKEN"] == redacted
        assert entry.environment_variables["DB_PASSWORD"] == redacted
        assert entry.environment_variables["MY_AUTH_HEADER"] == redacted

    def test_raw_plist_env_also_redacted(self) -> None:
        plist_path = Path("/Users/test/Library/LaunchAgents/com.test.raw.plist")
        redacted = "***REDACTED***"
        plist_data = {
            "Label": "com.test.raw",
            "EnvironmentVariables": {
                "SAFE": "ok",
                "API_TOKEN": "secret",
            },
        }

        with (
            patch(
                "mac2nix.scanners.launch_agents.read_launchd_plists",
                return_value=[(plist_path, "user", plist_data)],
            ),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = LaunchAgentsScanner().scan()

        entry = result.entries[0]
        assert entry.raw_plist["EnvironmentVariables"]["API_TOKEN"] == redacted
        assert entry.raw_plist["EnvironmentVariables"]["SAFE"] == "ok"

    def test_raw_plist_is_deep_copy(self) -> None:
        plist_data = {
            "Label": "com.test.copy",
            "EnvironmentVariables": {"API_KEY": "secret"},
        }
        original_data = {"Label": "com.test.copy", "EnvironmentVariables": {"API_KEY": "secret"}}

        with (
            patch(
                "mac2nix.scanners.launch_agents.read_launchd_plists",
                return_value=[(Path("/Users/test/Library/LaunchAgents/test.plist"), "user", plist_data)],
            ),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            LaunchAgentsScanner().scan()

        # Original data should not be mutated
        assert plist_data["EnvironmentVariables"]["API_KEY"] == original_data["EnvironmentVariables"]["API_KEY"]

    def test_empty_plist_skipped(self) -> None:
        plist_path = Path("/Users/test/Library/LaunchAgents/empty.plist")

        with (
            patch(
                "mac2nix.scanners.launch_agents.read_launchd_plists",
                return_value=[(plist_path, "user", {})],
            ),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = LaunchAgentsScanner().scan()

        assert isinstance(result, LaunchAgentsResult)
        assert result.entries == []

    def test_btm_enabled_disposition(self, cmd_result) -> None:
        with (
            patch("mac2nix.scanners.launch_agents.read_launchd_plists", return_value=[]),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=cmd_result(_BTM_OUTPUT)),
            patch("mac2nix.scanners.launch_agents.os.getuid", return_value=501),
        ):
            result = LaunchAgentsScanner().scan()

        login_entries = [e for e in result.entries if e.source == LaunchAgentSource.LOGIN_ITEM]
        for entry in login_entries:
            assert entry.enabled is True  # disposition says "enabled"

    def test_system_agent(self) -> None:
        plist_path = Path("/Library/LaunchAgents/com.system.agent.plist")
        plist_data = {"Label": "com.system.agent", "Program": "/usr/bin/agent"}

        with (
            patch(
                "mac2nix.scanners.launch_agents.read_launchd_plists",
                return_value=[(plist_path, "system", plist_data)],
            ),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = LaunchAgentsScanner().scan()

        assert result.entries[0].source == LaunchAgentSource.SYSTEM
        assert result.entries[0].plist_path == plist_path
