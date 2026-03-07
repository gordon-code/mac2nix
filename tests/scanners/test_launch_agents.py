"""Tests for launch agents scanner."""

import json
from pathlib import Path
from unittest.mock import patch

from mac2nix.models.services import LaunchAgentSource, LaunchAgentsResult
from mac2nix.scanners.launch_agents import LaunchAgentsScanner


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

    def test_sfltool_login_items(self, cmd_result) -> None:
        login_items = [
            {"name": "Dropbox", "bundleIdentifier": "com.getdropbox.dropbox"},
            {"name": "Alfred", "bundleIdentifier": "com.runningwithcrayons.Alfred"},
        ]
        sfltool_output = json.dumps(login_items)

        with (
            patch("mac2nix.scanners.launch_agents.read_launchd_plists", return_value=[]),
            patch(
                "mac2nix.scanners.launch_agents.run_command",
                return_value=cmd_result(sfltool_output),
            ),
        ):
            result = LaunchAgentsScanner().scan()

        assert isinstance(result, LaunchAgentsResult)
        login_entries = [e for e in result.entries if e.source == LaunchAgentSource.LOGIN_ITEM]
        assert len(login_entries) == 2
        labels = {e.label for e in login_entries}
        assert "Dropbox" in labels
        assert "Alfred" in labels

    def test_sfltool_unavailable(self) -> None:
        with (
            patch("mac2nix.scanners.launch_agents.read_launchd_plists", return_value=[]),
            patch("mac2nix.scanners.launch_agents.run_command", return_value=None),
        ):
            result = LaunchAgentsScanner().scan()

        assert isinstance(result, LaunchAgentsResult)
        assert result.entries == []

    def test_malformed_plist_skipped(self) -> None:
        """read_launchd_plists already filters bad plists; empty list means nothing parsed."""
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

    def test_sfltool_dict_format(self, cmd_result) -> None:
        """Test sfltool output in dict format with 'items' key instead of list format."""
        login_items = {
            "items": [
                {"name": "Spotify", "bundleIdentifier": "com.spotify.client"},
                {"name": "Steam", "bundleIdentifier": "com.valvesoftware.steam"},
            ]
        }
        sfltool_output = json.dumps(login_items)

        with (
            patch("mac2nix.scanners.launch_agents.read_launchd_plists", return_value=[]),
            patch(
                "mac2nix.scanners.launch_agents.run_command",
                return_value=cmd_result(sfltool_output),
            ),
        ):
            result = LaunchAgentsScanner().scan()

        assert isinstance(result, LaunchAgentsResult)
        login_entries = [e for e in result.entries if e.source == LaunchAgentSource.LOGIN_ITEM]
        assert len(login_entries) == 2
        labels = {e.label for e in login_entries}
        assert "Spotify" in labels
        assert "Steam" in labels
