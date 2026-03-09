"""Tests for cron scanner."""

from pathlib import Path
from unittest.mock import patch

from mac2nix.models.services import ScheduledTasks
from mac2nix.scanners.cron import CronScanner


class TestCronScanner:
    def test_name_property(self) -> None:
        assert CronScanner().name == "cron"

    def test_standard_cron_entry(self, cmd_result) -> None:
        crontab = "0 5 * * * /usr/bin/backup\n30 2 * * 0 /usr/local/bin/cleanup\n"

        with (
            patch(
                "mac2nix.scanners.cron.run_command",
                return_value=cmd_result(crontab),
            ),
            patch("mac2nix.scanners.cron.read_launchd_plists", return_value=[]),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert len(result.cron_entries) == 2
        assert result.cron_entries[0].schedule == "0 5 * * *"
        assert result.cron_entries[0].command == "/usr/bin/backup"
        assert result.cron_entries[1].schedule == "30 2 * * 0"

    def test_at_reboot_entry(self, cmd_result) -> None:
        crontab = "@reboot /usr/local/bin/startup-task\n"

        with (
            patch(
                "mac2nix.scanners.cron.run_command",
                return_value=cmd_result(crontab),
            ),
            patch("mac2nix.scanners.cron.read_launchd_plists", return_value=[]),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert len(result.cron_entries) == 1
        assert result.cron_entries[0].schedule == "@reboot"
        assert result.cron_entries[0].command == "/usr/local/bin/startup-task"

    def test_no_crontab(self, cmd_result) -> None:
        with (
            patch(
                "mac2nix.scanners.cron.run_command",
                return_value=cmd_result(stderr="no crontab for user", returncode=1),
            ),
            patch("mac2nix.scanners.cron.read_launchd_plists", return_value=[]),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert result.cron_entries == []

    def test_comments_skipped(self, cmd_result) -> None:
        crontab = "# This is a comment\n\n0 * * * * /usr/bin/task\n# Another comment\n"

        with (
            patch(
                "mac2nix.scanners.cron.run_command",
                return_value=cmd_result(crontab),
            ),
            patch("mac2nix.scanners.cron.read_launchd_plists", return_value=[]),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert len(result.cron_entries) == 1

    def test_launchd_scheduled(self) -> None:
        plist_path = Path("/Users/test/Library/LaunchAgents/com.test.scheduled.plist")
        scheduled_data = {
            "Label": "com.test.scheduled",
            "StartCalendarInterval": {"Hour": 5, "Minute": 0},
        }
        keepalive_path = Path("/Users/test/Library/LaunchAgents/com.test.keepalive.plist")
        keepalive_data = {"Label": "com.test.keepalive", "KeepAlive": True}

        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch(
                "mac2nix.scanners.cron.read_launchd_plists",
                return_value=[
                    (plist_path, "user", scheduled_data),
                    (keepalive_path, "user", keepalive_data),
                ],
            ),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert result.launchd_scheduled == ["com.test.scheduled"]

    def test_crontab_command_fails(self) -> None:
        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch("mac2nix.scanners.cron.read_launchd_plists", return_value=[]),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert result.cron_entries == []
        assert result.launchd_scheduled == []

    def test_returns_scheduled_tasks(self) -> None:
        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch("mac2nix.scanners.cron.read_launchd_plists", return_value=[]),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
