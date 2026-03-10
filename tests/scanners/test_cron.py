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
        assert len(result.launchd_scheduled) == 1
        assert result.launchd_scheduled[0].label == "com.test.scheduled"
        assert result.launchd_scheduled[0].trigger_type == "calendar"
        assert result.launchd_scheduled[0].schedule == [{"Hour": 5, "Minute": 0}]

    def test_crontab_command_fails(self) -> None:
        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch("mac2nix.scanners.cron.read_launchd_plists", return_value=[]),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert result.cron_entries == []
        assert len(result.launchd_scheduled) == 0

    def test_returns_scheduled_tasks(self) -> None:
        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch("mac2nix.scanners.cron.read_launchd_plists", return_value=[]),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)

    def test_launchd_watch_trigger(self) -> None:
        plist_path = Path("/Users/test/Library/LaunchAgents/com.test.watcher.plist")
        data = {
            "Label": "com.test.watcher",
            "WatchPaths": ["/Users/test/Documents/inbox"],
            "Program": "/usr/local/bin/process-inbox",
        }

        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch(
                "mac2nix.scanners.cron.read_launchd_plists",
                return_value=[(plist_path, "user", data)],
            ),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert len(result.launchd_scheduled) == 1
        assert result.launchd_scheduled[0].trigger_type == "watch"
        assert result.launchd_scheduled[0].watch_paths == ["/Users/test/Documents/inbox"]
        assert result.launchd_scheduled[0].program == "/usr/local/bin/process-inbox"

    def test_launchd_queue_trigger(self) -> None:
        plist_path = Path("/Users/test/Library/LaunchAgents/com.test.queue.plist")
        data = {
            "Label": "com.test.queue",
            "QueueDirectories": ["/Users/test/Documents/queue"],
            "ProgramArguments": ["/usr/local/bin/process-queue", "--batch"],
        }

        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch(
                "mac2nix.scanners.cron.read_launchd_plists",
                return_value=[(plist_path, "user", data)],
            ),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert len(result.launchd_scheduled) == 1
        assert result.launchd_scheduled[0].trigger_type == "queue"
        assert result.launchd_scheduled[0].queue_directories == ["/Users/test/Documents/queue"]

    def test_launchd_interval_trigger(self) -> None:
        plist_path = Path("/Users/test/Library/LaunchAgents/com.test.interval.plist")
        data = {
            "Label": "com.test.interval",
            "StartInterval": 3600,
            "Program": "/usr/local/bin/periodic-task",
        }

        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch(
                "mac2nix.scanners.cron.read_launchd_plists",
                return_value=[(plist_path, "user", data)],
            ),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert len(result.launchd_scheduled) == 1
        assert result.launchd_scheduled[0].trigger_type == "interval"
        assert result.launchd_scheduled[0].start_interval == 3600
        assert result.launchd_scheduled[0].schedule == []

    def test_launchd_calendar_list_schedule(self) -> None:
        plist_path = Path("/Users/test/Library/LaunchAgents/com.test.multi.plist")
        data = {
            "Label": "com.test.multi",
            "StartCalendarInterval": [
                {"Hour": 8, "Minute": 0},
                {"Hour": 17, "Minute": 30},
            ],
        }

        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch(
                "mac2nix.scanners.cron.read_launchd_plists",
                return_value=[(plist_path, "user", data)],
            ),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert len(result.launchd_scheduled) == 1
        assert result.launchd_scheduled[0].trigger_type == "calendar"
        assert len(result.launchd_scheduled[0].schedule) == 2

    def test_cron_env_variables(self, cmd_result) -> None:
        crontab = "SHELL=/bin/bash\nPATH=/usr/bin:/usr/local/bin\n0 5 * * * /usr/bin/task\n"

        with (
            patch(
                "mac2nix.scanners.cron.run_command",
                return_value=cmd_result(crontab),
            ),
            patch("mac2nix.scanners.cron.read_launchd_plists", return_value=[]),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert result.cron_env["SHELL"] == "/bin/bash"
        assert result.cron_env["PATH"] == "/usr/bin:/usr/local/bin"
        assert len(result.cron_entries) == 1

    def test_launchd_no_label_skipped(self) -> None:
        plist_path = Path("/Users/test/Library/LaunchAgents/com.test.nolabel.plist")
        data = {"StartCalendarInterval": {"Hour": 5, "Minute": 0}}

        with (
            patch("mac2nix.scanners.cron.run_command", return_value=None),
            patch(
                "mac2nix.scanners.cron.read_launchd_plists",
                return_value=[(plist_path, "user", data)],
            ),
        ):
            result = CronScanner().scan()

        assert isinstance(result, ScheduledTasks)
        assert len(result.launchd_scheduled) == 0
