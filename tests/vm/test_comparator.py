"""Tests for vm/comparator.py — FileSystemComparator filesystem diffing and noise filters."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from mac2nix.vm._utils import VMError
from mac2nix.vm.comparator import _DEFAULT_EXCLUDE_DIRS, FileSystemComparator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_vm(exec_result: tuple[bool, str, str] = (True, "", "")) -> MagicMock:
    """Return a mock TartVMManager whose exec_command returns a fixed result."""
    vm = MagicMock()
    vm.exec_command = AsyncMock(return_value=exec_result)
    return vm


def _make_comparator(
    exec_result: tuple[bool, str, str] = (True, "", ""),
    scan_root: str = "/System/Volumes/Data",
    exclude_dirs: list[str] | None = None,
) -> FileSystemComparator:
    return FileSystemComparator(_make_vm(exec_result), scan_root=scan_root, exclude_dirs=exclude_dirs)


# ---------------------------------------------------------------------------
# Constructor defaults
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_default_scan_root(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc._scan_root == "/System/Volumes/Data"

    def test_custom_scan_root(self) -> None:
        fc = FileSystemComparator(_make_vm(), scan_root="/custom/root")
        assert fc._scan_root == "/custom/root"

    def test_default_exclude_dirs_matches_module_default(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc._exclude_dirs == list(_DEFAULT_EXCLUDE_DIRS)

    def test_custom_exclude_dirs(self) -> None:
        fc = FileSystemComparator(_make_vm(), exclude_dirs=["Foo", "Bar"])
        assert fc._exclude_dirs == ["Foo", "Bar"]

    def test_none_exclude_dirs_uses_defaults(self) -> None:
        fc = FileSystemComparator(_make_vm(), exclude_dirs=None)
        assert fc._exclude_dirs == list(_DEFAULT_EXCLUDE_DIRS)

    def test_default_exclude_dirs_is_copy_not_reference(self) -> None:
        """Mutating the instance's exclude_dirs shouldn't affect the module default."""
        fc = FileSystemComparator(_make_vm())
        fc._exclude_dirs.append("extra")
        assert "extra" not in _DEFAULT_EXCLUDE_DIRS


# ---------------------------------------------------------------------------
# filter_noise() — per-category
# ---------------------------------------------------------------------------


class TestFilterNoise:
    def test_empty_list_returns_empty(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise([]) == []

    def test_empty_strings_discarded(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["", "  ", "\t"]) == []

    def test_signal_file_passes_through(self) -> None:
        fc = FileSystemComparator(_make_vm())
        result = fc.filter_noise(["/Users/admin/.config/myapp/settings.toml"])
        assert result == ["/Users/admin/.config/myapp/settings.toml"]

    def test_strips_whitespace_from_paths(self) -> None:
        fc = FileSystemComparator(_make_vm())
        result = fc.filter_noise(["  /Users/admin/.config/myapp/config.yml  "])
        assert result == ["/Users/admin/.config/myapp/config.yml"]

    # apple_services
    def test_apple_services_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        noise = [
            "/Users/admin/Library/Preferences/com.apple.finder.plist",
            "/private/var/db/com.apple.xpc.launchd/config/user/501/com.apple.Accessibility-Settings.daemon.plist",
        ]
        assert fc.filter_noise(noise) == []

    def test_non_apple_service_not_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        signal = ["/Users/admin/.config/starship.toml"]
        assert fc.filter_noise(signal) == signal

    # system_directories
    def test_private_var_spool_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/private/var/spool/something"]) == []

    def test_private_var_run_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/private/var/run/launchd.pid"]) == []

    def test_private_tmp_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/private/tmp/some_temp_file"]) == []

    def test_private_etc_cups_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/private/etc/cups/printers.conf"]) == []

    def test_volumes_cryptex_fseventsd_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Volumes/Preboot_Cryptex/.fseventsd/0000001"]) == []

    # library_system_data
    def test_library_caches_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/Library/Caches/com.example.app/cache.db"]) == []

    def test_library_logs_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/Library/Logs/DiagnosticReports/crash.ips"]) == []

    def test_library_keychains_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/Library/Keychains/login.keychain-db"]) == []

    def test_library_biome_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/Library/Biome/streams/public.data"]) == []

    def test_library_application_support_crashreporter_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/Library/Application Support/CrashReporter/some.log"]) == []

    # homebrew_noise
    def test_homebrew_git_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/opt/homebrew/.git/index"]) == []

    def test_homebrew_cellar_go_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/opt/homebrew/Cellar/go/1.21.0/bin/go"]) == []

    def test_homebrew_share_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/opt/homebrew/share/doc/something.txt"]) == []

    def test_homebrew_cellar_share_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/opt/homebrew/Cellar/wget/1.21/share/man/man1/wget.1"]) == []

    def test_homebrew_ruby_file_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/opt/homebrew/Library/Homebrew/utils/analytics.rb"]) == []

    def test_homebrew_taps_git_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/opt/homebrew/Library/Taps/homebrew/homebrew-core/.git/COMMIT_EDITMSG"]) == []

    def test_homebrew_bin_not_filtered(self) -> None:
        """An installed binary in Homebrew bin should pass noise filter."""
        fc = FileSystemComparator(_make_vm())
        result = fc.filter_noise(["/opt/homebrew/bin/wget"])
        assert result == ["/opt/homebrew/bin/wget"]

    # app_internals
    def test_app_frameworks_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Applications/MyApp.app/Contents/Frameworks/Sparkle.framework/Sparkle"]) == []

    def test_app_code_signature_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Applications/MyApp.app/Contents/_CodeSignature/CodeResources"]) == []

    def test_app_resources_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Applications/MyApp.app/Contents/Resources/icon.icns"]) == []

    def test_app_macos_binary_not_filtered(self) -> None:
        """The app's own executable in MacOS/ should pass through."""
        fc = FileSystemComparator(_make_vm())
        result = fc.filter_noise(["/Applications/MyApp.app/Contents/MacOS/MyApp"])
        assert result == ["/Applications/MyApp.app/Contents/MacOS/MyApp"]

    # database_files
    def test_sqlite_wal_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/Library/SomeApp/data.sqlite-wal"]) == []

    def test_sqlite_shm_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/Library/SomeApp/data.sqlite-shm"]) == []

    def test_sqlite3_wal_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/some/app.sqlite3-wal"]) == []

    def test_db_shm_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/some/app.db-shm"]) == []

    def test_plain_sqlite_not_filtered(self) -> None:
        """A bare .sqlite file (without -wal/-shm suffix) should pass."""
        fc = FileSystemComparator(_make_vm())
        result = fc.filter_noise(["/Users/admin/myapp/store.sqlite"])
        assert result == ["/Users/admin/myapp/store.sqlite"]

    # caches
    def test_caches_dir_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/Library/Caches/SomeApp/somefile"]) == []

    def test_lowercase_cache_dir_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/home/user/.cache/pip/something"]) == []

    def test_spotlight_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Volumes/Macintosh HD/.Spotlight-V100/Store-V2/something"]) == []

    # temp_and_system
    def test_ds_store_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/Projects/.DS_Store"]) == []

    def test_swp_file_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/.config/myapp/.config.yml.swp"]) == []

    def test_tmp_file_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/something.tmp"]) == []

    def test_git_dir_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/projects/myrepo/.git/index"]) == []

    def test_localized_file_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/Documents/.localized"]) == []

    # test_artifacts
    def test_before_txt_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/before.txt"]) == []

    def test_after_txt_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/after.txt"]) == []

    def test_non_test_artifact_txt_not_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        result = fc.filter_noise(["/Users/admin/readme.txt"])
        assert result == ["/Users/admin/readme.txt"]

    # always_modified
    def test_submit_diag_info_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/private/var/root/Library/Preferences/SubmitDiagInfo.plist"]) == []

    def test_network_interfaces_plist_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist"]) == []

    def test_homebrew_locks_update_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/opt/homebrew/var/homebrew/locks/update"]) == []

    def test_zsh_history_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/.zsh_history"]) == []

    def test_zshenv_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/.zshenv"]) == []

    def test_global_preferences_filtered(self) -> None:
        fc = FileSystemComparator(_make_vm())
        assert fc.filter_noise(["/Users/admin/Library/Preferences/.GlobalPreferences.plist"]) == []

    # Mixed signal + noise
    def test_mixed_list_keeps_signal_removes_noise(self) -> None:
        fc = FileSystemComparator(_make_vm())
        files = [
            "/Users/admin/.config/fish/config.fish",  # signal
            "/Users/admin/Library/Preferences/com.apple.dock.plist",  # apple_services noise
            "/opt/homebrew/bin/fish",  # signal (homebrew binary)
            "/private/tmp/install_tmp_file",  # system_directories noise
            "/Users/admin/.zsh_history",  # always_modified noise
            "/Applications/Fish.app/Contents/MacOS/fish",  # signal (app executable)
        ]
        result = fc.filter_noise(files)
        assert "/Users/admin/.config/fish/config.fish" in result
        assert "/opt/homebrew/bin/fish" in result
        assert "/Applications/Fish.app/Contents/MacOS/fish" in result
        assert len(result) == 3


# ---------------------------------------------------------------------------
# snapshot()
# ---------------------------------------------------------------------------


class TestSnapshot:
    def test_calls_exec_command_with_bash_c(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.snapshot("/tmp/before.txt")

        asyncio.run(_run())
        vm.exec_command.assert_called_once()
        cmd_arg = vm.exec_command.call_args[0][0]
        assert cmd_arg[0] == "bash"
        assert cmd_arg[1] == "-c"

    def test_pipeline_contains_find(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.snapshot("/tmp/before.txt")

        asyncio.run(_run())
        pipeline = vm.exec_command.call_args[0][0][2]
        assert "find" in pipeline

    def test_pipeline_contains_sort(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.snapshot("/tmp/snap.txt")

        asyncio.run(_run())
        pipeline = vm.exec_command.call_args[0][0][2]
        assert "sort" in pipeline

    def test_pipeline_contains_save_path(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.snapshot("/tmp/my_snapshot.txt")

        asyncio.run(_run())
        pipeline = vm.exec_command.call_args[0][0][2]
        assert "/tmp/my_snapshot.txt" in pipeline

    def test_pipeline_contains_scan_root(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm, scan_root="/custom/root")

        async def _run() -> None:
            await fc.snapshot("/tmp/snap.txt")

        asyncio.run(_run())
        pipeline = vm.exec_command.call_args[0][0][2]
        assert "/custom/root" in pipeline

    def test_pipeline_contains_sed_strip(self) -> None:
        """sed should strip the scan_root prefix from each path."""
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.snapshot("/tmp/snap.txt")

        asyncio.run(_run())
        pipeline = vm.exec_command.call_args[0][0][2]
        # Pipeline uses awk substr to strip the scan_root prefix (no regex, no injection)
        assert "awk" in pipeline

    def test_failure_raises_vm_error(self) -> None:
        vm = _make_vm((False, "", "disk full"))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.snapshot("/tmp/snap.txt")

        with pytest.raises(VMError, match="snapshot"):
            asyncio.run(_run())

    def test_uses_timeout_45(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.snapshot("/tmp/snap.txt")

        asyncio.run(_run())
        kwargs = vm.exec_command.call_args[1]
        assert kwargs.get("timeout") == 45

    def test_exclude_dirs_in_pipeline(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm, exclude_dirs=["MySpecialDir"])

        async def _run() -> None:
            await fc.snapshot("/tmp/snap.txt")

        asyncio.run(_run())
        pipeline = vm.exec_command.call_args[0][0][2]
        assert "MySpecialDir" in pipeline


# ---------------------------------------------------------------------------
# get_created_files()
# ---------------------------------------------------------------------------


class TestGetCreatedFiles:
    def test_returns_parsed_file_list(self) -> None:
        output = "/opt/homebrew/bin/wget\n/Users/admin/.config/fish/config.fish\n"
        vm = _make_vm((True, output, ""))
        fc = FileSystemComparator(vm)

        async def _run() -> list[str]:
            return await fc.get_created_files("/tmp/before.txt", "/tmp/after.txt")

        result = asyncio.run(_run())
        assert "/opt/homebrew/bin/wget" in result
        assert "/Users/admin/.config/fish/config.fish" in result

    def test_noise_is_filtered_from_result(self) -> None:
        output = "/opt/homebrew/bin/wget\n/Users/admin/.zsh_history\n"
        vm = _make_vm((True, output, ""))
        fc = FileSystemComparator(vm)

        async def _run() -> list[str]:
            return await fc.get_created_files("/tmp/before.txt", "/tmp/after.txt")

        result = asyncio.run(_run())
        assert "/opt/homebrew/bin/wget" in result
        assert "/Users/admin/.zsh_history" not in result

    def test_calls_comm_minus_13(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.get_created_files("/tmp/before.txt", "/tmp/after.txt")

        asyncio.run(_run())
        pipeline = vm.exec_command.call_args[0][0][2]
        assert "comm -13" in pipeline
        assert "/tmp/before.txt" in pipeline
        assert "/tmp/after.txt" in pipeline

    def test_empty_output_returns_empty_list(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> list[str]:
            return await fc.get_created_files("/tmp/before.txt", "/tmp/after.txt")

        assert asyncio.run(_run()) == []

    def test_failure_returns_empty_list_not_raises(self) -> None:
        vm = _make_vm((False, "", "error"))
        fc = FileSystemComparator(vm)

        async def _run() -> list[str]:
            return await fc.get_created_files("/tmp/before.txt", "/tmp/after.txt")

        result = asyncio.run(_run())
        assert result == []

    def test_uses_timeout_45(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.get_created_files("/tmp/before.txt", "/tmp/after.txt")

        asyncio.run(_run())
        kwargs = vm.exec_command.call_args[1]
        assert kwargs.get("timeout") == 45


# ---------------------------------------------------------------------------
# get_deleted_files()
# ---------------------------------------------------------------------------


class TestGetDeletedFiles:
    def test_returns_parsed_file_list(self) -> None:
        output = "/Users/admin/.config/oldtool/config\n"
        vm = _make_vm((True, output, ""))
        fc = FileSystemComparator(vm)

        async def _run() -> list[str]:
            return await fc.get_deleted_files("/tmp/before.txt", "/tmp/after.txt")

        result = asyncio.run(_run())
        assert "/Users/admin/.config/oldtool/config" in result

    def test_calls_comm_minus_23(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.get_deleted_files("/tmp/before.txt", "/tmp/after.txt")

        asyncio.run(_run())
        pipeline = vm.exec_command.call_args[0][0][2]
        assert "comm -23" in pipeline
        assert "/tmp/before.txt" in pipeline
        assert "/tmp/after.txt" in pipeline

    def test_noise_is_filtered(self) -> None:
        output = "/Users/admin/.zshenv\n/Users/admin/.config/myapp/config.toml\n"
        vm = _make_vm((True, output, ""))
        fc = FileSystemComparator(vm)

        async def _run() -> list[str]:
            return await fc.get_deleted_files("/tmp/before.txt", "/tmp/after.txt")

        result = asyncio.run(_run())
        assert "/Users/admin/.config/myapp/config.toml" in result
        assert "/Users/admin/.zshenv" not in result

    def test_failure_returns_empty_list(self) -> None:
        vm = _make_vm((False, "", "error"))
        fc = FileSystemComparator(vm)

        async def _run() -> list[str]:
            return await fc.get_deleted_files("/tmp/before.txt", "/tmp/after.txt")

        assert asyncio.run(_run()) == []

    def test_empty_output_returns_empty(self) -> None:
        vm = _make_vm((True, "   \n", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> list[str]:
            return await fc.get_deleted_files("/tmp/before.txt", "/tmp/after.txt")

        assert asyncio.run(_run()) == []


# ---------------------------------------------------------------------------
# get_modified_files()
# ---------------------------------------------------------------------------


class TestGetModifiedFiles:
    def _make_since(self) -> datetime:
        return datetime(2026, 3, 18, 12, 0, 0, tzinfo=UTC)

    def test_returns_parsed_file_list(self) -> None:
        output = "/Users/admin/.config/fish/config.fish\n/opt/homebrew/bin/wget\n"
        vm = _make_vm((True, output, ""))
        fc = FileSystemComparator(vm)

        async def _run() -> list[str]:
            return await fc.get_modified_files(self._make_since())

        result = asyncio.run(_run())
        assert "/Users/admin/.config/fish/config.fish" in result
        assert "/opt/homebrew/bin/wget" in result

    def test_calls_exec_command_with_bash_c(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.get_modified_files(self._make_since())

        asyncio.run(_run())
        cmd_arg = vm.exec_command.call_args[0][0]
        assert cmd_arg[0] == "bash"
        assert cmd_arg[1] == "-c"

    def test_pipeline_contains_newermt(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.get_modified_files(self._make_since())

        asyncio.run(_run())
        pipeline = vm.exec_command.call_args[0][0][2]
        assert "newermt" in pipeline

    def test_pipeline_contains_since_timestamp(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)
        since = self._make_since()

        async def _run() -> None:
            await fc.get_modified_files(since)

        asyncio.run(_run())
        pipeline = vm.exec_command.call_args[0][0][2]
        # ISO format timestamp should appear in pipeline
        ts_iso = since.replace(microsecond=0).isoformat()
        assert ts_iso in pipeline

    def test_scan_root_override(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm, scan_root="/System/Volumes/Data")

        async def _run() -> None:
            await fc.get_modified_files(self._make_since(), scan_root="/Users")

        asyncio.run(_run())
        pipeline = vm.exec_command.call_args[0][0][2]
        assert "/Users" in pipeline

    def test_noise_filtered_from_result(self) -> None:
        output = "/Users/admin/.zsh_history\n/Users/admin/.config/fish/config.fish\n"
        vm = _make_vm((True, output, ""))
        fc = FileSystemComparator(vm)

        async def _run() -> list[str]:
            return await fc.get_modified_files(self._make_since())

        result = asyncio.run(_run())
        assert "/Users/admin/.config/fish/config.fish" in result
        assert "/Users/admin/.zsh_history" not in result

    def test_failure_returns_empty_list(self) -> None:
        vm = _make_vm((False, "", "permission denied"))
        fc = FileSystemComparator(vm)

        async def _run() -> list[str]:
            return await fc.get_modified_files(self._make_since())

        assert asyncio.run(_run()) == []

    def test_uses_timeout_45(self) -> None:
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.get_modified_files(self._make_since())

        asyncio.run(_run())
        kwargs = vm.exec_command.call_args[1]
        assert kwargs.get("timeout") == 45

    def test_pipeline_contains_awk_cutoff(self) -> None:
        """awk with cutoff= must be present to exclude newly-created files."""
        vm = _make_vm((True, "", ""))
        fc = FileSystemComparator(vm)

        async def _run() -> None:
            await fc.get_modified_files(self._make_since())

        asyncio.run(_run())
        pipeline = vm.exec_command.call_args[0][0][2]
        assert "awk" in pipeline
        assert "cutoff" in pipeline
