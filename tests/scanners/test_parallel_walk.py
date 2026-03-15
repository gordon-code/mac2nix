"""Unit tests for parallel_walk_dirs() and related constants in _utils.py."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from mac2nix.scanners._utils import (
    NON_CONFIG_EXTENSIONS,
    WALK_SKIP_DIRS,
    WALK_SKIP_SUFFIXES,
    parallel_walk_dirs,
)


class TestParallelWalkDirs:
    def test_empty_dirs_list(self) -> None:
        """Returns [] for empty input."""
        result = parallel_walk_dirs([], lambda d: d.name)
        assert result == []

    def test_single_dir_skips_pool(self, tmp_path: Path) -> None:
        """≤2 dirs bypass ThreadPoolExecutor (serial path)."""
        dirs = [tmp_path / "a", tmp_path / "b"]
        for d in dirs:
            d.mkdir()

        called: list[Path] = []

        def collect(d: Path) -> str:
            called.append(d)
            return d.name

        result = parallel_walk_dirs(dirs, collect)
        assert sorted(result) == ["a", "b"]
        assert set(called) == set(dirs)

    def test_parallel_collects_all_results(self, tmp_path: Path) -> None:
        """All dirs processed and results collected when >2 dirs (pool path)."""
        dirs = [tmp_path / f"dir{i}" for i in range(6)]
        for d in dirs:
            d.mkdir()

        result = parallel_walk_dirs(dirs, lambda d: d.name)
        assert sorted(result) == [f"dir{i}" for i in range(6)]

    def test_failed_dir_logged_not_raised(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Exception in one worker doesn't stop others; error is logged."""
        dirs = [tmp_path / f"d{i}" for i in range(5)]
        for d in dirs:
            d.mkdir()

        def maybe_raise(d: Path) -> str:
            if d.name == "d2":
                msg = "deliberate failure"
                raise ValueError(msg)
            return d.name

        # Run — should not raise, d2 skipped, others collected
        with caplog.at_level(logging.ERROR, logger="mac2nix.scanners._utils"):
            results = parallel_walk_dirs(dirs, maybe_raise)
        # 4 successful workers (d0, d1, d3, d4), d2 raises
        assert len(results) == 4
        assert "d2" not in results
        assert "Failed to process directory" in caplog.text
        assert "d2" in caplog.text

    def test_failed_dir_serial_path_logged(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Serial path (≤2 dirs) also logs exceptions and continues."""
        dirs = [tmp_path / "good", tmp_path / "bad"]
        for d in dirs:
            d.mkdir()

        def maybe_raise(d: Path) -> str:
            if d.name == "bad":
                msg = "serial failure"
                raise ValueError(msg)
            return d.name

        with caplog.at_level(logging.ERROR, logger="mac2nix.scanners._utils"):
            results = parallel_walk_dirs(dirs, maybe_raise)
        assert results == ["good"]
        assert "Failed to process directory" in caplog.text
        assert "bad" in caplog.text

    def test_max_workers_capped_at_dir_count(self, tmp_path: Path) -> None:
        """Pool size is min(max_workers, len(dirs)) — no idle threads."""
        # 4 dirs but max_workers=100 → pool of 4 at most
        dirs = [tmp_path / f"x{i}" for i in range(4)]
        for d in dirs:
            d.mkdir()

        # Just verifying it completes without error with a large max_workers
        result = parallel_walk_dirs(dirs, lambda d: d.name, max_workers=100)
        assert sorted(result) == [f"x{i}" for i in range(4)]

    def test_process_fn_receives_path(self, tmp_path: Path) -> None:
        """Callback receives the exact Path objects passed in."""
        dirs = [tmp_path / f"p{i}" for i in range(4)]
        for d in dirs:
            d.mkdir()

        received: list[Path] = []

        def capture(d: Path) -> int:
            received.append(d)
            return 1

        parallel_walk_dirs(dirs, capture)
        assert set(received) == set(dirs)

    def test_results_order_not_guaranteed(self, tmp_path: Path) -> None:
        """Results may arrive in any order — sorted comparison is valid."""
        dirs = [tmp_path / f"z{i}" for i in range(5)]
        for d in dirs:
            d.mkdir()

        result = parallel_walk_dirs(dirs, lambda d: d.name)
        # Order not guaranteed, but sorted must match
        assert sorted(result) == sorted(f"z{i}" for i in range(5))

    def test_walk_skip_dirs_contains_new_entries(self) -> None:
        """Verify key new entries added to WALK_SKIP_DIRS."""
        assert "site-packages" in WALK_SKIP_DIRS
        assert "Crashpad" in WALK_SKIP_DIRS
        assert ".Spotlight-V100" in WALK_SKIP_DIRS
        # Spot-check a few more new categories
        assert ".direnv" in WALK_SKIP_DIRS
        assert "CoreSimulator" in WALK_SKIP_DIRS
        assert "steamapps" in WALK_SKIP_DIRS

    def test_non_config_extensions_contains_key_types(self) -> None:
        """Verify representative extensions across all categories."""
        # Source code
        assert ".py" in NON_CONFIG_EXTENSIONS
        assert ".js" in NON_CONFIG_EXTENSIONS
        # Media/images
        assert ".png" in NON_CONFIG_EXTENSIONS
        # Compiled/binary
        assert ".so" in NON_CONFIG_EXTENSIONS
        assert ".dylib" in NON_CONFIG_EXTENSIONS

    def test_walk_skip_suffixes_contains_expected(self) -> None:
        """WALK_SKIP_SUFFIXES contains .noindex and .lproj."""
        assert ".noindex" in WALK_SKIP_SUFFIXES
        assert ".lproj" in WALK_SKIP_SUFFIXES

    def test_parallel_results_match_serial(self, tmp_path: Path) -> None:
        """Serial (max_workers=1) and parallel (max_workers=4) produce identical sorted results."""
        dirs = [tmp_path / f"m{i}" for i in range(6)]
        for d in dirs:
            d.mkdir()
            # Give each dir a predictable value via a file
            (d / "marker.txt").write_text(d.name)

        def process(d: Path) -> str:
            return (d / "marker.txt").read_text()

        # Serial path: ≤2 bypasses pool, so use max_workers=1 on 6 dirs to test pool
        serial = parallel_walk_dirs(dirs, process, max_workers=1)
        parallel = parallel_walk_dirs(dirs, process, max_workers=4)

        assert sorted(serial) == sorted(parallel)
        assert sorted(serial) == sorted(f"m{i}" for i in range(6))
