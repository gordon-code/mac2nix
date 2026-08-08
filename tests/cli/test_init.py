"""Tests for the mac2nix init CLI command."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from mac2nix.cli import main


class TestInitCommand:
    def test_registered(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "init" in result.output

    def test_succeeds_on_empty_directory(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"

        runner = CliRunner()
        result = runner.invoke(main, ["init", str(output_dir)])

        assert result.exit_code == 0, result.output
        assert (output_dir / "flake.nix").is_file()
        assert (output_dir / ".gitignore").is_file()
        assert (output_dir / "lib" / "helpers.nix").is_file()

    def test_succeeds_on_nonexistent_directory(self, tmp_path: Path) -> None:
        """output_dir doesn't need to exist yet — init creates it."""
        output_dir = tmp_path / "does-not-exist-yet"

        runner = CliRunner()
        result = runner.invoke(main, ["init", str(output_dir)])

        assert result.exit_code == 0, result.output
        assert output_dir.is_dir()

    def test_prints_next_step_guidance(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"

        runner = CliRunner()
        result = runner.invoke(main, ["init", str(output_dir)])

        assert result.exit_code == 0
        assert "add-host" in result.output

    def test_rerun_against_populated_directory_fails_cleanly(self, tmp_path: Path) -> None:
        output_dir = tmp_path / "repo"
        runner = CliRunner()

        first = runner.invoke(main, ["init", str(output_dir)])
        assert first.exit_code == 0, first.output

        before = sorted(p.relative_to(output_dir) for p in output_dir.rglob("*"))

        second = runner.invoke(main, ["init", str(output_dir)])

        assert second.exit_code != 0
        assert "not empty" in second.output

        after = sorted(p.relative_to(output_dir) for p in output_dir.rglob("*"))
        assert before == after, "a failed re-run must not modify the existing directory"
