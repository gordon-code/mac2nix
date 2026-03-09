"""Shared test helpers for scanner tests."""

import subprocess

import pytest


@pytest.fixture
def cmd_result():
    """Factory fixture that creates subprocess.CompletedProcess instances for mocking."""

    def _make(stdout: str = "", stderr: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)

    return _make
