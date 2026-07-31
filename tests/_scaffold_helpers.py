"""Shared test-support helpers for add_host()'s real age-keygen/sops integration tests.

Not a test module itself (pytest's python_files pattern doesn't match this
name) — imported by tests/cli/test_add_host.py and tests/generators/test_scaffold.py.
"""

from __future__ import annotations

import contextlib
import shutil
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch


def _has_add_host_crypto_deps() -> bool:
    return shutil.which("age-keygen") is not None and shutil.which("sops") is not None


@contextlib.contextmanager
def _redirect_age_keys(key_root: Path) -> Iterator[None]:
    """Redirect generate_age_key()'s real key file location from the real
    `/Users/<username>/...` tree to a tmp-based directory, so real
    age-keygen/sops can run safely in tests without touching the actual
    filesystem's /Users tree.
    """

    def fake_age_key_path(username: str, key_dir: Path | None = None) -> Path:
        return (key_dir or key_root / username) / "keys.txt"

    with patch("mac2nix.generators.scaffold._age_key_path", side_effect=fake_age_key_path):
        yield
