"""Shared test-support helpers for generate_all()/`mac2nix generate` unit tests.

Not a test module itself (pytest's python_files pattern doesn't match this
name) — imported by tests/generators/test_generate_all.py and tests/cli/test_generate.py.
"""

from __future__ import annotations

import json
from pathlib import Path

from mac2nix.generators.scaffold import _read_template, _render_placeholders


def _register_fake_host(output_dir: Path, hostname: str, username: str = "testuser") -> Path:
    """Build a minimal, real-template-backed registered host without real age-keygen/sops.

    generate_all() only reads/writes configuration.nix and .mac2nix-meta.json
    -- it never touches secrets/flake.nix, so a full add_host() isn't needed
    for these unit tests.
    """
    host_dir = output_dir / "hosts" / "darwin" / hostname
    host_dir.mkdir(parents=True)
    template = _read_template("hosts", "darwin", "configuration.nix")
    (host_dir / "configuration.nix").write_text(_render_placeholders(template, hostname, username))
    meta = {"hostname": hostname, "username": username, "system": "aarch64-darwin", "age_public_key": "age1fake"}
    (host_dir / ".mac2nix-meta.json").write_text(json.dumps(meta))
    return host_dir
