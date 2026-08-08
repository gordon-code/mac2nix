"""Shared test-support helpers for add_host()'s real age-keygen/sops integration tests.

Not a test module itself (pytest's python_files pattern doesn't match this
name) — imported by tests/cli/test_add_host.py and tests/generators/test_scaffold.py.
"""

from __future__ import annotations

import contextlib
import os
import shutil
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch


def _nix_extra_access_tokens_args() -> list[str]:
    """Extra `nix` CLI args authenticating `github:` flake-input fetches.

    Without this, Nix's own flake-input resolution hits GitHub's REST API
    unauthenticated (e.g. resolving `github:nix-darwin/nix-darwin` to a
    commit) — capped at 60/hr *per shared egress IP*, not per caller, so on
    GitHub-hosted runners this pool is exhausted by unrelated traffic from
    other customers on the same NAT'd IP, independent of how many requests
    *we've* made. Passed as an explicit CLI flag rather than via NIX_CONFIG
    or a nix.conf file: `sudo` strips environment variables by default
    (would need `-E`, itself a broader change), and multi-user/daemon Nix
    installs don't reliably pick up client-side NIX_CONFIG for the daemon's
    own fetches. A CLI flag applies directly to the invoked process either
    way. Returns an empty list (fails open, not closed — matches this
    project's other real-network tests) if GITHUB_TOKEN isn't set, since
    that should only happen outside GitHub Actions.
    """
    token = os.environ.get("GITHUB_TOKEN")
    return ["--extra-access-tokens", f"github.com={token}"] if token else []


def _nix_config_env_prefix_args() -> list[str]:
    """`env NIX_CONFIG=...` argv prefix authenticating nix invocations reached through `sudo`.

    `_nix_extra_access_tokens_args()`'s CLI flag only configures the single
    `nix` process it's passed to. `sudo nix run nix-darwin -- switch` execs
    `darwin-rebuild`, which spawns its own separate, fresh `nix build`/`nix
    flake lock` subprocess to resolve the *target flake's own* inputs
    (nixpkgs, home-manager, sops-nix) — that child process never sees a CLI
    flag given to its parent. An environment variable does survive fork/exec
    down that whole chain, which is why this returns an `env NAME=value`
    argv prefix (to place directly after `sudo -n`, before the real command)
    instead of a plain env var: `sudo` resets almost the entire environment
    of the process *it* execs by default, but running `env` as the thing sudo
    execs sidesteps that — `env` is just a normal program that sets a var in
    *its own* clean environment before exec-ing the real command, and that
    var then flows down normally to every descendant from there.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        return []
    env_bin = shutil.which("env")
    if env_bin is None:
        return []
    return [env_bin, f"NIX_CONFIG=extra-access-tokens = github.com={token}"]


def _has_age_keygen() -> bool:
    return shutil.which("age-keygen") is not None


def _has_add_host_crypto_deps() -> bool:
    return _has_age_keygen() and shutil.which("sops") is not None


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
