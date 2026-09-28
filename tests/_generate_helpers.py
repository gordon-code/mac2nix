"""Shared test-support helpers for generate_all()/`mac2nix generate` unit tests.

Not a test module itself (pytest's python_files pattern doesn't match this
name) — imported by tests/generators/test_generate_all.py and tests/cli/test_generate.py.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from mac2nix.generators._nix_render import nix_string
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


def _quoted_spans(text: str) -> list[tuple[int, int]]:
    """Return (start, end) index spans of Nix double-quoted string literals in `text`.

    Approximate scanner (treats `\\"` as a non-terminating escaped quote,
    everything else literally) -- good enough for the structural injection
    check below, not a full Nix parser.
    """
    spans: list[tuple[int, int]] = []
    in_string = False
    start = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if not in_string:
            if ch == '"':
                in_string = True
                start = i
            i += 1
        elif ch == "\\":
            i += 2
        elif ch == '"':
            spans.append((start, i + 1))
            in_string = False
            i += 1
        else:
            i += 1
    return spans


def assert_activation_script_neutralizes_shell_metacharacters(
    rendered_body: str, injected_marker: str, tmp_path: Path
) -> None:
    """Assert an activation-script body safely neutralizes an adversarial dynamic value.

    Every activation-script code path built from scanned (untrusted) data --
    the wallpaper path (Step 9/11) and any case promoted by Steps 13/14 --
    must pass an adversarial value containing a backtick, `$()`, `;`, a
    literal `"`, and a newline through this helper before shipping.

    Two checks:
    (a) the body still parses as valid Nix once wrapped in a minimal module
        -- no Nix-syntax breakout via the injected marker.
    (b) the marker's escaped form (as produced by this codebase's own
        `nix_string()`) appears only inside a Nix double-quoted string
        literal in the rendered text -- a marker sitting outside any quoted
        span would mean it reached shell/Nix source unescaped.

    `[ASSUMPTION: detail]` This is a structural approximation, not a full
    round-trip proof (it doesn't execute the shell body). Acceptable for
    this generator's current cases; revisit if a future case's shell logic
    gets meaningfully more complex. Callers should mark their test
    `@pytest.mark.nix`.
    """
    if shutil.which("nix-instantiate") is None:
        pytest.skip("nix-instantiate not on PATH")

    escaped_inner = nix_string(injected_marker)[1:-1]
    assert escaped_inner in rendered_body, "fixture bug: escaped marker not present in rendered body"

    module_source = f"{{ config, lib, pkgs, ... }}:\n{{\n  {rendered_body}\n}}\n"
    module_path = tmp_path / "activation_fixture.nix"
    module_path.write_text(module_source)

    result = subprocess.run(  # noqa: S603
        ["nix-instantiate", "--parse", str(module_path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr

    spans = _quoted_spans(rendered_body)
    pos = rendered_body.find(escaped_inner)
    while pos != -1:
        assert any(start <= pos < end for start, end in spans), (
            f"marker at position {pos} is not inside a quoted Nix string literal -- "
            "possible injection: value may reach shell/Nix source unescaped"
        )
        pos = rendered_body.find(escaped_inner, pos + 1)
