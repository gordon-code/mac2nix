"""Shared Nix value rendering and Jinja2 template plumbing for generators."""

from __future__ import annotations

import math
import re
from typing import Any

import jinja2

_BARE_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_'-]*$")


def nix_string(s: str) -> str:
    """Render a Python string as a double-quoted Nix string literal."""
    escaped = s.replace("\\", "\\\\").replace('"', '\\"').replace("${", "\\${")
    return f'"{escaped}"'


def python_to_nix(value: Any) -> str:
    """Recursively render a Python value as a Nix literal."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and (math.isinf(value) or math.isnan(value)):
        # str() renders these as `inf`/`nan`/`-inf` -- not valid Nix number
        # literals ("undefined variable 'inf'" at nix-instantiate time,
        # pointing at the generated file rather than the offending value).
        msg = f"cannot render {value!r} as a Nix literal -- not a finite number"
        raise TypeError(msg)
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return "null"
    if isinstance(value, str):
        return nix_string(value)
    if isinstance(value, list):
        return "[ " + " ".join(python_to_nix(v) for v in value) + " ]"
    if isinstance(value, dict):
        items = " ".join(
            f"{key if _BARE_KEY_RE.match(key) else nix_string(key)} = {python_to_nix(val)};"
            for key, val in value.items()
        )
        return "{ " + items + " }"
    msg = f"cannot render {type(value).__name__!r} as a Nix literal"
    raise TypeError(msg)


def nix_mkdefault(nix_expr: str) -> str:
    """Wrap a rendered Nix expression in `lib.mkDefault`."""
    return f"lib.mkDefault {nix_expr}"


def nix_post_activation_script(bodies: list[str]) -> str:
    """Wrap one or more caller-built shell-body expressions into a single
    `system.activationScripts.postActivation.text` assignment.

    nix-darwin's own activation-scripts.nix module concatenates only a
    fixed, hardcoded sequence of named entries (preActivation, etcChecks,
    ..., defaults, launchd, ..., postActivation) into the real script that
    `darwin-rebuild switch` runs -- confirmed against nix-darwin's real
    source and a real Tart-VM switch where an arbitrary custom key (e.g.
    `system.activationScripts.mac2nixWallpaper.text`) evaluated to valid
    Nix and built successfully but was silently never executed, since
    nix-darwin's own script-assembly code never references it.
    `postActivation` is one of the few real, always-concatenated hook
    points. Every caller-built body (already a complete Nix expression
    evaluating to a string, typically `let ... in ''...''`) must route
    through this single function -- there is no other valid destination
    for a custom activation script.

    `bodies` is rendered as a Nix list joined with `lib.concatStringsSep`
    rather than string-concatenated in Python, so each body stays visually
    separate in the generated source for readability/debugging. Each body
    is wrapped in parens: a bare `let ... in ''...''` is not itself a valid
    list-literal element in Nix's grammar (list elements must be
    application-level terms), so the parens are required, not cosmetic.

    Deliberately NOT wrapped in `lib.mkDefault`. `postActivation.text` is a
    `types.lines` option: multiple definitions at the SAME priority merge
    (concatenate) via that type's own merge function, but the NixOS module
    system first discards every definition that isn't at the single lowest
    priority number present across ALL modules -- it does not merge across
    priority tiers. `lib.mkDefault` sets priority 1000 (lower precedence);
    home-manager's own nix-darwin integration
    (`home-manager/nix-darwin/default.nix`) sets this exact same option
    with a plain, unwrapped assignment (priority 100, higher precedence).
    Confirmed for real: with `mkDefault`, home-manager's definition won
    outright and this module's entire activation-script content was
    silently discarded -- not merged, not overridden-with-a-warning, just
    absent -- verified by building the real system derivation and grepping
    its `activate` script, which contained zero trace of any
    mac2nix-authored command. A plain assignment here merges at the same
    priority as home-manager's own fragment instead of losing to it.
    """
    items = "\n    ".join(f"({body})" for body in bodies)
    return f'system.activationScripts.postActivation.text = (\n  lib.concatStringsSep "\\n" [\n    {items}\n  ]\n);'


def nix_comment(text: str) -> str:
    """Render *text* as safe content for a single-line Nix `#` comment.

    A `#` comment ends at the first newline -- free-text that ultimately
    derives from scanned, attacker-writable data (e.g. a plist key name
    via `defaults write`) could otherwise embed a newline and break out of
    the comment, turning the rest of the string into live Nix syntax.
    Replace rather than strip so multi-line input stays visible (if
    garbled) instead of silently disappearing.
    """
    return text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def setup_jinja_env(loader: jinja2.BaseLoader | None = None) -> jinja2.Environment:
    """Build the Jinja2 environment shared by every mac2nix Nix template.

    Uses `<% %>`/`<< >>` delimiters instead of Jinja2's defaults so they don't
    collide with Nix's `{ }` attribute-set syntax, which appears throughout
    every template.
    """
    env = jinja2.Environment(
        loader=loader or jinja2.PackageLoader("mac2nix", "templates/modules"),
        block_start_string="<%",
        block_end_string="%>",
        variable_start_string="<<",
        variable_end_string=">>",
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,  # noqa: S701 -- output is Nix, not HTML; escaping would corrupt syntax
    )
    env.filters["nix_value"] = python_to_nix
    env.filters["nix_str"] = nix_string
    env.filters["mkdefault"] = nix_mkdefault
    env.filters["nix_comment"] = nix_comment
    return env


def render_template(
    template_name: str,
    context: dict[str, Any],
    loader: jinja2.BaseLoader | None = None,
) -> str:
    """Render a named template through the shared mac2nix Jinja2 environment."""
    return setup_jinja_env(loader).get_template(template_name).render(**context)
