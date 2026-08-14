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
