"""Shared Nix value rendering and Jinja2 template plumbing for generators."""

from __future__ import annotations

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
    return env


def render_template(
    template_name: str,
    context: dict[str, Any],
    loader: jinja2.BaseLoader | None = None,
) -> str:
    """Render a named template through the shared mac2nix Jinja2 environment."""
    return setup_jinja_env(loader).get_template(template_name).render(**context)
