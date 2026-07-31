"""Tests for mac2nix.generators._nix_render: Python-to-Nix literal rendering and Jinja2 plumbing."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import jinja2
import pytest

from mac2nix.generators._nix_render import (
    nix_mkdefault,
    nix_string,
    python_to_nix,
    render_template,
    setup_jinja_env,
)

_BACKSLASH = chr(92)
_DQUOTE = chr(34)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, "true"),
        (False, "false"),
        (42, "42"),
        (3.14, "3.14"),
        (None, "null"),
        ("hello", '"hello"'),
        (["a", 1, True], '[ "a" 1 true ]'),
        ({"key": "value"}, '{ key = "value"; }'),
        ({"outer": {"inner": 1}}, "{ outer = { inner = 1; }; }"),
        ({"has space": 1}, '{ "has space" = 1; }'),
    ],
    ids=[
        "bool_true",
        "bool_false",
        "int",
        "float",
        "none",
        "str",
        "list",
        "dict_bare_key",
        "nested_dict",
        "dict_key_needs_quoting",
    ],
)
def test_python_to_nix(value: Any, expected: str) -> None:
    assert python_to_nix(value) == expected


def test_python_to_nix_raises_typeerror_for_unsupported_type() -> None:
    with pytest.raises(TypeError):
        python_to_nix((1, 2, 3))


def test_nix_string_escapes_backslash() -> None:
    value = "a" + _BACKSLASH + "b"
    assert nix_string(value) == _DQUOTE + "a" + _BACKSLASH + _BACKSLASH + "b" + _DQUOTE


def test_nix_string_escapes_double_quote() -> None:
    value = "say " + _DQUOTE + "hi" + _DQUOTE
    expected = _DQUOTE + "say " + _BACKSLASH + _DQUOTE + "hi" + _BACKSLASH + _DQUOTE + _DQUOTE
    assert nix_string(value) == expected


def test_nix_string_escapes_dollar_brace_interpolation() -> None:
    value = "${danger}"
    assert nix_string(value) == _DQUOTE + _BACKSLASH + "${danger}" + _DQUOTE


def test_nix_mkdefault_wraps_expression() -> None:
    assert nix_mkdefault("true") == "lib.mkDefault true"


def test_jinja_env_custom_delimiters_do_not_collide_with_nix_braces() -> None:
    loader = jinja2.DictLoader({"fixture.nix.j2": "<% if x %>{ y = << y|nix_value >>; }<% endif %>"})
    env = setup_jinja_env(loader=loader)
    template = env.get_template("fixture.nix.j2")

    assert template.render(x=True, y=5) == "{ y = 5; }"
    assert template.render(x=False, y=5) == ""


def test_render_template_delegates_to_environment() -> None:
    loader = jinja2.DictLoader({"fixture.nix.j2": "<< value|nix_str >>"})
    result = render_template("fixture.nix.j2", {"value": "hi"}, loader=loader)
    assert result == '"hi"'


@pytest.fixture
def require_nix_instantiate() -> None:
    if shutil.which("nix-instantiate") is None:
        pytest.skip("nix-instantiate not on PATH")


@pytest.mark.nix
@pytest.mark.parametrize(
    "value",
    [
        pytest.param({"a": {"b": 1, "c": "x"}}, id="nested_dict"),
        pytest.param(["a", "b", "c"], id="list_of_strings"),
        pytest.param('has "quotes" and $dollar', id="string_with_quote_and_dollar"),
    ],
)
def test_nix_instantiate_parses_rendered_value(
    require_nix_instantiate: None,
    value: Any,
    tmp_path: Path,
) -> None:
    rendered = python_to_nix(value)
    module_source = f"{{ config, lib, pkgs, ... }}: {{ test = {rendered}; }}"
    module_path = tmp_path / "fixture.nix"
    module_path.write_text(module_source)

    result = subprocess.run(  # noqa: S603
        ["nix-instantiate", "--parse", str(module_path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
