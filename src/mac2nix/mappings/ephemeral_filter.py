"""Heuristic filters for ephemeral, non-reproducible plist state.

Ported from defaults2nix's noise-filtering heuristics, with fixes for its
substring-overmatch bugs. defaults2nix flags any key containing "time",
"at", or "when" as a timestamp, which wrongly filters real settings like
``autohide-time-modifier``, ``TimeFormat``, or ``Authenticate``. This module
matches timestamp-like keys by camelCase-aware suffix instead: a key is only
flagged when one of the known timestamp words is its trailing word (or pair
of words), not merely a substring anywhere in it.
"""

from __future__ import annotations

import re
from typing import Any

_UI_STATE_KEY_PREFIXES: tuple[str, ...] = (
    "NSWindow Frame ",
    "NSSplitView Subview Frames ",
    "NSTableView Columns ",
    "NSTableView Sort Ordering ",
    "NSTableView Supports ",
    "NSToolbar Configuration",
    "ExtensionsToolbarConfiguration",
)

_UI_STATE_KEY_EXACT: frozenset[str] = frozenset(
    {
        "NSNavPanelExpandedSize",
        "NSNavPanelFileLastListMode",
        "NSNavPanelFileListMode",
        "NSPreferencesContentSize",
        "TB Icon Size Mode",
        "TB Size Mode",
        "UserColumnSortPerTab",
        "UserColumnsPerTab",
    }
)

_UI_STATE_KEY_CONTAINS: tuple[str, ...] = (
    "Column Width",
    "image window frame",
    "image window parent frame",
    "CropRect",
)

# CamelCase-tokenized (lowercased) suffixes that indicate a timestamp-ish key.
# Deliberately narrower than defaults2nix's substring list (no bare "time",
# "date", "updated", "at", "when" — those overmatch real settings).
_TIMESTAMP_KEY_SUFFIXES: frozenset[str] = frozenset(
    {
        "lastused",
        "lastseen",
        "lastaccess",
        "lastconnected",
        "lastlaunch",
        "lastopen",
        "lastvisit",
        "checkedat",
        "setat",
        "startedat",
        "endedat",
        "timestamp",
        "epoch",
        "expiry",
        "expires",
    }
)

_UNIX_TIMESTAMP_MIN = 946_684_800  # 2000-01-01
_UNIX_TIMESTAMP_MAX = 2_208_988_800  # 2040-01-01
_CFABSOLUTE_TIME_MIN = 100_000_000  # ~2004, seconds since 2001-01-01
_CFABSOLUTE_TIME_MAX = 1_230_768_000  # ~2040

_DATE_STRING_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?)?$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HASHED_ID_RE = re.compile(r"^_[0-9a-fA-F]{32}$")
_BINARY_DATA_SENTINEL_RE = re.compile(r"^<data:\d+ bytes>$")

# sanitize_plist_values() (scanners/_utils.py) converts plist <data> blobs into
# this sentinel string before scanner output ever reaches the mapping layer,
# so bytes objects never appear here — matching the sentinel format is the
# only way to detect binary-origin values.
_SPARKLE_ALLOWLIST: frozenset[str] = frozenset({"SUEnableAutomaticChecks"})

_CAMEL_TOKEN_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z0-9]+")
_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]+")


def _tokenize(key: str) -> list[str]:
    tokens: list[str] = []
    for segment in _NON_ALNUM_RE.split(key):
        if segment:
            tokens.extend(match.lower() for match in _CAMEL_TOKEN_RE.findall(segment))
    return tokens


def _is_ui_state_key(key: str) -> bool:
    if key in _UI_STATE_KEY_EXACT:
        return True
    if any(key.startswith(prefix) for prefix in _UI_STATE_KEY_PREFIXES):
        return True
    if any(pattern in key for pattern in _UI_STATE_KEY_CONTAINS):
        return True
    return key.endswith("Frame") and ("Window" in key or "window" in key)


def _is_timestamp_key(key: str) -> bool:
    tokens = _tokenize(key)
    widths = (1, 2)
    return any(len(tokens) >= width and "".join(tokens[-width:]) in _TIMESTAMP_KEY_SUFFIXES for width in widths)


def _is_uuid_string(text: str) -> bool:
    return bool(_UUID_RE.match(text)) or bool(_HASHED_ID_RE.match(text))


def _is_uuid_key(key: str) -> bool:
    return _is_uuid_string(key)


def _is_sparkle_key(key: str) -> bool:
    return key.startswith("SU") and key not in _SPARKLE_ALLOWLIST


def _is_timestamp_value_range(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    return _UNIX_TIMESTAMP_MIN <= value <= _UNIX_TIMESTAMP_MAX or _CFABSOLUTE_TIME_MIN <= value <= _CFABSOLUTE_TIME_MAX


def _is_date_string_value(value: Any) -> bool:
    return isinstance(value, str) and bool(_DATE_STRING_RE.match(value))


def _is_uuid_value(value: Any) -> bool:
    return isinstance(value, str) and _is_uuid_string(value)


def _is_binary_data_sentinel(value: Any) -> bool:
    return isinstance(value, str) and bool(_BINARY_DATA_SENTINEL_RE.match(value))


def _parses_as_float(token: str) -> bool:
    try:
        float(token)
    except ValueError:
        return False
    return True


def _is_ui_geometry_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value.startswith("{{") and value.endswith("}}"):
        return True
    if value.startswith("{") and value.endswith("}") and value.count(",") == 1 and "=" not in value:
        return True
    tokens = value.split()
    if len(tokens) == 8 and all(_parses_as_float(token) for token in tokens):
        return True
    return value.count(",") == 5 and value.endswith(("NO", "YES"))


_KEY_PREDICATES: tuple[Any, ...] = (
    _is_ui_state_key,
    _is_timestamp_key,
    _is_uuid_key,
    _is_sparkle_key,
)

_VALUE_PREDICATES: tuple[Any, ...] = (
    _is_timestamp_value_range,
    _is_date_string_value,
    _is_uuid_value,
    _is_binary_data_sentinel,
    _is_ui_geometry_value,
)


def is_ephemeral(key: str, value: Any) -> bool:
    """Return True if key/value looks like ephemeral UI or runtime state.

    Note on cache keys: there is deliberately no key-pattern rule for
    ``*Cache*``/``*CacheSize*``/``*CachePath*`` — real config like
    ``WebKitCacheModel``, ``DiskCacheSize``, and ``CachePolicy`` would be
    wrongly filtered. A cache key is only caught here when its *value* is
    independently timestamp-like (via ``_is_timestamp_value_range`` or
    ``_is_date_string_value``), never from the key name alone.
    """
    if any(predicate(key) for predicate in _KEY_PREDICATES):
        return True
    return any(predicate(value) for predicate in _VALUE_PREDICATES)


def filter_ephemeral(keys: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of keys with all is_ephemeral-matching entries removed."""
    return {k: v for k, v in keys.items() if not is_ephemeral(k, v)}
