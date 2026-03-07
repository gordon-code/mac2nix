"""Shell scanner — reads shell configuration files."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from mac2nix.models.services import ShellConfig
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_RC_FILES: dict[str, list[str]] = {
    "fish": [".config/fish/config.fish"],
    "zsh": [".zshrc", ".zprofile", ".zshenv"],
    "bash": [".bashrc", ".bash_profile", ".profile"],
}

_FISH_FUNCTION_DIR = ".config/fish/functions"

_SENSITIVE_PATTERNS = {"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH"}

_ALIAS_PATTERN = re.compile(r"^alias\s+(\S+?)=(.+)$")
_FISH_ALIAS_PATTERN = re.compile(r"^alias\s+(\S+)\s+(.+)$")
_EXPORT_PATTERN = re.compile(r"^export\s+([A-Za-z_][A-Za-z0-9_]*)=(.+)$")
_FISH_SET_EXPORT = re.compile(r"^set\s+-gx\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+)$")
_FISH_ADD_PATH = re.compile(r"^fish_add_path\s+(.+)$")
_PATH_EXPORT = re.compile(r"^export\s+PATH=(.+)$")
_FUNCTION_PATTERN = re.compile(r"^\s*(?:function\s+)?(\w+)\s*\(\)\s*\{?")
_FISH_FUNCTION_PATTERN = re.compile(r"^function\s+(\S+)")


@dataclass
class _ParsedShellData:
    """Accumulator for parsed shell configuration data."""

    aliases: dict[str, str] = field(default_factory=dict)
    env_vars: dict[str, str] = field(default_factory=dict)
    path_components: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)


@register
class ShellScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "shell"

    def scan(self) -> ShellConfig:
        shell_path = os.environ.get("SHELL", "/bin/zsh")
        shell_type = Path(shell_path).name
        # Normalize to known types
        if shell_type not in _RC_FILES:
            shell_type = "zsh"

        home = Path.home()
        rc_files: list[Path] = []
        parsed = _ParsedShellData()

        rc_names = _RC_FILES.get(shell_type, [])
        for rc_name in rc_names:
            rc_path = home / rc_name
            if rc_path.is_file():
                rc_files.append(rc_path)
                self._parse_rc_file(rc_path, shell_type, parsed)

        # Fish functions directory
        if shell_type == "fish":
            func_dir = home / _FISH_FUNCTION_DIR
            if func_dir.is_dir():
                for func_file in sorted(func_dir.glob("*.fish")):
                    parsed.functions.append(func_file.stem)

        return ShellConfig(
            shell_type=shell_type,
            rc_files=rc_files,
            path_components=parsed.path_components,
            aliases=parsed.aliases,
            functions=parsed.functions,
            env_vars=parsed.env_vars,
        )

    def _parse_rc_file(self, rc_path: Path, shell_type: str, parsed: _ParsedShellData) -> None:
        try:
            content = rc_path.read_text()
        except (PermissionError, OSError) as exc:
            logger.warning("Failed to read shell config %s: %s", rc_path, exc)
            return

        for raw_line in content.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if shell_type == "fish":
                self._parse_fish_line(stripped, parsed)
            else:
                self._parse_posix_line(stripped, parsed)

    def _parse_fish_line(self, line: str, parsed: _ParsedShellData) -> None:
        match = _FISH_ALIAS_PATTERN.match(line)
        if match:
            parsed.aliases[match.group(1)] = match.group(2).strip("'\"")
            return

        match = _FISH_SET_EXPORT.match(line)
        if match:
            key = match.group(1)
            if any(p in key.upper() for p in _SENSITIVE_PATTERNS):
                logger.debug("Skipping sensitive env var: %s", key)
                return
            parsed.env_vars[key] = match.group(2).strip("'\"")
            return

        match = _FISH_ADD_PATH.match(line)
        if match:
            parsed.path_components.append(match.group(1).strip("'\""))
            return

        match = _FISH_FUNCTION_PATTERN.match(line)
        if match:
            parsed.functions.append(match.group(1))

    def _parse_posix_line(self, line: str, parsed: _ParsedShellData) -> None:
        match = _ALIAS_PATTERN.match(line)
        if match:
            parsed.aliases[match.group(1)] = match.group(2).strip("'\"")
            return

        match = _PATH_EXPORT.match(line)
        if match:
            raw = match.group(1).strip("'\"")
            for part in raw.split(":"):
                component = part.strip()
                if component and component != "$PATH":
                    parsed.path_components.append(component)
            return

        match = _EXPORT_PATTERN.match(line)
        if match:
            key = match.group(1)
            if any(p in key.upper() for p in _SENSITIVE_PATTERNS):
                logger.debug("Skipping sensitive env var: %s", key)
                return
            parsed.env_vars[key] = match.group(2).strip("'\"")
            return

        match = _FUNCTION_PATTERN.match(line)
        if match:
            parsed.functions.append(match.group(1))
