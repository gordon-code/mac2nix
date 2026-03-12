"""Shell scanner — reads shell configuration files."""

from __future__ import annotations

import getpass
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from mac2nix.models.services import ShellConfig, ShellFramework
from mac2nix.scanners._utils import run_command
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
# Line-by-line parsing — may false-positive inside heredocs, which is acceptable
# for rc-file scanning since heredocs in rc files are rare.
_FUNCTION_PATTERN = re.compile(r"^(?:function\s+)?(\w+)\s*\(\)\s*\{?")
_FISH_FUNCTION_PATTERN = re.compile(r"^function\s+(\S+)")

_SOURCE_PATTERN = re.compile(r"^(?:source|\.)\s+(.+)$")
_FISH_SOURCE_PATTERN = re.compile(r"^source\s+(.+)$")
_EVAL_PATTERN = re.compile(r'^eval\s+["\(]|^eval\s+"?\$\(')
_FISH_EVAL_PATTERN = re.compile(r"^eval\s+\(|^\s*\w+\s*\|")


@dataclass
class _ParsedShellData:
    """Accumulator for parsed shell configuration data."""

    aliases: dict[str, str] = field(default_factory=dict)
    env_vars: dict[str, str] = field(default_factory=dict)
    path_components: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    sourced_files: list[Path] = field(default_factory=list)
    dynamic_commands: list[str] = field(default_factory=list)


@register("shell")
class ShellScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "shell"

    def scan(self) -> ShellConfig:
        shell_path = self._get_login_shell()
        shell_type = Path(shell_path).name
        # Normalize to known types
        if shell_type not in _RC_FILES:
            shell_type = "zsh"

        home = Path.home()
        rc_files: list[Path] = []
        parsed = _ParsedShellData()
        seen_files: set[Path] = set()

        rc_names = _RC_FILES.get(shell_type, [])
        for rc_name in rc_names:
            # Respect XDG_CONFIG_HOME for fish
            if shell_type == "fish" and rc_name.startswith(".config/"):
                xdg = os.environ.get("XDG_CONFIG_HOME")
                rc_path = Path(xdg) / rc_name.removeprefix(".config/") if xdg else home / rc_name
            else:
                rc_path = home / rc_name
            if rc_path.is_file():
                rc_files.append(rc_path)
                seen_files.add(rc_path.resolve())
                self._parse_rc_file(rc_path, shell_type, parsed, home, seen_files)

        # Fish functions directory
        if shell_type == "fish":
            func_dir = self._get_fish_config_dir(home) / "functions"
            if func_dir.is_dir():
                for func_file in sorted(func_dir.glob("*.fish")):
                    parsed.functions.append(func_file.stem)

        # Scan conf.d and completions directories
        conf_d_files = self._scan_conf_d(home, shell_type)
        completion_files = self._scan_completions(home, shell_type)

        # Detect shell frameworks
        frameworks = self._detect_frameworks(home, shell_type)

        return ShellConfig(
            shell_type=shell_type,
            rc_files=rc_files,
            path_components=parsed.path_components,
            aliases=parsed.aliases,
            functions=parsed.functions,
            env_vars=parsed.env_vars,
            conf_d_files=conf_d_files,
            completion_files=completion_files,
            sourced_files=parsed.sourced_files,
            frameworks=frameworks,
            dynamic_commands=parsed.dynamic_commands,
        )

    @staticmethod
    def _get_login_shell() -> str:
        """Get the user's login shell via dscl (macOS directory service).

        Falls back to $SHELL, then /bin/zsh.
        """
        username = getpass.getuser()
        result = run_command(["dscl", ".", "-read", f"/Users/{username}", "UserShell"])
        if result is not None and result.returncode == 0:
            # Output: "UserShell: /opt/homebrew/bin/fish"
            output = result.stdout.strip()
            if "UserShell:" in output:
                return output.split("UserShell:", 1)[1].strip()

        return os.environ.get("SHELL", "/bin/zsh")

    @staticmethod
    def _get_fish_config_dir(home: Path) -> Path:
        """Get fish config directory, respecting XDG_CONFIG_HOME."""
        xdg = os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            return Path(xdg) / "fish"
        return home / ".config" / "fish"

    def _scan_conf_d(self, home: Path, shell_type: str) -> list[Path]:
        """Scan conf.d directories for shell configuration snippets."""
        files: list[Path] = []
        if shell_type == "fish":
            conf_d = self._get_fish_config_dir(home) / "conf.d"
            if conf_d.is_dir():
                try:
                    for f in sorted(conf_d.glob("*.fish")):
                        files.append(f)
                except PermissionError:
                    logger.warning("Permission denied reading: %s", conf_d)
        elif shell_type == "zsh":
            for zsh_dir in [home / ".zsh", home / ".config" / "zsh"]:
                if zsh_dir.is_dir():
                    try:
                        for f in sorted(zsh_dir.iterdir()):
                            if f.is_file():
                                files.append(f)
                    except PermissionError:
                        logger.warning("Permission denied reading: %s", zsh_dir)
        return files

    def _scan_completions(self, home: Path, shell_type: str) -> list[Path]:
        """Scan completions directories."""
        files: list[Path] = []
        if shell_type == "fish":
            comp_dir = self._get_fish_config_dir(home) / "completions"
            if comp_dir.is_dir():
                try:
                    for f in sorted(comp_dir.glob("*.fish")):
                        files.append(f)
                except PermissionError:
                    logger.warning("Permission denied reading: %s", comp_dir)
        elif shell_type == "zsh":
            for comp_dir in [home / ".zsh" / "completions", home / ".config" / "zsh" / "completions"]:
                if comp_dir.is_dir():
                    try:
                        for f in sorted(comp_dir.iterdir()):
                            if f.is_file():
                                files.append(f)
                    except PermissionError:
                        logger.warning("Permission denied reading: %s", comp_dir)
        return files

    def _parse_rc_file(
        self,
        rc_path: Path,
        shell_type: str,
        parsed: _ParsedShellData,
        home: Path,
        seen_files: set[Path],
    ) -> None:
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
                self._check_source_fish(stripped, parsed, home, seen_files)
            else:
                self._parse_posix_line(stripped, parsed)
                self._check_source_posix(stripped, parsed, home, seen_files)

    def _check_source_posix(self, line: str, parsed: _ParsedShellData, home: Path, seen_files: set[Path]) -> None:
        match = _SOURCE_PATTERN.match(line)
        if not match:
            return
        self._resolve_and_track_source(match.group(1).strip("'\""), parsed, home, seen_files, shell_type="bash")

    def _check_source_fish(self, line: str, parsed: _ParsedShellData, home: Path, seen_files: set[Path]) -> None:
        match = _FISH_SOURCE_PATTERN.match(line)
        if not match:
            return
        self._resolve_and_track_source(match.group(1).strip("'\""), parsed, home, seen_files, shell_type="fish")

    def _resolve_and_track_source(
        self, raw_path: str, parsed: _ParsedShellData, home: Path, seen_files: set[Path], shell_type: str = "fish"
    ) -> None:
        """Resolve a sourced file path, add to sourced_files, and parse it (one level only)."""
        # Expand ~ and $HOME
        resolved_str = raw_path.replace("$HOME", str(home)).replace("~", str(home))
        try:
            resolved = Path(resolved_str).expanduser().resolve()
        except (ValueError, OSError):
            return

        if not resolved.is_file():
            return
        if resolved in seen_files:
            return

        seen_files.add(resolved)
        parsed.sourced_files.append(resolved)

        # Parse the sourced file for aliases/env vars (one level — no recursive sourcing)
        try:
            content = resolved.read_text()
        except (PermissionError, OSError):
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
            # Extract the actual path, skipping flags like --prepend --move --global
            args = match.group(1).split()
            path_arg = next((a for a in args if not a.startswith("-")), None)
            if path_arg:
                parsed.path_components.append(path_arg.strip("'\""))
            return

        match = _FISH_FUNCTION_PATTERN.match(line)
        if match:
            parsed.functions.append(match.group(1))
            return

        # Detect eval/command substitution
        if _FISH_EVAL_PATTERN.match(line):
            parsed.dynamic_commands.append(line)

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
            return

        # Detect eval/command substitution
        if _EVAL_PATTERN.match(line):
            parsed.dynamic_commands.append(line)

    def _detect_frameworks(self, home: Path, shell_type: str) -> list[ShellFramework]:
        """Detect installed shell frameworks."""
        frameworks: list[ShellFramework] = []
        fish_config = self._get_fish_config_dir(home)

        if shell_type == "fish":
            # Oh My Fish
            omf_dir = fish_config / "omf"
            if not omf_dir.is_dir():
                omf_dir = home / ".local" / "share" / "omf"
            if omf_dir.is_dir():
                plugins = self._list_dir_names(omf_dir / "pkg")
                theme = self._read_first_line(omf_dir / "theme")
                frameworks.append(ShellFramework(name="oh-my-fish", path=omf_dir, plugins=plugins, theme=theme))

            # Fisher
            fish_plugins = fish_config / "fish_plugins"
            if fish_plugins.is_file():
                try:
                    plugins = [line.strip() for line in fish_plugins.read_text().splitlines() if line.strip()]
                except OSError:
                    plugins = []
                frameworks.append(ShellFramework(name="fisher", path=fish_plugins, plugins=plugins))

        elif shell_type == "zsh":
            # Oh My Zsh
            omz_dir = home / ".oh-my-zsh"
            if omz_dir.is_dir():
                plugins = self._list_dir_names(omz_dir / "custom" / "plugins")
                frameworks.append(ShellFramework(name="oh-my-zsh", path=omz_dir, plugins=plugins))

            # Prezto
            prezto_dir = home / ".zprezto"
            if prezto_dir.is_dir():
                frameworks.append(ShellFramework(name="prezto", path=prezto_dir))

        # Starship (works with any shell)
        starship_config = home / ".config" / "starship.toml"
        if not starship_config.is_file():
            xdg = os.environ.get("XDG_CONFIG_HOME")
            if xdg:
                starship_config = Path(xdg) / "starship.toml"
        if starship_config.is_file():
            frameworks.append(ShellFramework(name="starship", path=starship_config))

        return frameworks

    @staticmethod
    def _list_dir_names(path: Path) -> list[str]:
        """List directory names in a path."""
        if not path.is_dir():
            return []
        try:
            return sorted(d.name for d in path.iterdir() if d.is_dir())
        except PermissionError:
            return []

    @staticmethod
    def _read_first_line(path: Path) -> str | None:
        """Read the first non-empty line from a file."""
        if not path.is_file():
            return None
        try:
            for line in path.read_text().splitlines():
                stripped = line.strip()
                if stripped:
                    return stripped
        except OSError:
            pass
        return None
