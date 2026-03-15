"""Nix ecosystem state scanner."""

from __future__ import annotations

import json
import logging
import re
import shutil
from pathlib import Path

from mac2nix.models.package_managers import (
    DevboxProject,
    DevenvProject,
    HomeManagerState,
    NixChannel,
    NixConfig,
    NixDarwinState,
    NixDirenvConfig,
    NixFlakeInput,
    NixInstallation,
    NixInstallType,
    NixProfile,
    NixProfilePackage,
    NixRegistryEntry,
    NixState,
)
from mac2nix.scanners._utils import WALK_SKIP_DIRS, WALK_SKIP_SUFFIXES, parallel_walk_dirs, run_command
from mac2nix.scanners.base import BaseScannerPlugin, register

logger = logging.getLogger(__name__)

_SENSITIVE_PATTERNS = {"ACCESS_TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "NETRC"}
_SENSITIVE_EXACT_KEYS = {"access-tokens", "netrc-file"}

_PACKAGE_CAP = 500
_ADJACENT_CAP = 50
_ADJACENT_MAX_DEPTH = 5
_NON_PROJECT_DIRS = frozenset(
    {
        # macOS non-project directories — checked at all walk depths.
        # These never contain devbox.json/devenv.nix/.envrc.
        "Library",
        "Applications",
        "Downloads",
        "Movies",
        "Music",
        "Pictures",
        "Public",
        ".Trash",
        ".local",
    }
)
_SYSTEM_NIX_CONF = Path("/etc/nix/nix.conf")

_VERSION_RE = re.compile(r"(\d+\.\d+[\w.]*)")
_REGISTRY_RE = re.compile(r"^\S+\s+flake:(\S+)\s+(\S+)")


@register("nix_state")
class NixStateScanner(BaseScannerPlugin):
    @property
    def name(self) -> str:
        return "nix_state"

    def scan(self) -> NixState:
        installation = self._detect_installation()
        if not installation.present:
            return NixState(installation=installation)

        profiles = self._detect_profiles()
        darwin = self._detect_darwin()
        home_manager = self._detect_home_manager()
        channels, flake_inputs, registries = self._detect_channels_and_flakes()
        config = self._detect_config()
        devbox_projects, devenv_projects, direnv_configs = self._detect_nix_adjacent()

        return NixState(
            installation=installation,
            profiles=profiles,
            darwin=darwin,
            home_manager=home_manager,
            channels=channels,
            flake_inputs=flake_inputs,
            registries=registries,
            config=config,
            devbox_projects=devbox_projects,
            devenv_projects=devenv_projects,
            direnv_configs=direnv_configs,
        )

    def _detect_installation(self) -> NixInstallation:
        nix_store = Path("/nix/store")
        if not nix_store.exists():
            return NixInstallation(present=False)

        version = self._get_nix_version()
        install_type = self._get_install_type()
        daemon_running = self._is_daemon_running()

        return NixInstallation(
            present=True,
            version=version,
            install_type=install_type,
            daemon_running=daemon_running,
        )

    def _get_nix_version(self) -> str | None:
        result = run_command(["nix", "--version"])
        if result is None or result.returncode != 0:
            # Fallback: try the default profile path
            fallback_path = "/nix/var/nix/profiles/default/bin/nix"
            if Path(fallback_path).exists():
                result = run_command([fallback_path, "--version"])
        if result is not None and result.returncode == 0:
            match = _VERSION_RE.search(result.stdout)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _get_install_type() -> NixInstallType:
        # Determinate installer
        if Path("/nix/receipt.json").exists():
            return NixInstallType.DETERMINATE
        if Path.home().joinpath(".config", "determinate").is_dir():
            return NixInstallType.DETERMINATE
        # Multi-user
        if Path("/Library/LaunchDaemons/org.nixos.nix-daemon.plist").exists():
            return NixInstallType.MULTI_USER
        return NixInstallType.UNKNOWN

    @staticmethod
    def _is_daemon_running() -> bool:
        # Try both official and Determinate installer service names via launchctl
        for service in ("org.nixos.nix-daemon", "systems.determinate.nix-daemon"):
            result = run_command(["launchctl", "list", service])
            if result is None or result.returncode != 0:
                continue
            # launchctl list output: PID\tStatus\tLabel
            # If PID is "-", the daemon is not running
            first_line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
            parts = first_line.split()
            if len(parts) < 3:
                continue
            if parts[0] != "-":
                try:
                    int(parts[0])
                    return True
                except ValueError:
                    pass
        # Fallback: launchctl in user domain can't see system services,
        # so check for the process directly
        for proc_name in ("nix-daemon", "determinate-nixd"):
            result = run_command(["pgrep", "-x", proc_name])
            if result is not None and result.returncode == 0 and result.stdout.strip():
                return True
        return False

    def _detect_profiles(self) -> list[NixProfile]:
        profiles: list[NixProfile] = []

        # Try nix profile list --json (Nix 2.4+)
        result = run_command(["nix", "profile", "list", "--json"])
        if result is not None and result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                packages = self._parse_profile_json(data)
                if packages:
                    nix_profile_path = Path.home() / ".nix-profile"
                    profiles.append(
                        NixProfile(
                            name="default",
                            path=nix_profile_path,
                            packages=packages[:_PACKAGE_CAP],
                        )
                    )
                    return profiles
            except (json.JSONDecodeError, ValueError):
                pass

        # Fallback: manifest.json
        manifest_path = Path.home() / ".nix-profile" / "manifest.json"
        if manifest_path.exists():
            try:
                data = json.loads(manifest_path.read_text())
                packages = self._parse_profile_json(data)
                if packages:
                    profiles.append(
                        NixProfile(
                            name="default",
                            path=Path.home() / ".nix-profile",
                            packages=packages[:_PACKAGE_CAP],
                        )
                    )
                    return profiles
            except (json.JSONDecodeError, ValueError, OSError):
                pass

        # Fallback: nix-env -q
        result = run_command(["nix-env", "-q"])
        if result is not None and result.returncode == 0:
            packages = []
            for line in result.stdout.strip().splitlines():
                pkg = line.strip()
                if pkg:
                    packages.append(NixProfilePackage(name=pkg))
            if packages:
                profiles.append(
                    NixProfile(
                        name="default",
                        path=Path.home() / ".nix-profile",
                        packages=packages[:_PACKAGE_CAP],
                    )
                )

        return profiles

    @staticmethod
    def _parse_profile_json(data: dict) -> list[NixProfilePackage]:
        packages: list[NixProfilePackage] = []
        elements = data.get("elements", [])
        # Nix 3.x: elements is a dict keyed by package name
        # Nix 2.4+: elements is a list of dicts
        items: list[tuple[str | None, dict]] = []
        if isinstance(elements, dict):
            items = [(name, elem) for name, elem in elements.items() if isinstance(elem, dict)]
        elif isinstance(elements, list):
            items = [(None, elem) for elem in elements if isinstance(elem, dict)]

        for pkg_name, elem in items:
            store_paths = elem.get("storePaths", [])
            store_path = Path(store_paths[0]) if store_paths else None
            # Derive name and version from store path: /nix/store/hash-name-version
            version: str | None = None
            if pkg_name:
                name = pkg_name
            elif store_path:
                name = store_path.name.split("-", 1)[1] if "-" in store_path.name else store_path.name
            else:
                name = elem.get("attrPath", "unknown")
            # Extract version from store path (e.g., "awscli2-2.33.2" → "2.33.2")
            if store_path and "-" in store_path.name:
                store_name = store_path.name.split("-", 1)[1]  # strip hash
                match = _VERSION_RE.search(store_name)
                if match:
                    version = match.group(1)
            packages.append(
                NixProfilePackage(
                    name=name,
                    version=version,
                    store_path=store_path,
                )
            )
        return packages

    def _detect_darwin(self) -> NixDarwinState:
        current_system = Path("/run/current-system")
        has_darwin_rebuild = shutil.which("darwin-rebuild") is not None

        if not current_system.exists() and not has_darwin_rebuild:
            return NixDarwinState(present=False)

        generation = self._get_darwin_generation()
        config_path = self._find_darwin_config()

        return NixDarwinState(
            present=True,
            generation=generation,
            config_path=config_path,
        )

    @staticmethod
    def _get_darwin_generation() -> int | None:
        result = run_command(["darwin-rebuild", "--list-generations"])
        if result is None or result.returncode != 0:
            return None
        lines = result.stdout.strip().splitlines()
        if not lines:
            return None
        # Last line format: "  2024-03-01 12:00 : id 3 -> /nix/var/..."
        last_line = lines[-1]
        match = re.search(r"id\s+(\d+)", last_line)
        if match:
            return int(match.group(1))
        return None

    @staticmethod
    def _find_darwin_config() -> Path | None:
        # Legacy path
        legacy = Path.home() / ".nixpkgs" / "darwin-configuration.nix"
        if legacy.exists():
            return legacy

        # Flake-based: resolve /run/current-system/flake symlink
        flake_link = Path("/run/current-system/flake")
        if flake_link.is_symlink():
            try:
                flake_dir = flake_link.resolve().parent
                flake_nix = flake_dir / "flake.nix"
                if flake_nix.exists():
                    return flake_nix
            except OSError:
                pass

        return None

    def _detect_home_manager(self) -> HomeManagerState:
        if shutil.which("home-manager") is None:
            return HomeManagerState(present=False)

        generation = self._get_hm_generation()
        config_path = self._find_hm_config()
        packages = self._get_hm_packages()

        return HomeManagerState(
            present=True,
            generation=generation,
            config_path=config_path,
            packages=packages,
        )

    @staticmethod
    def _get_hm_generation() -> int | None:
        result = run_command(["home-manager", "generations"])
        if result is None or result.returncode != 0:
            return None
        lines = result.stdout.strip().splitlines()
        if not lines:
            return None
        # First line is the newest generation: "2024-01-01 : id 42 -> ..."
        first_line = lines[0]
        match = re.search(r"id\s+(\d+)", first_line)
        if match:
            return int(match.group(1))
        return None

    @staticmethod
    def _find_hm_config() -> Path | None:
        candidates = [
            Path.home() / ".config" / "home-manager" / "home.nix",
            Path.home() / ".config" / "home-manager" / "flake.nix",
            Path.home() / ".config" / "nixpkgs" / "home.nix",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    @staticmethod
    def _get_hm_packages() -> list[str]:
        result = run_command(["home-manager", "packages"])
        if result is None or result.returncode != 0:
            return []
        packages = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
        return packages[:_PACKAGE_CAP]

    def _detect_channels_and_flakes(
        self,
    ) -> tuple[list[NixChannel], list[NixFlakeInput], list[NixRegistryEntry]]:
        channels = self._get_channels()
        flake_inputs = self._get_flake_inputs()
        registries = self._get_registries()
        return channels, flake_inputs, registries

    @staticmethod
    def _get_channels() -> list[NixChannel]:
        result = run_command(["nix-channel", "--list"])
        if result is None or result.returncode != 0:
            return []
        channels: list[NixChannel] = []
        for line in result.stdout.strip().splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                channels.append(NixChannel(name=parts[0], url=parts[1]))
        return channels

    @staticmethod
    def _get_flake_inputs() -> list[NixFlakeInput]:
        lock_paths = [
            Path("/run/current-system/flake.lock"),
            Path.home() / ".config" / "home-manager" / "flake.lock",
        ]
        inputs: list[NixFlakeInput] = []
        seen_names: set[str] = set()

        for lock_path in lock_paths:
            if not lock_path.exists():
                continue
            try:
                data = json.loads(lock_path.read_text())
            except (json.JSONDecodeError, OSError):
                continue

            nodes = data.get("nodes", {})
            for node_name, node_data in nodes.items():
                if node_name == "root" or node_name in seen_names:
                    continue
                if not isinstance(node_data, dict):
                    continue
                seen_names.add(node_name)

                locked = node_data.get("locked", {})
                original = node_data.get("original", {})
                locked_rev = locked.get("rev") if isinstance(locked, dict) else None
                url = original.get("url") if isinstance(original, dict) else None
                # Build URL from original type/owner/repo if url is not set
                if not url and isinstance(original, dict):
                    owner = original.get("owner")
                    repo = original.get("repo")
                    if owner and repo:
                        url = f"github:{owner}/{repo}"

                inputs.append(
                    NixFlakeInput(
                        name=node_name,
                        url=url,
                        locked_rev=locked_rev,
                    )
                )

        return inputs

    @staticmethod
    def _get_registries() -> list[NixRegistryEntry]:
        result = run_command(["nix", "registry", "list"])
        if result is None or result.returncode != 0:
            return []
        entries: list[NixRegistryEntry] = []
        for line in result.stdout.strip().splitlines():
            match = _REGISTRY_RE.match(line)
            if match:
                entries.append(NixRegistryEntry(from_name=match.group(1), to_url=match.group(2)))
        return entries

    def _detect_config(self) -> NixConfig:
        config_files = [
            _SYSTEM_NIX_CONF,
            Path.home() / ".config" / "nix" / "nix.conf",
        ]

        merged: dict[str, str] = {}
        for config_file in config_files:
            if not config_file.exists():
                continue
            try:
                content = config_file.read_text()
            except OSError:
                continue
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "=" not in stripped:
                    continue
                key, _, value = stripped.partition("=")
                key = key.strip()
                value = value.strip()

                # Redact sensitive values
                if key in _SENSITIVE_EXACT_KEYS:
                    value = "**REDACTED**"
                else:
                    normalized_key = key.upper().replace("-", "_")
                    if any(p in normalized_key for p in _SENSITIVE_PATTERNS):
                        value = "**REDACTED**"

                merged[key] = value

        # Nix supports both "key" and "extra-key" variants — merge them
        def _merge_list(key: str) -> list[str]:
            base = merged.get(key, "").split() if merged.get(key) else []
            extra = merged.get(f"extra-{key}", "").split() if merged.get(f"extra-{key}") else []
            return base + extra

        known_keys = {
            "experimental-features",
            "extra-experimental-features",
            "substituters",
            "extra-substituters",
            "trusted-users",
            "extra-trusted-users",
            "max-jobs",
            "sandbox",
        }

        return NixConfig(
            experimental_features=_merge_list("experimental-features"),
            substituters=_merge_list("substituters"),
            trusted_users=_merge_list("trusted-users"),
            max_jobs=self._parse_max_jobs(merged.get("max-jobs")),
            sandbox=merged["sandbox"] == "true" if merged.get("sandbox") else None,
            extra_config={k: v for k, v in merged.items() if k not in known_keys},
        )

    @staticmethod
    def _parse_max_jobs(value: str | None) -> int | None:
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    def _detect_nix_adjacent(
        self,
    ) -> tuple[list[DevboxProject], list[DevenvProject], list[NixDirenvConfig]]:
        home = Path.home()
        try:
            children = sorted(home.iterdir())
        except (PermissionError, OSError):
            return [], [], []

        walkable = [
            c
            for c in children
            if c.is_dir()
            and c.name not in _NON_PROJECT_DIRS
            and c.name not in WALK_SKIP_DIRS
            and not c.name.endswith(WALK_SKIP_SUFFIXES)
        ]

        results = parallel_walk_dirs(walkable, self._walk_child_for_adjacent)

        devbox: list[DevboxProject] = []
        devenv: list[DevenvProject] = []
        direnv: list[NixDirenvConfig] = []
        for db, de, dc in results:
            devbox.extend(db)
            devenv.extend(de)
            direnv.extend(dc)

        return devbox[:_ADJACENT_CAP], devenv[:_ADJACENT_CAP], direnv[:_ADJACENT_CAP]

    def _walk_child_for_adjacent(
        self,
        child: Path,
    ) -> tuple[list[DevboxProject], list[DevenvProject], list[NixDirenvConfig]]:
        devbox: list[DevboxProject] = []
        devenv: list[DevenvProject] = []
        direnv: list[NixDirenvConfig] = []
        self._walk_recursive(child, 1, devbox, devenv, direnv)
        return devbox, devenv, direnv

    def _walk_recursive(
        self,
        directory: Path,
        depth: int,
        devbox_projects: list[DevboxProject],
        devenv_projects: list[DevenvProject],
        direnv_configs: list[NixDirenvConfig],
    ) -> None:
        if depth > _ADJACENT_MAX_DEPTH:
            return

        try:
            entries = sorted(directory.iterdir())
        except (PermissionError, OSError):
            return

        for entry in entries:
            if entry.is_dir() and not entry.is_symlink():
                if (
                    entry.name in WALK_SKIP_DIRS
                    or entry.name in _NON_PROJECT_DIRS
                    or entry.name.endswith(WALK_SKIP_SUFFIXES)
                ):
                    continue
                self._walk_recursive(entry, depth + 1, devbox_projects, devenv_projects, direnv_configs)
            elif entry.is_file():
                if entry.name == "devbox.json":
                    packages = self._parse_devbox_json(entry)
                    devbox_projects.append(DevboxProject(path=entry.parent, packages=packages))
                elif entry.name == "devenv.nix":
                    has_lock = (entry.parent / "devenv.lock").exists()
                    devenv_projects.append(DevenvProject(path=entry.parent, has_lock=has_lock))
                elif entry.name == ".envrc":
                    self._check_envrc(entry, direnv_configs)

    @staticmethod
    def _parse_devbox_json(path: Path) -> list[str]:
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return []
        packages = data.get("packages", [])
        if isinstance(packages, list):
            return [str(p) for p in packages]
        return []

    @staticmethod
    def _check_envrc(path: Path, direnv_configs: list[NixDirenvConfig]) -> None:
        try:
            content = path.read_text()
        except OSError:
            return
        use_flake = "use flake" in content
        use_nix = "use_nix" in content or "use nix" in content
        if use_flake or use_nix:
            direnv_configs.append(NixDirenvConfig(path=path, use_flake=use_flake, use_nix=use_nix))
