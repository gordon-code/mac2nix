"""Nix, version manager, and third-party package manager models."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field


class NixInstallType(StrEnum):
    SINGLE_USER = "single_user"
    MULTI_USER = "multi_user"
    DETERMINATE = "determinate"
    UNKNOWN = "unknown"


class NixInstallation(BaseModel):
    present: bool = False
    version: str | None = None
    store_path: Path = Path("/nix/store")
    install_type: NixInstallType = NixInstallType.UNKNOWN
    daemon_running: bool = False


class NixProfilePackage(BaseModel):
    name: str
    version: str | None = None
    store_path: Path | None = None


class NixProfile(BaseModel):
    name: str
    path: Path
    packages: list[NixProfilePackage] = []


class NixDarwinState(BaseModel):
    present: bool = False
    generation: int | None = None
    config_path: Path | None = None
    system_packages: list[str] = []


class HomeManagerState(BaseModel):
    present: bool = False
    generation: int | None = None
    config_path: Path | None = None
    packages: list[str] = []


class NixChannel(BaseModel):
    name: str
    url: str


class NixFlakeInput(BaseModel):
    name: str
    url: str | None = None
    locked_rev: str | None = None


class NixRegistryEntry(BaseModel):
    from_name: str
    to_url: str


class NixConfig(BaseModel):
    """Key settings from nix.conf.

    SECURITY: access-tokens and netrc-file values MUST be redacted before storing.
    """

    experimental_features: list[str] = []
    substituters: list[str] = []
    trusted_users: list[str] = []
    max_jobs: int | None = None
    sandbox: bool | None = None
    extra_config: dict[str, str] = Field(default_factory=dict)


class DevboxProject(BaseModel):
    path: Path
    packages: list[str] = []


class DevenvProject(BaseModel):
    path: Path
    has_lock: bool = False


class NixDirenvConfig(BaseModel):
    """Tracks .envrc files that use nix-direnv or use_nix."""

    path: Path
    use_flake: bool = False
    use_nix: bool = False


class NixState(BaseModel):
    """Aggregate Nix ecosystem state."""

    installation: NixInstallation = Field(default_factory=NixInstallation)
    profiles: list[NixProfile] = []
    darwin: NixDarwinState = Field(default_factory=NixDarwinState)
    home_manager: HomeManagerState = Field(default_factory=HomeManagerState)
    channels: list[NixChannel] = []
    flake_inputs: list[NixFlakeInput] = []
    registries: list[NixRegistryEntry] = []
    config: NixConfig = Field(default_factory=NixConfig)
    devbox_projects: list[DevboxProject] = []
    devenv_projects: list[DevenvProject] = []
    direnv_configs: list[NixDirenvConfig] = []


class VersionManagerType(StrEnum):
    ASDF = "asdf"
    MISE = "mise"
    NVM = "nvm"
    PYENV = "pyenv"
    RBENV = "rbenv"
    JENV = "jenv"
    SDKMAN = "sdkman"


class ManagedRuntime(BaseModel):
    """A single runtime version managed by a version manager."""

    manager: VersionManagerType
    language: str
    version: str
    path: Path | None = None
    active: bool = False


class VersionManagerInfo(BaseModel):
    """State of one version manager installation."""

    manager_type: VersionManagerType
    version: str | None = None
    config_path: Path | None = None
    runtimes: list[ManagedRuntime] = []


class VersionManagersResult(BaseModel):
    """Aggregate version manager state."""

    managers: list[VersionManagerInfo] = []
    global_tool_versions: Path | None = None


class MacPortsPackage(BaseModel):
    name: str
    version: str | None = None
    active: bool = True
    variants: list[str] = []


class MacPortsState(BaseModel):
    present: bool = False
    version: str | None = None
    prefix: Path = Path("/opt/local")
    packages: list[MacPortsPackage] = []


class CondaPackage(BaseModel):
    name: str
    version: str | None = None
    channel: str | None = None


class CondaEnvironment(BaseModel):
    name: str
    path: Path
    is_active: bool = False
    packages: list[CondaPackage] = []


class CondaState(BaseModel):
    present: bool = False
    version: str | None = None
    environments: list[CondaEnvironment] = []


class PackageManagersResult(BaseModel):
    """Third-party (non-Homebrew, non-Nix) package managers."""

    macports: MacPortsState = Field(default_factory=MacPortsState)
    conda: CondaState = Field(default_factory=CondaState)


class ContainerRuntimeType(StrEnum):
    DOCKER = "docker"
    PODMAN = "podman"
    COLIMA = "colima"
    ORBSTACK = "orbstack"
    LIMA = "lima"


class ContainerRuntimeInfo(BaseModel):
    runtime_type: ContainerRuntimeType
    version: str | None = None
    running: bool = False
    config_path: Path | None = None
    socket_path: Path | None = None


class ContainersResult(BaseModel):
    runtimes: list[ContainerRuntimeInfo] = []
