"""Tests for Nix, version manager, and third-party package manager models."""

from __future__ import annotations

from pathlib import Path

from mac2nix.models.package_managers import (
    CondaEnvironment,
    CondaPackage,
    CondaState,
    ContainerRuntimeInfo,
    ContainerRuntimeType,
    ContainersResult,
    DevboxProject,
    DevenvProject,
    HomeManagerState,
    MacPortsPackage,
    MacPortsState,
    ManagedRuntime,
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
    PackageManagersResult,
    VersionManagerInfo,
    VersionManagersResult,
    VersionManagerType,
)


class TestNixInstallation:
    def test_defaults(self) -> None:
        inst = NixInstallation()
        assert inst.present is False
        assert inst.version is None
        assert inst.store_path == Path("/nix/store")
        assert inst.install_type == NixInstallType.UNKNOWN
        assert inst.daemon_running is False

    def test_with_values(self) -> None:
        inst = NixInstallation(
            present=True,
            version="2.18.1",
            install_type=NixInstallType.MULTI_USER,
            daemon_running=True,
        )
        assert inst.present is True
        assert inst.version == "2.18.1"
        assert inst.install_type == NixInstallType.MULTI_USER
        assert inst.daemon_running is True

    def test_determinate_type(self) -> None:
        inst = NixInstallation(
            present=True,
            version="2.24.0",
            install_type=NixInstallType.DETERMINATE,
        )
        assert inst.install_type == NixInstallType.DETERMINATE


class TestNixProfilePackage:
    def test_minimal(self) -> None:
        pkg = NixProfilePackage(name="ripgrep")
        assert pkg.name == "ripgrep"
        assert pkg.version is None
        assert pkg.store_path is None

    def test_with_store_path(self) -> None:
        pkg = NixProfilePackage(
            name="ripgrep",
            version="14.1.0",
            store_path=Path("/nix/store/abc123-ripgrep-14.1.0"),
        )
        assert pkg.version == "14.1.0"
        assert pkg.store_path == Path("/nix/store/abc123-ripgrep-14.1.0")


class TestNixProfile:
    def test_empty_profile(self) -> None:
        profile = NixProfile(name="default", path=Path("/nix/var/nix/profiles/default"))
        assert profile.name == "default"
        assert profile.packages == []

    def test_with_packages(self) -> None:
        profile = NixProfile(
            name="default",
            path=Path("/nix/var/nix/profiles/default"),
            packages=[
                NixProfilePackage(name="ripgrep", version="14.1.0"),
                NixProfilePackage(name="fd", version="9.0.0"),
            ],
        )
        assert len(profile.packages) == 2
        assert profile.packages[0].name == "ripgrep"


class TestNixDarwinState:
    def test_defaults(self) -> None:
        darwin = NixDarwinState()
        assert darwin.present is False
        assert darwin.generation is None
        assert darwin.config_path is None
        assert darwin.system_packages == []

    def test_with_values(self) -> None:
        darwin = NixDarwinState(
            present=True,
            generation=42,
            config_path=Path("/etc/nix-darwin"),
            system_packages=["vim", "git"],
        )
        assert darwin.present is True
        assert darwin.generation == 42
        assert len(darwin.system_packages) == 2


class TestHomeManagerState:
    def test_defaults(self) -> None:
        hm = HomeManagerState()
        assert hm.present is False
        assert hm.generation is None
        assert hm.config_path is None
        assert hm.packages == []

    def test_with_values(self) -> None:
        hm = HomeManagerState(
            present=True,
            generation=7,
            config_path=Path("/Users/test/.config/home-manager"),
            packages=["htop", "jq", "bat"],
        )
        assert hm.present is True
        assert len(hm.packages) == 3


class TestNixChannel:
    def test_construction(self) -> None:
        ch = NixChannel(name="nixpkgs", url="https://nixos.org/channels/nixpkgs-unstable")
        assert ch.name == "nixpkgs"
        assert "nixpkgs-unstable" in ch.url


class TestNixFlakeInput:
    def test_minimal(self) -> None:
        inp = NixFlakeInput(name="nixpkgs")
        assert inp.name == "nixpkgs"
        assert inp.url is None
        assert inp.locked_rev is None

    def test_with_locked_rev(self) -> None:
        inp = NixFlakeInput(
            name="nixpkgs",
            url="github:NixOS/nixpkgs/nixpkgs-unstable",
            locked_rev="abc123def456",
        )
        assert inp.locked_rev == "abc123def456"


class TestNixRegistryEntry:
    def test_construction(self) -> None:
        entry = NixRegistryEntry(from_name="nixpkgs", to_url="github:NixOS/nixpkgs")
        assert entry.from_name == "nixpkgs"
        assert entry.to_url == "github:NixOS/nixpkgs"


class TestNixConfig:
    def test_defaults(self) -> None:
        cfg = NixConfig()
        assert cfg.experimental_features == []
        assert cfg.substituters == []
        assert cfg.trusted_users == []
        assert cfg.max_jobs is None
        assert cfg.sandbox is None
        assert cfg.extra_config == {}

    def test_with_values(self) -> None:
        cfg = NixConfig(
            experimental_features=["nix-command", "flakes"],
            substituters=["https://cache.nixos.org"],
            trusted_users=["root", "testuser"],
            max_jobs=8,
            sandbox=True,
            extra_config={"warn-dirty": "false"},
        )
        assert len(cfg.experimental_features) == 2
        assert cfg.max_jobs == 8
        assert cfg.sandbox is True


class TestDevboxProject:
    def test_construction(self) -> None:
        proj = DevboxProject(path=Path("/home/user/myproject"), packages=["python3", "nodejs"])
        assert proj.path == Path("/home/user/myproject")
        assert len(proj.packages) == 2


class TestDevenvProject:
    def test_defaults(self) -> None:
        proj = DevenvProject(path=Path("/home/user/devenv-proj"))
        assert proj.has_lock is False

    def test_with_lock(self) -> None:
        proj = DevenvProject(path=Path("/home/user/devenv-proj"), has_lock=True)
        assert proj.has_lock is True


class TestNixDirenvConfig:
    def test_defaults(self) -> None:
        cfg = NixDirenvConfig(path=Path("/home/user/project/.envrc"))
        assert cfg.use_flake is False
        assert cfg.use_nix is False

    def test_use_flake(self) -> None:
        cfg = NixDirenvConfig(
            path=Path("/home/user/project/.envrc"),
            use_flake=True,
        )
        assert cfg.use_flake is True
        assert cfg.use_nix is False


class TestNixState:
    def test_defaults(self) -> None:
        state = NixState()
        assert state.installation.present is False
        assert state.profiles == []
        assert state.darwin.present is False
        assert state.home_manager.present is False
        assert state.channels == []
        assert state.flake_inputs == []
        assert state.registries == []
        assert state.config.experimental_features == []
        assert state.devbox_projects == []
        assert state.devenv_projects == []
        assert state.direnv_configs == []

    def test_roundtrip(self) -> None:
        state = NixState(
            installation=NixInstallation(
                present=True,
                version="2.18.1",
                install_type=NixInstallType.MULTI_USER,
                daemon_running=True,
            ),
            profiles=[
                NixProfile(
                    name="default",
                    path=Path("/nix/var/nix/profiles/default"),
                    packages=[NixProfilePackage(name="ripgrep", version="14.1.0")],
                ),
            ],
            darwin=NixDarwinState(present=True, generation=42, system_packages=["vim"]),
            home_manager=HomeManagerState(present=True, generation=7, packages=["htop"]),
            channels=[NixChannel(name="nixpkgs", url="https://nixos.org/channels/nixpkgs-unstable")],
            flake_inputs=[
                NixFlakeInput(name="nixpkgs", url="github:NixOS/nixpkgs", locked_rev="abc123"),
            ],
            registries=[NixRegistryEntry(from_name="nixpkgs", to_url="github:NixOS/nixpkgs")],
            config=NixConfig(
                experimental_features=["nix-command", "flakes"],
                max_jobs=8,
            ),
            devbox_projects=[DevboxProject(path=Path("/tmp/proj"), packages=["python3"])],
            devenv_projects=[DevenvProject(path=Path("/tmp/devenv"), has_lock=True)],
            direnv_configs=[NixDirenvConfig(path=Path("/tmp/.envrc"), use_flake=True)],
        )
        json_str = state.model_dump_json()
        restored = NixState.model_validate_json(json_str)
        assert restored.installation.present is True
        assert restored.installation.version == "2.18.1"
        assert restored.installation.install_type == NixInstallType.MULTI_USER
        assert len(restored.profiles) == 1
        assert restored.profiles[0].packages[0].name == "ripgrep"
        assert restored.darwin.present is True
        assert restored.darwin.generation == 42
        assert restored.home_manager.present is True
        assert len(restored.channels) == 1
        assert restored.flake_inputs[0].locked_rev == "abc123"
        assert restored.registries[0].from_name == "nixpkgs"
        assert restored.config.max_jobs == 8
        assert len(restored.devbox_projects) == 1
        assert restored.devenv_projects[0].has_lock is True
        assert restored.direnv_configs[0].use_flake is True

    def test_mutable_defaults_isolated(self) -> None:
        """Ensure Field(default_factory=...) prevents shared mutable state."""
        state1 = NixState()
        state2 = NixState()
        state1.profiles.append(NixProfile(name="test", path=Path("/nix/var/nix/profiles/test")))
        assert len(state2.profiles) == 0


class TestVersionManagerType:
    def test_enum_values(self) -> None:
        assert VersionManagerType.ASDF == "asdf"
        assert VersionManagerType.MISE == "mise"
        assert VersionManagerType.NVM == "nvm"
        assert VersionManagerType.PYENV == "pyenv"
        assert VersionManagerType.RBENV == "rbenv"
        assert VersionManagerType.JENV == "jenv"
        assert VersionManagerType.SDKMAN == "sdkman"


class TestManagedRuntime:
    def test_construction(self) -> None:
        rt = ManagedRuntime(
            manager=VersionManagerType.PYENV,
            language="python",
            version="3.12.1",
            path=Path("/Users/user/.pyenv/versions/3.12.1"),
            active=True,
        )
        assert rt.manager == VersionManagerType.PYENV
        assert rt.language == "python"
        assert rt.version == "3.12.1"
        assert rt.active is True

    def test_defaults(self) -> None:
        rt = ManagedRuntime(
            manager=VersionManagerType.NVM,
            language="node",
            version="20.11.1",
        )
        assert rt.path is None
        assert rt.active is False

    def test_roundtrip(self) -> None:
        rt = ManagedRuntime(
            manager=VersionManagerType.RBENV,
            language="ruby",
            version="3.3.0",
            active=True,
        )
        json_str = rt.model_dump_json()
        restored = ManagedRuntime.model_validate_json(json_str)
        assert restored.manager == VersionManagerType.RBENV
        assert restored.active is True


class TestVersionManagerInfo:
    def test_construction(self) -> None:
        info = VersionManagerInfo(
            manager_type=VersionManagerType.ASDF,
            version="0.14.0",
            config_path=Path("/Users/user/.tool-versions"),
            runtimes=[
                ManagedRuntime(
                    manager=VersionManagerType.ASDF,
                    language="python",
                    version="3.12.1",
                ),
            ],
        )
        assert info.manager_type == VersionManagerType.ASDF
        assert info.version == "0.14.0"
        assert len(info.runtimes) == 1

    def test_defaults(self) -> None:
        info = VersionManagerInfo(manager_type=VersionManagerType.MISE)
        assert info.version is None
        assert info.config_path is None
        assert info.runtimes == []


class TestVersionManagersResult:
    def test_defaults(self) -> None:
        result = VersionManagersResult()
        assert result.managers == []
        assert result.global_tool_versions is None

    def test_with_managers(self) -> None:
        result = VersionManagersResult(
            managers=[
                VersionManagerInfo(manager_type=VersionManagerType.PYENV),
                VersionManagerInfo(manager_type=VersionManagerType.NVM),
            ],
            global_tool_versions=Path("/Users/user/.tool-versions"),
        )
        assert len(result.managers) == 2
        assert result.global_tool_versions is not None

    def test_roundtrip(self) -> None:
        result = VersionManagersResult(
            managers=[
                VersionManagerInfo(
                    manager_type=VersionManagerType.ASDF,
                    runtimes=[
                        ManagedRuntime(
                            manager=VersionManagerType.ASDF,
                            language="nodejs",
                            version="20.0.0",
                        ),
                    ],
                ),
            ],
        )
        json_str = result.model_dump_json()
        restored = VersionManagersResult.model_validate_json(json_str)
        assert len(restored.managers) == 1
        assert len(restored.managers[0].runtimes) == 1


class TestMacPortsPackage:
    def test_construction(self) -> None:
        pkg = MacPortsPackage(
            name="curl",
            version="8.5.0_0",
            active=True,
            variants=["+ssl"],
        )
        assert pkg.name == "curl"
        assert pkg.version == "8.5.0_0"
        assert pkg.active is True
        assert pkg.variants == ["+ssl"]

    def test_defaults(self) -> None:
        pkg = MacPortsPackage(name="zlib")
        assert pkg.version is None
        assert pkg.active is True
        assert pkg.variants == []


class TestMacPortsState:
    def test_defaults(self) -> None:
        state = MacPortsState()
        assert state.present is False
        assert state.prefix == Path("/opt/local")
        assert state.packages == []


class TestCondaState:
    def test_defaults(self) -> None:
        state = CondaState()
        assert state.present is False
        assert state.environments == []

    def test_with_environments(self) -> None:
        state = CondaState(
            present=True,
            version="24.1.0",
            environments=[
                CondaEnvironment(
                    name="base",
                    path=Path("/Users/user/miniconda3"),
                    is_active=True,
                    packages=[CondaPackage(name="numpy", version="1.26.0", channel="defaults")],
                ),
            ],
        )
        assert len(state.environments) == 1
        assert state.environments[0].is_active is True


class TestPackageManagersResult:
    def test_defaults(self) -> None:
        result = PackageManagersResult()
        assert result.macports.present is False
        assert result.conda.present is False

    def test_roundtrip(self) -> None:
        result = PackageManagersResult(
            macports=MacPortsState(present=True, version="2.9.3"),
            conda=CondaState(present=True, version="24.1.0"),
        )
        json_str = result.model_dump_json()
        restored = PackageManagersResult.model_validate_json(json_str)
        assert restored.macports.present is True
        assert restored.conda.present is True


class TestContainerRuntimeType:
    def test_enum_values(self) -> None:
        assert ContainerRuntimeType.DOCKER == "docker"
        assert ContainerRuntimeType.PODMAN == "podman"
        assert ContainerRuntimeType.COLIMA == "colima"
        assert ContainerRuntimeType.ORBSTACK == "orbstack"
        assert ContainerRuntimeType.LIMA == "lima"


class TestContainerRuntimeInfo:
    def test_construction(self) -> None:
        info = ContainerRuntimeInfo(
            runtime_type=ContainerRuntimeType.DOCKER,
            version="24.0.7",
            running=True,
            config_path=Path("/Users/user/.docker/config.json"),
            socket_path=Path("/var/run/docker.sock"),
        )
        assert info.runtime_type == ContainerRuntimeType.DOCKER
        assert info.running is True

    def test_defaults(self) -> None:
        info = ContainerRuntimeInfo(runtime_type=ContainerRuntimeType.PODMAN)
        assert info.version is None
        assert info.running is False
        assert info.config_path is None
        assert info.socket_path is None


class TestContainersResult:
    def test_defaults(self) -> None:
        result = ContainersResult()
        assert result.runtimes == []

    def test_roundtrip(self) -> None:
        result = ContainersResult(
            runtimes=[
                ContainerRuntimeInfo(
                    runtime_type=ContainerRuntimeType.DOCKER,
                    version="24.0.7",
                    running=True,
                ),
            ],
        )
        json_str = result.model_dump_json()
        restored = ContainersResult.model_validate_json(json_str)
        assert len(restored.runtimes) == 1
        assert restored.runtimes[0].running is True
