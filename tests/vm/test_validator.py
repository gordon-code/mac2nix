"""Tests for vm/validator.py — fidelity scoring, Validator workflow, and Pydantic models."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel

from mac2nix.models.services import ShellConfig
from mac2nix.models.system import NetworkConfig, SecurityState
from mac2nix.models.system_state import SystemState
from mac2nix.vm._utils import VMError
from mac2nix.vm.validator import (
    DomainScore,
    FidelityReport,
    Mismatch,
    ValidationResult,
    Validator,
    _score_domain,
    compute_fidelity,
)

# ---------------------------------------------------------------------------
# Helpers — minimal SystemState construction
# ---------------------------------------------------------------------------


def _base_state(**overrides) -> SystemState:
    """Return a minimal all-None-domain SystemState."""
    defaults = {"hostname": "testhost", "macos_version": "15.0", "architecture": "arm64"}
    defaults.update(overrides)
    return SystemState(**defaults)


def _state_with_shell(shell_type: str = "fish", path_components: list[str] | None = None) -> SystemState:
    return _base_state(
        shell=ShellConfig(
            shell_type=shell_type,
            path_components=path_components or ["/usr/bin", "/opt/homebrew/bin"],
        )
    )


def _state_with_network(dns_servers: list[str] | None = None, wifi_networks: list[str] | None = None) -> SystemState:
    return _base_state(
        network=NetworkConfig(
            dns_servers=dns_servers or ["1.1.1.1", "8.8.8.8"],
            wifi_networks=wifi_networks or ["HomeNetwork"],
        )
    )


def _state_with_security(filevault: bool | None = True, sip: bool | None = True) -> SystemState:
    return _base_state(
        security=SecurityState(
            filevault_enabled=filevault,
            sip_enabled=sip,
        )
    )


# ---------------------------------------------------------------------------
# Pydantic model construction
# ---------------------------------------------------------------------------


class TestModels:
    def test_mismatch_model(self) -> None:
        m = Mismatch(domain="shell", field="shell.shell_type")
        assert m.domain == "shell"
        assert m.field == "shell.shell_type"

    def test_domain_score_model(self) -> None:
        ds = DomainScore(domain="shell", score=0.75, total_fields=4, matching_fields=3, mismatches=["shell.env_vars"])
        assert ds.score == 0.75
        assert ds.total_fields == 4
        assert ds.matching_fields == 3

    def test_fidelity_report_model(self) -> None:
        ds = DomainScore(domain="shell", score=1.0, total_fields=2, matching_fields=2, mismatches=[])
        report = FidelityReport(overall_score=1.0, domain_scores={"shell": ds}, mismatches=[])
        assert report.overall_score == 1.0
        assert "shell" in report.domain_scores

    def test_validation_result_success(self) -> None:
        ds = DomainScore(domain="shell", score=1.0, total_fields=1, matching_fields=1, mismatches=[])
        report = FidelityReport(overall_score=1.0, domain_scores={"shell": ds}, mismatches=[])
        vr = ValidationResult(success=True, fidelity=report, build_output="switched", errors=[])
        assert vr.success is True
        assert vr.fidelity is not None
        assert vr.errors == []

    def test_validation_result_failure(self) -> None:
        vr = ValidationResult(success=False, fidelity=None, build_output="", errors=["copy_flake failed: no IP"])
        assert vr.success is False
        assert vr.fidelity is None
        assert len(vr.errors) == 1

    def test_models_are_pydantic_serializable(self) -> None:
        ds = DomainScore(domain="shell", score=0.5, total_fields=2, matching_fields=1, mismatches=["shell.x"])
        report = FidelityReport(overall_score=0.5, domain_scores={"shell": ds}, mismatches=[])
        vr = ValidationResult(success=True, fidelity=report, build_output="ok", errors=[])
        # Should not raise
        json_str = vr.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["success"] is True


# ---------------------------------------------------------------------------
# _score_domain()
# ---------------------------------------------------------------------------


class TestScoreDomain:
    def test_identical_objects_score_one(self) -> None:
        shell = ShellConfig(shell_type="fish", path_components=["/usr/bin"])
        ds = _score_domain("shell", shell, shell)
        assert ds.score == 1.0
        assert ds.mismatches == []

    def test_target_none_scores_zero(self) -> None:
        shell = ShellConfig(shell_type="fish")
        ds = _score_domain("shell", shell, None)
        assert ds.score == 0.0
        assert ds.matching_fields == 0
        assert any("missing in target" in m for m in ds.mismatches)

    def test_target_none_reports_domain_name(self) -> None:
        shell = ShellConfig(shell_type="zsh")
        ds = _score_domain("shell", shell, None)
        assert ds.domain == "shell"

    def test_single_field_mismatch(self) -> None:
        src = ShellConfig(shell_type="fish")
        tgt = ShellConfig(shell_type="zsh")
        ds = _score_domain("shell", src, tgt)
        # shell_type differs → one mismatch
        assert ds.matching_fields < ds.total_fields
        assert any("shell_type" in m for m in ds.mismatches)

    def test_single_field_match(self) -> None:
        src = ShellConfig(shell_type="fish")
        tgt = ShellConfig(shell_type="fish")
        ds = _score_domain("shell", src, tgt)
        assert ds.score == 1.0

    def test_source_none_field_skipped(self) -> None:
        """Fields that are None in source should not count toward total."""
        # SecurityState has many optional bool fields; set only filevault_enabled.
        src = SecurityState(filevault_enabled=True)
        tgt = SecurityState(filevault_enabled=True)
        ds = _score_domain("security", src, tgt)
        # filevault_enabled + 2 default list fields (firewall_app_rules, custom_certificates) = 3
        assert ds.total_fields == 3
        assert ds.matching_fields == 3
        assert ds.score == 1.0

    def test_list_comparison_is_order_independent(self) -> None:
        src = NetworkConfig(dns_servers=["8.8.8.8", "1.1.1.1"])
        tgt = NetworkConfig(dns_servers=["1.1.1.1", "8.8.8.8"])
        ds = _score_domain("network", src, tgt)
        # dns_servers differ only in order — should match
        assert "network.dns_servers" not in ds.mismatches

    def test_list_order_independent_mismatch(self) -> None:
        src = NetworkConfig(dns_servers=["8.8.8.8", "1.1.1.1"])
        tgt = NetworkConfig(dns_servers=["8.8.8.8", "9.9.9.9"])
        ds = _score_domain("network", src, tgt)
        assert any("dns_servers" in m for m in ds.mismatches)

    def test_empty_source_no_non_none_fields_scores_one(self) -> None:
        """When source has only default list fields, score is 1.0."""
        src = SecurityState()  # bool fields all None, list fields default to []
        tgt = SecurityState()
        ds = _score_domain("security", src, tgt)
        assert ds.score == 1.0
        # 2 list fields (firewall_app_rules, custom_certificates) have default [] (non-None)
        assert ds.total_fields == 2

    def test_nested_model_recursion(self) -> None:
        """Nested BaseModel fields are scored recursively, expanding total_fields."""

        class _Inner(BaseModel):
            x: str | None = None
            y: str | None = None

        class _Outer(BaseModel):
            inner: _Inner | None = None
            top: str | None = None

        src = _Outer(inner=_Inner(x="a", y="b"), top="c")
        tgt = _Outer(inner=_Inner(x="a", y="z"), top="c")
        ds = _score_domain("outer", src, tgt)
        # top matches (1), inner.x matches (1), inner.y mismatches → 2/3
        assert ds.total_fields == 3
        assert ds.matching_fields == 2
        assert any("y" in m for m in ds.mismatches)

    def test_nested_model_all_none_source(self) -> None:
        """Nested model with all-None source fields contributes zero to total."""

        class _Inner(BaseModel):
            x: str | None = None

        class _Outer(BaseModel):
            inner: _Inner | None = None
            top: str | None = None

        src = _Outer(inner=_Inner(), top="c")  # inner.x is None
        tgt = _Outer(inner=_Inner(x="a"), top="c")
        ds = _score_domain("outer", src, tgt)
        # Only top is non-None in source; inner.x is None → skipped
        assert ds.total_fields == 1
        assert ds.matching_fields == 1
        assert ds.score == 1.0


# ---------------------------------------------------------------------------
# compute_fidelity()
# ---------------------------------------------------------------------------


class TestComputeFidelity:
    def test_identical_states_score_one(self) -> None:
        state = _state_with_shell("fish")
        report = compute_fidelity(state, state)
        assert report.overall_score == 1.0
        assert report.mismatches == []

    def test_empty_states_score_one(self) -> None:
        """Both states with all-None domains → no domains compared → overall 1.0."""
        src = _base_state()
        tgt = _base_state()
        report = compute_fidelity(src, tgt)
        assert report.overall_score == 1.0
        assert report.domain_scores == {}

    def test_source_domain_none_skipped(self) -> None:
        """Domains that are None in source are not scored."""
        src = _base_state()  # all domains None
        tgt = _state_with_shell("fish")
        report = compute_fidelity(src, tgt)
        # No source domains → no domain_scores
        assert "shell" not in report.domain_scores

    def test_target_domain_none_scores_zero(self) -> None:
        """When source has a domain but target does not, that domain scores 0.0."""
        src = _state_with_shell("fish")
        tgt = _base_state()  # shell is None in target
        report = compute_fidelity(src, tgt)
        assert "shell" in report.domain_scores
        assert report.domain_scores["shell"].score == 0.0

    def test_partially_matching_state(self) -> None:
        """Partial match: one domain matches, one doesn't."""
        src = _base_state(
            shell=ShellConfig(shell_type="fish"),
            network=NetworkConfig(dns_servers=["1.1.1.1"]),
        )
        tgt = _base_state(
            shell=ShellConfig(shell_type="fish"),  # matches
            network=NetworkConfig(dns_servers=["9.9.9.9"]),  # differs
        )
        report = compute_fidelity(src, tgt)
        assert report.domain_scores["shell"].score == 1.0
        assert report.domain_scores["network"].score < 1.0

    def test_overall_score_is_weighted_average(self) -> None:
        """Overall score is weighted by total_fields per domain, not simple mean."""
        # Two domains, one with more fields matching
        src = _base_state(
            shell=ShellConfig(shell_type="fish"),
            security=SecurityState(filevault_enabled=True),
        )
        tgt = _base_state(
            shell=ShellConfig(shell_type="fish"),  # shell matches (1.0)
            security=SecurityState(filevault_enabled=False),  # security mismatches (0.0)
        )
        report = compute_fidelity(src, tgt)
        assert 0.0 < report.overall_score < 1.0

    def test_mismatches_populated_for_differing_domains(self) -> None:
        src = _state_with_shell("fish")
        tgt = _state_with_shell("zsh")
        report = compute_fidelity(src, tgt)
        assert len(report.mismatches) > 0
        mismatch_domains = {m.domain for m in report.mismatches}
        assert "shell" in mismatch_domains

    def test_mismatches_empty_for_identical_states(self) -> None:
        state = _state_with_shell("fish")
        report = compute_fidelity(state, state)
        assert report.mismatches == []

    def test_meta_fields_not_compared(self) -> None:
        """hostname, scan_timestamp, macos_version, architecture are not domain fields."""
        src = _base_state(hostname="machine-a", macos_version="15.0")
        tgt = _base_state(hostname="machine-b", macos_version="14.0")
        report = compute_fidelity(src, tgt)
        # No domain scores since all scanner domains are None
        assert report.domain_scores == {}

    def test_list_order_independent_in_compute_fidelity(self) -> None:
        src = _state_with_network(dns_servers=["8.8.8.8", "1.1.1.1"])
        tgt = _state_with_network(dns_servers=["1.1.1.1", "8.8.8.8"])
        report = compute_fidelity(src, tgt)
        # dns_servers same content different order — should not mismatch
        assert report.domain_scores["network"].score == 1.0

    def test_fidelity_report_has_correct_structure(self) -> None:
        state = _state_with_shell("fish")
        report = compute_fidelity(state, state)
        assert isinstance(report, FidelityReport)
        assert isinstance(report.overall_score, float)
        assert isinstance(report.domain_scores, dict)
        assert isinstance(report.mismatches, list)

    def test_domain_score_matching_fields_le_total(self) -> None:
        src = _state_with_shell("fish")
        tgt = _state_with_shell("zsh")
        report = compute_fidelity(src, tgt)
        for ds in report.domain_scores.values():
            assert ds.matching_fields <= ds.total_fields

    def test_overall_score_clamped_between_zero_and_one(self) -> None:
        src = _state_with_shell("fish")
        tgt = _base_state()
        report = compute_fidelity(src, tgt)
        assert 0.0 <= report.overall_score <= 1.0

    def test_multiple_domains_scored(self) -> None:
        src = _base_state(
            shell=ShellConfig(shell_type="fish"),
            network=NetworkConfig(dns_servers=["1.1.1.1"]),
            security=SecurityState(filevault_enabled=True),
        )
        tgt = _base_state(
            shell=ShellConfig(shell_type="fish"),
            network=NetworkConfig(dns_servers=["1.1.1.1"]),
            security=SecurityState(filevault_enabled=True),
        )
        report = compute_fidelity(src, tgt)
        assert len(report.domain_scores) == 3
        assert report.overall_score == 1.0


# ---------------------------------------------------------------------------
# Validator._copy_flake_to_vm()  (tested via validate() with mocking)
# ---------------------------------------------------------------------------


def _make_vm(
    get_ip_result: str | None = "192.168.64.5",
    exec_result: tuple[bool, str, str] = (True, "", ""),
) -> MagicMock:
    vm = MagicMock()
    vm.get_ip = AsyncMock(return_value=get_ip_result)
    vm.exec_command = AsyncMock(return_value=exec_result)
    vm.vm_user = "admin"
    vm.vm_password = "admin"
    return vm


def _minimal_source_state() -> SystemState:
    return _base_state(shell=ShellConfig(shell_type="fish"))


def _make_json_state(shell_type: str = "fish") -> str:
    state = _base_state(shell=ShellConfig(shell_type=shell_type))
    return state.model_dump_json()


class TestValidatorCopyFlake:
    def test_no_ip_raises_vm_error(self) -> None:
        vm = _make_vm(get_ip_result=None)

        async def _run() -> None:
            v = Validator(vm)
            await v._copy_flake_to_vm(Path("/tmp/flake"))

        with pytest.raises(VMError, match="no IP"):
            asyncio.run(_run())

    def test_mkdir_failure_raises_vm_error(self) -> None:
        vm = _make_vm(exec_result=(False, "", "permission denied"))

        async def _run() -> None:
            v = Validator(vm)
            await v._copy_flake_to_vm(Path("/tmp/flake"))

        with pytest.raises(VMError, match="mkdir"):
            asyncio.run(_run())

    def test_scp_failure_raises_vm_error(self) -> None:
        # First exec_command (mkdir) succeeds; scp (async_run_command) fails.
        vm = _make_vm(exec_result=(True, "", ""))

        async def _run() -> None:
            v = Validator(vm)
            with patch(
                "mac2nix.vm.validator.async_run_command",
                new=AsyncMock(return_value=(1, "", "permission denied")),
            ):
                await v._copy_flake_to_vm(Path("/tmp/flake"))

        with pytest.raises(VMError, match="scp flake"):
            asyncio.run(_run())

    def test_scp_success_does_not_raise(self) -> None:
        vm = _make_vm(exec_result=(True, "", ""))

        async def _run() -> None:
            v = Validator(vm)
            with patch(
                "mac2nix.vm.validator.async_run_command",
                new=AsyncMock(return_value=(0, "", "")),
            ):
                await v._copy_flake_to_vm(Path("/tmp/flake"))

        asyncio.run(_run())  # Should not raise

    def test_scp_cmd_contains_sshpass(self) -> None:
        vm = _make_vm(exec_result=(True, "", ""))
        captured: list[list[str]] = []

        async def recording_run(cmd: list[str], **_kw) -> tuple[int, str, str]:
            captured.append(cmd)
            return (0, "", "")

        async def _run() -> None:
            v = Validator(vm)
            with patch("mac2nix.vm.validator.async_run_command", side_effect=recording_run):
                await v._copy_flake_to_vm(Path("/tmp/flake"))

        asyncio.run(_run())
        assert captured, "async_run_command not called"
        cmd = captured[0]
        assert cmd[0] == "sshpass"
        assert "scp" in cmd

    def test_scp_cmd_no_shell_true(self) -> None:
        """SCP must use sshpass -e with SSHPASS env var (not -p password in argv)."""
        vm = _make_vm(exec_result=(True, "", ""))
        captured: list[list[str]] = []
        captured_env: list[dict[str, str] | None] = []

        async def recording_run(cmd: list[str], **kw: object) -> tuple[int, str, str]:
            captured.append(cmd)
            captured_env.append(kw.get("env"))  # type: ignore[arg-type]
            return (0, "", "")

        async def _run() -> None:
            v = Validator(vm)
            with patch("mac2nix.vm.validator.async_run_command", side_effect=recording_run):
                await v._copy_flake_to_vm(Path("/tmp/flake"))

        asyncio.run(_run())
        cmd = captured[0]
        # sshpass -e reads password from SSHPASS env var — not in argv
        assert cmd[0] == "sshpass"
        assert cmd[1] == "-e"
        assert "admin" not in cmd  # password must not appear in argv
        assert captured_env[0] == {"SSHPASS": "admin"}


# ---------------------------------------------------------------------------
# Validator.validate() — full pipeline
# ---------------------------------------------------------------------------


class TestValidatorValidate:
    def _success_vm(self, _vm_json: str) -> MagicMock:
        """VM mock where all steps succeed and scan returns _vm_json."""
        vm = _make_vm()
        # exec_command always succeeds
        vm.exec_command = AsyncMock(return_value=(True, "admin", ""))

        # async_run_command: first call = scp flake (success), second = scp result back (success)
        # We patch async_run_command and from_json separately.
        return vm

    def test_success_returns_validation_result(self) -> None:
        vm = _make_vm(exec_result=(True, "admin", ""))
        source = _minimal_source_state()
        vm_state = _base_state(shell=ShellConfig(shell_type="fish"))

        async def _run() -> ValidationResult:
            v = Validator(vm)
            with (
                patch("mac2nix.vm.validator.async_run_command", new=AsyncMock(return_value=(0, "", ""))),
                patch.object(SystemState, "from_json", return_value=vm_state),
            ):
                return await v.validate(Path("/tmp/flake"), source)

        result = asyncio.run(_run())
        assert isinstance(result, ValidationResult)
        assert result.success is True
        assert result.fidelity is not None
        assert result.errors == []

    def test_copy_flake_failure_returns_early(self) -> None:
        vm = _make_vm(get_ip_result=None)  # No IP → copy_flake fails
        source = _minimal_source_state()

        async def _run() -> ValidationResult:
            v = Validator(vm)
            return await v.validate(Path("/tmp/flake"), source)

        result = asyncio.run(_run())
        assert result.success is False
        assert any("copy_flake" in e for e in result.errors)
        assert result.fidelity is None

    def test_bootstrap_failure_returns_early(self) -> None:
        # mkdir succeeds, then first exec_command call in bootstrap fails
        call_count = 0

        async def exec_side_effect(cmd, **_kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (True, "", "")  # mkdir in copy_flake
            return (False, "", "curl: not found")  # download in bootstrap

        vm = _make_vm()
        vm.exec_command = AsyncMock(side_effect=exec_side_effect)
        source = _minimal_source_state()

        async def _run() -> ValidationResult:
            v = Validator(vm)
            with patch("mac2nix.vm.validator.async_run_command", new=AsyncMock(return_value=(0, "", ""))):
                return await v.validate(Path("/tmp/flake"), source)

        result = asyncio.run(_run())
        assert result.success is False
        assert any("bootstrap" in e for e in result.errors)

    def test_rebuild_failure_returns_early(self) -> None:
        # All bootstrap steps succeed, darwin-rebuild switch fails
        call_count = 0

        async def exec_side_effect(cmd, **_kw):
            nonlocal call_count
            call_count += 1
            # mkdir(1) + curl(2) + chmod(3) + installer(4) + nix-darwin bootstrap(5) succeed
            # darwin-rebuild switch (6th call) fails
            if call_count <= 5:
                return (True, "admin", "")
            return (False, "", "nix-darwin build error")

        vm = _make_vm()
        vm.exec_command = AsyncMock(side_effect=exec_side_effect)
        source = _minimal_source_state()

        async def _run() -> ValidationResult:
            v = Validator(vm)
            with patch("mac2nix.vm.validator.async_run_command", new=AsyncMock(return_value=(0, "", ""))):
                return await v.validate(Path("/tmp/flake"), source)

        result = asyncio.run(_run())
        assert result.success is False
        assert any("nix-darwin" in e or "darwin-rebuild" in e for e in result.errors)

    def test_scan_failure_returns_early(self) -> None:
        # All VM exec_commands succeed, but mac2nix scan fails
        call_count = 0

        async def exec_side_effect(cmd, **_kw):
            nonlocal call_count
            call_count += 1
            # mkdir + curl + chmod + installer + nix-darwin + darwin-rebuild all succeed
            if call_count <= 6:
                return (True, "admin", "")
            # mac2nix scan fails
            return (False, "", "scan failed")

        vm = _make_vm()
        vm.exec_command = AsyncMock(side_effect=exec_side_effect)
        source = _minimal_source_state()

        async def _run() -> ValidationResult:
            v = Validator(vm)
            with patch("mac2nix.vm.validator.async_run_command", new=AsyncMock(return_value=(0, "", ""))):
                return await v.validate(Path("/tmp/flake"), source)

        result = asyncio.run(_run())
        assert result.success is False
        assert any("scan" in e for e in result.errors)

    def test_scan_parse_failure_returns_error(self) -> None:
        """If SCP back succeeds but JSON parse fails, validate returns failure."""
        vm = _make_vm(exec_result=(True, "admin", ""))
        source = _minimal_source_state()

        async def _run() -> ValidationResult:
            v = Validator(vm)
            with (
                patch("mac2nix.vm.validator.async_run_command", new=AsyncMock(return_value=(0, "", ""))),
                patch.object(SystemState, "from_json", side_effect=ValueError("bad json")),
            ):
                return await v.validate(Path("/tmp/flake"), source)

        result = asyncio.run(_run())
        assert result.success is False
        assert any("scan" in e for e in result.errors)

    def test_success_build_output_captured(self) -> None:
        vm = _make_vm()
        vm.exec_command = AsyncMock(return_value=(True, "build output text", ""))
        source = _minimal_source_state()
        vm_state = _base_state(shell=ShellConfig(shell_type="fish"))

        async def _run() -> ValidationResult:
            v = Validator(vm)
            with (
                patch("mac2nix.vm.validator.async_run_command", new=AsyncMock(return_value=(0, "", ""))),
                patch.object(SystemState, "from_json", return_value=vm_state),
            ):
                return await v.validate(Path("/tmp/flake"), source)

        result = asyncio.run(_run())
        assert result.success is True
        # build_output is the combined stdout+stderr from darwin-rebuild
        assert isinstance(result.build_output, str)

    def test_success_fidelity_report_populated(self) -> None:
        vm = _make_vm(exec_result=(True, "admin", ""))
        source = _base_state(shell=ShellConfig(shell_type="fish"))
        vm_state = _base_state(shell=ShellConfig(shell_type="fish"))

        async def _run() -> ValidationResult:
            v = Validator(vm)
            with (
                patch("mac2nix.vm.validator.async_run_command", new=AsyncMock(return_value=(0, "", ""))),
                patch.object(SystemState, "from_json", return_value=vm_state),
            ):
                return await v.validate(Path("/tmp/flake"), source)

        result = asyncio.run(_run())
        assert result.fidelity is not None
        assert isinstance(result.fidelity, FidelityReport)
        assert result.fidelity.overall_score == 1.0

    def test_fidelity_reflects_vm_state_difference(self) -> None:
        """Fidelity < 1.0 when VM state differs from source."""
        vm = _make_vm(exec_result=(True, "admin", ""))
        source = _base_state(shell=ShellConfig(shell_type="fish"))
        vm_state = _base_state(shell=ShellConfig(shell_type="zsh"))  # different

        async def _run() -> ValidationResult:
            v = Validator(vm)
            with (
                patch("mac2nix.vm.validator.async_run_command", new=AsyncMock(return_value=(0, "", ""))),
                patch.object(SystemState, "from_json", return_value=vm_state),
            ):
                return await v.validate(Path("/tmp/flake"), source)

        result = asyncio.run(_run())
        assert result.success is True
        assert result.fidelity is not None
        assert result.fidelity.overall_score < 1.0

    def test_scp_result_back_no_ip_returns_scan_error(self) -> None:
        """If VM has no IP when SCPing result back, scan fails gracefully."""
        get_ip_calls = 0
        vm = _make_vm()

        async def get_ip_side_effect():
            nonlocal get_ip_calls
            get_ip_calls += 1
            # First call (in copy_flake) succeeds; subsequent calls fail
            return "192.168.64.5" if get_ip_calls <= 2 else None

        vm.get_ip = AsyncMock(side_effect=get_ip_side_effect)
        vm.exec_command = AsyncMock(return_value=(True, "admin", ""))
        source = _minimal_source_state()

        async def _run() -> ValidationResult:
            v = Validator(vm)
            with patch("mac2nix.vm.validator.async_run_command", new=AsyncMock(return_value=(0, "", ""))):
                return await v.validate(Path("/tmp/flake"), source)

        result = asyncio.run(_run())
        assert result.success is False
        assert any("scan" in e for e in result.errors)
