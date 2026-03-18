"""Validator — nix-darwin config validation with fidelity scoring."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from mac2nix.models.system_state import SystemState
from mac2nix.vm._utils import VMError, async_run_command
from mac2nix.vm.manager import TartVMManager

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Models (co-located per architect decision)
# ---------------------------------------------------------------------------


class Mismatch(BaseModel):
    domain: str
    field: str
    source_value: Any
    target_value: Any


class DomainScore(BaseModel):
    domain: str
    score: float
    total_fields: int
    matching_fields: int
    mismatches: list[str]


class FidelityReport(BaseModel):
    overall_score: float
    domain_scores: dict[str, DomainScore]
    mismatches: list[Mismatch]


class ValidationResult(BaseModel):
    success: bool
    fidelity: FidelityReport | None
    build_output: str
    errors: list[str]


# ---------------------------------------------------------------------------
# Fidelity comparison (pure function, no I/O)
# ---------------------------------------------------------------------------

# SystemState fields that are metadata, not scanner domains — skip comparison.
_META_FIELDS = frozenset({"hostname", "scan_timestamp", "macos_version", "architecture"})

# Domain fields on SystemState that hold optional scanner results.
_DOMAIN_FIELDS: list[str] = [f for f in SystemState.model_fields if f not in _META_FIELDS]


def _compare_values(source: Any, target: Any) -> bool:
    """Compare two values order-independently where possible."""
    if isinstance(source, list) and isinstance(target, list):
        # Order-independent set comparison for flat lists of hashable items.
        try:
            return set(source) == set(target)
        except TypeError:
            # Unhashable elements — fall back to sorted repr comparison.
            return sorted(str(x) for x in source) == sorted(str(x) for x in target)
    return source == target


def _score_domain(domain: str, source_obj: BaseModel, target_obj: BaseModel | None) -> DomainScore:
    """Compute a fidelity score for one domain."""
    if target_obj is None:
        return DomainScore(
            domain=domain,
            score=0.0,
            total_fields=sum(1 for f in type(source_obj).model_fields if getattr(source_obj, f) is not None),
            matching_fields=0,
            mismatches=[f"{domain}: entire domain missing in target"],
        )

    total = 0
    matching = 0
    mismatches: list[str] = []

    for field_name in type(source_obj).model_fields:
        src_val = getattr(source_obj, field_name)
        tgt_val = getattr(target_obj, field_name, None)

        if src_val is None:
            # Source has no data for this field — skip (not a mismatch).
            continue

        total += 1

        if isinstance(src_val, BaseModel):
            # Recurse into nested models.
            sub = _score_domain(f"{domain}.{field_name}", src_val, tgt_val if isinstance(tgt_val, BaseModel) else None)
            matching += sub.matching_fields
            total = total - 1 + sub.total_fields  # replace 1 field with sub-field count
            mismatches.extend(sub.mismatches)
        elif _compare_values(src_val, tgt_val):
            matching += 1
        else:
            mismatches.append(f"{domain}.{field_name}")

    score = (matching / total) if total > 0 else 1.0
    return DomainScore(
        domain=domain,
        score=round(score, 4),
        total_fields=total,
        matching_fields=matching,
        mismatches=mismatches,
    )


def compute_fidelity(source: SystemState, target: SystemState) -> FidelityReport:
    """Compare *target* against *source* and return a fidelity report.

    For each non-None domain in *source*, fields are compared field-by-field.
    Lists are compared as sets (order-independent). Nested Pydantic models are
    compared recursively. A domain absent in *target* when present in *source*
    scores 0.0.

    Returns a :class:`FidelityReport` with per-domain scores and an overall
    weighted average.
    """
    domain_scores: dict[str, DomainScore] = {}
    all_mismatches: list[Mismatch] = []

    for field_name in _DOMAIN_FIELDS:
        src_domain = getattr(source, field_name)
        if src_domain is None:
            continue  # Source has no data for this domain — skip.

        tgt_domain = getattr(target, field_name, None)
        ds = _score_domain(field_name, src_domain, tgt_domain)
        domain_scores[field_name] = ds

        for mismatch_desc in ds.mismatches:
            # mismatch_desc is a full dot-path like "domain.field" or "domain.sub.field".
            # Store the full path — nested paths make getattr lookups fragile.
            all_mismatches.append(
                Mismatch(
                    domain=field_name,
                    field=mismatch_desc,
                    source_value=None,
                    target_value=None,
                )
            )

    # Overall score: weighted by total_fields per domain.
    total_weight = sum(ds.total_fields for ds in domain_scores.values())
    if total_weight > 0:
        overall = sum(ds.score * ds.total_fields for ds in domain_scores.values()) / total_weight
    else:
        overall = 1.0

    return FidelityReport(
        overall_score=round(overall, 4),
        domain_scores=domain_scores,
        mismatches=all_mismatches,
    )


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


class Validator:
    """Validates a generated nix-darwin config by deploying it into a Tart VM.

    Steps performed by :meth:`validate`:
    1. Copy the flake directory into the VM via SCP.
    2. Bootstrap Nix + nix-darwin in the VM.
    3. Run ``darwin-rebuild switch --flake .``.
    4. Install mac2nix in the VM, run a scan, SCP the result back.
    5. Compare the VM's :class:`SystemState` against the source using
       :func:`compute_fidelity`.

    :param vm: Active :class:`TartVMManager` with a running clone.
    """

    # Remote paths inside the VM.
    _REMOTE_FLAKE_DIR = "/tmp/mac2nix-flake"  # noqa: S108
    _REMOTE_SCAN_PATH = "/tmp/mac2nix-state.json"  # noqa: S108

    def __init__(self, vm: TartVMManager) -> None:
        self._vm = vm

    async def validate(self, flake_path: Path, source_state: SystemState) -> ValidationResult:
        """Run the full validation pipeline.

        Returns a :class:`ValidationResult` with fidelity scores if successful,
        or error details if any step fails.
        """
        errors: list[str] = []
        build_output = ""

        try:
            await self._copy_flake_to_vm(flake_path)
        except VMError as exc:
            errors.append(f"copy_flake failed: {exc}")
            return ValidationResult(success=False, fidelity=None, build_output="", errors=errors)

        try:
            await self._bootstrap_nix_darwin()
        except VMError as exc:
            errors.append(f"bootstrap_nix_darwin failed: {exc}")
            return ValidationResult(success=False, fidelity=None, build_output="", errors=errors)

        try:
            build_output = await self._rebuild_switch()
        except VMError as exc:
            errors.append(f"darwin-rebuild switch failed: {exc}")
            return ValidationResult(success=False, fidelity=None, build_output=build_output, errors=errors)

        try:
            vm_state = await self._scan_vm()
        except VMError as exc:
            errors.append(f"vm scan failed: {exc}")
            return ValidationResult(success=False, fidelity=None, build_output=build_output, errors=errors)

        report = compute_fidelity(source_state, vm_state)
        return ValidationResult(
            success=True,
            fidelity=report,
            build_output=build_output,
            errors=[],
        )

    async def _copy_flake_to_vm(self, flake_path: Path) -> None:
        """SCP the flake directory into the VM at :attr:`_REMOTE_FLAKE_DIR`.

        Uses sshpass + scp with argument lists (no shell=True).
        Raises :exc:`VMError` if scp fails or the VM has no IP.
        """
        ip = await self._vm.get_ip()
        if not ip:
            raise VMError("Cannot copy flake — VM has no IP address")

        # Ensure remote destination exists.
        ok, _out, err = await self._vm.exec_command(["mkdir", "-p", self._REMOTE_FLAKE_DIR])
        if not ok:
            raise VMError(f"mkdir {self._REMOTE_FLAKE_DIR!r} failed: {err.strip()}")

        # scp -r <local> user@ip:<remote>  — uses sshpass -e for password auth.
        # Password passed via SSHPASS env var to avoid exposure in ps aux.
        scp_cmd = [
            "sshpass",
            "-e",
            "scp",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-r",
            str(flake_path) + "/.",
            f"{self._vm.vm_user}@{ip}:{self._REMOTE_FLAKE_DIR}",
        ]

        returncode, _stdout, stderr = await async_run_command(
            scp_cmd, timeout=120, env={"SSHPASS": self._vm.vm_password}
        )
        if returncode != 0:
            raise VMError(f"scp flake to VM failed (exit {returncode}): {stderr.strip()}")

        logger.debug("Flake copied to VM at %s", self._REMOTE_FLAKE_DIR)

    async def _bootstrap_nix_darwin(self) -> None:
        """Install Nix and nix-darwin inside the VM.

        Raises :exc:`VMError` if any bootstrap step fails.
        """
        logger.debug("Bootstrapping Nix in VM")

        installer_path = "/tmp/nix-installer.sh"  # noqa: S108

        # Step 1: Download the Determinate Systems nix installer to a file.
        ok, _out, err = await self._vm.exec_command(
            [
                "curl",
                "--proto",
                "=https",
                "--tlsv1.2",
                "-sSf",
                "-L",
                "https://install.determinate.systems/nix",
                "-o",
                installer_path,
            ],
            timeout=60,
        )
        if not ok:
            raise VMError(f"Failed to download Nix installer: {err.strip()}")

        # Step 2: Make it executable.
        ok, _out, err = await self._vm.exec_command(["chmod", "+x", installer_path])
        if not ok:
            raise VMError(f"chmod +x nix-installer.sh failed: {err.strip()}")

        # Step 3: Run the installer.
        ok, _out, err = await self._vm.exec_command(
            [installer_path, "install", "--no-confirm"],
            timeout=300,
        )
        if not ok:
            raise VMError(f"Nix installation failed: {err.strip()}")

        # Source nix profile so subsequent commands can find nix binaries.
        # Note: nix-darwin is applied via _rebuild_switch(), not here.
        # The bootstrap only installs Nix itself.
        logger.debug("Nix installed successfully")

    async def _rebuild_switch(self) -> str:
        """Bootstrap nix-darwin and apply the flake configuration.

        On a fresh VM (no nix-darwin yet), uses ``nix run nix-darwin -- switch``
        to install nix-darwin and apply the flake in a single step. On subsequent
        calls, ``darwin-rebuild switch`` would suffice, but the ``nix run``
        approach works in both cases.

        Returns the combined stdout+stderr output.
        Raises :exc:`VMError` if the rebuild fails.
        """
        logger.debug("Running nix-darwin switch")
        cmd = (
            f"cd {self._REMOTE_FLAKE_DIR}"
            " && . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh"
            " && nix run nix-darwin -- switch --flake ."
        )
        ok, out, err = await self._vm.exec_command(["bash", "-c", cmd], timeout=600)
        combined = (out + "\n" + err).strip()
        if not ok:
            raise VMError(f"darwin-rebuild switch failed: {err.strip()}")

        logger.debug("darwin-rebuild switch succeeded")
        return combined

    async def _scan_vm(self) -> SystemState:
        """Run mac2nix inside the VM via nix run, SCP the result back, parse it.

        Raises :exc:`VMError` if any step fails or the result cannot be parsed.
        """
        logger.debug("Running mac2nix scan in VM via nix run")

        # Run mac2nix directly from GitHub using nix run — no pip needed.
        nix_run_cmd = (
            ". /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh"
            f" && nix run github:gordon-code/mac2nix -- scan -o {self._REMOTE_SCAN_PATH}"
        )
        ok, _out, err = await self._vm.exec_command(["bash", "-c", nix_run_cmd], timeout=300)
        if not ok:
            raise VMError(f"mac2nix scan failed: {err.strip()}")

        # SCP the result back to a local temp file.
        ip = await self._vm.get_ip()
        if not ip:
            raise VMError("Cannot SCP scan result — VM has no IP")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            local_path = Path(tmp.name)

        try:
            scp_cmd = [
                "sshpass",
                "-e",
                "scp",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                f"{self._vm.vm_user}@{ip}:{self._REMOTE_SCAN_PATH}",
                str(local_path),
            ]

            returncode, _stdout, stderr = await async_run_command(
                scp_cmd, timeout=60, env={"SSHPASS": self._vm.vm_password}
            )
            if returncode != 0:
                raise VMError(f"scp scan result from VM failed (exit {returncode}): {stderr.strip()}")

            try:
                return SystemState.from_json(local_path)
            except Exception as exc:
                raise VMError(f"Failed to parse VM scan result: {exc}") from exc
        finally:
            local_path.unlink(missing_ok=True)
