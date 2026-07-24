"""Async scan orchestrator — dispatches all scanners concurrently."""

from __future__ import annotations

import asyncio
import json
import logging
import platform
import shutil
import socket
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from mac2nix.models.system_state import SystemState
from mac2nix.scan_report import ScannerOutcome, ScannerStatus, _ScannerLogCapture, attribute_to_scanner
from mac2nix.scanners import get_all_scanners
from mac2nix.scanners._utils import read_launchd_plists, run_command
from mac2nix.scanners.audio import AudioScanner
from mac2nix.scanners.cron import CronScanner
from mac2nix.scanners.display import DisplayScanner
from mac2nix.scanners.launch_agents import LaunchAgentsScanner
from mac2nix.scanners.system_scanner import SystemScanner

logger = logging.getLogger(__name__)

# Scanners that share pre-fetched data — excluded from generic dispatch.
_PREFETCH_SCANNERS = frozenset({"display", "audio", "system", "launch_agents", "cron"})


def _get_system_metadata() -> tuple[str, str, str]:
    """Return (hostname, macos_version, architecture)."""
    hostname = socket.gethostname()
    architecture = platform.machine()  # arm64 or x86_64

    # Try sw_vers for macOS version string
    result = run_command(["sw_vers", "-productVersion"])
    if result is not None and result.returncode == 0:
        macos_version = result.stdout.strip()
    else:
        macos_version = platform.mac_ver()[0] or "unknown"

    return hostname, macos_version, architecture


def _fetch_system_profiler_batch() -> dict[str, Any]:
    """Run a single batched system_profiler call for display, audio, and hardware data.

    Returns the parsed JSON dict with ``SPDisplaysDataType``,
    ``SPAudioDataType``, and ``SPHardwareDataType`` as top-level keys.
    Returns an empty dict on failure.
    """
    if shutil.which("system_profiler") is None:
        logger.warning("system_profiler not found — display/audio/hardware data unavailable")
        return {}

    result = run_command(
        ["system_profiler", "SPDisplaysDataType", "SPAudioDataType", "SPHardwareDataType", "-json"],
        timeout=20,
    )
    if result is None or result.returncode != 0:
        logger.warning("Batched system_profiler call failed")
        return {}

    try:
        return json.loads(result.stdout)  # type: ignore[no-any-return]
    except (json.JSONDecodeError, ValueError):
        logger.warning("Failed to parse batched system_profiler output")
        return {}


async def _run_scanner_async(
    scanner_name: str,
    scanner_cls: type,
    kwargs: dict[str, Any],
    progress_callback: Callable[[ScannerOutcome], None] | None,
    log_handler: _ScannerLogCapture | None,
) -> tuple[str, BaseModel | None]:
    """Dispatch a single scanner in a thread and return (name, result)."""
    start = time.monotonic()
    # Pre-initialized in case a BaseException (e.g. asyncio.CancelledError) skips
    # the `except Exception` clause below, leaving the finally block's read safe.
    status = ScannerStatus.ERROR
    warnings: tuple[str, ...] = ()
    error: str | None = None
    try:
        # Covers the whole lifecycle (construction, is_available, scan, and the
        # exception handler below) so any WARNING+ log emitted anywhere in it is
        # attributed to this scanner, not left `unattributed` once the block exits.
        with attribute_to_scanner(scanner_name):
            try:
                scanner = scanner_cls(**kwargs)
                if not scanner.is_available():
                    logger.info("Scanner '%s' not available — skipping", scanner_name)
                    status = ScannerStatus.SKIPPED
                    return scanner_name, None

                result: BaseModel = await asyncio.to_thread(scanner.scan)
                logger.debug("Scanner '%s' completed", scanner_name)

                records = log_handler.pop_records(scanner_name) if log_handler is not None else []
                if records:
                    status = ScannerStatus.WARNING
                    warnings = tuple(records)
                else:
                    status = ScannerStatus.SUCCESS
                return scanner_name, result
            except Exception as exc:
                logger.exception("Scanner '%s' raised an exception", scanner_name)
                status = ScannerStatus.ERROR
                error = f"{type(exc).__name__}: {exc}"
                if log_handler is not None:
                    warnings = tuple(log_handler.pop_records(scanner_name))
                return scanner_name, None
    finally:
        elapsed = time.monotonic() - start
        outcome = ScannerOutcome(
            name=scanner_name,
            status=status,
            elapsed=elapsed,
            warnings=warnings,
            error=error,
        )
        # Safe: this runs on the event loop thread (after the await), not the
        # worker thread, so the callback sees serialised access.
        if progress_callback is not None:
            try:
                progress_callback(outcome)
            except Exception:
                logger.debug("Progress callback failed for '%s'", scanner_name)


async def run_scan(
    scanners: list[str] | None = None,
    progress_callback: Callable[[ScannerOutcome], None] | None = None,
    log_handler: _ScannerLogCapture | None = None,
) -> SystemState:
    """Run all (or selected) scanners concurrently and return a SystemState.

    Args:
        scanners: List of scanner names to run. ``None`` runs all registered
            scanners. Unknown names are silently ignored.
        progress_callback: Optional callable invoked with a ``ScannerOutcome``
            after each scanner completes, is skipped, or errors. Suitable for
            updating a progress bar. Called from the asyncio event loop thread.
        log_handler: Optional ``_ScannerLogCapture`` used to attribute each
            scanner's WARNING+ log records to its ``ScannerOutcome``. This
            function does not create or attach the handler itself — the caller
            (``cli.py``) owns the ``capture_scanner_logs()`` context and passes
            the handler in so it can also inspect ``.unattributed`` (warnings
            logged during the pre-fetch phase, before any scanner started) once
            this function returns. ``None`` disables warning attribution;
            outcomes will never be classified as ``WARNING`` in that case.

    Returns:
        Populated :class:`~mac2nix.models.system_state.SystemState`.
    """
    hostname, macos_version, architecture = _get_system_metadata()

    all_registered = get_all_scanners()
    if scanners is not None:
        selected = {name: cls for name, cls in all_registered.items() if name in scanners}
    else:
        selected = dict(all_registered)

    need_sp = "display" in selected or "audio" in selected or "system" in selected
    need_launchd = "launch_agents" in selected or "cron" in selected

    # --- Dispatch independent scanners immediately ---
    # These 14 scanners need no pre-fetched data; start them now.
    tasks: list[asyncio.Task[tuple[str, BaseModel | None]]] = []
    for name, cls in selected.items():
        if name in _PREFETCH_SCANNERS:
            continue
        tasks.append(
            asyncio.create_task(
                _run_scanner_async(name, cls, {}, progress_callback, log_handler),
                name=f"scanner-{name}",
            )
        )

    # --- Run pre-fetches concurrently while independent scanners are running ---
    batched_sp: dict[str, Any]
    launchd_plists: list[tuple[Path, str, dict[str, Any]]] | None
    batched_sp, launchd_plists = await asyncio.gather(
        asyncio.to_thread(_fetch_system_profiler_batch) if need_sp else asyncio.sleep(0, result={}),
        asyncio.to_thread(read_launchd_plists) if need_launchd else asyncio.sleep(0, result=None),
    )

    # --- Dispatch prefetch-dependent scanners ---
    if "display" in selected:
        tasks.append(
            asyncio.create_task(
                _run_scanner_async(
                    "display",
                    DisplayScanner,
                    {"prefetched_data": batched_sp},
                    progress_callback,
                    log_handler,
                ),
                name="scanner-display",
            )
        )
    if "audio" in selected:
        tasks.append(
            asyncio.create_task(
                _run_scanner_async(
                    "audio",
                    AudioScanner,
                    {"prefetched_data": batched_sp},
                    progress_callback,
                    log_handler,
                ),
                name="scanner-audio",
            )
        )
    if "system" in selected:
        tasks.append(
            asyncio.create_task(
                _run_scanner_async(
                    "system",
                    SystemScanner,
                    {"prefetched_data": batched_sp},
                    progress_callback,
                    log_handler,
                ),
                name="scanner-system",
            )
        )
    if "launch_agents" in selected:
        tasks.append(
            asyncio.create_task(
                _run_scanner_async(
                    "launch_agents",
                    LaunchAgentsScanner,
                    {"launchd_plists": launchd_plists},
                    progress_callback,
                    log_handler,
                ),
                name="scanner-launch_agents",
            )
        )
    if "cron" in selected:
        tasks.append(
            asyncio.create_task(
                _run_scanner_async(
                    "cron",
                    CronScanner,
                    {"launchd_plists": launchd_plists},
                    progress_callback,
                    log_handler,
                ),
                name="scanner-cron",
            )
        )

    results = await asyncio.gather(*tasks, return_exceptions=False)

    # --- Assemble SystemState ---
    domain_results: dict[str, BaseModel | None] = {}
    for scanner_name, result in results:
        domain_results[scanner_name] = result

    return SystemState(
        hostname=hostname,
        macos_version=macos_version,
        architecture=architecture,
        **{k: v for k, v in domain_results.items() if v is not None},  # type: ignore[arg-type]
    )
