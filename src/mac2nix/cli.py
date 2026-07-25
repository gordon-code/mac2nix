"""mac2nix CLI."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Sequence
from pathlib import Path

import click
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from mac2nix.models.system_state import SystemState
from mac2nix.orchestrator import run_scan
from mac2nix.scan_report import ScannerOutcome, ScannerStatus, capture_scanner_logs, get_remediation_hint
from mac2nix.scanners import get_all_scanners
from mac2nix.vm.discovery import DiscoveryRunner
from mac2nix.vm.manager import TartVMManager
from mac2nix.vm.validator import Validator

_STATUS_ICONS: dict[ScannerStatus, tuple[str, str]] = {
    ScannerStatus.SUCCESS: ("✓", "green"),
    ScannerStatus.WARNING: ("⚠", "yellow"),
    ScannerStatus.ERROR: ("✗", "red"),
    ScannerStatus.SKIPPED: ("⊘", "dim"),
}


def _status_icon(status: ScannerStatus) -> tuple[str, str]:
    """Return (icon, style) for a scanner's status."""
    return _STATUS_ICONS[status]


def _add_message_row(table: Table, message: str) -> None:
    """Add a sub-row for a warning/error message, plus a remediation hint if one applies."""
    table.add_row("", Text(f"  ↳ {message}", style="dim"), "", "")
    hint = get_remediation_hint(message)
    if hint is not None:
        table.add_row("", Text(f"     → {hint}", style="dim italic"), "", "")


def _build_scan_table(outcomes: dict[str, ScannerOutcome], order: Sequence[str]) -> Table:
    """Render one row per scanner in `order`, with sub-rows for warnings/errors."""
    table = Table(box=None, show_header=False, padding=(0, 1))
    table.add_column(width=2, justify="center")
    table.add_column()
    table.add_column(justify="right")
    table.add_column()

    for name in order:
        outcome = outcomes.get(name)
        if outcome is None:
            table.add_row(Spinner("dots"), name, "", "")
            continue

        icon, style = _status_icon(outcome.status)
        detail = ""
        if outcome.status is ScannerStatus.WARNING:
            detail = f"{len(outcome.warnings)} warning(s)"
        elif outcome.status is ScannerStatus.ERROR:
            detail = "error"

        table.add_row(Text(icon, style=style), name, f"{outcome.elapsed:.1f}s", detail)

        if outcome.status in (ScannerStatus.WARNING, ScannerStatus.ERROR):
            for warning in outcome.warnings:
                _add_message_row(table, warning)
            if outcome.status is ScannerStatus.ERROR and outcome.error is not None:
                _add_message_row(table, outcome.error)

    return table


@click.group()
@click.version_option()
def main() -> None:
    """Generate nix-darwin configurations from macOS system scans."""


@main.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Write JSON output to FILE instead of stdout.",
    metavar="FILE",
)
@click.option(
    "--scanner",
    "-s",
    "selected_scanners",
    multiple=True,
    help="Run only this scanner (repeatable). Defaults to all scanners.",
    metavar="NAME",
)
def scan(output: Path | None, selected_scanners: tuple[str, ...]) -> None:
    """Scan the current macOS system state."""
    all_names = list(get_all_scanners().keys())
    scanners: list[str] | None = list(selected_scanners) if selected_scanners else None

    # Validate any explicitly requested scanner names
    if scanners is not None:
        unknown = [s for s in scanners if s not in all_names]
        if unknown:
            available = ", ".join(sorted(all_names))
            raise click.UsageError(f"Unknown scanner(s): {', '.join(unknown)}. Available: {available}")

    scanner_names: list[str] = scanners if scanners is not None else all_names

    outcomes: dict[str, ScannerOutcome] = {}
    start = time.monotonic()

    with (
        capture_scanner_logs() as log_handler,
        Live(
            _build_scan_table(outcomes, scanner_names),
            console=Console(stderr=True),
            refresh_per_second=8,
            transient=False,
        ) as live,
    ):

        def progress_callback(outcome: ScannerOutcome) -> None:
            outcomes[outcome.name] = outcome
            live.update(_build_scan_table(outcomes, scanner_names))

        try:
            state = asyncio.run(
                run_scan(scanners=scanners, progress_callback=progress_callback, log_handler=log_handler)
            )
        except RuntimeError as e:
            raise click.ClickException(str(e)) from e

    elapsed = time.monotonic() - start

    if log_handler.unattributed:
        click.echo("General warnings:", err=True)
        for warning in log_handler.unattributed:
            click.echo(f"  {warning}", err=True)
            hint = get_remediation_hint(warning)
            if hint is not None:
                click.echo(f"    → {hint}", err=True)

    tally_counts: dict[ScannerStatus, int] = {}
    for outcome in outcomes.values():
        tally_counts[outcome.status] = tally_counts.get(outcome.status, 0) + 1
    tally = ", ".join(
        f"{tally_counts[status]} {status.value}"
        for status in (ScannerStatus.SUCCESS, ScannerStatus.WARNING, ScannerStatus.ERROR, ScannerStatus.SKIPPED)
        if tally_counts.get(status, 0) > 0
    )

    json_output = state.to_json()
    summary = f"Scanned {len(outcomes)} scanner(s) in {elapsed:.1f}s ({tally})"

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json_output)
        click.echo(f"{summary} — wrote {output}", err=True)
    else:
        click.echo(summary, err=True)
        click.echo(json_output)


def _vm_options(f: click.decorators.FC) -> click.decorators.FC:
    """Shared CLI options for Tart VM commands (--base-vm, --vm-user, --vm-password)."""
    # Applied in reverse order — Click decorators are bottom-up.
    return click.option("--base-vm", default="base-macos", show_default=True, help="Base Tart VM name.")(
        click.option("--vm-user", default="admin", show_default=True, help="SSH username inside the VM.")(
            click.option("--vm-password", default="admin", show_default=False, help="SSH password inside the VM.")(f)
        )
    )


@main.command()
def generate() -> None:
    """Generate nix-darwin configuration from a scan snapshot."""
    click.echo("generate: not yet implemented")


@main.command()
@click.option(
    "--flake-path",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Path to the nix-darwin flake directory.",
)
@click.option(
    "--scan-file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Source SystemState JSON produced by 'mac2nix scan'.",
)
@_vm_options
def validate(
    flake_path: Path,
    scan_file: Path,
    base_vm: str,
    vm_user: str,
    vm_password: str,
) -> None:
    """Validate generated configuration in a Tart VM."""
    if not TartVMManager.is_available():
        raise click.ClickException("tart CLI not found — install tart to use 'validate'.")

    try:
        source_state = SystemState.from_json(scan_file)
    except Exception as exc:
        raise click.ClickException(f"Failed to load scan file: {exc}") from exc

    async def _run() -> None:
        async with TartVMManager(base_vm, vm_user, vm_password) as vm:
            clone_name = f"mac2nix-validate-{uuid.uuid4().hex[:8]}"
            await vm.clone(clone_name)
            await vm.start()
            result = await Validator(vm).validate(flake_path, source_state)

        if result.errors:
            click.echo("Validation errors:", err=True)
            for error in result.errors:
                click.echo(f"  {error}", err=True)

        if result.fidelity:
            click.echo(f"Overall fidelity: {result.fidelity.overall_score:.1%}")
            for domain, ds in sorted(result.fidelity.domain_scores.items()):
                click.echo(f"  {domain}: {ds.score:.1%} ({ds.matching_fields}/{ds.total_fields})")

        if not result.success:
            raise click.ClickException("Validation failed.")

    try:
        asyncio.run(_run())
    except click.ClickException:
        raise
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc


@main.command()
def diff() -> None:
    """Compare current system state against last scan or declared config."""
    click.echo("diff: not yet implemented")


@main.command()
@click.option("--package", required=True, help="Package name to install and discover.")
@click.option(
    "--type",
    "package_type",
    default="brew",
    show_default=True,
    type=click.Choice(["brew", "cask"]),
    help="Package manager type.",
)
@_vm_options
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    metavar="FILE",
    help="Write JSON result to FILE instead of stdout.",
)
def discover(  # noqa: PLR0913
    package: str,
    package_type: str,
    base_vm: str,
    vm_user: str,
    vm_password: str,
    output: Path | None,
) -> None:
    """Discover app config paths by installing in a Tart VM."""
    if not TartVMManager.is_available():
        raise click.ClickException("tart CLI not found — install tart to use 'discover'.")

    async def _run() -> str:
        async with TartVMManager(base_vm, vm_user, vm_password) as vm:
            result = await DiscoveryRunner(vm).discover(package, package_type)
        return result.model_dump_json(indent=2)

    try:
        json_output = asyncio.run(_run())
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json_output)
        click.echo(f"Discovery result written to {output}", err=True)
    else:
        click.echo(json_output)
