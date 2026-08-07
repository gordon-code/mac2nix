"""mac2nix CLI."""

from __future__ import annotations

import asyncio
import getpass
import re
import shutil
import subprocess
import time
import uuid
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

import click
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from mac2nix import onepassword
from mac2nix.generators.scaffold import add_host, age_key_path, init_framework
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

_TALLY_LABELS: dict[ScannerStatus, str] = {
    ScannerStatus.SUCCESS: "success",
    ScannerStatus.WARNING: "completed with warnings",
    ScannerStatus.ERROR: "failed",
    ScannerStatus.SKIPPED: "skipped",
}


def _status_icon(status: ScannerStatus) -> tuple[str, str]:
    """Return (icon, style) for a scanner's status."""
    return _STATUS_ICONS[status]


def _message_lines(message: str) -> list[Text]:
    """Render a warning/error message plus its remediation hint (if any).

    Returned as standalone Text objects (not table cells) so they wrap at the
    full console width instead of being squeezed into a narrow shared column.
    A message with embedded newlines (e.g. a "...\\nstderr: ..." continuation
    from run_command()) gets each continuation line indented to nest under the
    first, rather than resetting to the left margin.
    """
    first, *continuation = message.split("\n")
    lines = [Text(f"  ↳ {first}", style="dim")]
    lines.extend(Text(f"     {line}", style="dim") for line in continuation)
    hint = get_remediation_hint(message)
    if hint is not None:
        lines.append(Text(f"     → {hint}", style="dim italic"))
    return lines


def _build_scan_table(outcomes: dict[str, ScannerOutcome], order: Sequence[str]) -> Group:
    """Render one compact summary line per scanner, with full-width lines for warnings/errors.

    Each scanner gets its own small grid for the summary line (status icon, name,
    elapsed, detail) so that line's width is driven only by scanner names, never
    by warning/error text -- that text is rendered separately, below, as
    unconstrained lines so it wraps at the full console width instead of forcing
    every summary line wide.
    """
    name_width = max((len(name) for name in order), default=0)
    renderables: list[RenderableType] = []

    for name in order:
        grid = Table.grid(padding=(0, 1))
        grid.add_column(width=2, justify="center")
        grid.add_column(width=name_width)
        grid.add_column(width=6, justify="right")
        grid.add_column()

        outcome = outcomes.get(name)
        if outcome is None:
            grid.add_row(Spinner("dots"), name, "", "")
            renderables.append(grid)
            continue

        icon, style = _status_icon(outcome.status)
        detail = ""
        if outcome.status is ScannerStatus.WARNING:
            detail = f"{len(outcome.warnings)} warning(s)"
        elif outcome.status is ScannerStatus.ERROR:
            detail = "error"

        grid.add_row(Text(icon, style=style), name, f"{outcome.elapsed:.1f}s", detail)
        renderables.append(grid)

        if outcome.status in (ScannerStatus.WARNING, ScannerStatus.ERROR):
            for warning in outcome.warnings:
                renderables.extend(_message_lines(warning))
            if outcome.status is ScannerStatus.ERROR and outcome.error is not None:
                renderables.extend(_message_lines(outcome.error))

    return Group(*renderables)


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

    tally_counts = Counter(outcome.status for outcome in outcomes.values())
    tally = ", ".join(
        f"{tally_counts[status]} {_TALLY_LABELS[status]}" for status in ScannerStatus if tally_counts.get(status, 0) > 0
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
@click.argument("output_dir", type=click.Path(path_type=Path))
def init(output_dir: Path) -> None:
    """Scaffold a host-less nix-darwin + home-manager + sops-nix framework."""
    try:
        init_framework(output_dir)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"Framework scaffolded at {output_dir}")
    click.echo("Next: mac2nix add-host --hostname <name> [--username <name>] to register a machine.")


_HOSTNAME_RE = re.compile(r"^[a-z][a-z0-9-]*$")
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]*$")
_SYSTEM_CHOICES = ("aarch64-darwin", "x86_64-darwin")


def _check_hostname(value: str) -> str:
    if not _HOSTNAME_RE.match(value):
        msg = "hostname must match ^[a-z][a-z0-9-]*$ (lowercase alphanumeric and hyphens, starting with a letter)"
        raise click.BadParameter(msg)
    return value


def _check_username(value: str) -> str:
    if not _USERNAME_RE.match(value):
        msg = "username must match ^[a-z_][a-z0-9_-]*$"
        raise click.BadParameter(msg)
    return value


def _validate_hostname(_ctx: click.Context, _param: click.Parameter, value: str) -> str:
    return _check_hostname(value)


def _validate_username(_ctx: click.Context, _param: click.Parameter, value: str) -> str:
    return _check_username(value)


def _confirm_or_default(prompt: str, *, default: bool) -> bool:
    """Like `click.confirm()`, but resolves to *default* on EOF instead of aborting.

    For the two trailing, non-destructive prompts (register another host,
    run `nix flake lock` now) — by the time these run, any host registered
    earlier in this invocation is already fully committed, so an exhausted
    stdin here should behave like silently declining, not like aborting a
    command that already did its real work.
    """
    try:
        return click.confirm(prompt, default=default)
    except EOFError:
        return default


def _run_nix_flake_lock(output_dir: Path) -> None:
    """Run `nix flake lock` in *output_dir*, streaming its real output live.

    A small, separately-named wrapper (rather than inlining the subprocess
    call at its call site) so tests can patch just this one call without
    touching the shared `subprocess` module object — patching
    `subprocess.run` globally would also intercept scaffold.py's real
    `age-keygen`/`sops` calls made earlier in the same command invocation.

    Raises :exc:`click.ClickException` if `nix` isn't on PATH or the lock
    fails.
    """
    if shutil.which("nix") is None:
        raise click.ClickException("nix is not installed or not on PATH")
    result = subprocess.run(["nix", "flake", "lock"], cwd=output_dir, check=False)  # noqa: S607
    if result.returncode != 0:
        raise click.ClickException(f"nix flake lock failed (exit {result.returncode})")


@main.command("add-host")
@click.argument("output_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--hostname",
    required=True,
    callback=_validate_hostname,
    help="Hostname to register (lowercase alphanumeric + hyphens, starting with a letter).",
)
@click.option(
    "--username",
    default=getpass.getuser,
    callback=_validate_username,
    show_default="current OS user",
    help="Account username for this host.",
)
@click.option(
    "--system",
    default="aarch64-darwin",
    show_default=True,
    type=click.Choice(_SYSTEM_CHOICES),
    help="Darwin system double.",
)
@click.option(
    "--op-vault",
    default=None,
    help="Back up the new age key to this 1Password vault via `op` (verified by read-back) instead of a manual "
    "confirmation. Falls back to the manual confirmation if `op` is unavailable, unauthenticated, or the "
    "backup/verify fails.",
)
def add_host_cmd(output_dir: Path, hostname: str, username: str, system: str, op_vault: str | None) -> None:
    """Register a host with an existing mac2nix-scaffolded framework."""

    def _confirm_backup(_fingerprint: str, current_username: str, current_hostname: str) -> bool:
        if op_vault:
            title = f"mac2nix age key — {current_hostname}/{current_username}"
            try:
                onepassword.store_age_key(age_key_path(current_username), vault=op_vault, title=title)
            except onepassword.OnePasswordError as exc:
                click.echo(f"1Password backup failed ({exc}) — falling back to manual confirmation.")
            else:
                # The item's title, not its raw uuid — a uuid isn't something
                # you can search for in the 1Password app, the title is.
                click.echo(f"Backed up to 1Password vault {op_vault!r} as {title!r}, verified by read-back.")
                return True
        while not click.confirm("Have you backed up the private key?", default=False):
            click.echo("This key cannot be recovered if lost — please back it up before continuing.")
        return True

    def _register_one(current_hostname: str, current_username: str, current_system: str) -> str:
        try:
            fingerprint = add_host(
                output_dir,
                current_hostname,
                current_username,
                current_system,
                confirm_backup=lambda fp: _confirm_backup(fp, current_username, current_hostname),
            )
        except EOFError:
            raise
        except Exception as exc:
            raise click.ClickException(str(exc)) from exc

        key_path = age_key_path(current_username)
        click.echo(f"Host {current_hostname!r} registered (age key fingerprint: {fingerprint}).")
        click.echo(f"Age key stored at {key_path} — make sure it's backed up somewhere safe.")
        return fingerprint

    _register_one(hostname, username, system)

    while _confirm_or_default("Register another host now?", default=False):
        next_hostname = click.prompt("Hostname", value_proc=_check_hostname)
        next_username = click.prompt("Username", default=getpass.getuser(), value_proc=_check_username)
        next_system = click.prompt("System", default=system, type=click.Choice(_SYSTEM_CHOICES), show_default=True)
        _register_one(next_hostname, next_username, next_system)

    if _confirm_or_default("Run `nix flake lock` now?", default=True):
        _run_nix_flake_lock(output_dir)
    else:
        click.echo(f"Next: run `nix flake lock` inside {output_dir} before the first build for this host.")

    click.echo(
        "Reminder: push this repo as a PRIVATE GitHub repo — sops-nix keeps the actual secrets encrypted, "
        "but each host's hostname/username are embedded in flake.nix/configuration.nix as plain, "
        "unencrypted metadata."
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
@click.option(
    "--mac2nix-source",
    default="github:gordon-code/mac2nix",
    show_default=True,
    help="mac2nix source the VM re-scans with — a flake ref, or a local checkout path (e.g. '.') "
    "to validate not-yet-published code.",
)
@_vm_options
def validate(  # noqa: PLR0913
    flake_path: Path,
    scan_file: Path,
    mac2nix_source: str,
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
            result = await Validator(vm, mac2nix_source=mac2nix_source).validate(flake_path, source_state)

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
