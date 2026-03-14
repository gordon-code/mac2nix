"""mac2nix CLI."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import click
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from mac2nix.orchestrator import run_scan
from mac2nix.scanners import get_all_scanners


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

    total = len(scanners) if scanners is not None else len(all_names)

    completed: int = 0
    start = time.monotonic()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=Console(stderr=True),
        transient=True,
        redirect_stdout=False,
        redirect_stderr=False,
    ) as progress:
        task_id = progress.add_task("Scanning...", total=total)

        def progress_callback(name: str) -> None:
            nonlocal completed
            completed += 1
            progress.advance(task_id)
            progress.update(task_id, description=f"[bold cyan]{name}[/] done")

        try:
            state = asyncio.run(run_scan(scanners=scanners, progress_callback=progress_callback))
        except RuntimeError as e:
            raise click.ClickException(str(e)) from e

    elapsed = time.monotonic() - start
    scanner_count = completed

    json_output = state.to_json()

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json_output)
        click.echo(
            f"Scanned {scanner_count} scanner(s) in {elapsed:.1f}s — wrote {output}",
            err=True,
        )
    else:
        click.echo(
            f"Scanned {scanner_count} scanner(s) in {elapsed:.1f}s",
            err=True,
        )
        click.echo(json_output)


@main.command()
def generate() -> None:
    """Generate nix-darwin configuration from a scan snapshot."""
    click.echo("generate: not yet implemented")


@main.command()
def validate() -> None:
    """Validate generated configuration in a Tart VM."""
    click.echo("validate: not yet implemented")


@main.command()
def diff() -> None:
    """Compare current system state against last scan or declared config."""
    click.echo("diff: not yet implemented")


@main.command()
def discover() -> None:
    """Discover app config paths by installing in a Tart VM."""
    click.echo("discover: not yet implemented")
