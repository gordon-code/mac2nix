"""mac2nix CLI."""

import click


@click.group()
@click.version_option()
def main() -> None:
    """Generate nix-darwin configurations from macOS system scans."""


@main.command()
def scan() -> None:
    """Scan the current macOS system state."""
    click.echo("scan: not yet implemented")


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
