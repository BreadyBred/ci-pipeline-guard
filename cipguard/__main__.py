from __future__ import annotations

import sys
from pathlib import Path

import click

from cipguard.reporter import render_json, render_table
from cipguard.scanner import scan_path


@click.group()
def cli() -> None:
    """ci-pipeline-guard: supply chain and misconfiguration scanner for CI/CD YAML."""


@cli.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(),
    default=None,
    help="Write results to this file instead of stdout.",
)
def scan(path: Path, fmt: str, output_file: str | None) -> None:
    """Scan CI/CD configuration files for security misconfigurations.

    PATH may be a single file or a directory (searched recursively).
    Supported formats: .github/workflows/*.yml and .gitlab-ci.yml.
    """
    results = scan_path(path)

    if not results:
        click.echo("No supported CI configuration files found.", err=True)
        sys.exit(0)

    if fmt == "json":
        render_json(results, output_file)
    else:
        render_table(results, output_file)


if __name__ == "__main__":
    cli()
