"""Command-line interface for LogHunter"""

from typing import Annotated

import typer

from loghunter import __version__

app = typer.Typer(
    name="loghunter",
    help="Analyze OpenSSH authentication logs and detect suspicious activity.",
    no_args_is_help=True,
    add_completion=False,
)


def version_callback(value: bool) -> None:
    """Print the installed version and terminate the application."""
    if value:
        typer.echo(f"LogHunter CLI {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=version_callback,
            is_eager=True,
            help="Show the installed LogHunter version",
        ),
    ] = False,
) -> None:
    """Analyze OpenSSH authentication logs."""
    del version


def run() -> None:
    """Run the LogHunter CLI application."""
    app()
