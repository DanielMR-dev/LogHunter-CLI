import typer

app = typer.Typer(
    name="loghunter",
    help="Analyze OpenSSH authentication logs and detect suspicious activity.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Show the installed LogHunter version."""
    typer.echo("LogHunter CLI 0.1.0")


def main() -> None:
    app()


if __name__ == "__main__":
    main()