"""Tests for the LogHunter CLI"""

from typer.testing import CliRunner

from loghunter.cli import app

runner = CliRunner()


def test_help_command_succeeds() -> None:
    """The root help command should be available."""
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Analyze OpenSSH authentication logs" in result.stdout


def test_version_option_succeeds() -> None:
    """The version should print the installed version."""
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "LogHunter CLI 0.1.0" in result.stdout
