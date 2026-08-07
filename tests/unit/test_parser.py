"""Unit tests for OpenSSH authentication log parsing."""

from datetime import datetime
from ipaddress import IPv4Address

import pytest

from loghunter.models import AuthEventType, AuthMethod
from loghunter.parser import parse_line

VALID_FAILED_PASSWORD_LINE = (
    "Jul 30 18:14:22 server01 sshd[4128]: "
    "Failed password for root from 192.168.1.50 port 54321 ssh2"
)


def test_parses_failed_password_event() -> None:
    """A supported failed-password record should produce an AuthEvent."""
    event = parse_line(
        VALID_FAILED_PASSWORD_LINE,
        line_number=1,
        year=2026,
    )

    assert event is not None
    assert event.timestamp == datetime(2026, 7, 30, 18, 14, 22)
    assert event.hostname == "server01"
    assert event.process_id == 4128
    assert event.event_type is AuthEventType.LOGIN_FAILED
    assert event.username == "root"
    assert event.source_ip == IPv4Address("192.168.1.50")
    assert event.source_port == 54321
    assert event.auth_method is AuthMethod.PASSWORD
    assert event.line_number == 1
    assert event.invalid_user is False


def test_preserves_supplied_line_number() -> None:
    """The parser should preserve one-based source-line traceability."""
    event = parse_line(
        VALID_FAILED_PASSWORD_LINE,
        line_number=57,
        year=2026,
    )

    assert event is not None
    assert event.line_number == 57


def test_accepts_single_digit_syslog_day() -> None:
    """Traditional syslog may pad a one-digit day with two spaces."""
    line = "Jan  3 05:04:09 ubuntu sshd[99]: Failed password for admin from 10.0.0.5 port 22 ssh2"

    event = parse_line(
        line,
        line_number=2,
        year=2026,
    )

    assert event is not None
    assert event.timestamp == datetime(2026, 1, 3, 5, 4, 9)
    assert event.hostname == "ubuntu"
    assert event.process_id == 99
    assert event.username == "admin"
    assert event.source_ip == IPv4Address("10.0.0.5")
    assert event.source_port == 22


def test_accepts_trailing_newline() -> None:
    """Lines read directly from a file may include a newline character."""
    event = parse_line(
        f"{VALID_FAILED_PASSWORD_LINE}\n",
        line_number=3,
        year=2026,
    )

    assert event is not None
    assert event.username == "root"


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "This is not an OpenSSH authentication record",
        "Jul 30 18:14:22 server01 kernel: unrelated message",
        "Jul 30 18:14:22 server01 sshd[4128]: Failed password",
        ("Jan  3 05:04:09 ubuntu sshd[99]Failed password for admin from 10.0.0.5 port 22 ssh2"),
        (
            "Jul 30 18:14:22 server01 sshd[4128]: "
            "Accepted password for root from 192.168.1.50 port 54321 ssh2"
        ),
        (
            "Jul 30 18:14:22 server01 sshd[4128]: "
            "Failed password for invalid user admin "
            "from 192.168.1.50 port 54321 ssh2"
        ),
    ],
)
def test_returns_none_for_unsupported_lines(line: str) -> None:
    """Unsupported or malformed records should not interrupt analysis."""
    assert parse_line(line, line_number=1, year=2026) is None


@pytest.mark.parametrize(
    "line",
    [
        (
            "Jul 30 18:14:22 server01 sshd[4128]: "
            "Failed password for root from 999.1.1.1 port 54321 ssh2"
        ),
        (
            "Jul 30 18:14:22 server01 sshd[4128]: "
            "Failed password for root from not-an-ip port 54321 ssh2"
        ),
        (
            "Jul 30 18:14:22 server01 sshd[4128]: "
            "Failed password for root from 2001:db8::25 port 54321 ssh2"
        ),
    ],
)
def test_returns_none_for_unsupported_or_invalid_source_addresses(
    line: str,
) -> None:
    """The first parser iteration should accept only valid IPv4 sources."""
    assert parse_line(line, line_number=1, year=2026) is None


@pytest.mark.parametrize(
    "port",
    [
        0,
        65_536,
    ],
)
def test_returns_none_for_invalid_source_ports(port: int) -> None:
    """Invalid source ports should make the record unsupported."""
    line = (
        "Jul 30 18:14:22 server01 sshd[4128]: "
        f"Failed password for root from 192.168.1.50 port {port} ssh2"
    )

    assert parse_line(line, line_number=1, year=2026) is None


@pytest.mark.parametrize(
    "line",
    [
        (
            "Feb 30 18:14:22 server01 sshd[4128]: "
            "Failed password for root from 192.168.1.50 port 54321 ssh2"
        ),
        (
            "Foo 30 18:14:22 server01 sshd[4128]: "
            "Failed password for root from 192.168.1.50 port 54321 ssh2"
        ),
        (
            "Jul 30 25:14:22 server01 sshd[4128]: "
            "Failed password for root from 192.168.1.50 port 54321 ssh2"
        ),
    ],
)
def test_returns_none_for_invalid_timestamps(line: str) -> None:
    """Malformed dates from log input should not raise exceptions."""
    assert parse_line(line, line_number=1, year=2026) is None


@pytest.mark.parametrize("line_number", [0, -1])
def test_rejects_invalid_line_numbers(line_number: int) -> None:
    """Caller configuration errors should be reported explicitly."""
    with pytest.raises(
        ValueError,
        match="line_number must be greater than zero",
    ):
        parse_line(
            VALID_FAILED_PASSWORD_LINE,
            line_number=line_number,
            year=2026,
        )


@pytest.mark.parametrize("year", [0, 10_000])
def test_rejects_invalid_years(year: int) -> None:
    """Years must be valid values accepted by datetime."""
    with pytest.raises(
        ValueError,
        match="year must be between 1 and 9999",
    ):
        parse_line(
            VALID_FAILED_PASSWORD_LINE,
            line_number=1,
            year=year,
        )
