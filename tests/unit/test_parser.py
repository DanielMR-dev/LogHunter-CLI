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

VALID_FAILED_PASSWORD_INVALID_USER_LINE = (
    "Jul 30 18:15:03 server01 sshd[4132]: "
    "Failed password for invalid user administrator from 192.168.1.50 port 54322 ssh2"
)

VALID_INVALID_USER_LINE = (
    "Jul 30 18:15:02 server01 sshd[4132]: Invalid user administrator from 192.168.1.50 port 54322"
)

VALID_ACCEPTED_PASSWORD_LINE = (
    "Jul 30 18:20:15 server01 sshd[4200]: "
    "Accepted password for daniel from 192.168.1.25 port 50930 ssh2"
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


def test_parses_failed_password_invalid_user_event() -> None:
    """A supported failed-password record for an invalid user should produce an AuthEvent."""
    event = parse_line(
        VALID_FAILED_PASSWORD_INVALID_USER_LINE,
        line_number=2,
        year=2026,
    )

    assert event is not None
    assert event.timestamp == datetime(2026, 7, 30, 18, 15, 3)
    assert event.hostname == "server01"
    assert event.process_id == 4132
    assert event.event_type is AuthEventType.LOGIN_FAILED
    assert event.username == "administrator"
    assert event.source_ip == IPv4Address("192.168.1.50")
    assert event.source_port == 54322
    assert event.auth_method is AuthMethod.PASSWORD
    assert event.line_number == 2
    assert event.invalid_user is True


def test_parses_standalone_invalid_user_event() -> None:
    """A standalone invalid user record should produce an AuthEvent with event_type INVALID_USER."""
    event = parse_line(
        VALID_INVALID_USER_LINE,
        line_number=3,
        year=2026,
    )

    assert event is not None
    assert event.timestamp == datetime(2026, 7, 30, 18, 15, 2)
    assert event.hostname == "server01"
    assert event.process_id == 4132
    assert event.event_type is AuthEventType.INVALID_USER
    assert event.username == "administrator"
    assert event.source_ip == IPv4Address("192.168.1.50")
    assert event.source_port == 54322
    assert event.auth_method is None
    assert event.line_number == 3
    assert event.invalid_user is True


def test_parses_accepted_password_event() -> None:
    """A supported accepted-password record should produce an AuthEvent."""
    event = parse_line(
        VALID_ACCEPTED_PASSWORD_LINE,
        line_number=4,
        year=2026,
    )

    assert event is not None
    assert event.timestamp == datetime(2026, 7, 30, 18, 20, 15)
    assert event.hostname == "server01"
    assert event.process_id == 4200
    assert event.event_type is AuthEventType.LOGIN_SUCCEEDED
    assert event.username == "daniel"
    assert event.source_ip == IPv4Address("192.168.1.25")
    assert event.source_port == 50930
    assert event.auth_method is AuthMethod.PASSWORD
    assert event.line_number == 4
    assert event.invalid_user is False


@pytest.mark.parametrize(
    "line_template",
    [
        (
            "Jul 30 18:15:02 server01 sshd[4132]: "
            "Invalid user {username} from 192.168.1.50 port 54322"
        ),
        (
            "Jul 30 18:20:15 server01 sshd[4200]: "
            "Accepted password for {username} from 192.168.1.25 port 50930 ssh2"
        ),
    ],
)
@pytest.mark.parametrize(
    "username",
    [
        "test-user",
        "test_user",
        "test.user",
    ],
)
def test_accepts_valid_username_characters(username: str, line_template: str) -> None:
    """The parser should preserve usernames containing valid special characters."""
    line = line_template.format(username=username)
    event = parse_line(line, line_number=1, year=2026)
    assert event is not None
    assert event.username == username


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


@pytest.mark.parametrize(
    ("base_line", "expected_type"),
    [
        (VALID_FAILED_PASSWORD_LINE, AuthEventType.LOGIN_FAILED),
        (VALID_FAILED_PASSWORD_INVALID_USER_LINE, AuthEventType.LOGIN_FAILED),
        (VALID_INVALID_USER_LINE, AuthEventType.INVALID_USER),
        (VALID_ACCEPTED_PASSWORD_LINE, AuthEventType.LOGIN_SUCCEEDED),
    ],
)
def test_accepts_trailing_newline(base_line: str, expected_type: AuthEventType) -> None:
    """Lines read directly from a file may include a newline character."""
    event = parse_line(
        f"{base_line}\n",
        line_number=3,
        year=2026,
    )

    assert event is not None
    assert event.event_type is expected_type


@pytest.mark.parametrize(
    "line",
    [
        "",
        "   ",
        "This is not an OpenSSH authentication record",
        "Jul 30 18:14:22 server01 kernel: unrelated message",
        "Jul 30 18:14:22 server01 sshd[4128]: Failed password",
        "Jul 30 18:15:03 server01 sshd[4132]: Failed password for invalid user",
        "Jul 30 18:15:02 server01 sshd[4132]: Invalid user",
        ("Jan  3 05:04:09 ubuntu sshd[99]Failed password for admin from 10.0.0.5 port 22 ssh2"),
        (
            "Jul 30 18:20:15 server01 sshd[4200]: "
            "Accepted publickey for daniel from 192.168.1.25 port 50931 ssh2"
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
        (
            "Jul 30 18:15:03 server01 sshd[4132]: "
            "Failed password for invalid user administrator from 999.1.1.1 port 54322 ssh2"
        ),
        (
            "Jul 30 18:15:02 server01 sshd[4132]: "
            "Invalid user administrator from 999.1.1.1 port 54322"
        ),
        (
            "Jul 30 18:15:02 server01 sshd[4132]: "
            "Invalid user administrator from 2001:db8::25 port 54322"
        ),
        (
            "Jul 30 18:20:15 server01 sshd[4200]: "
            "Accepted password for daniel from 999.1.1.1 port 50930 ssh2"
        ),
        (
            "Jul 30 18:20:15 server01 sshd[4200]: "
            "Accepted password for daniel from 2001:db8::25 port 50930 ssh2"
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

    line_invalid_user = (
        "Jul 30 18:15:03 server01 sshd[4132]: "
        f"Failed password for invalid user administrator from 192.168.1.50 port {port} ssh2"
    )

    assert parse_line(line_invalid_user, line_number=1, year=2026) is None

    line_standalone_invalid = (
        "Jul 30 18:15:02 server01 sshd[4132]: "
        f"Invalid user administrator from 192.168.1.50 port {port}"
    )

    assert parse_line(line_standalone_invalid, line_number=1, year=2026) is None

    line_accepted_password = (
        "Jul 30 18:20:15 server01 sshd[4200]: "
        f"Accepted password for daniel from 192.168.1.25 port {port} ssh2"
    )

    assert parse_line(line_accepted_password, line_number=1, year=2026) is None


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
        (
            "Foo 30 18:15:03 server01 sshd[4132]: "
            "Failed password for invalid user administrator from 192.168.1.50 port 54322 ssh2"
        ),
        (
            "Foo 30 18:15:02 server01 sshd[4132]: "
            "Invalid user administrator from 192.168.1.50 port 54322"
        ),
        (
            "Foo 30 18:20:15 server01 sshd[4200]: "
            "Accepted password for daniel from 192.168.1.25 port 50930 ssh2"
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
