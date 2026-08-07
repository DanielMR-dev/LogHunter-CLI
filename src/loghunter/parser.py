"""Parser for supported OpenSSH authentication log records."""

import re
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address

from loghunter.models import AuthEvent, AuthEventType, AuthMethod

_MIN_YEAR = 1
_MAX_YEAR = 9_999

_MONTHS: dict[str, int] = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


@dataclass(frozen=True, slots=True)
class _SyslogEnvelope:
    """Internal representation of a parsed syslog envelope."""

    timestamp: datetime
    hostname: str
    process_id: int
    message: str


_SYSLOG_ENVELOPE_PATTERN = re.compile(
    r"(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"sshd\[(?P<process_id>\d+)\]:\s+"
    r"(?P<message>.*)"
)

_FAILED_PASSWORD_MESSAGE_PATTERN = re.compile(
    r"Failed password for (?:(?P<invalid_user>invalid user)\s+)?(?P<username>\S+)\s+"
    r"from (?P<source_ip>\S+)\s+"
    r"port (?P<source_port>\d+)\s+"
    r"ssh2"
)

_INVALID_USER_MESSAGE_PATTERN = re.compile(
    r"Invalid user (?P<username>\S+)\s+"
    r"from (?P<source_ip>\S+)\s+"
    r"port (?P<source_port>\d+)"
)

_ACCEPTED_PASSWORD_MESSAGE_PATTERN = re.compile(
    r"Accepted password for (?P<username>\S+)\s+"
    r"from (?P<source_ip>\S+)\s+"
    r"port (?P<source_port>\d+)\s+"
    r"ssh2"
)


def _validate_arguments(*, line_number: int, year: int) -> None:
    """Validate caller-provided parser configuration"""
    if line_number < 1:
        raise ValueError("line_number must be greater than zero")

    if not _MIN_YEAR <= year <= _MAX_YEAR:
        raise ValueError(f"year must be between {_MIN_YEAR} and {_MAX_YEAR}")


def _build_timestamp(
    *,
    year: int,
    month: str,
    day: str,
    hour: str,
    minute: str,
    second: str,
) -> datetime:
    """Build a timestamp from traditional syslog date componentes."""
    return datetime(
        year=year,
        month=_MONTHS[month],
        day=int(day),
        hour=int(hour),
        minute=int(minute),
        second=int(second),
    )


def _parse_syslog_envelope(line: str, *, year: int) -> _SyslogEnvelope | None:
    """Parse the traditional syslog envelope from a log line."""
    match = _SYSLOG_ENVELOPE_PATTERN.fullmatch(line)

    if match is None:
        return None

    try:
        timestamp = _build_timestamp(
            year=year,
            month=match.group("month"),
            day=match.group("day"),
            hour=match.group("hour"),
            minute=match.group("minute"),
            second=match.group("second"),
        )
        return _SyslogEnvelope(
            timestamp=timestamp,
            hostname=match.group("hostname"),
            process_id=int(match.group("process_id")),
            message=match.group("message"),
        )
    except ValueError:
        return None


def _parse_failed_password_message(
    envelope: _SyslogEnvelope,
    *,
    line_number: int,
) -> AuthEvent | None:
    """Parse a failed password OpenSSH message."""
    match = _FAILED_PASSWORD_MESSAGE_PATTERN.fullmatch(envelope.message)

    if match is None:
        return None

    try:
        source_ip = IPv4Address(match.group("source_ip"))
        source_port = int(match.group("source_port"))

        return AuthEvent(
            timestamp=envelope.timestamp,
            hostname=envelope.hostname,
            process_id=envelope.process_id,
            event_type=AuthEventType.LOGIN_FAILED,
            username=match.group("username"),
            source_ip=source_ip,
            source_port=source_port,
            auth_method=AuthMethod.PASSWORD,
            line_number=line_number,
            invalid_user=match.group("invalid_user") is not None,
        )
    except ValueError:
        return None


def _parse_invalid_user_message(
    envelope: _SyslogEnvelope,
    *,
    line_number: int,
) -> AuthEvent | None:
    """Parse a standalone invalid user OpenSSH message."""
    match = _INVALID_USER_MESSAGE_PATTERN.fullmatch(envelope.message)

    if match is None:
        return None

    try:
        source_ip = IPv4Address(match.group("source_ip"))
        source_port = int(match.group("source_port"))

        return AuthEvent(
            timestamp=envelope.timestamp,
            hostname=envelope.hostname,
            process_id=envelope.process_id,
            event_type=AuthEventType.INVALID_USER,
            username=match.group("username"),
            source_ip=source_ip,
            source_port=source_port,
            auth_method=None,
            line_number=line_number,
            invalid_user=True,
        )
    except ValueError:
        return None


def _parse_accepted_password_message(
    envelope: _SyslogEnvelope,
    *,
    line_number: int,
) -> AuthEvent | None:
    """Parse a successful password OpenSSH message."""
    match = _ACCEPTED_PASSWORD_MESSAGE_PATTERN.fullmatch(envelope.message)

    if match is None:
        return None

    try:
        source_ip = IPv4Address(match.group("source_ip"))
        source_port = int(match.group("source_port"))

        return AuthEvent(
            timestamp=envelope.timestamp,
            hostname=envelope.hostname,
            process_id=envelope.process_id,
            event_type=AuthEventType.LOGIN_SUCCEEDED,
            username=match.group("username"),
            source_ip=source_ip,
            source_port=source_port,
            auth_method=AuthMethod.PASSWORD,
            line_number=line_number,
            invalid_user=False,
        )
    except ValueError:
        return None


def parse_line(
    line: str,
    *,
    line_number: int,
    year: int,
) -> AuthEvent | None:
    """Parse one supported OpenSSH authentication log line.

    The first parser iteration supports only failed password
    and standalone invalid user authentication events using
    IPv4 source addresses.

    Unsupported or malformed log records return ``None``. Invalid
    caller configuration, such as a non-positive line number or an
    invalid year, raises ``ValueError``.
    """
    _validate_arguments(
        line_number=line_number,
        year=year,
    )

    normalized_line = line.rstrip("\r\n")

    if not normalized_line.strip():
        return None

    envelope = _parse_syslog_envelope(normalized_line, year=year)

    if envelope is None:
        return None

    event = _parse_failed_password_message(envelope, line_number=line_number)
    if event is not None:
        return event

    event = _parse_invalid_user_message(envelope, line_number=line_number)
    if event is not None:
        return event

    event = _parse_accepted_password_message(envelope, line_number=line_number)
    if event is not None:
        return event

    return None


__all__ = ["parse_line"]
