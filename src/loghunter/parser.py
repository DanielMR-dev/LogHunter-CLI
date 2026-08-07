"""Parser for supported OpenSSH authentication log records."""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

from loghunter.exceptions import (
    EmptyInputFileError,
    InputFileNotFoundError,
    InputFileUnreadableError,
    InputPathNotFileError,
)
from loghunter.models import AuthEvent, AuthEventType, AuthMethod, ParseStats

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

_ACCEPTED_PUBLICKEY_MESSAGE_PATTERN = re.compile(
    r"Accepted publickey for (?P<username>\S+)\s+"
    r"from (?P<source_ip>\S+)\s+"
    r"port (?P<source_port>\d+)\s+"
    r"ssh2"
)


def _validate_year(year: int) -> None:
    """Validate the year parameter."""
    if not _MIN_YEAR <= year <= _MAX_YEAR:
        raise ValueError(f"year must be between {_MIN_YEAR} and {_MAX_YEAR}")


def _validate_arguments(*, line_number: int, year: int) -> None:
    """Validate caller-provided parser configuration"""
    if line_number < 1:
        raise ValueError("line_number must be greater than zero")

    _validate_year(year)


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
        source_ip = ip_address(match.group("source_ip"))
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
        source_ip = ip_address(match.group("source_ip"))
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
        source_ip = ip_address(match.group("source_ip"))
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


def _parse_accepted_publickey_message(
    envelope: _SyslogEnvelope,
    *,
    line_number: int,
) -> AuthEvent | None:
    """Parse a successful public-key OpenSSH message."""
    match = _ACCEPTED_PUBLICKEY_MESSAGE_PATTERN.fullmatch(envelope.message)

    if match is None:
        return None

    try:
        source_ip = ip_address(match.group("source_ip"))
        source_port = int(match.group("source_port"))

        return AuthEvent(
            timestamp=envelope.timestamp,
            hostname=envelope.hostname,
            process_id=envelope.process_id,
            event_type=AuthEventType.LOGIN_SUCCEEDED,
            username=match.group("username"),
            source_ip=source_ip,
            source_port=source_port,
            auth_method=AuthMethod.PUBLIC_KEY,
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

    The parser supports failed password, invalid-user events,
    accepted password, and accepted publickey authentication events
    using IPv4 or IPv6 source addresses.

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

    event = _parse_accepted_publickey_message(envelope, line_number=line_number)
    if event is not None:
        return event

    return None


def _iter_parse_results(
    path: Path,
    *,
    year: int,
) -> Iterator[AuthEvent | None]:
    """Incrementally stream a log file, yielding one result per physical line."""
    _validate_year(year)

    if not path.exists():
        raise InputFileNotFoundError(f"Input path does not exist: {path}")

    if not path.is_file():
        raise InputPathNotFileError(f"Input path is not a regular file: {path}")

    try:
        if path.stat().st_size == 0:
            raise EmptyInputFileError(f"Input file is physically empty: {path}")
    except OSError as exc:
        raise InputFileUnreadableError(f"Failed to stat input file {path}: {exc}") from exc

    try:
        with path.open(encoding="utf-8", errors="strict") as handle:
            for line_number, line in enumerate(handle, start=1):
                yield parse_line(line, line_number=line_number, year=year)
    except OSError as exc:
        raise InputFileUnreadableError(f"Failed to read input file {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise InputFileUnreadableError(
            f"Failed to decode input file {path} as UTF-8: {exc}"
        ) from exc


def iter_events(
    path: Path,
    *,
    year: int,
) -> Iterator[AuthEvent]:
    """Incrementally stream a local OpenSSH authentication log file into normalized events.

    The file is read incrementally to maintain bounded memory. Only supported and successfully
    parsed records are yielded. Unsupported lines are ignored.

    Args:
        path: Path to the regular local log file.
        year: The year to apply to traditional syslog timestamps.

    Raises:
        ValueError: If caller configuration (like year) is invalid.
        InputFileNotFoundError: If the path does not exist.
        InputPathNotFileError: If the path is not a regular file.
        EmptyInputFileError: If the file is physically empty (zero bytes).
        InputFileUnreadableError: If the file cannot be read or is not valid UTF-8.
    """
    for result in _iter_parse_results(path, year=year):
        if result is not None:
            yield result


def collect_parse_stats(
    path: Path,
    *,
    year: int,
) -> ParseStats:
    """Calculate parser statistics and coverage for a local OpenSSH authentication log file.

    The file is read incrementally to maintain bounded memory. It computes statistics based on
    physical lines parsed vs ignored.

    Args:
        path: Path to the regular local log file.
        year: The year to apply to traditional syslog timestamps.

    Raises:
        ValueError: If caller configuration (like year) is invalid.
        InputFileNotFoundError: If the path does not exist.
        InputPathNotFileError: If the path is not a regular file.
        EmptyInputFileError: If the file is physically empty (zero bytes).
        InputFileUnreadableError: If the file cannot be read or is not valid UTF-8.
    """
    parsed_lines = 0
    ignored_lines = 0

    for result in _iter_parse_results(path, year=year):
        if result is not None:
            parsed_lines += 1
        else:
            ignored_lines += 1

    return ParseStats(
        total_lines=parsed_lines + ignored_lines,
        parsed_lines=parsed_lines,
        ignored_lines=ignored_lines,
    )


__all__ = ["collect_parse_stats", "iter_events", "parse_line"]
