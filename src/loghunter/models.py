"""Domain models for normalized OpenSSH authentication events."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

type IPAddress = IPv4Address | IPv6Address

_MIN_SOURCE_PORT = 1
_MAX_SOURCE_PORT = 65_535


def _validate_ip_address(value: object) -> None:
    """Ensure a source address was normalized before model construction."""
    if not isinstance(value, (IPv4Address, IPv6Address)):
        raise TypeError("source_ip must be an IPv4Address or IPv6Address")


class AuthEventType(StrEnum):
    """Supported normalized OpenSSH authentication event types."""

    LOGIN_FAILED = "login_failed"
    LOGIN_SUCCEEDED = "login_succeeded"
    INVALID_USER = "invalid_user"


class AuthMethod(StrEnum):
    """Supported OpenSSH authentication methods."""

    PASSWORD = "password"
    PUBLIC_KEY = "publickey"


@dataclass(frozen=True, slots=True)
class AuthEvent:
    """A normalized OpenSSH authentication event.

    The object stores only the structured information required by the
    analysis and detection layers. The original raw log line is
    intentionally not retained.
    """

    timestamp: datetime
    hostname: str
    process_id: int
    event_type: AuthEventType
    username: str
    source_ip: IPAddress
    source_port: int
    auth_method: AuthMethod | None
    line_number: int
    invalid_user: bool = False

    def __post_init__(self) -> None:
        """Validate invariants shared by normalized events."""
        if not self.hostname.strip():
            raise ValueError("hostname must not be empty")

        if self.process_id < 1:
            raise ValueError("process_id must be greater than zero")

        if not self.username.strip():
            raise ValueError("username must not be empty")

        _validate_ip_address(self.source_ip)

        if not (_MIN_SOURCE_PORT <= self.source_port <= _MAX_SOURCE_PORT):
            raise ValueError(
                f"source_port must be between {_MIN_SOURCE_PORT} and {_MAX_SOURCE_PORT}"
            )

        if self.line_number < 1:
            raise ValueError("line_number must be greater than zero")

        if (
            self.event_type
            in {
                AuthEventType.LOGIN_FAILED,
                AuthEventType.LOGIN_SUCCEEDED,
            }
            and self.auth_method is None
        ):
            raise ValueError("login events must include an authentication method")

        if self.event_type is AuthEventType.INVALID_USER:
            if not self.invalid_user:
                raise ValueError("invalid-user events must set invalid_user to True")

            if self.auth_method is not None:
                raise ValueError("invalid-user events must not include an authentication method")

        if self.event_type is AuthEventType.LOGIN_SUCCEEDED and self.invalid_user:
            raise ValueError("successful login events cannot target an invalid user")


@dataclass(frozen=True, slots=True)
class ParseStats:
    """Immutable parsing statistics and input-coverage accounting."""

    total_lines: int
    parsed_lines: int
    ignored_lines: int

    def __post_init__(self) -> None:
        """Validate invariant line counts."""
        if self.total_lines < 0:
            raise ValueError("total_lines cannot be negative")
        if self.parsed_lines < 0:
            raise ValueError("parsed_lines cannot be negative")
        if self.ignored_lines < 0:
            raise ValueError("ignored_lines cannot be negative")
        if self.parsed_lines + self.ignored_lines != self.total_lines:
            raise ValueError("parsed_lines + ignored_lines must exactly equal total_lines")

    @property
    def coverage_percentage(self) -> float:
        """Calculate the percentage of physical lines that were supported/parsed."""
        if self.total_lines == 0:
            return 0.0
        return (self.parsed_lines / self.total_lines) * 100


@dataclass(frozen=True, slots=True)
class AnalysisSummary:
    """Immutable authentication-analysis summary."""

    parse_stats: ParseStats
    failed_logins: int
    successful_logins: int
    invalid_user_events: int
    unique_source_addresses: int
    first_observed: datetime | None
    last_observed: datetime | None

    def __post_init__(self) -> None:
        """Validate summary invariants."""
        if self.failed_logins < 0:
            raise ValueError("failed_logins cannot be negative")
        if self.successful_logins < 0:
            raise ValueError("successful_logins cannot be negative")
        if self.invalid_user_events < 0:
            raise ValueError("invalid_user_events cannot be negative")
        if self.unique_source_addresses < 0:
            raise ValueError("unique_source_addresses cannot be negative")

        total_semantic = self.failed_logins + self.successful_logins + self.invalid_user_events
        if total_semantic != self.parse_stats.parsed_lines:
            raise ValueError("sum of classified events must equal parse_stats.parsed_lines")

        if self.parse_stats.parsed_lines == 0:
            if self.first_observed is not None or self.last_observed is not None:
                raise ValueError(
                    "first_observed and last_observed must be None when no events are parsed"
                )
            if self.unique_source_addresses != 0:
                raise ValueError("unique_source_addresses must be 0 when no events are parsed")
        else:
            if self.first_observed is None or self.last_observed is None:
                raise ValueError(
                    "first_observed and last_observed must not be None when events are parsed"
                )
            if self.first_observed > self.last_observed:
                raise ValueError("first_observed cannot be strictly greater than last_observed")

        if self.unique_source_addresses > self.parse_stats.parsed_lines:
            raise ValueError("unique_source_addresses cannot exceed parsed_lines")

    @property
    def total_lines(self) -> int:
        return self.parse_stats.total_lines

    @property
    def parsed_lines(self) -> int:
        return self.parse_stats.parsed_lines

    @property
    def ignored_lines(self) -> int:
        return self.parse_stats.ignored_lines

    @property
    def parser_coverage_percentage(self) -> float:
        return self.parse_stats.coverage_percentage


__all__ = [
    "AnalysisSummary",
    "AuthEvent",
    "AuthEventType",
    "AuthMethod",
    "IPAddress",
    "ParseStats",
]
