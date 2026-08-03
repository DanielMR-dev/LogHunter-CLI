"""Domain models for normalized OpenSSH authentication events."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

type IPAddress = IPv4Address | IPv6Address

_MIN_SOURCE_PORT = 1
_MAX_SOURCE_PORT = 65_535


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

        if not isinstance(self.source_ip, (IPv4Address, IPv6Address)):
            raise TypeError("source_ip must be an IPv4Address or IPv6Address")

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


__all__ = [
    "AuthEvent",
    "AuthEventType",
    "AuthMethod",
    "IPAddress",
]
