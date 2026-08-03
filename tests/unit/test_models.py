"""Unit tests for LogHunter domain models."""

from dataclasses import FrozenInstanceError
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import cast

import pytest

from loghunter.models import (
    AuthEvent,
    AuthEventType,
    AuthMethod,
    IPAddress,
)

FIXED_TIMESTAMP = datetime(2026, 7, 30, 18, 14, 22)
FIXED_IPV4 = IPv4Address("192.168.1.50")


def make_event(
    *,
    timestamp: datetime = FIXED_TIMESTAMP,
    hostname: str = "server01",
    process_id: int = 4128,
    event_type: AuthEventType = AuthEventType.LOGIN_FAILED,
    username: str = "root",
    source_ip: IPAddress = FIXED_IPV4,
    source_port: int = 54321,
    auth_method: AuthMethod | None = AuthMethod.PASSWORD,
    line_number: int = 1,
    invalid_user: bool = False,
) -> AuthEvent:
    """Build a valid authentication event for focused unit tests."""
    return AuthEvent(
        timestamp=timestamp,
        hostname=hostname,
        process_id=process_id,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        source_port=source_port,
        auth_method=auth_method,
        line_number=line_number,
        invalid_user=invalid_user,
    )


def test_auth_event_type_values_are_stable() -> None:
    """Event types should expose stable values for future serialization."""
    assert AuthEventType.LOGIN_FAILED.value == "login_failed"
    assert AuthEventType.LOGIN_SUCCEEDED.value == "login_succeeded"
    assert AuthEventType.INVALID_USER.value == "invalid_user"


def test_auth_method_values_are_stable() -> None:
    """Authentication methods should match OpenSSH terminology."""
    assert AuthMethod.PASSWORD.value == "password"
    assert AuthMethod.PUBLIC_KEY.value == "publickey"


def test_creates_valid_failed_login_event() -> None:
    """A complete failed-password event should be constructible."""
    event = make_event()

    assert event.timestamp == FIXED_TIMESTAMP
    assert event.hostname == "server01"
    assert event.process_id == 4128
    assert event.event_type is AuthEventType.LOGIN_FAILED
    assert event.username == "root"
    assert event.source_ip == IPv4Address("192.168.1.50")
    assert event.source_port == 54321
    assert event.auth_method is AuthMethod.PASSWORD
    assert event.line_number == 1
    assert event.invalid_user is False


def test_supports_ipv6_source_addresses() -> None:
    """The domain model should support normalized IPv6 addresses."""
    ipv6 = IPv6Address("2001:db8::25")

    event = make_event(source_ip=ipv6)

    assert event.source_ip == ipv6
    assert isinstance(event.source_ip, IPv6Address)


def test_event_is_immutable_and_uses_slots() -> None:
    """Normalized events should not be mutable or expose a dynamic dict."""
    event = make_event()

    with pytest.raises(FrozenInstanceError):
        setattr(event, "username", "admin")

    assert not hasattr(event, "__dict__")


@pytest.mark.parametrize("process_id", [0, -1])
def test_rejects_non_positive_process_ids(
    process_id: int,
) -> None:
    """OpenSSH process identifiers must be positive integers."""
    with pytest.raises(
        ValueError,
        match="process_id must be greater than zero",
    ):
        make_event(process_id=process_id)


@pytest.mark.parametrize("source_port", [0, 65_536])
def test_rejects_source_ports_outside_valid_range(
    source_port: int,
) -> None:
    """Source ports must belong to the TCP/UDP port range."""
    with pytest.raises(
        ValueError,
        match="source_port must be between 1 and 65535",
    ):
        make_event(source_port=source_port)


@pytest.mark.parametrize("source_port", [1, 65_535])
def test_accepts_source_port_boundaries(
    source_port: int,
) -> None:
    """The minimum and maximum valid ports should be accepted."""
    event = make_event(source_port=source_port)

    assert event.source_port == source_port


@pytest.mark.parametrize("line_number", [0, -1])
def test_rejects_non_positive_line_numbers(
    line_number: int,
) -> None:
    """Line numbers must remain one-based for traceability."""
    with pytest.raises(
        ValueError,
        match="line_number must be greater than zero",
    ):
        make_event(line_number=line_number)


@pytest.mark.parametrize("hostname", ["", "   "])
def test_rejects_empty_hostnames(
    hostname: str,
) -> None:
    """Every normalized event must identify the emitting host."""
    with pytest.raises(
        ValueError,
        match="hostname must not be empty",
    ):
        make_event(hostname=hostname)


@pytest.mark.parametrize("username", ["", "   "])
def test_rejects_empty_usernames(
    username: str,
) -> None:
    """Authentication events must contain a non-empty username."""
    with pytest.raises(
        ValueError,
        match="username must not be empty",
    ):
        make_event(username=username)


def test_rejects_non_ip_address_objects() -> None:
    """Raw IP strings must be normalized before model construction."""
    raw_ip = cast(IPAddress, "192.168.1.50")

    with pytest.raises(
        TypeError,
        match="source_ip must be an IPv4Address or IPv6Address",
    ):
        make_event(source_ip=raw_ip)


@pytest.mark.parametrize(
    "event_type",
    [
        AuthEventType.LOGIN_FAILED,
        AuthEventType.LOGIN_SUCCEEDED,
    ],
)
def test_login_events_require_authentication_method(
    event_type: AuthEventType,
) -> None:
    """Failed and successful logins must declare their method."""
    with pytest.raises(
        ValueError,
        match="login events must include an authentication method",
    ):
        make_event(
            event_type=event_type,
            auth_method=None,
        )


def test_accepts_standalone_invalid_user_event() -> None:
    """An Invalid user record should not require an auth method."""
    event = make_event(
        event_type=AuthEventType.INVALID_USER,
        username="administrator",
        auth_method=None,
        invalid_user=True,
    )

    assert event.event_type is AuthEventType.INVALID_USER
    assert event.auth_method is None
    assert event.invalid_user is True


def test_invalid_user_event_requires_invalid_user_marker() -> None:
    """Standalone invalid-user records must preserve that distinction."""
    with pytest.raises(
        ValueError,
        match="invalid-user events must set invalid_user to True",
    ):
        make_event(
            event_type=AuthEventType.INVALID_USER,
            auth_method=None,
            invalid_user=False,
        )


def test_invalid_user_event_rejects_authentication_method() -> None:
    """Standalone Invalid user records do not expose an auth method."""
    with pytest.raises(
        ValueError,
        match=("invalid-user events must not include an authentication method"),
    ):
        make_event(
            event_type=AuthEventType.INVALID_USER,
            auth_method=AuthMethod.PASSWORD,
            invalid_user=True,
        )


def test_successful_login_cannot_target_invalid_user() -> None:
    """A successful authentication cannot belong to an unknown account."""
    with pytest.raises(
        ValueError,
        match="successful login events cannot target an invalid user",
    ):
        make_event(
            event_type=AuthEventType.LOGIN_SUCCEEDED,
            auth_method=AuthMethod.PUBLIC_KEY,
            invalid_user=True,
        )


def test_failed_login_may_target_invalid_user() -> None:
    """Failed-password records may explicitly identify invalid users."""
    event = make_event(
        event_type=AuthEventType.LOGIN_FAILED,
        username="administrator",
        auth_method=AuthMethod.PASSWORD,
        invalid_user=True,
    )

    assert event.event_type is AuthEventType.LOGIN_FAILED
    assert event.invalid_user is True
