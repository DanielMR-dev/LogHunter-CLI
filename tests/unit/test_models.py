"""Unit tests for LogHunter domain models."""

from dataclasses import FrozenInstanceError
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import cast

import pytest

from loghunter.models import (
    AnalysisSummary,
    AuthEvent,
    AuthEventType,
    AuthMethod,
    IPAddress,
    ParseStats,
    SourceStats,
    UsernameStats,
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
    assert event.source_ip == ip_address("192.168.1.50")
    assert event.source_port == 54321
    assert event.auth_method is AuthMethod.PASSWORD
    assert event.line_number == 1
    assert event.invalid_user is False


def test_parse_stats_valid_initialization() -> None:
    """ParseStats should initialize cleanly when counts are valid."""
    stats = ParseStats(total_lines=10, parsed_lines=7, ignored_lines=3)
    assert stats.total_lines == 10
    assert stats.parsed_lines == 7
    assert stats.ignored_lines == 3
    assert stats.coverage_percentage == pytest.approx(70.0)


def test_parse_stats_zero_counts() -> None:
    """ParseStats with zero total lines should defensively report 0.0% coverage."""
    stats = ParseStats(total_lines=0, parsed_lines=0, ignored_lines=0)
    assert stats.coverage_percentage == 0.0


def test_parse_stats_100_percent_coverage() -> None:
    """ParseStats with no ignored lines should report 100.0% coverage."""
    stats = ParseStats(total_lines=5, parsed_lines=5, ignored_lines=0)
    assert stats.coverage_percentage == pytest.approx(100.0)


@pytest.mark.parametrize(
    ("total", "parsed", "ignored"),
    [
        (-1, 0, 0),
        (10, -1, 11),
        (10, 11, -1),
    ],
)
def test_parse_stats_negative_counts_raise_value_error(
    total: int, parsed: int, ignored: int
) -> None:
    """ParseStats should reject negative count values."""
    with pytest.raises(ValueError, match="cannot be negative"):
        ParseStats(total_lines=total, parsed_lines=parsed, ignored_lines=ignored)


def test_parse_stats_mismatched_totals_raise_value_error() -> None:
    """ParseStats should reject instances where parsed + ignored != total."""
    with pytest.raises(ValueError, match="must exactly equal total_lines"):
        ParseStats(total_lines=10, parsed_lines=5, ignored_lines=4)


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
        event.__setattr__("username", "admin")

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


def test_analysis_summary_valid_initialization() -> None:
    """A valid AnalysisSummary should construct correctly."""
    stats = ParseStats(total_lines=10, parsed_lines=5, ignored_lines=5)
    summary = AnalysisSummary(
        parse_stats=stats,
        failed_logins=2,
        successful_logins=2,
        invalid_user_events=1,
        unique_source_addresses=3,
        first_observed=FIXED_TIMESTAMP,
        last_observed=FIXED_TIMESTAMP,
        source_stats=(
            SourceStats(
                source_ip=ip_address("192.168.1.1"),
                failed_logins=2,
                successful_logins=0,
                invalid_user_events=0,
                first_observed=FIXED_TIMESTAMP,
                last_observed=FIXED_TIMESTAMP,
            ),
            SourceStats(
                source_ip=ip_address("192.168.1.2"),
                failed_logins=0,
                successful_logins=2,
                invalid_user_events=0,
                first_observed=FIXED_TIMESTAMP,
                last_observed=FIXED_TIMESTAMP,
            ),
            SourceStats(
                source_ip=ip_address("192.168.1.3"),
                failed_logins=0,
                successful_logins=0,
                invalid_user_events=1,
                first_observed=FIXED_TIMESTAMP,
                last_observed=FIXED_TIMESTAMP,
            ),
        ),
        username_stats=(
            UsernameStats(
                username="admin",
                failed_logins=2,
                successful_logins=2,
                invalid_user_events=1,
                first_observed=FIXED_TIMESTAMP,
                last_observed=FIXED_TIMESTAMP,
            ),
        ),
    )

    assert summary.total_lines == 10
    assert summary.parsed_lines == 5
    assert summary.ignored_lines == 5
    assert summary.parser_coverage_percentage == 50.0
    assert summary.failed_logins == 2
    assert summary.successful_logins == 2
    assert summary.invalid_user_events == 1
    assert summary.unique_source_addresses == 3
    assert summary.first_observed == FIXED_TIMESTAMP
    assert summary.last_observed == FIXED_TIMESTAMP


def test_analysis_summary_valid_zero_initialization() -> None:
    """A valid zero-count AnalysisSummary should construct correctly."""
    stats = ParseStats(total_lines=10, parsed_lines=0, ignored_lines=10)
    summary = AnalysisSummary(
        parse_stats=stats,
        failed_logins=0,
        successful_logins=0,
        invalid_user_events=0,
        unique_source_addresses=0,
        first_observed=None,
        last_observed=None,
        source_stats=(),
        username_stats=(),
    )

    assert summary.failed_logins == 0


@pytest.mark.parametrize(
    ("failed", "success", "invalid", "unique"),
    [
        (-1, 0, 0, 0),
        (0, -1, 0, 0),
        (0, 0, -1, 0),
        (0, 0, 0, -1),
    ],
)
def test_analysis_summary_rejects_negative_counts(
    failed: int, success: int, invalid: int, unique: int
) -> None:
    """AnalysisSummary rejects negative event or IP counts."""
    stats = ParseStats(total_lines=10, parsed_lines=0, ignored_lines=10)
    with pytest.raises(ValueError, match="cannot be negative"):
        AnalysisSummary(
            parse_stats=stats,
            failed_logins=failed,
            successful_logins=success,
            invalid_user_events=invalid,
            unique_source_addresses=unique,
            first_observed=None,
            last_observed=None,
            source_stats=(),
            username_stats=(),
        )


def test_analysis_summary_rejects_sum_mismatch() -> None:
    """The sum of categorized events must equal the parsed lines count."""
    stats = ParseStats(total_lines=10, parsed_lines=5, ignored_lines=5)
    with pytest.raises(
        ValueError, match=r"sum of classified events must equal parse_stats\.parsed_lines"
    ):
        AnalysisSummary(
            parse_stats=stats,
            failed_logins=2,
            successful_logins=2,
            invalid_user_events=0,  # Sum is 4, expected 5
            unique_source_addresses=3,
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
            source_stats=(),
            username_stats=(),
        )


def test_analysis_summary_rejects_excessive_unique_addresses() -> None:
    """Unique source addresses cannot logically exceed the number of parsed events."""
    stats = ParseStats(total_lines=10, parsed_lines=5, ignored_lines=5)
    with pytest.raises(ValueError, match="unique_source_addresses cannot exceed parsed_lines"):
        AnalysisSummary(
            parse_stats=stats,
            failed_logins=2,
            successful_logins=2,
            invalid_user_events=1,
            unique_source_addresses=6,  # Exceeds parsed_lines (5)
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
            source_stats=(),
            username_stats=(),
        )


@pytest.mark.parametrize(
    ("first", "last"),
    [
        (None, FIXED_TIMESTAMP),
        (FIXED_TIMESTAMP, None),
    ],
)
def test_analysis_summary_rejects_missing_timestamps_for_parsed_events(
    first: datetime | None, last: datetime | None
) -> None:
    """If parsed_lines > 0, first/last observed timestamps must be present."""
    stats = ParseStats(total_lines=10, parsed_lines=1, ignored_lines=9)
    with pytest.raises(ValueError, match="first_observed and last_observed must not be None"):
        AnalysisSummary(
            parse_stats=stats,
            failed_logins=1,
            successful_logins=0,
            invalid_user_events=0,
            unique_source_addresses=1,
            first_observed=first,
            last_observed=last,
            source_stats=(),
            username_stats=(),
        )


def test_analysis_summary_rejects_timestamps_for_zero_events() -> None:
    """If parsed_lines == 0, timestamps must be None."""
    stats = ParseStats(total_lines=10, parsed_lines=0, ignored_lines=10)
    with pytest.raises(ValueError, match="first_observed and last_observed must be None"):
        AnalysisSummary(
            parse_stats=stats,
            failed_logins=0,
            successful_logins=0,
            invalid_user_events=0,
            unique_source_addresses=0,
            first_observed=FIXED_TIMESTAMP,
            last_observed=None,
            source_stats=(),
            username_stats=(),
        )


def test_analysis_summary_rejects_unique_ips_for_zero_events() -> None:
    """If parsed_lines == 0, unique IPs must be 0."""
    stats = ParseStats(total_lines=10, parsed_lines=0, ignored_lines=10)
    with pytest.raises(ValueError, match="unique_source_addresses must be 0"):
        AnalysisSummary(
            parse_stats=stats,
            failed_logins=0,
            successful_logins=0,
            invalid_user_events=0,
            unique_source_addresses=1,
            first_observed=None,
            last_observed=None,
            source_stats=(),
            username_stats=(),
        )


def test_analysis_summary_rejects_out_of_order_timestamps() -> None:
    """first_observed cannot be greater than last_observed."""
    stats = ParseStats(total_lines=10, parsed_lines=2, ignored_lines=8)
    first = datetime(2026, 7, 30, 18, 20, 00)
    last = datetime(2026, 7, 30, 18, 10, 00)  # Before first

    with pytest.raises(
        ValueError, match="first_observed cannot be strictly greater than last_observed"
    ):
        AnalysisSummary(
            parse_stats=stats,
            failed_logins=2,
            successful_logins=0,
            invalid_user_events=0,
            unique_source_addresses=1,
            first_observed=first,
            last_observed=last,
            source_stats=(),
            username_stats=(),
        )


def test_source_stats_valid_initialization() -> None:
    """SourceStats should construct correctly with valid data."""
    stats = SourceStats(
        source_ip=FIXED_IPV4,
        failed_logins=2,
        successful_logins=1,
        invalid_user_events=0,
        first_observed=FIXED_TIMESTAMP,
        last_observed=FIXED_TIMESTAMP,
    )
    assert stats.source_ip == FIXED_IPV4
    assert stats.failed_logins == 2
    assert stats.successful_logins == 1
    assert stats.invalid_user_events == 0
    assert stats.total_events == 3
    assert stats.first_observed == FIXED_TIMESTAMP
    assert stats.last_observed == FIXED_TIMESTAMP


def test_source_stats_rejects_invalid_ip() -> None:
    """SourceStats rejects raw IP strings."""
    with pytest.raises(TypeError, match="source_ip must be an IPv4Address or IPv6Address"):
        SourceStats(
            source_ip=cast(IPAddress, "192.168.1.1"),
            failed_logins=1,
            successful_logins=0,
            invalid_user_events=0,
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
        )


@pytest.mark.parametrize(
    ("failed", "success", "invalid"),
    [
        (-1, 0, 0),
        (0, -1, 0),
        (0, 0, -1),
    ],
)
def test_source_stats_rejects_negative_counts(failed: int, success: int, invalid: int) -> None:
    """SourceStats rejects negative event counts."""
    with pytest.raises(ValueError, match="cannot be negative"):
        SourceStats(
            source_ip=FIXED_IPV4,
            failed_logins=failed,
            successful_logins=success,
            invalid_user_events=invalid,
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
        )


def test_source_stats_rejects_zero_events() -> None:
    """SourceStats rejects instances with zero total events."""
    with pytest.raises(ValueError, match="total_events must be at least 1"):
        SourceStats(
            source_ip=FIXED_IPV4,
            failed_logins=0,
            successful_logins=0,
            invalid_user_events=0,
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
        )


def test_source_stats_rejects_out_of_order_timestamps() -> None:
    """SourceStats requires first_observed <= last_observed."""
    first = datetime(2026, 7, 30, 18, 20)
    last = datetime(2026, 7, 30, 18, 10)
    with pytest.raises(
        ValueError, match="first_observed cannot be strictly greater than last_observed"
    ):
        SourceStats(
            source_ip=FIXED_IPV4,
            failed_logins=1,
            successful_logins=0,
            invalid_user_events=0,
            first_observed=first,
            last_observed=last,
        )


def test_username_stats_valid_initialization() -> None:
    """UsernameStats should construct correctly with valid data."""
    stats = UsernameStats(
        username="admin",
        failed_logins=2,
        successful_logins=1,
        invalid_user_events=0,
        first_observed=FIXED_TIMESTAMP,
        last_observed=FIXED_TIMESTAMP,
    )
    assert stats.username == "admin"
    assert stats.failed_logins == 2
    assert stats.successful_logins == 1
    assert stats.invalid_user_events == 0
    assert stats.total_events == 3
    assert stats.first_observed == FIXED_TIMESTAMP
    assert stats.last_observed == FIXED_TIMESTAMP


def test_username_stats_exact_username_preservation() -> None:
    """UsernameStats should not modify the case of the username."""
    stats = UsernameStats(
        username="AdMiN",
        failed_logins=1,
        successful_logins=0,
        invalid_user_events=0,
        first_observed=FIXED_TIMESTAMP,
        last_observed=FIXED_TIMESTAMP,
    )
    assert stats.username == "AdMiN"


@pytest.mark.parametrize("username", ["", "   "])
def test_username_stats_rejects_empty_username(username: str) -> None:
    """UsernameStats requires a non-empty username."""
    with pytest.raises(ValueError, match="username must not be empty"):
        UsernameStats(
            username=username,
            failed_logins=1,
            successful_logins=0,
            invalid_user_events=0,
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
        )


def test_username_stats_rejects_negative_counts() -> None:
    """UsernameStats rejects negative event counts."""
    with pytest.raises(ValueError, match="cannot be negative"):
        UsernameStats(
            username="admin",
            failed_logins=-1,
            successful_logins=0,
            invalid_user_events=0,
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
        )


def test_username_stats_rejects_zero_events() -> None:
    """UsernameStats rejects instances with zero total events."""
    with pytest.raises(ValueError, match="total_events must be at least 1"):
        UsernameStats(
            username="admin",
            failed_logins=0,
            successful_logins=0,
            invalid_user_events=0,
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
        )


def test_username_stats_rejects_out_of_order_timestamps() -> None:
    """UsernameStats requires first_observed <= last_observed."""
    first = datetime(2026, 7, 30, 18, 20)
    last = datetime(2026, 7, 30, 18, 10)
    with pytest.raises(
        ValueError, match="first_observed cannot be strictly greater than last_observed"
    ):
        UsernameStats(
            username="admin",
            failed_logins=1,
            successful_logins=0,
            invalid_user_events=0,
            first_observed=first,
            last_observed=last,
        )


def test_analysis_summary_rejects_duplicate_sources() -> None:
    """AnalysisSummary rejects duplicate source IPs in source_stats."""
    stats = ParseStats(total_lines=2, parsed_lines=2, ignored_lines=0)
    source = SourceStats(
        source_ip=FIXED_IPV4,
        failed_logins=1,
        successful_logins=0,
        invalid_user_events=0,
        first_observed=FIXED_TIMESTAMP,
        last_observed=FIXED_TIMESTAMP,
    )
    with pytest.raises(ValueError, match="source_stats contains duplicate source IPs"):
        AnalysisSummary(
            parse_stats=stats,
            failed_logins=2,
            successful_logins=0,
            invalid_user_events=0,
            unique_source_addresses=2,
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
            source_stats=(source, source),
            username_stats=(),
        )


def test_analysis_summary_rejects_duplicate_usernames() -> None:
    """AnalysisSummary rejects duplicate usernames in username_stats."""
    stats = ParseStats(total_lines=2, parsed_lines=2, ignored_lines=0)
    source = SourceStats(
        source_ip=FIXED_IPV4,
        failed_logins=2,
        successful_logins=0,
        invalid_user_events=0,
        first_observed=FIXED_TIMESTAMP,
        last_observed=FIXED_TIMESTAMP,
    )
    username = UsernameStats(
        username="admin",
        failed_logins=1,
        successful_logins=0,
        invalid_user_events=0,
        first_observed=FIXED_TIMESTAMP,
        last_observed=FIXED_TIMESTAMP,
    )
    with pytest.raises(ValueError, match="username_stats contains duplicate usernames"):
        AnalysisSummary(
            parse_stats=stats,
            failed_logins=2,
            successful_logins=0,
            invalid_user_events=0,
            unique_source_addresses=1,
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
            source_stats=(source,),
            username_stats=(username, username),
        )


def test_analysis_summary_rejects_source_stats_count_mismatch() -> None:
    """AnalysisSummary validates len(source_stats) == unique_source_addresses."""
    stats = ParseStats(total_lines=2, parsed_lines=2, ignored_lines=0)
    source = SourceStats(
        source_ip=FIXED_IPV4,
        failed_logins=1,
        successful_logins=0,
        invalid_user_events=0,
        first_observed=FIXED_TIMESTAMP,
        last_observed=FIXED_TIMESTAMP,
    )
    with pytest.raises(
        ValueError, match="len\\(source_stats\\) must equal unique_source_addresses"
    ):
        AnalysisSummary(
            parse_stats=stats,
            failed_logins=2,
            successful_logins=0,
            invalid_user_events=0,
            unique_source_addresses=2,  # Expected 1
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
            source_stats=(source,),
            username_stats=(),
        )


def test_analysis_summary_rejects_source_stats_sum_mismatch() -> None:
    """AnalysisSummary validates sum(source.failed_logins) == failed_logins."""
    stats = ParseStats(total_lines=1, parsed_lines=1, ignored_lines=0)
    source = SourceStats(
        source_ip=FIXED_IPV4,
        failed_logins=0,  # Expected 1
        successful_logins=1,
        invalid_user_events=0,
        first_observed=FIXED_TIMESTAMP,
        last_observed=FIXED_TIMESTAMP,
    )
    with pytest.raises(
        ValueError, match="source_stats failed_logins sum does not match global count"
    ):
        AnalysisSummary(
            parse_stats=stats,
            failed_logins=1,
            successful_logins=0,
            invalid_user_events=0,
            unique_source_addresses=1,
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
            source_stats=(source,),
            username_stats=(),
        )


def test_analysis_summary_rejects_username_stats_sum_mismatch() -> None:
    """AnalysisSummary validates sum(username.total_events) == parsed_lines."""
    stats = ParseStats(total_lines=2, parsed_lines=2, ignored_lines=0)
    source = SourceStats(
        source_ip=FIXED_IPV4,
        failed_logins=2,
        successful_logins=0,
        invalid_user_events=0,
        first_observed=FIXED_TIMESTAMP,
        last_observed=FIXED_TIMESTAMP,
    )
    username = UsernameStats(
        username="admin",
        failed_logins=1,  # Only 1 event, expected 2
        successful_logins=0,
        invalid_user_events=0,
        first_observed=FIXED_TIMESTAMP,
        last_observed=FIXED_TIMESTAMP,
    )
    with pytest.raises(
        ValueError, match="username_stats failed_logins sum does not match global count"
    ):
        AnalysisSummary(
            parse_stats=stats,
            failed_logins=2,
            successful_logins=0,
            invalid_user_events=0,
            unique_source_addresses=1,
            first_observed=FIXED_TIMESTAMP,
            last_observed=FIXED_TIMESTAMP,
            source_stats=(source,),
            username_stats=(username,),
        )
