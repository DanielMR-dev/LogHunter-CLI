"""Unit tests for OpenSSH authentication log file streaming."""

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from loghunter.exceptions import (
    EmptyInputFileError,
    InputFileNotFoundError,
    InputFileUnreadableError,
    InputPathNotFileError,
)
from loghunter.models import AuthEventType, AuthMethod
from loghunter.parser import collect_parse_stats, iter_events


def _run_iter_events(path: Path, year: int) -> Any:
    return list(iter_events(path, year=year))


def _run_collect_parse_stats(path: Path, year: int) -> Any:
    return collect_parse_stats(path, year=year)


@pytest.fixture(
    params=[
        _run_iter_events,
        _run_collect_parse_stats,
    ]
)
def file_parser(request: pytest.FixtureRequest) -> Callable[[Path, int], Any]:
    """Fixture to execute identical file-error tests against both public APIs."""
    return request.param


def test_stream_mixed_file(tmp_path: Path) -> None:
    """Stream should incrementally parse and yield only supported records in order,
    preserving physical line numbers.
    """
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        (
            "Jul 30 18:14:22 server01 sshd[4128]: "
            "Failed password for root from 192.168.1.50 port 54321 ssh2\n"
        )
        + "unrelated message\n"
        + (
            "Jul 30 18:20:15 server01 sshd[4200]: "
            "Accepted publickey for daniel from 2001:db8::25 port 50931 ssh2\n"
        )
        + "malformed OpenSSH record\n"
        + (
            "Jul 30 18:15:02 server01 sshd[4132]: "
            "Invalid user administrator from 192.168.1.50 port 54322\n"
        ),
        encoding="utf-8",
    )

    events = list(iter_events(log_file, year=2026))

    assert len(events) == 3

    assert events[0].line_number == 1
    assert events[0].event_type is AuthEventType.LOGIN_FAILED

    assert events[1].line_number == 3
    assert events[1].event_type is AuthEventType.LOGIN_SUCCEEDED
    assert events[1].auth_method is AuthMethod.PUBLIC_KEY

    assert events[2].line_number == 5
    assert events[2].event_type is AuthEventType.INVALID_USER


def test_stream_missing_file(tmp_path: Path) -> None:
    """A missing input path should raise InputFileNotFoundError."""
    missing_file = tmp_path / "does_not_exist.log"

    iterator = iter_events(missing_file, year=2026)
    with pytest.raises(InputFileNotFoundError):
        next(iterator)


def test_stream_directory_path(tmp_path: Path) -> None:
    """A directory path should raise InputPathNotFileError."""
    iterator = iter_events(tmp_path, year=2026)
    with pytest.raises(InputPathNotFileError):
        next(iterator)


def test_stream_empty_file(tmp_path: Path) -> None:
    """A physically empty file should raise EmptyInputFileError."""
    empty_file = tmp_path / "empty.log"
    empty_file.write_text("", encoding="utf-8")

    iterator = iter_events(empty_file, year=2026)
    with pytest.raises(EmptyInputFileError):
        next(iterator)


def test_stream_non_empty_unsupported_file(tmp_path: Path) -> None:
    """A file with no supported records should yield zero events without error."""
    unsupported_file = tmp_path / "unsupported.log"
    unsupported_file.write_text(
        "kernel: unrelated message\ngarbage\nanother unsupported line\n",
        encoding="utf-8",
    )

    events = list(iter_events(unsupported_file, year=2026))
    assert events == []


def test_stats_mixed_file(tmp_path: Path) -> None:
    """Statistics should correctly identify coverage for mixed-event files."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        (
            "Jul 30 18:14:22 server01 sshd[4128]: "
            "Failed password for root from 192.168.1.50 port 54321 ssh2\n"
        )
        + "unrelated message\n"
        + (
            "Jul 30 18:20:15 server01 sshd[4200]: "
            "Accepted publickey for daniel from 2001:db8::25 port 50931 ssh2\n"
        )
        + "malformed OpenSSH record\n"
        + (
            "Jul 30 18:15:02 server01 sshd[4132]: "
            "Invalid user administrator from 192.168.1.50 port 54322\n"
        ),
        encoding="utf-8",
    )

    stats = collect_parse_stats(log_file, year=2026)
    assert stats.total_lines == 5
    assert stats.parsed_lines == 3
    assert stats.ignored_lines == 2
    assert stats.coverage_percentage == pytest.approx(60.0)


def test_stats_all_supported_file(tmp_path: Path) -> None:
    """A file with only supported records should have 100.0% coverage."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        (
            "Jul 30 18:14:22 server01 sshd[4128]: "
            "Failed password for root from 192.168.1.50 port 54321 ssh2\n"
        )
        + (
            "Jul 30 18:20:15 server01 sshd[4200]: "
            "Accepted publickey for daniel from 2001:db8::25 port 50931 ssh2\n"
        ),
        encoding="utf-8",
    )

    stats = collect_parse_stats(log_file, year=2026)
    assert stats.total_lines == 2
    assert stats.parsed_lines == 2
    assert stats.ignored_lines == 0
    assert stats.coverage_percentage == pytest.approx(100.0)


def test_stats_zero_supported_file(tmp_path: Path) -> None:
    """A file with zero supported records should have 0.0% coverage, raising no errors."""
    unsupported_file = tmp_path / "unsupported.log"
    unsupported_file.write_text(
        "kernel: unrelated message\ngarbage\nanother unsupported line\n",
        encoding="utf-8",
    )

    stats = collect_parse_stats(unsupported_file, year=2026)
    assert stats.total_lines == 3
    assert stats.parsed_lines == 0
    assert stats.ignored_lines == 3
    assert stats.coverage_percentage == 0.0


def test_stats_blank_line_accounting(tmp_path: Path) -> None:
    """Blank and whitespace-only lines must contribute to total and ignored lines."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Jul 30 18:14:22 server01 sshd[4128]: Failed password for root from 1.1.1.1 port 22 ssh2\n"
        "\n"
        "   \t  \n"
        "unrelated message\n",
        encoding="utf-8",
    )

    stats = collect_parse_stats(log_file, year=2026)
    assert stats.total_lines == 4
    assert stats.parsed_lines == 1
    assert stats.ignored_lines == 3
    assert stats.coverage_percentage == pytest.approx(25.0)


def test_stats_final_line_without_newline(tmp_path: Path) -> None:
    """A final physical line missing a trailing newline should be counted exactly once."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Jul 30 18:14:22 server01 sshd[4128]: Failed password for root from 1.1.1.1 port 22 ssh2",
        encoding="utf-8",
    )

    stats = collect_parse_stats(log_file, year=2026)
    assert stats.total_lines == 1
    assert stats.parsed_lines == 1
    assert stats.ignored_lines == 0
    assert stats.coverage_percentage == pytest.approx(100.0)


def test_stats_crlf_file(tmp_path: Path) -> None:
    """A file with CRLF line endings should be accounted identically."""
    log_file = tmp_path / "auth.log"
    log_file.write_bytes(
        (
            b"Jul 30 18:14:22 server01 sshd[4128]: "
            b"Failed password for root from 1.1.1.1 port 22 ssh2\r\n"
        )
        + b"garbage\r\n"
    )

    stats = collect_parse_stats(log_file, year=2026)
    assert stats.total_lines == 2
    assert stats.parsed_lines == 1
    assert stats.ignored_lines == 1
    assert stats.coverage_percentage == pytest.approx(50.0)


def test_file_missing_file(tmp_path: Path, file_parser: Callable[[Path, int], Any]) -> None:
    """A missing input path should raise InputFileNotFoundError."""
    missing_file = tmp_path / "does_not_exist.log"
    with pytest.raises(InputFileNotFoundError):
        file_parser(missing_file, 2026)


def test_file_directory_path(tmp_path: Path, file_parser: Callable[[Path, int], Any]) -> None:
    """A directory path should raise InputPathNotFileError."""
    with pytest.raises(InputPathNotFileError):
        file_parser(tmp_path, 2026)


def test_file_empty_file(tmp_path: Path, file_parser: Callable[[Path, int], Any]) -> None:
    """A physically empty file should raise EmptyInputFileError."""
    empty_file = tmp_path / "empty.log"
    empty_file.write_text("", encoding="utf-8")
    with pytest.raises(EmptyInputFileError):
        file_parser(empty_file, 2026)


def test_file_unreadable_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, file_parser: Callable[[Path, int], Any]
) -> None:
    """A permission error or equivalent OSError during open should raise
    InputFileUnreadableError.
    """
    log_file = tmp_path / "auth.log"
    log_file.write_text("some content", encoding="utf-8")

    def mock_open(*args: Any, **kwargs: Any) -> Any:
        raise PermissionError("Access denied")

    monkeypatch.setattr(Path, "open", mock_open)

    iterator = iter_events(log_file, year=2026)
    with pytest.raises(InputFileUnreadableError):
        next(iterator)


def test_stream_invalid_utf8_file(tmp_path: Path) -> None:
    """Invalid UTF-8 sequences should raise InputFileUnreadableError."""
    binary_file = tmp_path / "invalid.log"
    binary_file.write_bytes(b"\xff\xfe\xfd")

    iterator = iter_events(binary_file, year=2026)
    with pytest.raises(InputFileUnreadableError):
        list(iterator)


def test_stream_invalid_year(tmp_path: Path) -> None:
    """Caller configuration validation should use the exact same semantics as parse_line."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        (
            "Jul 30 18:14:22 server01 sshd[4128]: "
            "Failed password for root from 192.168.1.50 port 54321 ssh2\n"
        ),
        encoding="utf-8",
    )

    iterator = iter_events(log_file, year=0)
    with pytest.raises(ValueError, match="year must be between"):
        next(iterator)
