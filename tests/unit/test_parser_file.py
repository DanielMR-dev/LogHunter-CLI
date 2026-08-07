"""Unit tests for OpenSSH authentication log file streaming."""

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
from loghunter.parser import iter_events


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


def test_stream_unreadable_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
