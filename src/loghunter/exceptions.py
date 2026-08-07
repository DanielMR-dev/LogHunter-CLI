"""Expected application exceptions for LogHunter CLI."""


class LogHunterError(Exception):
    """Base exception for expected LogHunter application errors."""


class InputFileError(LogHunterError):
    """Base exception for expected input-file failures."""


class InputFileNotFoundError(InputFileError):
    """Raised when the requested input path does not exist."""


class InputPathNotFileError(InputFileError):
    """Raised when the input path is not a regular file."""


class InputFileUnreadableError(InputFileError):
    """Raised when an input file cannot be read or decoded safely."""


class EmptyInputFileError(InputFileError):
    """Raised when the input file contains zero physical lines."""
