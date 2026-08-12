"""Errors shared by discovery, inspection, CLI rendering, and API payloads."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_serializer

# Error categories for structured error classification
ErrorCategory = Literal[
    "file_not_found",  # Config file does not exist (not a failure)
    "unknown_config",  # Unknown/unsupported MCP config format (not a failure)
    "parse_error",  # Config file exists but couldn't be parsed
    "server_startup",  # MCP server failed to start
    "server_http_error",  # MCP server returned HTTP error
    "analysis_error",  # Could not reach/use analysis server
    "skill_scan_error",  # Could not scan skill
    "user_declined",  # User declined to start a stdio server during consent prompt
]


# Mapping from failure categories to codes
# These codes are different from the ones from analysis findings like E001, E002, etc
FAILURE_CATEGORY_TO_CODE: dict[ErrorCategory | None, str] = {
    "server_startup": "X001",
    "skill_scan_error": "X002",
    "file_not_found": "X003",
    "unknown_config": "X004",
    "parse_error": "X005",
    "server_http_error": "X006",
    "analysis_error": "X007",
    None: "X008",
    "user_declined": "X009",
}


class ScanError(BaseModel):
    """Serializable error attached to an inspected or analyzed object."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    message: str | None = None
    exception: Exception | str | None = None
    traceback: str | None = None
    is_failure: bool = True
    category: ErrorCategory | None = None
    server_output: str | None = None

    @field_serializer("exception")
    def serialize_exception(self, exception: Exception | str | None, _info) -> str | None:
        return str(exception) if exception else None

    @property
    def text(self) -> str:
        return self.message or (str(self.exception) or "")

    def clone(self) -> "ScanError":
        """Create a copy of the ScanError instance.

        This is NOT the same as ``model_copy(deep=True)``, because it does not clone
        the exception. This is crucial to avoid issues with serialization of
        exceptions - do not replace this with ``model_copy``.
        """
        return ScanError(
            message=self.message,
            exception=self.exception,
            traceback=self.traceback,
            is_failure=self.is_failure,
            category=self.category,
            server_output=self.server_output,
        )


class SerializedException(BaseModel):
    """Structured error used while discovery and inspection are in progress."""

    message: str
    traceback: str | None = None
    is_failure: bool = True
    sub_exception_message: str | None = None
    category: ErrorCategory


class FileNotFoundConfig(SerializedException):
    category: Literal["file_not_found"] = "file_not_found"
    is_failure: Literal[False] = False


class UnknownConfigFormat(SerializedException):
    category: Literal["unknown_config"] = "unknown_config"
    is_failure: Literal[False] = False


class CouldNotParseMCPConfig(SerializedException):
    category: Literal["parse_error"] = "parse_error"


class ServerStartupError(SerializedException):
    category: Literal["server_startup"] = "server_startup"
    server_output: str | None = None


class SkillScanError(SerializedException):
    category: Literal["skill_scan_error"] = "skill_scan_error"


class ServerHTTPError(SerializedException):
    category: Literal["server_http_error"] = "server_http_error"
    server_output: str | None = None


class UserDeclinedError(SerializedException):
    category: Literal["user_declined"] = "user_declined"


class AnalysisError(SerializedException):
    category: Literal["analysis_error"] = "analysis_error"
