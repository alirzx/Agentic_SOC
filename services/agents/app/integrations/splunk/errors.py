"""Splunk integration errors (Phase 8.7)."""

from __future__ import annotations


class SplunkError(Exception):
    """Base Splunk integration error."""

    status: str = "SPLUNK_QUERY_ERROR"

    def __init__(self, message: str, *, status: str | None = None, http_status: int | None = None) -> None:
        super().__init__(message)
        if status:
            self.status = status
        self.http_status = http_status


class SplunkAuthenticationError(SplunkError):
    status = "SPLUNK_AUTH_FAILURE"


class SplunkAuthorizationError(SplunkError):
    status = "SPLUNK_AUTHORIZATION_FAILURE"


class SplunkUnavailableError(SplunkError):
    status = "SPLUNK_UNAVAILABLE"


class SplunkTimeoutError(SplunkError):
    status = "SPLUNK_TIMEOUT"


class SplunkQueryError(SplunkError):
    status = "SPLUNK_QUERY_ERROR"


class SplunkQueryValidationError(SplunkError):
    status = "SPLUNK_QUERY_REJECTED"
