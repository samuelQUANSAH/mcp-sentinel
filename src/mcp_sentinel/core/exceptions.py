"""Custom exception hierarchy for MCP Sentinel security gateway."""

from typing import Any, Dict, Optional


class SentinelError(Exception):
    """Base exception for all MCP Sentinel runtime and policy errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class PolicyViolationError(SentinelError):
    """Raised when an MCP tool invocation violates declarative security policies."""

    def __init__(self, message: str, tool_name: str, rule_name: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)
        self.tool_name = tool_name
        self.rule_name = rule_name


class RateLimitExceededError(SentinelError):
    """Raised when an MCP client exceeds tool invocation velocity limits."""

    def __init__(self, message: str, client_id: str, limit: int, window_seconds: float):
        super().__init__(message, {"client_id": client_id, "limit": limit, "window_seconds": window_seconds})
        self.client_id = client_id
        self.limit = limit
        self.window_seconds = window_seconds


class PIIRedactionError(SentinelError):
    """Raised when PII scrubbing encounters unrecoverable syntax or malformed tokens."""


class ConfigurationError(SentinelError):
    """Raised when policy files, YAML definitions, or gateway flags fail validation."""


class TransportError(SentinelError):
    """Raised when stdio or HTTP/SSE streams fail or terminate unexpectedly."""
