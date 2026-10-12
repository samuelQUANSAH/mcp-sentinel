"""MCP Sentinel: Enterprise Security, Policy Enforcement & PII Redaction Gateway for the Model Context Protocol."""

__version__ = "0.1.0"
__author__ = "Samuel K. Quansah"

from mcp_sentinel.audit.auditor import AuditLogger
from mcp_sentinel.core.config import load_policy
from mcp_sentinel.core.models import (
    AuditEvent,
    AuditEventType,
    GlobalPolicy,
    PolicyAction,
    ToolRule,
)
from mcp_sentinel.proxy.stdio_proxy import StdioSentinelProxy
from mcp_sentinel.security.pii_redactor import PIIRedactor
from mcp_sentinel.security.policy_engine import PolicyEngine
from mcp_sentinel.security.rate_limiter import SlidingWindowRateLimiter

__all__ = [
    "__version__",
    "__author__",
    "GlobalPolicy",
    "PolicyAction",
    "ToolRule",
    "AuditEvent",
    "AuditEventType",
    "load_policy",
    "PolicyEngine",
    "PIIRedactor",
    "SlidingWindowRateLimiter",
    "AuditLogger",
    "StdioSentinelProxy",
]
