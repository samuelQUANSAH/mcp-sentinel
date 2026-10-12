"""Core Pydantic data models for JSON-RPC 2.0, MCP payloads, policy definitions, and audit events."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
import uuid

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 & MCP Wire Models
# ---------------------------------------------------------------------------

class JsonRpcRequest(BaseModel):
    """Standard JSON-RPC 2.0 request envelope."""

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version must be 2.0")
    id: Optional[Union[str, int]] = Field(default=None, description="Request identifier")
    method: str = Field(..., description="Target JSON-RPC method name")
    params: Optional[Dict[str, Any]] = Field(default=None, description="Invocation parameters")


class JsonRpcResponse(BaseModel):
    """Standard JSON-RPC 2.0 response envelope."""

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version must be 2.0")
    id: Optional[Union[str, int]] = Field(default=None, description="Matching request identifier")
    result: Optional[Any] = Field(default=None, description="Result payload if succeeded")
    error: Optional[Dict[str, Any]] = Field(default=None, description="Error payload if failed")


class ToolCallParams(BaseModel):
    """Normalized payload of an MCP tools/call request."""

    name: str = Field(..., description="Tool name being invoked")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Dictionary of tool arguments")


# ---------------------------------------------------------------------------
# Security Policy Models
# ---------------------------------------------------------------------------

class PolicyAction(str, Enum):
    """Actions the security gateway can take upon evaluating a policy rule."""

    ALLOW = "allow"
    DENY = "deny"
    REDACT = "redact"
    REQUIRE_APPROVAL = "require_approval"


class ArgumentRule(BaseModel):
    """Fine-grained inspection rule for a specific tool argument."""

    param_name: str = Field(..., description="Target parameter argument name")
    forbidden_regex: Optional[str] = Field(default=None, description="Regex pattern that triggers denial if matched")
    match_regex: Optional[str] = Field(default=None, description="Required regex pattern that parameter must match")
    action: PolicyAction = Field(default=PolicyAction.DENY, description="Action to take when violation occurs")
    message: Optional[str] = Field(default=None, description="Custom rejection explanation")


class ToolRule(BaseModel):
    """Policy rule governing a tool or wildcard family of tools."""

    tool_pattern: str = Field(..., description="Exact tool name or wildcard pattern (e.g. bash_*, sql_*)")
    action: PolicyAction = Field(default=PolicyAction.ALLOW, description="Default action for this tool pattern")
    argument_rules: List[ArgumentRule] = Field(default_factory=list, description="Rules applied to tool parameters")
    allowed_roles: Optional[List[str]] = Field(default=None, description="Required roles to execute this tool")
    rate_limit_per_minute: Optional[int] = Field(default=None, description="Specific velocity limit for this tool")
    check_injection: Optional[bool] = Field(default=None, description="Per-tool override for prompt injection scanning")
    description: Optional[str] = Field(default=None, description="Human readable rule explanation")


class GlobalPolicy(BaseModel):
    """Root configuration for MCP Sentinel security guardrails."""

    version: str = Field(default="1.0", description="Policy schema version")
    policy_name: str = Field(default="default-enterprise-guardrails", description="Policy identifier")
    default_action: PolicyAction = Field(default=PolicyAction.ALLOW, description="Fallback action for unmatched tools")
    enable_pii_redaction: bool = Field(default=True, description="Enable automatic scrubbing of PII in arguments & results")
    enable_secret_redaction: bool = Field(default=True, description="Enable automatic scrubbing of API keys/tokens")
    enable_injection_guard: bool = Field(default=True, description="Enable automated detection of prompt injection and jailbreak attacks")
    injection_risk_threshold: float = Field(default=0.60, description="Risk threshold (0.0 - 1.0) above which requests are blocked")
    rate_limit_per_minute: int = Field(default=120, description="Global velocity cap per client across all tools")
    rules: List[ToolRule] = Field(default_factory=list, description="Ordered tool rules evaluated first-to-last")


# ---------------------------------------------------------------------------
# Audit & Telemetry Models
# ---------------------------------------------------------------------------

class AuditEventType(str, Enum):
    """Classification of security and lifecycle events recorded in audit log."""

    TOOL_CALL = "tool_call"
    POLICY_BLOCK = "policy_block"
    INJECTION_BLOCK = "injection_block"
    PII_REDACTION = "pii_redaction"
    RATE_LIMIT_BLOCK = "rate_limit_block"
    SSE_STREAM = "sse_stream"
    SYSTEM = "system"


class AuditEvent(BaseModel):
    """Structured audit trail record persisted for governance and SOC compliance."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: AuditEventType
    tool_name: Optional[str] = None
    client_id: str = "default"
    arguments_summary: Optional[Dict[str, Any]] = None
    arguments_hash: Optional[str] = None
    status: str = Field(..., description="ALLOWED, BLOCKED, REDACTED, or ERROR")
    reason: Optional[str] = None
    duration_ms: Optional[float] = None
    details: Dict[str, Any] = Field(default_factory=dict)
