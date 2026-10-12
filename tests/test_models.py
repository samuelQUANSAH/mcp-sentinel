"""Unit tests for MCP Sentinel data models and serialization."""

from mcp_sentinel.core.models import (
    ArgumentRule,
    AuditEvent,
    AuditEventType,
    GlobalPolicy,
    JsonRpcRequest,
    JsonRpcResponse,
    PolicyAction,
    ToolCallParams,
    ToolRule,
)


def test_json_rpc_request_serialization():
    req = JsonRpcRequest(
        id=1,
        method="tools/call",
        params={"name": "read_file", "arguments": {"path": "/tmp/test.txt"}},
    )
    json_str = req.model_dump_json()
    assert '"jsonrpc":"2.0"' in json_str
    assert '"id":1' in json_str
    assert '"method":"tools/call"' in json_str


def test_json_rpc_response_error():
    resp = JsonRpcResponse(
        id=1,
        error={"code": -32003, "message": "Policy violation"},
    )
    assert resp.error is not None
    assert resp.error["code"] == -32003
    assert resp.result is None


def test_tool_call_params():
    params = ToolCallParams(name="execute_sql", arguments={"query": "SELECT 1;"})
    assert params.name == "execute_sql"
    assert params.arguments["query"] == "SELECT 1;"


def test_global_policy_defaults():
    policy = GlobalPolicy()
    assert policy.version == "1.0"
    assert policy.default_action == PolicyAction.ALLOW
    assert policy.enable_pii_redaction is True
    assert policy.enable_secret_redaction is True
    assert policy.rate_limit_per_minute == 120


def test_audit_event_creation():
    event = AuditEvent(
        event_type=AuditEventType.TOOL_CALL,
        tool_name="test_tool",
        status="ALLOWED",
        details={"ip": "127.0.0.1"},
    )
    assert event.event_id is not None
    assert event.timestamp is not None
    assert event.status == "ALLOWED"
    assert event.details["ip"] == "127.0.0.1"
