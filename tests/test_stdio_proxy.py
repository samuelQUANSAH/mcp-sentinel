"""Unit and integration tests for StdioSentinelProxy tool interception and response scrubbing."""

import json
from pathlib import Path
import tempfile
import pytest

from mcp_sentinel.audit.auditor import AuditLogger
from mcp_sentinel.core.models import (
    ArgumentRule,
    GlobalPolicy,
    JsonRpcRequest,
    PolicyAction,
    ToolRule,
)
from mcp_sentinel.proxy.stdio_proxy import StdioSentinelProxy


@pytest.fixture
def temp_proxy():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test.sqlite")
        jsonl_path = str(Path(tmpdir) / "test.jsonl")
        logger = AuditLogger(db_path=db_path, jsonl_path=jsonl_path)

        policy = GlobalPolicy(
            rate_limit_per_minute=2,
            rules=[
                ToolRule(
                    tool_pattern="bash*",
                    action=PolicyAction.ALLOW,
                    argument_rules=[
                        ArgumentRule(
                            param_name="cmd",
                            forbidden_regex=r"rm\s+-rf\s+/",
                            action=PolicyAction.DENY,
                            message="Destructive root deletion blocked",
                        )
                    ],
                )
            ],
        )

        proxy = StdioSentinelProxy(
            server_command=["echo", "server"],
            policy=policy,
            audit_logger=logger,
            client_id="test_agent",
        )
        yield proxy


@pytest.mark.asyncio
async def test_proxy_handle_allowed_tool_call(temp_proxy):
    req = JsonRpcRequest(
        id="call-1",
        method="tools/call",
        params={"name": "bash_exec", "arguments": {"cmd": "echo hello"}},
    )
    blocked_response = await temp_proxy._handle_tool_call(req)
    assert blocked_response is None
    assert req.params["arguments"]["cmd"] == "echo hello"


@pytest.mark.asyncio
async def test_proxy_handle_blocked_tool_call(temp_proxy):
    req = JsonRpcRequest(
        id="call-2",
        method="tools/call",
        params={"name": "bash_exec", "arguments": {"cmd": "rm -rf /"}},
    )
    blocked_response = await temp_proxy._handle_tool_call(req)
    assert blocked_response is not None
    assert blocked_response.id == "call-2"
    assert blocked_response.error["code"] == -32003
    assert "Destructive root deletion blocked" in blocked_response.error["message"]


@pytest.mark.asyncio
async def test_proxy_handle_rate_limited_tool_call(temp_proxy):
    # Proxy rate limit is configured to 2
    req1 = JsonRpcRequest(id=1, method="tools/call", params={"name": "bash_exec", "arguments": {"cmd": "ls"}})
    req2 = JsonRpcRequest(id=2, method="tools/call", params={"name": "bash_exec", "arguments": {"cmd": "ls"}})
    req3 = JsonRpcRequest(id=3, method="tools/call", params={"name": "bash_exec", "arguments": {"cmd": "ls"}})

    assert (await temp_proxy._handle_tool_call(req1)) is None
    assert (await temp_proxy._handle_tool_call(req2)) is None

    # 3rd should be rate limited
    blocked = await temp_proxy._handle_tool_call(req3)
    assert blocked is not None
    assert blocked.error["code"] == -32000
    assert "Rate limit velocity exceeded" in blocked.error["message"]


@pytest.mark.asyncio
async def test_proxy_sanitize_server_response(temp_proxy):
    raw_server_output = json.dumps({
        "jsonrpc": "2.0",
        "id": "1",
        "result": {
            "content": [
                {"type": "text", "text": "Customer email is vip@enterprise.com and API key is sk-proj-1234567890abcdef1234567890"}
            ]
        },
    })

    sanitized = await temp_proxy._sanitize_server_response(raw_server_output)
    parsed = json.loads(sanitized)
    text = parsed["result"]["content"][0]["text"]
    assert "[REDACTED_EMAIL]" in text
    assert "[REDACTED_OPENAI_KEY]" in text
    assert "vip@enterprise.com" not in text
    assert "sk-proj-1234567890" not in text
