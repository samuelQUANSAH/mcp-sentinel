"""Asynchronous Stdio Interceptor Proxy for Model Context Protocol (MCP) clients and servers."""

import asyncio
import json
import os
import sys
from typing import List, Optional

from mcp_sentinel.audit.auditor import AuditLogger
from mcp_sentinel.audit.telemetry import TelemetryProvider
from mcp_sentinel.core.models import (
    AuditEventType,
    GlobalPolicy,
    JsonRpcRequest,
    JsonRpcResponse,
    PolicyAction,
)
from mcp_sentinel.security.pii_redactor import PIIRedactor
from mcp_sentinel.security.policy_engine import PolicyEngine
from mcp_sentinel.security.rate_limiter import SlidingWindowRateLimiter


class StdioSentinelProxy:
    """Binds to client stdio, monitors JSON-RPC frames, enforces guardrails, and proxies to server."""

    def __init__(
        self,
        server_command: List[str],
        policy: Optional[GlobalPolicy] = None,
        audit_logger: Optional[AuditLogger] = None,
        client_id: str = "default_client",
        roles: Optional[List[str]] = None,
    ):
        self.server_command = server_command
        self.policy = policy or GlobalPolicy()
        self.client_id = client_id
        self.roles = roles or ["default"]

        self.policy_engine = PolicyEngine(self.policy)
        self.rate_limiter = SlidingWindowRateLimiter(default_limit=self.policy.rate_limit_per_minute)
        self.auditor = audit_logger or AuditLogger()
        self.telemetry = TelemetryProvider()
        self.result_redactor = PIIRedactor(
            enable_pii=self.policy.enable_pii_redaction,
            enable_secrets=self.policy.enable_secret_redaction,
        )

        self._server_process: Optional[asyncio.subprocess.Process] = None
        self._running = False

    async def _handle_tool_call(self, req: JsonRpcRequest) -> Optional[JsonRpcResponse]:
        """Intercept and gate a tools/call request.

        Returns:
            JsonRpcResponse with error if blocked/denied, or None if allowed to proceed.
        """
        params = req.params or {}
        tool_name = params.get("name", "unknown_tool")
        arguments = params.get("arguments", {})

        # 1. Rate limiting check
        allowed, retry_after, _ = self.rate_limiter.check_and_consume(self.client_id, tool_name)
        if not allowed:
            reason = f"Rate limit velocity exceeded for tool '{tool_name}'. Retry in {retry_after:.1f}s"
            self.auditor.log_tool_decision(
                event_type=AuditEventType.RATE_LIMIT_BLOCK,
                tool_name=tool_name,
                client_id=self.client_id,
                status="RATE_LIMITED",
                reason=reason,
                arguments=arguments,
            )
            return JsonRpcResponse(
                id=req.id,
                error={
                    "code": -32000,
                    "message": reason,
                    "data": {"retry_after_seconds": retry_after},
                },
            )

        # 2. Declarative policy evaluation & parameter inspection
        eval_result = self.policy_engine.evaluate_tool_call(
            tool_name=tool_name,
            arguments=arguments,
            roles=self.roles,
        )

        if not eval_result.allowed:
            is_injection = bool(eval_result.matched_rule and eval_result.matched_rule.startswith("injection_guard:"))
            event_type = AuditEventType.INJECTION_BLOCK if is_injection else AuditEventType.POLICY_BLOCK
            self.auditor.log_tool_decision(
                event_type=event_type,
                tool_name=tool_name,
                client_id=self.client_id,
                status="BLOCKED",
                reason=eval_result.reason,
                arguments=arguments,
                details={
                    "matched_rule": eval_result.matched_rule,
                    "action": eval_result.action.value,
                    "injection_details": eval_result.injection_scan.model_dump() if eval_result.injection_scan else None,
                },
            )
            return JsonRpcResponse(
                id=req.id,
                error={
                    "code": -32003,
                    "message": f"Security Policy Violation: {eval_result.reason}",
                    "data": {
                        "tool": tool_name,
                        "rule": eval_result.matched_rule,
                        "action": eval_result.action.value,
                    },
                },
            )

        # 3. Apply sanitized / redacted arguments
        req.params["arguments"] = eval_result.redacted_arguments

        # 4. Audit allowed execution
        status = "REDACTED" if eval_result.pii_entities_detected else "ALLOWED"
        self.auditor.log_tool_decision(
            event_type=AuditEventType.TOOL_CALL,
            tool_name=tool_name,
            client_id=self.client_id,
            status=status,
            reason="Passed policy evaluation",
            arguments=eval_result.redacted_arguments,
            details={
                "pii_detected": eval_result.pii_entities_detected,
                "matched_rule": eval_result.matched_rule,
            },
        )
        return None

    async def _sanitize_server_response(self, raw_line: str) -> str:
        """Sanitize outbound responses from the server before sending to client."""
        try:
            data = json.loads(raw_line)
            if isinstance(data, dict) and "result" in data:
                clean_result, detected = self.result_redactor.redact_value(data["result"])
                if detected:
                    data["result"] = clean_result
                    self.auditor.log_tool_decision(
                        event_type=AuditEventType.PII_REDACTION,
                        tool_name="response_sanitizer",
                        client_id=self.client_id,
                        status="REDACTED",
                        reason=f"Scrubbed sensitive entities: {detected}",
                        details={"entities": detected},
                    )
                    return json.dumps(data)
        except Exception:
            pass
        return raw_line

    async def _pipe_client_to_server(self, reader: asyncio.StreamReader, server_stdin: asyncio.StreamWriter) -> None:
        """Read client requests from stdin, evaluate policies, and pass to server."""
        while self._running:
            line_bytes = await reader.readline()
            if not line_bytes:
                break

            line_str = line_bytes.decode("utf-8").strip()
            if not line_str:
                continue

            try:
                payload = json.loads(line_str)
                if isinstance(payload, dict) and payload.get("method") == "tools/call":
                    req = JsonRpcRequest.model_validate(payload)
                    blocked_response = await self._handle_tool_call(req)
                    if blocked_response:
                        # Write error directly to client stdout without sending to server
                        sys.stdout.write(blocked_response.model_dump_json() + "\n")
                        sys.stdout.flush()
                        continue
                    else:
                        # Forward request with any redacted arguments
                        line_str = req.model_dump_json()
            except Exception:
                # Malformed JSON or non-standard frame: pass through
                pass

            server_stdin.write((line_str + "\n").encode("utf-8"))
            await server_stdin.drain()

    async def _pipe_server_to_client(self, server_stdout: asyncio.StreamReader) -> None:
        """Read server responses, scrub sensitive results, and stream to client stdout."""
        while self._running:
            line_bytes = await server_stdout.readline()
            if not line_bytes:
                break

            line_str = line_bytes.decode("utf-8").strip()
            if not line_str:
                continue

            sanitized = await self._sanitize_server_response(line_str)
            sys.stdout.write(sanitized + "\n")
            sys.stdout.flush()

    async def start(self) -> None:
        """Launch the downstream MCP server subprocess and connect bidirectional proxy."""
        self._running = True

        # Spawn backend MCP server subprocess
        self._server_process = await asyncio.create_subprocess_exec(
            *self.server_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
        )

        assert self._server_process.stdin is not None
        assert self._server_process.stdout is not None

        # Setup asynchronous stdin reader
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        # Run duplex forwarding tasks
        try:
            await asyncio.gather(
                self._pipe_client_to_server(reader, self._server_process.stdin),
                self._pipe_server_to_client(self._server_process.stdout),
            )
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        """Terminate the server process and close streams."""
        self._running = False
        if self._server_process:
            try:
                self._server_process.terminate()
                await asyncio.wait_for(self._server_process.wait(), timeout=3.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                if self._server_process:
                    self._server_process.kill()
