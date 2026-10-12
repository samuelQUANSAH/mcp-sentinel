"""Server-Sent Events (SSE) HTTP Reverse Proxy Gateway for Model Context Protocol (MCP).

Intercepts remote MCP HTTP and SSE transports, gates tool execution, redacts PII/secrets,
blocks adversarial prompt injection attacks, and provides full audit telemetry.
"""

import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import httpx

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

logger = logging.getLogger("mcp_sentinel.sse_proxy")


class SSESentinelProxy:
    """Enterprise HTTP & SSE Reverse Proxy Gateway for remote MCP servers."""

    def __init__(
        self,
        upstream_url: str,
        host: str = "127.0.0.1",
        port: int = 8080,
        policy: Optional[GlobalPolicy] = None,
        audit_logger: Optional[AuditLogger] = None,
        client_id: str = "default_sse_client",
        roles: Optional[List[str]] = None,
    ):
        self.upstream_url = upstream_url.rstrip("/")
        self.host = host
        self.port = port
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

        self._server: Optional[asyncio.Server] = None
        self._running = False
        self._http_client: Optional[httpx.AsyncClient] = None

    @property
    def proxy_base_url(self) -> str:
        """Base URL on which the Sentinel SSE proxy is listening."""
        return f"http://{self.host}:{self.port}"

    async def _handle_tool_call(self, payload: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Dict[str, Any]]:
        """Gate a tool invocation against rate limits, policies, and injection guards.

        Returns:
            Tuple of (is_allowed, error_dict_if_blocked, sanitized_payload).
        """
        params = payload.get("params") or {}
        tool_name = params.get("name", "unknown_tool")
        arguments = params.get("arguments") or {}

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
            err_resp = {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {
                    "code": -32000,
                    "message": reason,
                    "data": {"retry_after_seconds": retry_after},
                },
            }
            return False, err_resp, payload

        # 2. Evaluate Policy & Prompt Injection Guard
        eval_result = self.policy_engine.evaluate_tool_call(
            tool_name=tool_name,
            arguments=arguments,
            roles=self.roles,
        )

        if not eval_result.allowed:
            is_injection = bool(
                eval_result.matched_rule and eval_result.matched_rule.startswith("injection_guard:")
            )
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
                    "injection_details": eval_result.injection_scan.model_dump()
                    if eval_result.injection_scan
                    else None,
                },
            )
            err_resp = {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {
                    "code": -32003,
                    "message": f"Security Policy Violation: {eval_result.reason}",
                    "data": {
                        "tool": tool_name,
                        "rule": eval_result.matched_rule,
                        "action": eval_result.action.value,
                    },
                },
            }
            return False, err_resp, payload

        # 3. Apply sanitized/redacted arguments
        payload["params"]["arguments"] = eval_result.redacted_arguments
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
        return True, None, payload

    def _sanitize_sse_message(self, raw_data: str) -> str:
        """Sanitize outbound SSE JSON-RPC tool result payloads."""
        try:
            parsed = json.loads(raw_data)
            if isinstance(parsed, dict) and "result" in parsed:
                clean_result, detected = self.result_redactor.redact_value(parsed["result"])
                if detected:
                    parsed["result"] = clean_result
                    self.auditor.log_tool_decision(
                        event_type=AuditEventType.PII_REDACTION,
                        tool_name="sse_sanitizer",
                        client_id=self.client_id,
                        status="REDACTED",
                        reason=f"Scrubbed sensitive entities in SSE result: {detected}",
                        details={"entities": detected},
                    )
                    return json.dumps(parsed)
        except Exception:
            pass
        return raw_data

    async def _handle_sse_stream(
        self, writer: asyncio.StreamWriter, query_string: str
    ) -> None:
        """Connect to upstream SSE endpoint and stream sanitized events downstream to client."""
        upstream_sse_url = f"{self.upstream_url}/sse"
        if query_string:
            upstream_sse_url += f"?{query_string}"

        # Send HTTP 200 SSE header to client
        response_headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
        )
        writer.write(response_headers.encode("utf-8"))
        await writer.drain()

        client = httpx.AsyncClient(timeout=None)
        try:
            async with client.stream("GET", upstream_sse_url) as stream:
                current_event: Optional[str] = None
                async for line in stream.aiter_lines():
                    if not self._running:
                        break

                    if line.startswith("event:"):
                        current_event = line.replace("event:", "", 1).strip()
                        writer.write(f"{line}\r\n".encode("utf-8"))
                        await writer.drain()
                    elif line.startswith("data:"):
                        data_content = line.replace("data:", "", 1).strip()

                        # Rewrite upstream endpoint event to point to Sentinel proxy
                        if current_event == "endpoint":
                            parsed_endpoint = urlparse(data_content)
                            endpoint_path = parsed_endpoint.path
                            if parsed_endpoint.query:
                                endpoint_path += f"?{parsed_endpoint.query}"
                            rewritten_data = f"{self.proxy_base_url}{endpoint_path}"
                            writer.write(f"data: {rewritten_data}\r\n\r\n".encode("utf-8"))
                            await writer.drain()
                            current_event = None
                        else:
                            # Sanitize PII / secrets from message payloads
                            sanitized_data = self._sanitize_sse_message(data_content)
                            writer.write(f"data: {sanitized_data}\r\n\r\n".encode("utf-8"))
                            await writer.drain()
                    elif line == "":
                        writer.write(b"\r\n")
                        await writer.drain()
                    else:
                        writer.write(f"{line}\r\n".encode("utf-8"))
                        await writer.drain()
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            logger.error("SSE upstream streaming error: %s", exc)
        finally:
            await client.aclose()

    async def _handle_messages_post(
        self,
        writer: asyncio.StreamWriter,
        path: str,
        query_string: str,
        body: bytes,
    ) -> None:
        """Handle incoming client JSON-RPC POST requests, evaluate security, and proxy to upstream."""
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            err = b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n{\"error\":\"Invalid JSON body\"}"
            writer.write(err)
            await writer.drain()
            return

        # If tools/call request, evaluate policies and guards
        if isinstance(payload, dict) and payload.get("method") == "tools/call":
            allowed, blocked_err, sanitized_payload = await self._handle_tool_call(payload)
            if not allowed and blocked_err:
                resp_bytes = json.dumps(blocked_err).encode("utf-8")
                response = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(resp_bytes)}\r\n"
                    f"Access-Control-Allow-Origin: *\r\n"
                    f"\r\n"
                ).encode("utf-8") + resp_bytes
                writer.write(response)
                await writer.drain()
                return
            payload = sanitized_payload

        # Forward request to upstream server
        upstream_post_url = f"{self.upstream_url}{path}"
        if query_string:
            upstream_post_url += f"?{query_string}"

        client = httpx.AsyncClient(timeout=60.0)
        try:
            upstream_resp = await client.post(
                upstream_post_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp_content = upstream_resp.content
            status_code = upstream_resp.status_code

            response = (
                f"HTTP/1.1 {status_code} OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(resp_content)}\r\n"
                f"Access-Control-Allow-Origin: *\r\n"
                f"\r\n"
            ).encode("utf-8") + resp_content
            writer.write(response)
            await writer.drain()
        except Exception as exc:
            logger.error("Failed forwarding POST request to upstream %s: %s", upstream_post_url, exc)
            err_content = json.dumps({"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": -32603, "message": f"Proxy upstream error: {exc}"}}).encode("utf-8")
            err_resp = (
                f"HTTP/1.1 502 Bad Gateway\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(err_content)}\r\n"
                f"\r\n"
            ).encode("utf-8") + err_content
            writer.write(err_resp)
            await writer.drain()
        finally:
            await client.aclose()

    async def _handle_client_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Parse incoming HTTP/1.1 connection and dispatch to SSE or POST router."""
        try:
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                return

            line_str = request_line.decode("utf-8").strip()
            parts = line_str.split(" ")
            if len(parts) < 2:
                writer.close()
                return

            method, full_path = parts[0].upper(), parts[1]
            parsed_url = urlparse(full_path)
            path = parsed_url.path
            query = parsed_url.query

            # Read HTTP Headers
            headers: Dict[str, str] = {}
            while True:
                header_line = await reader.readline()
                if not header_line or header_line in (b"\r\n", b"\n", b""):
                    break
                header_str = header_line.decode("utf-8").strip()
                if ":" in header_str:
                    hk, hv = header_str.split(":", 1)
                    headers[hk.strip().lower()] = hv.strip()

            # Handle Health & Status Check
            if path in ("/health", "/status"):
                body = json.dumps({
                    "status": "healthy",
                    "gateway": "mcp-sentinel-sse-proxy",
                    "upstream": self.upstream_url,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }).encode("utf-8")
                resp = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Access-Control-Allow-Origin: *\r\n"
                    f"\r\n"
                ).encode("utf-8") + body
                writer.write(resp)
                await writer.drain()
                writer.close()
                return

            # Handle CORS preflight requests
            if method == "OPTIONS":
                cors_resp = (
                    "HTTP/1.1 204 No Content\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                    "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                    "\r\n"
                ).encode("utf-8")
                writer.write(cors_resp)
                await writer.drain()
                writer.close()
                return

            # Dispatch SSE Stream
            if method == "GET" and path == "/sse":
                await self._handle_sse_stream(writer, query)
                writer.close()
                return

            # Dispatch POST Message
            if method == "POST":
                content_length = int(headers.get("content-length", 0))
                body = await reader.readexactly(content_length) if content_length > 0 else b""
                await self._handle_messages_post(writer, path, query, body)
                writer.close()
                return

            # Fallback 404
            not_found = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nRoute not found on Sentinel Proxy"
            writer.write(not_found)
            await writer.drain()
            writer.close()
        except Exception as exc:
            logger.error("Error processing client connection: %s", exc)
            try:
                writer.close()
            except Exception:
                pass

    async def start(self) -> None:
        """Start the asynchronous HTTP and SSE reverse proxy gateway."""
        self._running = True
        self._server = await asyncio.start_server(
            self._handle_client_connection, self.host, self.port
        )
        logger.info("MCP Sentinel SSE Gateway listening on %s -> Upstream: %s", self.proxy_base_url, self.upstream_url)
        async with self._server:
            await self._server.serve_forever()

    async def shutdown(self) -> None:
        """Gracefully stop proxy server."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
