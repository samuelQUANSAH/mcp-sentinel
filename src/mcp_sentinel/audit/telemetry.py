"""OpenTelemetry distributed tracing and metrics instrumentation for MCP tool invocations."""

from contextlib import asynccontextmanager
import time
from typing import Any, AsyncGenerator, Dict, Optional

try:
    from opentelemetry import trace
    from opentelemetry.trace import Status, StatusCode
    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False


class TelemetryProvider:
    """Manages telemetry spans and metrics instrumentation for MCP tool executions."""

    def __init__(self, service_name: str = "mcp-sentinel"):
        self.service_name = service_name
        if HAS_OTEL:
            self.tracer = trace.get_tracer(service_name)
        else:
            self.tracer = None

    @asynccontextmanager
    async def trace_tool_call(
        self,
        tool_name: str,
        client_id: str,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Async context manager recording execution duration and span attributes."""
        start_time = time.monotonic()
        context: Dict[str, Any] = {
            "tool_name": tool_name,
            "client_id": client_id,
            "status": "UNKNOWN",
            "duration_ms": 0.0,
        }

        if HAS_OTEL and self.tracer:
            with self.tracer.start_as_current_span(f"mcp.tool_call.{tool_name}") as span:
                span.set_attribute("mcp.tool.name", tool_name)
                span.set_attribute("mcp.client.id", client_id)
                try:
                    yield context
                    context["duration_ms"] = (time.monotonic() - start_time) * 1000.0
                    span.set_attribute("mcp.decision.status", context.get("status", "UNKNOWN"))
                    span.set_attribute("mcp.duration_ms", context["duration_ms"])
                    if context.get("status") in ["ALLOWED", "REDACTED"]:
                        span.set_status(Status(StatusCode.OK))
                    else:
                        span.set_status(Status(StatusCode.ERROR, description=context.get("reason", "Blocked")))
                except Exception as exc:
                    span.record_exception(exc)
                    span.set_status(Status(StatusCode.ERROR, description=str(exc)))
                    raise
        else:
            # Fallback zero-overhead timer without external OTel dependencies
            try:
                yield context
            finally:
                context["duration_ms"] = (time.monotonic() - start_time) * 1000.0
