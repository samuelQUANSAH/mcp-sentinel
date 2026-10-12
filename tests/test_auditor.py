"""Unit tests for the SQLite and JSONL audit logging engine."""

import json
from pathlib import Path
import tempfile

from mcp_sentinel.audit.auditor import AuditLogger
from mcp_sentinel.core.models import AuditEventType


def test_audit_logger_sqlite_and_jsonl():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = str(Path(tmpdir) / "test_audit.sqlite")
        jsonl_path = str(Path(tmpdir) / "test_audit.jsonl")

        logger = AuditLogger(db_path=db_path, jsonl_path=jsonl_path)

        # Log an allowed tool execution
        ev1 = logger.log_tool_decision(
            event_type=AuditEventType.TOOL_CALL,
            tool_name="read_query",
            client_id="client_test",
            status="ALLOWED",
            arguments={"query": "SELECT * FROM users"},
        )
        assert ev1.event_id is not None
        assert ev1.arguments_hash is not None

        # Log a policy block
        ev2 = logger.log_tool_decision(
            event_type=AuditEventType.POLICY_BLOCK,
            tool_name="bash_exec",
            client_id="client_test",
            status="BLOCKED",
            reason="Forbidden rm -rf",
            arguments={"cmd": "rm -rf /"},
        )

        # Query back from SQLite
        all_events = logger.query_events(limit=10)
        assert len(all_events) == 2

        blocked_events = logger.query_events(limit=10, status="BLOCKED")
        assert len(blocked_events) == 1
        assert blocked_events[0]["tool_name"] == "bash_exec"

        # Verify JSONL lines
        lines = Path(jsonl_path).read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        p1 = json.loads(lines[0])
        assert p1["tool_name"] == "read_query"
