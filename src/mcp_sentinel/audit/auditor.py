"""Enterprise audit trail logging to both SQLite relational tables and structured JSONL streams."""

import hashlib
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from mcp_sentinel.core.models import AuditEvent, AuditEventType


class AuditLogger:
    """Persists security events, tool calls, policy blocks, and PII redactor outcomes."""

    def __init__(self, db_path: Optional[str] = None, jsonl_path: Optional[str] = None):
        self.db_path = db_path or "audit_logs/sentinel_audit.sqlite"
        self.jsonl_path = jsonl_path or "audit_logs/sentinel_audit.jsonl"
        self._lock = threading.Lock()

        # Ensure directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.jsonl_path).parent.mkdir(parents=True, exist_ok=True)

        self._init_sqlite()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_sqlite(self) -> None:
        """Initialize the relational audit schema with indexes."""
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    tool_name TEXT,
                    client_id TEXT NOT NULL,
                    arguments_hash TEXT,
                    status TEXT NOT NULL,
                    reason TEXT,
                    duration_ms REAL,
                    details_json TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events (timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_events (tool_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_events (status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events (event_type)")
            conn.commit()

    @staticmethod
    def compute_payload_hash(payload: Any) -> str:
        """Generate SHA-256 fingerprint for audit argument integrity."""
        raw = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def record_event(self, event: AuditEvent) -> None:
        """Persist an audit event atomically to SQLite and append to JSONL."""
        event_dict = event.model_dump(mode="json")
        details_str = json.dumps(event.details, default=str)

        with self._lock:
            # 1. Insert into SQLite
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_events (
                        event_id, timestamp, event_type, tool_name, client_id,
                        arguments_hash, status, reason, duration_ms, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.event_id,
                        event.timestamp,
                        event.event_type.value,
                        event.tool_name,
                        event.client_id,
                        event.arguments_hash,
                        event.status,
                        event.reason,
                        event.duration_ms,
                        details_str,
                    ),
                )
                conn.commit()

            # 2. Append to JSONL file
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event_dict) + "\n")

    def log_tool_decision(
        self,
        event_type: AuditEventType,
        tool_name: str,
        client_id: str,
        status: str,
        reason: Optional[str] = None,
        duration_ms: Optional[float] = None,
        arguments: Optional[Dict[str, Any]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Convenience method to construct and record an audit event."""
        arg_hash = self.compute_payload_hash(arguments) if arguments else None
        event = AuditEvent(
            event_type=event_type,
            tool_name=tool_name,
            client_id=client_id,
            arguments_hash=arg_hash,
            status=status,
            reason=reason,
            duration_ms=duration_ms,
            details=details or {},
        )
        self.record_event(event)
        return event

    def query_events(
        self,
        limit: int = 50,
        event_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query recent audit events for compliance inspection or SOC review."""
        query = "SELECT * FROM audit_events WHERE 1=1"
        params: List[Any] = []

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            rows = cursor.execute(query, params).fetchall()
            return [dict(row) for row in rows]
