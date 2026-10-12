# 🛡️ MCP Sentinel

> **Enterprise Security, Policy Enforcement & PII Redaction Gateway for the Model Context Protocol (MCP)**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-brightgreen.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-36%2F36%20Passing-success.svg)]()
[![Architecture](https://img.shields.io/badge/Architecture-Clean%20Architecture%20%2F%20Zero--Trust-orange.svg)]()

---

## 📌 Executive Summary

The **Model Context Protocol (MCP)** is the open industry standard enabling LLMs and autonomous agents (Claude Desktop, Cursor, Antigravity, Claude Code) to invoke external tools, query databases, and manipulate local environments.

However, **native MCP has zero security guardrails**:
- An indirect prompt injection can trick an agent into executing destructive commands (`rm -rf /`, `DROP TABLE users;`).
- Sensitive PII (SSNs, credit card numbers, confidential emails) or API keys (`OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`) exposed in tool results are ingested directly into the model context window.
- Rogue loops or runaway agent reasoning can spam upstream APIs without velocity or cost limits.
- Regulated enterprises (HIPAA, SOC 2, FedRAMP, PCI-DSS) cannot audit tool invocations with forensic integrity.

**MCP Sentinel** is an ultra-low-latency, asynchronous security reverse-proxy and governance gateway that transparently wraps any MCP server across both **`stdio`** and **`SSE` (Server-Sent Events)** transports. It intercepts JSON-RPC 2.0 wire frames to enforce zero-trust policies, scrub sensitive data in real time, block adversarial prompt injection attacks, apply rate limits, and record cryptographic audit trails.

---

## 🏛️ High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 MCP Clients (Claude Desktop, Cursor, Antigravity)           │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ JSON-RPC 2.0 (stdio / SSE)
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           🛡️ MCP SENTINEL GATEWAY                           │
│                                                                             │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌─────────────────┐  │
│  │ Sliding Window        │  │ Declarative Policy    │  │ PII & Secret    │  │
│  │ Rate Limiter          │  │ Engine & RBAC         │  │ Redaction Engine│  │
│  │ (Velocity Protection) │  │ (Regex / Deny Rules)  │  │ (Luhn, SSN, API)│  │
│  └───────────┬───────────┘  └───────────┬───────────┘  └────────┬────────┘  │
│              │                          │                       │           │
│              └──────────────────────────┼───────────────────────┘           │
│                                         │                                   │
│                        ┌────────────────▼────────────────┐                  │
│                        │ Dual Audit & Telemetry Engine   │                  │
│                        │ • SQLite Indexed Relational DB  │                  │
│                        │ • Append-Only JSONL Event Stream│                  │
│                        │ • OpenTelemetry Spans & Tracing │                  │
│                        └────────────────┬────────────────┘                  │
└─────────────────────────────────────────┼───────────────────────────────────┘
                                          │ Sanitized & Authorized Frames
                                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                  Downstream MCP Servers (Filesystem, SQL, APIs)              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## ✨ Core Capabilities

### 1. Declarative Zero-Trust Policy Engine
- **Tool-Level Routing**: Match exact names or wildcards (`sql_*`, `bash*`, `admin_*`).
- **Deep Parameter Inspection**: Evaluate tool arguments with high-performance pre-compiled regular expressions to block SQL injection, destructive shell commands, and path traversals.
- **Role-Based Access Control (RBAC)**: Restrict privileged tool execution to specific authenticated roles (`admin`, `secops`).
- **Human-In-The-Loop (HITL)**: Configure sensitive operations (`action: require_approval`) to halt execution until manual confirmation is granted.

### 2. High-Precision PII & Secret Redaction
- **Credit Card Numbers**: Scanned with regex and validated via the **Luhn Checksum Algorithm** to prevent false positives.
- **PII Scrubbing**: Automatic detection and masking of US Social Security Numbers (`[REDACTED_SSN]`), email addresses, and phone numbers.
- **Credential & API Key Guard**: Real-time scrubbing of OpenAI API keys (`sk-...`), AWS Access Keys (`AKIA...`), Anthropic keys (`sk-ant-...`), GitHub PATs (`ghp_...`), and Bearer JWT tokens.
- **Bidirectional Sanitization**: Scrubs both incoming arguments and outbound tool result payloads before they enter the model context.

### 3. Sliding-Window Rate Limiting
- Thread-safe sliding window algorithm preventing runaway agent loops and API credit exhaustion.
- Supports both global client caps and granular per-tool velocity overrides with dynamic `retry_after` backoff calculations.

### 4. Forensic Audit Trail & Telemetry
- **SQLite Relational Store**: Indexed table tracking event timestamps, tool names, execution status (`ALLOWED`, `BLOCKED`, `REDACTED`), latency, and error codes.
- **Cryptographic Payload Fingerprinting**: Computes deterministic SHA-256 hashes of arguments for non-repudiation without storing cleartext sensitive data.
- **OpenTelemetry Native**: Emits distributed tracing spans and metrics for enterprise SOC / SIEM dashboards (Datadog, Grafana, Honeycomb).

---

## 🚀 Quickstart

### Installation

```bash
git clone https://github.com/samuelQUANSAH/mcp-sentinel.git
cd mcp-sentinel
pip install -e .
```

### 1. Initialize Default Enterprise Policy

```bash
mcp-sentinel init-policy --output config/sentinel_policy.yaml
```

### 2. Validate Security Policy

```bash
mcp-sentinel validate-policy --policy config/sentinel_policy.yaml
```

### 3. Run the Security Gateway

Wrap any existing MCP server command with `mcp-sentinel proxy`:

```bash
# Example: Secure a local stdio MCP Server
mcp-sentinel proxy \
  --policy config/sentinel_policy.yaml \
  --client-id agent-session-42 \
  -- python -m mcp_server_sqlite --db-path ./data/app.db
```

### 4. Run the Remote SSE Gateway (HTTP / SSE Transport)

Protect remote or cloud-hosted MCP servers with `mcp-sentinel sse-proxy`:

```bash
# Example: Run reverse proxy in front of remote MCP server on port 8000
mcp-sentinel sse-proxy \
  --upstream http://localhost:8000 \
  --host 127.0.0.1 \
  --port 8080 \
  --policy config/sentinel_policy.yaml \
  --client-id web-agent-client
```

Clients (Cursor, Claude Desktop, or web apps) connect to `http://127.0.0.1:8080/sse`. Sentinel dynamically intercepts the SSE stream, rewrites the message endpoint to route through Sentinel, redacts downstream PII/secrets, blocks prompt injections, and logs audit events.

### 5. Inspect Forensic Audit Logs

```bash
mcp-sentinel audit --limit 10
```

Sample output:
```text
TIMESTAMP                  | TYPE             | TOOL               | STATUS     | REASON
----------------------------------------------------------------------------------------------------
2026-10-12T19:30:00.123456 | tool_call        | bash_exec          | ALLOWED    | Passed policy evaluation
2026-10-12T19:30:02.789101 | policy_block     | bash_exec          | BLOCKED    | Destructive root deletion blocked
2026-10-12T19:30:05.456789 | pii_redaction    | response_sanitizer | REDACTED   | Scrubbed sensitive entities: ['EMAIL', 'OPENAI_KEY']
```

---

## ⚙️ Configuration Reference (`sentinel_policy.yaml`)

```yaml
version: "1.0"
policy_name: enterprise-sentinel-guardrails
default_action: allow
enable_pii_redaction: true
enable_secret_redaction: true
rate_limit_per_minute: 60

rules:
  # Block destructive shell wipes and remote pipe-to-shell attacks
  - tool_pattern: "bash*"
    action: allow
    description: "Guardrails on bash/terminal execution commands"
    argument_rules:
      - param_name: command
        forbidden_regex: "(rm\\s+-rf\\s+[/~]|mkfs|dd\\s+if=|:(){:|chmod\\s+-R\\s+777\\s+/)"
        action: deny
        message: "Destructive filesystem deletion commands are prohibited by security policy"
      - param_name: command
        forbidden_regex: "(curl|wget)\\s+.*\\|\\s*(bash|sh|zsh)"
        action: deny
        message: "Remote pipe-to-shell execution is strictly prohibited"

  # Protect database tables from DDL drop or truncate commands
  - tool_pattern: "sql*"
    action: allow
    description: "SQL database query guardrails"
    argument_rules:
      - param_name: query
        forbidden_regex: "\\b(DROP\\s+TABLE|DROP\\s+DATABASE|TRUNCATE\\s+TABLE|ALTER\\s+TABLE)\\b"
        action: deny
        message: "DDL drop and truncate schema mutations are blocked in production"

  # Restrict administrative operations to SecOps engineers
  - tool_pattern: "admin_*"
    action: require_approval
    allowed_roles:
      - admin
      - secops
    description: "Administrative tools require human-in-the-loop approval and secops role"
```

---

## 🖥️ Integration with Claude Desktop

Add `mcp-sentinel` directly into your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "secured-filesystem": {
      "command": "mcp-sentinel",
      "args": [
        "proxy",
        "--policy", "/path/to/sentinel_policy.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/username/Desktop"
      ]
    }
  }
}
```

---

## 🧪 Testing

Run the automated test suite:

```bash
pytest -v
```

```text
tests/test_auditor.py .                                                  [  2%]
tests/test_injection_guard.py ..........                                 [ 30%]
tests/test_models.py .....                                               [ 44%]
tests/test_pii_redactor.py .....                                         [ 58%]
tests/test_policy_engine.py ......                                       [ 75%]
tests/test_rate_limiter.py ...                                           [ 83%]
tests/test_sse_proxy.py ..                                               [ 88%]
tests/test_stdio_proxy.py ....                                           [100%]

============================== 36 passed in 2.25s ==============================
```

---

## 👨‍💻 Author

**Samuel K. Quansah**
- AI Systems Architect & Forward Deployed Engineer
- M.S. Cybersecurity (4.00 GPA) | M.S. Computer Information Systems (3.87 GPA)
- U.S. Navy Veteran (Secret Clearance)
- GitHub: [@samuelQUANSAH](https://github.com/samuelQUANSAH)

---

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
