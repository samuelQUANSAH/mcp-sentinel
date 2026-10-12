"""Command-line interface for running the MCP Sentinel proxy, querying audits, and validating policies."""

import argparse
import asyncio
import json
from pathlib import Path
import sys
from typing import List, Optional

from mcp_sentinel.audit.auditor import AuditLogger
from mcp_sentinel.core.config import dump_policy_yaml, load_policy
from mcp_sentinel.core.models import (
    ArgumentRule,
    GlobalPolicy,
    PolicyAction,
    ToolRule,
)
from mcp_sentinel.proxy.stdio_proxy import StdioSentinelProxy


def generate_starter_policy() -> GlobalPolicy:
    """Generate a production-grade default security policy."""
    return GlobalPolicy(
        policy_name="enterprise-mcp-guardrails",
        version="1.0",
        default_action=PolicyAction.ALLOW,
        enable_pii_redaction=True,
        enable_secret_redaction=True,
        rate_limit_per_minute=60,
        rules=[
            ToolRule(
                tool_pattern="bash*",
                action=PolicyAction.ALLOW,
                description="Guardrails on bash/terminal execution commands",
                argument_rules=[
                    ArgumentRule(
                        param_name="command",
                        forbidden_regex=r"(rm\s+-rf\s+[/~]|mkfs|dd\s+if=|:(){:|chmod\s+-R\s+777\s+/)",
                        action=PolicyAction.DENY,
                        message="Destructive system deletion commands are prohibited by security policy",
                    ),
                    ArgumentRule(
                        param_name="command",
                        forbidden_regex=r"(curl|wget)\s+.*\|\s*(bash|sh|zsh)",
                        action=PolicyAction.DENY,
                        message="Direct remote pipe-to-shell is strictly prohibited",
                    ),
                ],
            ),
            ToolRule(
                tool_pattern="sql*",
                action=PolicyAction.ALLOW,
                description="SQL database query guardrails",
                argument_rules=[
                    ArgumentRule(
                        param_name="query",
                        forbidden_regex=r"\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|ALTER\s+TABLE)\b",
                        action=PolicyAction.DENY,
                        message="DDL drop/truncate schema alteration commands are blocked in production",
                    ),
                ],
            ),
            ToolRule(
                tool_pattern="admin_*",
                action=PolicyAction.REQUIRE_APPROVAL,
                description="Administrative tools require explicit human approval",
                allowed_roles=["admin", "secops"],
            ),
        ],
    )


def cmd_proxy(args: argparse.Namespace) -> int:
    """Execute stdio proxy wrapping the target server command."""
    if not args.cmd:
        print("Error: No server command specified. Example: mcp-sentinel proxy -- npx -y @modelcontextprotocol/server-everything", file=sys.stderr)
        return 1

    try:
        policy = load_policy(args.policy) if args.policy else generate_starter_policy()
    except Exception as exc:
        print(f"Error loading policy: {exc}", file=sys.stderr)
        return 1

    audit_logger = AuditLogger(db_path=args.audit_db)
    roles = [r.strip() for r in args.roles.split(",")] if args.roles else ["default"]

    proxy = StdioSentinelProxy(
        server_command=args.cmd,
        policy=policy,
        audit_logger=audit_logger,
        client_id=args.client_id,
        roles=roles,
    )

    try:
        asyncio.run(proxy.start())
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"Fatal proxy runtime error: {exc}", file=sys.stderr)
        return 1


def cmd_audit(args: argparse.Namespace) -> int:
    """Query and display audit events from the SQLite store."""
    logger = AuditLogger(db_path=args.audit_db)
    events = logger.query_events(limit=args.limit, event_type=args.type, status=args.status)

    if not events:
        print("No audit events recorded yet.")
        return 0

    print(f"\n{'TIMESTAMP':<28} | {'TYPE':<16} | {'TOOL':<18} | {'STATUS':<10} | {'REASON'}")
    print("-" * 100)
    for ev in events:
        ts = ev.get("timestamp", "")[:26]
        ev_type = ev.get("event_type", "")
        tool = (ev.get("tool_name") or "-")[:17]
        status = ev.get("status", "")
        reason = ev.get("reason") or ""
        print(f"{ts:<28} | {ev_type:<16} | {tool:<18} | {status:<10} | {reason}")
    print(f"\nTotal queried: {len(events)} events\n")
    return 0


def cmd_init_policy(args: argparse.Namespace) -> int:
    """Generate default starter policy file."""
    output_path = Path(args.output)
    policy = generate_starter_policy()
    dump_policy_yaml(policy, output_path)
    print(f"✓ Starter security policy written to {output_path.resolve()}")
    return 0


def cmd_validate_policy(args: argparse.Namespace) -> int:
    """Validate a YAML or JSON security policy file."""
    try:
        policy = load_policy(args.policy)
        print(f"✓ Policy '{policy.policy_name}' (version {policy.version}) validated successfully.")
        print(f"  • Default action: {policy.default_action.value}")
        print(f"  • PII redaction: {policy.enable_pii_redaction}")
        print(f"  • Secret redaction: {policy.enable_secret_redaction}")
        print(f"  • Global rate limit: {policy.rate_limit_per_minute}/min")
        print(f"  • Configured tool rules: {len(policy.rules)}")
        return 0
    except Exception as exc:
        print(f"✗ Policy validation failed: {exc}", file=sys.stderr)
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI argument parser and dispatcher."""
    parser = argparse.ArgumentParser(
        prog="mcp-sentinel",
        description="Enterprise Security, Policy Enforcement & PII Redaction Gateway for the Model Context Protocol (MCP)",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # Proxy command
    proxy_parser = subparsers.add_parser("proxy", help="Run the stdio security gateway wrapping a backend MCP server")
    proxy_parser.add_argument("--policy", type=str, default=None, help="Path to YAML/JSON policy definition")
    proxy_parser.add_argument("--audit-db", type=str, default="audit_logs/sentinel_audit.sqlite", help="SQLite audit store path")
    proxy_parser.add_argument("--client-id", type=str, default="client-local", help="Client or session identifier")
    proxy_parser.add_argument("--roles", type=str, default="default", help="Comma-separated caller roles (e.g. user,developer)")
    proxy_parser.add_argument("cmd", nargs=argparse.REMAINDER, help="MCP server command to launch and proxy (e.g. -- python server.py)")

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="Inspect security audit events from the SQLite audit database")
    audit_parser.add_argument("--audit-db", type=str, default="audit_logs/sentinel_audit.sqlite", help="SQLite audit store path")
    audit_parser.add_argument("--limit", type=int, default=25, help="Maximum events to return")
    audit_parser.add_argument("--type", type=str, default=None, help="Filter by event type (tool_call, policy_block, pii_redaction)")
    audit_parser.add_argument("--status", type=str, default=None, help="Filter by status (ALLOWED, BLOCKED, REDACTED)")

    # Init-policy command
    init_parser = subparsers.add_parser("init-policy", help="Create a starter sentinel_policy.yaml with enterprise rules")
    init_parser.add_argument("--output", type=str, default="config/sentinel_policy.yaml", help="Destination policy filepath")

    # Validate-policy command
    val_parser = subparsers.add_parser("validate-policy", help="Validate syntax and regex patterns in a policy file")
    val_parser.add_argument("--policy", type=str, required=True, help="Path to policy YAML/JSON file")

    parsed_args = parser.parse_args(argv)
    if not parsed_args.subcommand:
        parser.print_help()
        return 0

    # Strip leading '--' separator from cmd if present in proxy mode
    if parsed_args.subcommand == "proxy" and parsed_args.cmd and parsed_args.cmd[0] == "--":
        parsed_args.cmd = parsed_args.cmd[1:]

    handlers = {
        "proxy": cmd_proxy,
        "audit": cmd_audit,
        "init-policy": cmd_init_policy,
        "validate-policy": cmd_validate_policy,
    }
    return handlers[parsed_args.subcommand](parsed_args)


if __name__ == "__main__":
    sys.exit(main())
