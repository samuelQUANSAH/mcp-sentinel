"""Unit tests for the declarative policy engine and argument inspection."""

from mcp_sentinel.core.models import (
    ArgumentRule,
    GlobalPolicy,
    PolicyAction,
    ToolRule,
)
from mcp_sentinel.security.policy_engine import PolicyEngine


def build_test_policy() -> GlobalPolicy:
    return GlobalPolicy(
        default_action=PolicyAction.ALLOW,
        rules=[
            ToolRule(
                tool_pattern="bash*",
                action=PolicyAction.ALLOW,
                argument_rules=[
                    ArgumentRule(
                        param_name="cmd",
                        forbidden_regex=r"rm\s+-rf\s+/",
                        action=PolicyAction.DENY,
                        message="Root wipe blocked",
                    )
                ],
            ),
            ToolRule(
                tool_pattern="sql*",
                action=PolicyAction.ALLOW,
                argument_rules=[
                    ArgumentRule(
                        param_name="query",
                        forbidden_regex=r"\bDROP\s+TABLE\b",
                        action=PolicyAction.DENY,
                        message="DROP TABLE blocked",
                    )
                ],
            ),
            ToolRule(
                tool_pattern="admin_*",
                action=PolicyAction.ALLOW,
                allowed_roles=["admin", "secops"],
                description="Admin restricted",
            ),
            ToolRule(
                tool_pattern="dangerous_operation",
                action=PolicyAction.REQUIRE_APPROVAL,
                description="Manual approval needed",
            ),
        ],
    )


def test_allowed_bash_command():
    engine = PolicyEngine(build_test_policy())
    res = engine.evaluate_tool_call("bash_exec", {"cmd": "ls -la /home"})
    assert res.allowed is True
    assert res.action == PolicyAction.ALLOW


def test_blocked_destructive_bash_command():
    engine = PolicyEngine(build_test_policy())
    res = engine.evaluate_tool_call("bash_exec", {"cmd": "rm -rf / --no-preserve-root"})
    assert res.allowed is False
    assert res.action == PolicyAction.DENY
    assert "Root wipe blocked" in res.reason


def test_blocked_sql_drop():
    engine = PolicyEngine(build_test_policy())
    res = engine.evaluate_tool_call("sql_query", {"query": "DROP TABLE accounts;"})
    assert res.allowed is False
    assert res.action == PolicyAction.DENY
    assert "DROP TABLE blocked" in res.reason


def test_rbac_denial_and_grant():
    engine = PolicyEngine(build_test_policy())
    # Unauthorized role
    denied = engine.evaluate_tool_call("admin_reset", {}, roles=["developer"])
    assert denied.allowed is False
    assert "Role unauthorized" in denied.reason

    # Authorized role
    granted = engine.evaluate_tool_call("admin_reset", {}, roles=["admin"])
    assert granted.allowed is True


def test_require_approval_action():
    engine = PolicyEngine(build_test_policy())
    res = engine.evaluate_tool_call("dangerous_operation", {})
    assert res.allowed is False
    assert res.action == PolicyAction.REQUIRE_APPROVAL
    assert "manual approval required" in res.reason.lower()


def test_pii_sanitization_in_arguments():
    engine = PolicyEngine(build_test_policy())
    res = engine.evaluate_tool_call("save_note", {"text": "Note with email john@doe.com"})
    assert res.allowed is True
    assert "[REDACTED_EMAIL]" in res.redacted_arguments["text"]
    assert "EMAIL" in res.pii_entities_detected
