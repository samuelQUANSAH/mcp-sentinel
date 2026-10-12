"""Declarative policy evaluation engine for fine-grained MCP tool authorization and input validation."""

import fnmatch
import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from mcp_sentinel.core.models import GlobalPolicy, PolicyAction, ToolRule
from mcp_sentinel.security.pii_redactor import PIIRedactor


class PolicyEvaluationResult(BaseModel):
    """Result payload produced when evaluating a tool call against the security policy."""

    allowed: bool
    action: PolicyAction
    matched_rule: Optional[str] = None
    reason: Optional[str] = None
    redacted_arguments: Dict[str, Any] = Field(default_factory=dict)
    pii_entities_detected: List[str] = Field(default_factory=list)
    rate_limit_override: Optional[int] = None


class PolicyEngine:
    """Evaluates incoming tool invocations against compiled rules, RBAC, and parameter validators."""

    def __init__(self, policy: Optional[GlobalPolicy] = None):
        self.policy = policy or GlobalPolicy()
        self.redactor = PIIRedactor(
            enable_pii=self.policy.enable_pii_redaction,
            enable_secrets=self.policy.enable_secret_redaction,
        )
        self._compiled_regex_cache: Dict[str, re.Pattern] = {}

    def _get_compiled_regex(self, pattern: str) -> re.Pattern:
        """Cache compiled regex objects for high-throughput rule evaluation."""
        if pattern not in self._compiled_regex_cache:
            self._compiled_regex_cache[pattern] = re.compile(pattern, re.IGNORECASE)
        return self._compiled_regex_cache[pattern]

    def _match_tool_rule(self, tool_name: str) -> Optional[ToolRule]:
        """Find the first matching ToolRule for a tool name using exact match or glob pattern."""
        for rule in self.policy.rules:
            if rule.tool_pattern == tool_name or fnmatch.fnmatch(tool_name, rule.tool_pattern):
                return rule
        return None

    def evaluate_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        roles: Optional[List[str]] = None,
    ) -> PolicyEvaluationResult:
        """Evaluate a tool invocation against active security policies.

        Args:
            tool_name: Name of the tool being called
            arguments: Dictionary of input parameters
            roles: Optional list of authorization roles possessed by the caller

        Returns:
            PolicyEvaluationResult determining whether execution proceeds.
        """
        caller_roles = set(roles or ["default"])

        # 1. Redact PII / Secrets in incoming arguments
        redacted_args, detected_pii = self.redactor.redact_value(arguments)

        # 2. Check tool-level rule match
        matched_rule = self._match_tool_rule(tool_name)

        if not matched_rule:
            # Fallback to default policy action
            if self.policy.default_action == PolicyAction.DENY:
                return PolicyEvaluationResult(
                    allowed=False,
                    action=PolicyAction.DENY,
                    matched_rule="default_action",
                    reason=f"Tool '{tool_name}' is blocked by default policy",
                    redacted_arguments=redacted_args,
                    pii_entities_detected=detected_pii,
                )
            return PolicyEvaluationResult(
                allowed=True,
                action=PolicyAction.ALLOW,
                matched_rule="default_action",
                redacted_arguments=redacted_args,
                pii_entities_detected=detected_pii,
            )

        # 3. Check Role-Based Access Control (RBAC)
        if matched_rule.allowed_roles:
            if not any(role in caller_roles for role in matched_rule.allowed_roles):
                return PolicyEvaluationResult(
                    allowed=False,
                    action=PolicyAction.DENY,
                    matched_rule=matched_rule.tool_pattern,
                    reason=f"Role unauthorized to invoke tool '{tool_name}'. Required: {matched_rule.allowed_roles}",
                    redacted_arguments=redacted_args,
                    pii_entities_detected=detected_pii,
                )

        # 4. Check Tool-Level Action
        if matched_rule.action == PolicyAction.DENY:
            return PolicyEvaluationResult(
                allowed=False,
                action=PolicyAction.DENY,
                matched_rule=matched_rule.tool_pattern,
                reason=matched_rule.description or f"Tool '{tool_name}' is explicitly denied by policy",
                redacted_arguments=redacted_args,
                pii_entities_detected=detected_pii,
            )

        # 5. Evaluate Parameter/Argument Rules
        for arg_rule in matched_rule.argument_rules:
            param_val = arguments.get(arg_rule.param_name)
            if param_val is not None:
                str_val = str(param_val)

                # Check forbidden pattern
                if arg_rule.forbidden_regex:
                    compiled = self._get_compiled_regex(arg_rule.forbidden_regex)
                    if compiled.search(str_val):
                        msg = arg_rule.message or (
                            f"Argument '{arg_rule.param_name}' matches forbidden security pattern "
                            f"'{arg_rule.forbidden_regex}'"
                        )
                        return PolicyEvaluationResult(
                            allowed=False,
                            action=arg_rule.action,
                            matched_rule=f"{matched_rule.tool_pattern}:{arg_rule.param_name}",
                            reason=msg,
                            redacted_arguments=redacted_args,
                            pii_entities_detected=detected_pii,
                            rate_limit_override=matched_rule.rate_limit_per_minute,
                        )

                # Check required match pattern
                if arg_rule.match_regex:
                    compiled = self._get_compiled_regex(arg_rule.match_regex)
                    if not compiled.search(str_val):
                        msg = arg_rule.message or (
                            f"Argument '{arg_rule.param_name}' does not satisfy required pattern "
                            f"'{arg_rule.match_regex}'"
                        )
                        return PolicyEvaluationResult(
                            allowed=False,
                            action=arg_rule.action,
                            matched_rule=f"{matched_rule.tool_pattern}:{arg_rule.param_name}",
                            reason=msg,
                            redacted_arguments=redacted_args,
                            pii_entities_detected=detected_pii,
                            rate_limit_override=matched_rule.rate_limit_per_minute,
                        )

        # If tool requires manual approval
        if matched_rule.action == PolicyAction.REQUIRE_APPROVAL:
            return PolicyEvaluationResult(
                allowed=False,
                action=PolicyAction.REQUIRE_APPROVAL,
                matched_rule=matched_rule.tool_pattern,
                reason="Human-in-the-loop manual approval required before execution",
                redacted_arguments=redacted_args,
                pii_entities_detected=detected_pii,
                rate_limit_override=matched_rule.rate_limit_per_minute,
            )

        return PolicyEvaluationResult(
            allowed=True,
            action=PolicyAction.ALLOW,
            matched_rule=matched_rule.tool_pattern,
            redacted_arguments=redacted_args,
            pii_entities_detected=detected_pii,
            rate_limit_override=matched_rule.rate_limit_per_minute,
        )
