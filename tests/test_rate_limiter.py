"""Unit tests for sliding-window rate limiter."""

import time

from mcp_sentinel.security.rate_limiter import SlidingWindowRateLimiter


def test_rate_limiter_within_capacity():
    limiter = SlidingWindowRateLimiter(default_limit=5, window_seconds=10.0)
    for _ in range(5):
        allowed, retry_after, remaining = limiter.check_and_consume("client_1")
        assert allowed is True
        assert retry_after == 0.0

    # 6th attempt exceeds capacity
    allowed, retry_after, remaining = limiter.check_and_consume("client_1")
    assert allowed is False
    assert retry_after > 0.0
    assert remaining == 0


def test_rate_limiter_isolation_between_clients():
    limiter = SlidingWindowRateLimiter(default_limit=2, window_seconds=10.0)
    assert limiter.check_and_consume("client_A")[0] is True
    assert limiter.check_and_consume("client_A")[0] is True
    assert limiter.check_and_consume("client_A")[0] is False

    # client_B should still have full quota
    assert limiter.check_and_consume("client_B")[0] is True
    assert limiter.check_and_consume("client_B")[0] is True
    assert limiter.check_and_consume("client_B")[0] is False


def test_rate_limiter_tool_specific_override():
    limiter = SlidingWindowRateLimiter(default_limit=10, window_seconds=10.0)
    # Tool specific limit of 1
    assert limiter.check_and_consume("client_1", tool_name="dangerous_tool", tool_limit=1)[0] is True
    assert limiter.check_and_consume("client_1", tool_name="dangerous_tool", tool_limit=1)[0] is False

    # Another tool should still pass under global limit
    assert limiter.check_and_consume("client_1", tool_name="safe_tool")[0] is True
