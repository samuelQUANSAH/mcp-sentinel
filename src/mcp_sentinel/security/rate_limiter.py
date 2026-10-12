"""Sliding window velocity limiter preventing runaway tool execution loops in autonomous agents."""

from collections import deque
import threading
import time
from typing import Dict, Optional, Tuple


class SlidingWindowRateLimiter:
    """Sliding-window memory rate limiter for tracking tool invocation frequencies."""

    def __init__(self, default_limit: int = 120, window_seconds: float = 60.0):
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        # client_id -> deque of timestamps
        self._global_timestamps: Dict[str, deque] = {}
        # (client_id, tool_name) -> deque of timestamps
        self._tool_timestamps: Dict[Tuple[str, str], deque] = {}
        self._lock = threading.Lock()

    def check_and_consume(
        self,
        client_id: str,
        tool_name: Optional[str] = None,
        tool_limit: Optional[int] = None,
    ) -> Tuple[bool, float, int]:
        """Verify if invocation is within rate limits and record execution if allowed.

        Args:
            client_id: Unique identifier for calling client/session
            tool_name: Specific tool being invoked
            tool_limit: Optional tool-specific velocity cap (overrides default_limit)

        Returns:
            Tuple of:
                allowed (bool): True if allowed, False if exceeded
                retry_after (float): Seconds until the client can retry
                remaining (int): Remaining invocations available in current window
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds

        with self._lock:
            # 1. Evaluate tool-specific rate limit if specified
            if tool_name and tool_limit is not None:
                key = (client_id, tool_name)
                if key not in self._tool_timestamps:
                    self._tool_timestamps[key] = deque()
                deq = self._tool_timestamps[key]

                # Evict expired entries
                while deq and deq[0] <= cutoff:
                    deq.popleft()

                if len(deq) >= tool_limit:
                    oldest = deq[0]
                    retry_after = max(0.0, self.window_seconds - (now - oldest))
                    return False, retry_after, 0

            # 2. Evaluate global client velocity cap
            if client_id not in self._global_timestamps:
                self._global_timestamps[client_id] = deque()
            global_deq = self._global_timestamps[client_id]

            while global_deq and global_deq[0] <= cutoff:
                global_deq.popleft()

            if len(global_deq) >= self.default_limit:
                oldest = global_deq[0]
                retry_after = max(0.0, self.window_seconds - (now - oldest))
                return False, retry_after, 0

            # Allowed - record timestamp
            global_deq.append(now)
            if tool_name and tool_limit is not None:
                self._tool_timestamps[(client_id, tool_name)].append(now)

            remaining = self.default_limit - len(global_deq)
            return True, 0.0, max(0, remaining)

    def reset(self) -> None:
        """Clear all active client rate limit windows."""
        with self._lock:
            self._global_timestamps.clear()
            self._tool_timestamps.clear()
