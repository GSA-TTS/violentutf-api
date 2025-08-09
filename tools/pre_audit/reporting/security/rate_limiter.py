"""
Rate limiting for report generation.

This module provides rate limiting to prevent DoS attacks
through excessive report generation.
"""

import logging
import threading
import time
from collections import deque
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Simple rate limiter for report generation.

    Implements a sliding window rate limiter to prevent
    excessive report generation that could DoS the system.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        """
        Initialize rate limiter.

        Args:
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = deque()
        self.lock = threading.Lock()

        # Statistics
        self.stats = {"allowed": 0, "denied": 0, "total": 0}

    def allow_request(self, identifier: Optional[str] = None) -> bool:
        """
        Check if request should be allowed.

        Args:
            identifier: Optional identifier for request source

        Returns:
            True if request allowed, False otherwise
        """
        current_time = time.time()

        with self.lock:
            # Update statistics
            self.stats["total"] += 1

            # Remove old requests outside window
            cutoff_time = current_time - self.window_seconds
            while self.requests and self.requests[0] < cutoff_time:
                self.requests.popleft()

            # Check if under limit
            if len(self.requests) < self.max_requests:
                self.requests.append(current_time)
                self.stats["allowed"] += 1

                if identifier:
                    logger.debug(f"Rate limit: Allowed request from {identifier}")

                return True
            else:
                self.stats["denied"] += 1

                if identifier:
                    logger.warning(
                        f"Rate limit: Denied request from {identifier}. "
                        f"Limit {self.max_requests} requests per {self.window_seconds}s"
                    )

                return False

    def reset(self):
        """Reset rate limiter state."""
        with self.lock:
            self.requests.clear()
            self.stats = {"allowed": 0, "denied": 0, "total": 0}

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        with self.lock:
            stats = self.stats.copy()
            stats["current_window_requests"] = len(self.requests)
            stats["window_utilization"] = len(self.requests) / self.max_requests
            return stats

    def time_until_next_allowed(self) -> float:
        """
        Get time until next request would be allowed.

        Returns:
            Seconds until next request allowed, or 0 if allowed now
        """
        with self.lock:
            if len(self.requests) < self.max_requests:
                return 0.0

            if not self.requests:
                return 0.0

            # Time when oldest request expires
            oldest_request = self.requests[0]
            expiry_time = oldest_request + self.window_seconds
            current_time = time.time()

            wait_time = expiry_time - current_time
            return max(0.0, wait_time)


class PerUserRateLimiter:
    """Rate limiter that tracks limits per user/identifier."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        """Initialize per-user rate limiter."""
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.limiters: Dict[str, RateLimiter] = {}
        self.lock = threading.Lock()

        # Cleanup old limiters periodically
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes

    def allow_request(self, identifier: str) -> bool:
        """Check if request from identifier should be allowed."""
        current_time = time.time()

        with self.lock:
            # Periodic cleanup
            if current_time - self.last_cleanup > self.cleanup_interval:
                self._cleanup_old_limiters()
                self.last_cleanup = current_time

            # Get or create limiter for identifier
            if identifier not in self.limiters:
                self.limiters[identifier] = RateLimiter(self.max_requests, self.window_seconds)

            limiter = self.limiters[identifier]

        # Check rate limit (outside lock to avoid holding it)
        return limiter.allow_request(identifier)

    def _cleanup_old_limiters(self):
        """Remove limiters that haven't been used recently."""
        current_time = time.time()
        cutoff_time = current_time - (self.window_seconds * 2)

        # Find limiters to remove
        to_remove = []
        for identifier, limiter in self.limiters.items():
            with limiter.lock:
                if not limiter.requests or limiter.requests[-1] < cutoff_time:
                    to_remove.append(identifier)

        # Remove old limiters
        for identifier in to_remove:
            del self.limiters[identifier]

        if to_remove:
            logger.debug(f"Cleaned up {len(to_remove)} inactive rate limiters")

    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all tracked identifiers."""
        with self.lock:
            return {identifier: limiter.get_stats() for identifier, limiter in self.limiters.items()}
