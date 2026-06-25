#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Hermes Shield — Rate Limiter (Token Bucket).

Prevents brute-force attacks by limiting input processing rate.
"""

from __future__ import annotations
import time
from threading import Lock


class TokenBucketRateLimiter:
    """Token bucket rate limiter for input processing.

    Args:
        rate: Tokens added per second
        burst: Maximum bucket size (burst capacity)
    """

    def __init__(self, rate: float = 100.0, burst: int = 200):
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = Lock()

    def allow(self) -> bool:
        """Check if a request is allowed.

        Returns:
            True if request can proceed, False if rate limited
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._last_refill = now

            # Refill tokens
            self._tokens = min(
                self.burst,
                self._tokens + elapsed * self.rate
            )

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

    @property
    def available_tokens(self) -> float:
        """Current available tokens."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            return min(self.burst, self._tokens + elapsed * self.rate)
