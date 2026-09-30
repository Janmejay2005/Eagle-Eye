"""
Sliding-window rate limiter for protecting verifier oracle against denial-of-service and probe attacks.
"""
from __future__ import annotations

import time
from typing import Dict, List, Tuple


class RateLimiter:
    """Sliding-window counter rate limiter per entity ID."""

    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        self._history: Dict[str, List[float]] = {}

    def is_allowed(self, entity_id: str, limit: int, current_time: float = None) -> Tuple[bool, int]:
        now = time.time() if current_time is None else current_time
        cutoff = now - self.window_seconds

        timestamps = self._history.setdefault(entity_id, [])
        # Prune older than window
        self._history[entity_id] = [t for t in timestamps if t > cutoff]

        current_count = len(self._history[entity_id])
        if current_count >= limit:
            return False, current_count

        self._history[entity_id].append(now)
        return True, current_count + 1
