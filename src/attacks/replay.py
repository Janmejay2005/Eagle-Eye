"""
Replay attack simulations: duplicate nonces, stale timestamps, and session re-use.
"""
from __future__ import annotations

import time
from src.schemas import Signature


class ReplaySimulator:
    """Generates replay attacks and freshness violations."""

    @staticmethod
    def create_identical_replay(signature: Signature) -> Signature:
        """Adversary captures and replays a previously accepted signature packet identically."""
        return signature.model_copy(deep=True)

    @staticmethod
    def create_stale_replay(signature: Signature, stale_seconds: float = 120.0) -> Signature:
        """Adversary delays or replays a captured signature packet with an expired timestamp."""
        stale_sig = signature.model_copy(deep=True)
        stale_sig.timestamp = signature.timestamp - stale_seconds
        return stale_sig

    @staticmethod
    def create_future_clock_skew(signature: Signature, future_seconds: float = 60.0) -> Signature:
        """Adversary transmits a packet with manipulated future timestamp."""
        future_sig = signature.model_copy(deep=True)
        future_sig.timestamp = signature.timestamp + future_seconds
        return future_sig
