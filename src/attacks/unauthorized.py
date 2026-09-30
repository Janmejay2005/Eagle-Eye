"""
Unauthorized verification attempts: rogue verifiers, permission escalation, and rate-limit attacks.
"""
from __future__ import annotations

from typing import List, Tuple
from src.guards import IdentityGuard, RateLimiter


class UnauthorizedVerificationSimulator:
    """Simulates reconnaissance and unauthorized verification queries against verifiers."""

    @staticmethod
    def simulate_unregistered_verifier_probe(
        identity_guard: IdentityGuard,
        unregistered_id: str = "spy@foreign-node.com",
    ) -> Tuple[bool, str]:
        """Adversary attempts to query verifier without valid identity registration."""
        return identity_guard.verify_verifier(unregistered_id)

    @staticmethod
    def simulate_unauthorized_role_probe(
        identity_guard: IdentityGuard,
        signer_id: str,
    ) -> Tuple[bool, str]:
        """A valid signer identity attempts to execute verifier queries without verifier permissions."""
        return identity_guard.verify_verifier(signer_id)

    @staticmethod
    def simulate_rate_limit_flood(
        rate_limiter: RateLimiter,
        entity_id: str,
        limit: int,
        excess_requests: int = 10,
    ) -> List[Tuple[bool, int]]:
        """Adversary floods the verifier endpoint to trigger DoS throttling."""
        results = []
        for _ in range(limit + excess_requests):
            res = rate_limiter.is_allowed(entity_id, limit=limit)
            results.append(res)
        return results
