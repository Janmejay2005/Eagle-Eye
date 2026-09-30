"""
Freshness and anti-replay guards enforcing timestamp limits, nonce uniqueness, and session status.
"""
from __future__ import annotations

import time
from typing import Dict, Optional, Tuple, Set

from src.schemas import Session, Signature, Policy


class FreshnessGuard:
    """Detects replay attacks, stale timestamps, clock skew, and session expiration."""

    def __init__(self):
        # Global cache of (signer_id, nonce) -> (first_seen_timestamp, signature_id)
        self._global_nonce_cache: Dict[Tuple[str, str], Tuple[float, str]] = {}
        # Active sessions: session_id -> Session
        self._sessions: Dict[str, Session] = {}

    def register_session(self, session: Session):
        self._sessions[session.session_id] = session

    def get_session(self, session_id: str) -> Optional[Session]:
        return self._sessions.get(session_id)

    def quarantine_session(self, session_id: str):
        if session_id in self._sessions:
            self._sessions[session_id].is_quarantined = True

    def check_freshness_and_replay(
        self,
        signature: Signature,
        policy: Policy,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, str, Optional[Dict[str, str]]]:
        """
        Validates:
        1. Session existence and validity (not expired, not quarantined).
        2. Timestamp freshness against policy.max_clock_skew_seconds.
        3. Nonce uniqueness in session and globally (anti-replay).
        """
        now = time.time() if current_time is None else current_time

        # 1. Session verification
        session = self._sessions.get(signature.session_id)
        if session is None:
            return False, f"INVALID_SESSION: Session '{signature.session_id}' not found.", None
        if not session.is_active:
            return False, f"INACTIVE_SESSION: Session '{signature.session_id}' is inactive.", None
        if session.is_quarantined:
            return False, f"QUARANTINED_SESSION: Session '{signature.session_id}' is quarantined due to channel disturbance.", None
        if session.is_expired(now):
            return False, f"EXPIRED_SESSION: Session '{signature.session_id}' has expired.", None

        # 2. Timestamp freshness & clock skew
        time_diff = abs(now - signature.timestamp)
        if time_diff > policy.max_clock_skew_seconds:
            if signature.timestamp < now:
                return (
                    False,
                    f"STALE_TIMESTAMP: Signature age ({time_diff:.2f}s) exceeds max clock skew ({policy.max_clock_skew_seconds}s).",
                    None,
                )
            else:
                return (
                    False,
                    f"CLOCK_SKEW_FUTURE: Signature timestamp is in the future by {time_diff:.2f}s (max allowed {policy.max_clock_skew_seconds}s).",
                    None,
                )

        # 3. Nonce uniqueness (Anti-Replay)
        nonce_key = (signature.signer_identity, signature.nonce)
        if nonce_key in self._global_nonce_cache:
            original_seen_time, original_sig_id = self._global_nonce_cache[nonce_key]
            evidence = {
                "replay_detected": "true",
                "nonce": signature.nonce,
                "first_seen_timestamp": f"{original_seen_time:.6f}",
                "original_signature_id": original_sig_id,
                "replay_signature_id": signature.signature_id,
            }
            return (
                False,
                f"REPLAY_DETECTED_NONCE_REUSE: Nonce '{signature.nonce}' was already used for signature '{original_sig_id}'.",
                evidence,
            )

        # Also check session-level nonces
        if not session.register_nonce(signature.nonce):
            return (
                False,
                f"REPLAY_DETECTED_SESSION_NONCE: Nonce '{signature.nonce}' replayed within session '{session.session_id}'.",
                {"nonce": signature.nonce, "session_id": session.session_id},
            )

        # Nonce is fresh: record in global cache
        self._global_nonce_cache[nonce_key] = (now, signature.signature_id)
        return True, "FRESHNESS_VERIFIED", None
