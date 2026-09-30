"""
Immutable SHA-256 hash-chained audit ledger for verification decisions and incident evidence.
"""
from __future__ import annotations

import copy
from typing import List, Optional, Tuple
from src.schemas import Decision


class AuditLedger:
    """Tamper-evident hash-chained event ledger."""

    def __init__(self):
        self._chain: List[Decision] = []
        self._genesis_hash: str = "0" * 64

    @property
    def chain(self) -> List[Decision]:
        return copy.deepcopy(self._chain)

    def get_latest_hash(self) -> str:
        if not self._chain:
            return self._genesis_hash
        return self._chain[-1].event_hash or self._genesis_hash

    def append_decision(self, decision: Decision) -> Decision:
        """Seals decision with current chain tail hash and appends to ledger."""
        prev_hash = self.get_latest_hash()
        decision.seal(previous_hash=prev_hash)
        self._chain.append(decision)
        return decision

    def verify_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Validates the complete hash chain from genesis to head.
        Fails if any decision payload, verdict, reasons, or hashes were modified.
        """
        if not self._chain:
            return True, None

        expected_prev_hash = self._genesis_hash
        for idx, dec in enumerate(self._chain):
            if dec.previous_event_hash != expected_prev_hash:
                return (
                    False,
                    f"CHAIN_BREAK_AT_INDEX_{idx}: Expected previous hash {expected_prev_hash}, got {dec.previous_event_hash}",
                )

            recomputed_hash = dec.compute_hash()
            if dec.event_hash != recomputed_hash:
                return (
                    False,
                    f"TAMPER_DETECTED_AT_INDEX_{idx}: Stored hash {dec.event_hash} does not match recomputed {recomputed_hash}",
                )

            expected_prev_hash = dec.event_hash

        return True, "LEDGER_INTEGRITY_VERIFIED"
