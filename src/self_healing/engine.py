"""
Controlled Self-Healing Engine managing rule proposals, shadow tests, cryptographic approvals,
policy deployment, and instant rollback.
Anti-Gravity Rule: Never auto-deploy; require approval, signing, and reversible rollbacks.
"""
from __future__ import annotations

import copy
import time
import uuid
from typing import Dict, List, Optional, Tuple

from src.schemas import Policy, Incident, IncidentStatus, Identity, IdentityRole
from src.self_healing.bundle import PolicyBundle
from src.self_healing.shadow import ShadowTestRunner
from src.self_healing.crypto_signing import sign_payload


class UnapprovedUpdateError(RuntimeError):
    """Raised when an attempt is made to apply an unapproved or unsigned policy bundle."""
    pass


class ShadowRegressionError(RuntimeError):
    """Raised when a candidate policy fails non-regression shadow testing."""
    pass


class SelfHealingEngine:
    """Manages the full lifecycle of policy adaptation and rollback."""

    def __init__(self, initial_policy: Policy, shadow_runner: Optional[ShadowTestRunner] = None):
        self.active_policy = initial_policy
        self.shadow_runner = shadow_runner or ShadowTestRunner()
        # History: version -> Policy
        self._policy_history: Dict[str, Policy] = {initial_policy.version: initial_policy}
        # Checkpoint stack: list of (checkpoint_id, timestamp, Policy, rationale)
        self._checkpoints: List[Tuple[str, float, Policy, str]] = []
        self._bundles: Dict[str, PolicyBundle] = {}

    def propose_update(
        self,
        candidate_policy: Policy,
        change_rationale: str,
        incident_id: Optional[str] = None,
    ) -> PolicyBundle:
        """Constructs an unapproved proposal bundle."""
        bundle_id = f"bundle-{uuid.uuid4().hex[:8]}"
        bundle = PolicyBundle(
            bundle_id=bundle_id,
            version=candidate_policy.version,
            previous_version=self.active_policy.version,
            target_policy=candidate_policy,
            change_rationale=change_rationale,
            incident_id=incident_id,
            shadow_test_passed=False,
        )
        self._bundles[bundle_id] = bundle
        return bundle

    def run_shadow_tests(self, bundle_id: str) -> Tuple[bool, Dict[str, float]]:
        """Runs candidate policy against golden regression suite."""
        if bundle_id not in self._bundles:
            raise ValueError(f"Bundle {bundle_id} not found.")

        bundle = self._bundles[bundle_id]
        passed, metrics = self.shadow_runner.run_regression_suite(bundle.target_policy)
        bundle.shadow_test_passed = passed
        bundle.shadow_test_metrics = metrics
        return passed, metrics

    def approve_and_sign(
        self,
        bundle_id: str,
        admin_identity: Identity,
        admin_private_key_b64: str,
    ) -> PolicyBundle:
        """Cryptographically approves and signs a proposed bundle using administrator Ed25519 key."""
        if bundle_id not in self._bundles:
            raise ValueError(f"Bundle {bundle_id} not found.")

        bundle = self._bundles[bundle_id]

        # Verify admin identity role
        if admin_identity.role != IdentityRole.ADMIN or not admin_identity.has_permission("admin"):
            raise PermissionError(f"Identity {admin_identity.identity_id} lacks admin privileges.")

        if not bundle.shadow_test_passed:
            raise ShadowRegressionError("Cannot approve bundle that has not passed shadow testing.")

        signature_b64 = sign_payload(admin_private_key_b64, bundle.canonical_bytes())
        bundle.admin_identity_id = admin_identity.identity_id
        bundle.ed25519_signature = signature_b64
        return bundle

    def apply_update(
        self,
        bundle_id: str,
        admin_public_key_b64: str,
    ) -> str:
        """
        Applies a signed bundle to update active policy.
        Fails closed if unsigned, unapproved, or shadow tests failed.
        """
        if bundle_id not in self._bundles:
            raise ValueError(f"Bundle {bundle_id} not found.")

        bundle = self._bundles[bundle_id]

        if not bundle.shadow_test_passed:
            raise UnapprovedUpdateError("Security violation: Candidate policy has not passed shadow testing.")

        if not bundle.ed25519_signature or not bundle.verify_signature(admin_public_key_b64):
            raise UnapprovedUpdateError("Security violation: Bundle signature is missing or invalid.")

        # Create checkpoint of current policy
        checkpoint_id = f"ckpt-{uuid.uuid4().hex[:8]}"
        self._checkpoints.append((checkpoint_id, time.time(), copy.deepcopy(self.active_policy), bundle.change_rationale))

        # Deploy update
        self.active_policy = copy.deepcopy(bundle.target_policy)
        self._policy_history[self.active_policy.version] = copy.deepcopy(self.active_policy)

        return checkpoint_id

    def rollback(self, target_checkpoint_id: Optional[str] = None) -> Policy:
        """Reverts active policy to the most recent or specified checkpoint."""
        if not self._checkpoints:
            raise RuntimeError("No checkpoints available to rollback to.")

        if target_checkpoint_id is None:
            _, _, restored_policy, _ = self._checkpoints.pop()
        else:
            found = False
            for idx, (cid, _, pol, _) in enumerate(self._checkpoints):
                if cid == target_checkpoint_id:
                    restored_policy = pol
                    self._checkpoints = self._checkpoints[:idx]
                    found = True
                    break
            if not found:
                raise ValueError(f"Checkpoint {target_checkpoint_id} not found.")

        self.active_policy = copy.deepcopy(restored_policy)
        return self.active_policy
