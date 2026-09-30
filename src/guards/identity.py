"""
Identity and role-context guards for QDS network participants.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple
from src.schemas import Identity, IdentityRole


class IdentityRegistry:
    """In-memory cryptographic identity directory for participants."""

    def __init__(self):
        self._identities: Dict[str, Identity] = {}
        self._keys: Dict[str, str] = {}  # identity_id -> secret key (mocked HSM / key store)

    def register(self, identity: Identity, secret_key: Optional[str] = None):
        self._identities[identity.identity_id] = identity
        if secret_key:
            self._keys[identity.identity_id] = secret_key

    def get_identity(self, identity_id: str) -> Optional[Identity]:
        return self._identities.get(identity_id)

    def get_secret_key(self, identity_id: str) -> Optional[str]:
        return self._keys.get(identity_id)

    def revoke(self, identity_id: str):
        if identity_id in self._identities:
            self._identities[identity_id].is_authorized = False


class IdentityGuard:
    """Enforces authorization, roles, and context permissions for signers and verifiers."""

    def __init__(self, registry: IdentityRegistry):
        self.registry = registry

    def verify_signer(self, signer_id: str) -> Tuple[bool, str]:
        ident = self.registry.get_identity(signer_id)
        if ident is None:
            return False, f"UNKNOWN_SIGNER: Signer identity '{signer_id}' not found in registry."
        if not ident.is_authorized:
            return False, f"REVOKED_SIGNER: Signer identity '{signer_id}' is revoked or unauthorized."
        if ident.role != IdentityRole.SIGNER:
            return False, f"INVALID_SIGNER_ROLE: Identity '{signer_id}' has role {ident.role.value}, expected SIGNER."
        return True, "SIGNER_IDENTITY_VALID"

    def verify_verifier(self, verifier_id: str, required_permission: str = "verify") -> Tuple[bool, str]:
        ident = self.registry.get_identity(verifier_id)
        if ident is None:
            return False, f"UNKNOWN_VERIFIER: Verifier identity '{verifier_id}' not found in registry."
        if not ident.is_authorized:
            return False, f"REVOKED_VERIFIER: Verifier identity '{verifier_id}' is revoked or unauthorized."
        if ident.role not in (IdentityRole.VERIFIER, IdentityRole.ADMIN):
            return False, f"INVALID_VERIFIER_ROLE: Identity '{verifier_id}' has role {ident.role.value}, expected VERIFIER."
        if not ident.has_permission(required_permission):
            return False, f"PERMISSION_DENIED: Verifier '{verifier_id}' lacks permission '{required_permission}'."
        return True, "VERIFIER_IDENTITY_VALID"
