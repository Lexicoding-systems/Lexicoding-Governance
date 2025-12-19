"""Core VARX Protocol components.

This module contains the fundamental protocol definitions and cryptographic
utilities for the VARX (Vector Architecture for Reasoning eXecution) Protocol.
"""

from .protocol import (
    Message,
    GovernanceRequest,
    GovernanceDecision,
    AuditRecord,
    DecisionType,
    RiskLevel,
)
from .crypto import (
    generate_keypair,
    sign_message,
    verify_signature,
    hash_data,
    derive_key,
)

__all__ = [
    "Message",
    "GovernanceRequest",
    "GovernanceDecision",
    "AuditRecord",
    "DecisionType",
    "RiskLevel",
    "generate_keypair",
    "sign_message",
    "verify_signature",
    "hash_data",
    "derive_key",
]
