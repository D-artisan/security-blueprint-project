"""
Pillar 1: Governance Schema
The policy rulebook. Every security decision references this file.
"""
from enum import Enum
from dataclasses import dataclass

class DataTier(str, Enum):
    UNCLASSIFIED = "unclassified"       # Tier 0: public
    INTERNAL = "internal"               # Tier 1: employees only
    CONFIDENTIAL = "confidential"       # Tier 2: encrypted + logged
    KEYS_TO_KINGDOM = "keys_to_kingdom" # Tier 3: zero trust + KMS

@dataclass
class DataPolicy:
    tier: DataTier
    encrypt_at_rest: bool
    encrypt_in_transit: bool     # always True for Tier 2+
    audit_every_access: bool
    retention_days: int
    requires_mfa: bool
    isolation_required: bool     # separate storage from other data

POLICY_MATRIX = {
    DataTier.UNCLASSIFIED: DataPolicy(
        tier=DataTier.UNCLASSIFIED,
        encrypt_at_rest=False,
        encrypt_in_transit=False,
        audit_every_access=False,
        retention_days=365,
        requires_mfa=False,
        isolation_required=False,
    ),
    DataTier.INTERNAL: DataPolicy(
        tier=DataTier.INTERNAL,
        encrypt_at_rest=False,
        encrypt_in_transit=True,
        audit_every_access=False,
        retention_days=180,
        requires_mfa=False,
        isolation_required=False,
    ),
    DataTier.CONFIDENTIAL: DataPolicy(
        tier=DataTier.CONFIDENTIAL,
        encrypt_at_rest=True,
        encrypt_in_transit=True,
        audit_every_access=True,
        retention_days=90,
        requires_mfa=False,
        isolation_required=False,
    ),
    DataTier.KEYS_TO_KINGDOM: DataPolicy(
        tier=DataTier.KEYS_TO_KINGDOM,
        encrypt_at_rest=True,
        encrypt_in_transit=True,
        audit_every_access=True,
        retention_days=30,
        requires_mfa=True,
        isolation_required=True,
    ),
}

def get_policy(tier: DataTier) -> DataPolicy:
    """Single source of truth for all security decisions."""
    return POLICY_MATRIX[tier]

def classify_by_content(data: str) -> DataTier:
    """
    Simple pattern-based auto-classification.
    In production, this is a ML model or a dedicated DLP scanner.
    """
    import re
    # UK National Insurance numbers
    if re.search(r'\b[A-Z]{2}\d{6}[A-D]\b', data):
        return DataTier.KEYS_TO_KINGDOM
    # Credit card numbers (basic Luhn pattern)
    if re.search(r'\b(?:\d[ -]?){13,16}\b', data):
        return DataTier.KEYS_TO_KINGDOM
    # API keys or secrets (heuristic: long alphanumeric strings)
    if re.search(r'\b[A-Za-z0-9_\-]{32,}\b', data):
        return DataTier.CONFIDENTIAL
    # Email addresses
    if re.search(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b', data):
        return DataTier.CONFIDENTIAL
    return DataTier.INTERNAL