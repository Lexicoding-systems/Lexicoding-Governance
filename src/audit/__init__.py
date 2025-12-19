"""Audit trail management.

This module provides the hash chain implementation for maintaining an
immutable, tamper-evident audit trail.
"""

from .hash_chain import HashChain, Block

__all__ = ["HashChain", "Block"]
