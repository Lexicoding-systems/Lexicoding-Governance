"""Secure nonce generation and validation for replay protection.

This module provides utilities for generating and validating nonces to prevent
replay attacks in the VARX Protocol.
"""

import secrets
import time
from typing import Tuple, Set


def generate_nonce_with_timestamp() -> Tuple[bytes, int]:
    """Generate a secure nonce with timestamp.
    
    Returns:
        Tuple of (nonce, timestamp) where nonce is 16 random bytes and
        timestamp is Unix timestamp in seconds
        
    Example:
        >>> nonce, timestamp = generate_nonce_with_timestamp()
        >>> assert len(nonce) == 16
        >>> assert timestamp <= int(time.time())
    """
    nonce = secrets.token_bytes(16)
    timestamp = int(time.time())
    return nonce, timestamp


class NonceValidator:
    """Validates nonces to prevent replay attacks.
    
    The validator maintains a set of recently seen nonces and rejects any
    nonce that has been used before within the validity window.
    
    Attributes:
        validity_window: Time window in seconds for nonce validity
        seen_nonces: Set of nonces seen within validity window
        last_cleanup: Timestamp of last cleanup operation
        
    Example:
        >>> validator = NonceValidator(validity_window=300)
        >>> 
        >>> # Generate and validate a nonce
        >>> nonce = secrets.token_bytes(16)
        >>> timestamp = int(time.time())
        >>> assert validator.validate(nonce, timestamp)
        >>> 
        >>> # Same nonce rejected on second use
        >>> assert not validator.validate(nonce, timestamp)
    """
    
    def __init__(self, validity_window: int = 300):
        """Initialize the nonce validator.
        
        Args:
            validity_window: Time window in seconds for nonce validity.
                Messages with timestamps outside this window are rejected.
                Default is 300 seconds (5 minutes).
        """
        self.validity_window = validity_window
        self.seen_nonces: Set[bytes] = set()
        self.last_cleanup = time.time()
        
        # Track nonces with their timestamps for proper expiration
        self._nonce_timestamps: dict[bytes, int] = {}
    
    def validate(self, nonce: bytes, timestamp: int) -> bool:
        """Validate a nonce for replay protection.
        
        A nonce is valid if:
        1. The timestamp is within the validity window
        2. The nonce has not been seen before
        
        Args:
            nonce: 16-byte random nonce
            timestamp: Unix timestamp when nonce was created
            
        Returns:
            True if nonce is valid and not replayed, False otherwise
            
        Example:
            >>> validator = NonceValidator()
            >>> nonce = secrets.token_bytes(16)
            >>> timestamp = int(time.time())
            >>> 
            >>> # First use: valid
            >>> assert validator.validate(nonce, timestamp)
            >>> 
            >>> # Second use: invalid (replay)
            >>> assert not validator.validate(nonce, timestamp)
        """
        current_time = int(time.time())
        
        # Check timestamp is within validity window
        time_diff = abs(current_time - timestamp)
        if time_diff > self.validity_window:
            return False
        
        # Check if nonce was already used
        if nonce in self.seen_nonces:
            return False
        
        # Add nonce to seen set
        self.seen_nonces.add(nonce)
        self._nonce_timestamps[nonce] = timestamp
        
        # Periodic cleanup of old nonces
        if current_time - self.last_cleanup > self.validity_window // 2:
            self._cleanup_old_nonces(current_time)
        
        return True
    
    def _cleanup_old_nonces(self, current_time: int):
        """Remove expired nonces from memory.
        
        Nonces older than the validity window are removed to prevent
        unbounded memory growth.
        
        Args:
            current_time: Current Unix timestamp
        """
        expired_nonces = [
            nonce for nonce, timestamp in self._nonce_timestamps.items()
            if current_time - timestamp > self.validity_window
        ]
        
        for nonce in expired_nonces:
            self.seen_nonces.discard(nonce)
            self._nonce_timestamps.pop(nonce, None)
        
        self.last_cleanup = current_time
        
        if expired_nonces:
            print(f"Cleaned up {len(expired_nonces)} expired nonces")
    
    def clear(self):
        """Clear all seen nonces.
        
        Warning: This should only be used for testing or when resetting
        the validator state. Clearing nonces in production could allow
        replay attacks.
        """
        self.seen_nonces.clear()
        self._nonce_timestamps.clear()
        self.last_cleanup = time.time()
    
    def get_stats(self) -> dict[str, int]:
        """Get statistics about nonce validation.
        
        Returns:
            Dictionary with statistics including:
                - total_nonces: Number of nonces currently tracked
                - validity_window: Configured validity window
        """
        return {
            "total_nonces": len(self.seen_nonces),
            "validity_window": self.validity_window
        }


def validate_nonce_format(nonce: bytes) -> bool:
    """Validate that a nonce has the correct format.
    
    Args:
        nonce: Nonce to validate
        
    Returns:
        True if nonce is valid format (16 bytes), False otherwise
        
    Example:
        >>> valid_nonce = secrets.token_bytes(16)
        >>> assert validate_nonce_format(valid_nonce)
        >>> 
        >>> invalid_nonce = b"too short"
        >>> assert not validate_nonce_format(invalid_nonce)
    """
    return isinstance(nonce, bytes) and len(nonce) == 16
