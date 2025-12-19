"""Cryptographic utilities for the VARX Protocol.

This module provides cryptographic primitives including Ed25519 digital
signatures, SHA256 hashing, HKDF key derivation, and secure nonce generation.
"""

import hashlib
import json
import secrets
from typing import Tuple, Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate an Ed25519 keypair for node identity.
    
    Ed25519 provides 128-bit security with small key sizes:
    - Private key: 32 bytes
    - Public key: 32 bytes
    - Signature: 64 bytes
    
    Returns:
        Tuple of (private_key, public_key)
        
    Example:
        >>> private_key, public_key = generate_keypair()
        >>> node_id = derive_node_id(serialize_public_key(public_key))
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Serialize an Ed25519 private key to bytes.
    
    Args:
        private_key: Ed25519 private key
        
    Returns:
        32-byte private key
        
    Warning:
        Private keys should be stored securely (e.g., HSM, encrypted storage)
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(public_key: ed25519.Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key to bytes.
    
    Args:
        public_key: Ed25519 public key
        
    Returns:
        32-byte public key
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def deserialize_private_key(key_bytes: bytes) -> ed25519.Ed25519PrivateKey:
    """Deserialize an Ed25519 private key from bytes.
    
    Args:
        key_bytes: 32-byte private key
        
    Returns:
        Ed25519 private key
        
    Raises:
        ValueError: If key_bytes is not 32 bytes
    """
    if len(key_bytes) != 32:
        raise ValueError("Private key must be exactly 32 bytes")
    return ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)


def deserialize_public_key(key_bytes: bytes) -> ed25519.Ed25519PublicKey:
    """Deserialize an Ed25519 public key from bytes.
    
    Args:
        key_bytes: 32-byte public key
        
    Returns:
        Ed25519 public key
        
    Raises:
        ValueError: If key_bytes is not 32 bytes
    """
    if len(key_bytes) != 32:
        raise ValueError("Public key must be exactly 32 bytes")
    return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)


def sign_message(data: dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Sign a message with Ed25519.
    
    The message is serialized to canonical JSON (sorted keys) before signing
    to ensure consistent signatures.
    
    Args:
        data: Message data to sign (must be JSON-serializable)
        private_key: Ed25519 private key
        
    Returns:
        64-byte Ed25519 signature
        
    Example:
        >>> private_key, public_key = generate_keypair()
        >>> message = {"type": "request", "data": "example"}
        >>> signature = sign_message(message, private_key)
        >>> assert len(signature) == 64
    """
    # Serialize to canonical JSON
    canonical = json.dumps(data, sort_keys=True).encode('utf-8')
    
    # Sign with Ed25519
    signature = private_key.sign(canonical)
    
    return signature


def verify_signature(
    data: dict[str, Any],
    signature: bytes,
    public_key: ed25519.Ed25519PublicKey
) -> bool:
    """Verify an Ed25519 signature on a message.
    
    Args:
        data: Message data that was signed
        signature: 64-byte Ed25519 signature
        public_key: Ed25519 public key of the signer
        
    Returns:
        True if signature is valid, False otherwise
        
    Example:
        >>> private_key, public_key = generate_keypair()
        >>> message = {"type": "request"}
        >>> signature = sign_message(message, private_key)
        >>> assert verify_signature(message, signature, public_key)
    """
    if len(signature) != 64:
        return False
    
    # Serialize to canonical JSON
    canonical = json.dumps(data, sort_keys=True).encode('utf-8')
    
    try:
        public_key.verify(signature, canonical)
        return True
    except InvalidSignature:
        return False


def hash_data(data: bytes) -> bytes:
    """Compute SHA256 hash of data.
    
    SHA256 provides 128-bit collision resistance and is used throughout
    the VARX Protocol for hash chains and integrity verification.
    
    Args:
        data: Data to hash
        
    Returns:
        32-byte SHA256 hash
        
    Example:
        >>> data = b"example data"
        >>> hash1 = hash_data(data)
        >>> hash2 = hash_data(data)
        >>> assert hash1 == hash2  # Deterministic
        >>> assert len(hash1) == 32
    """
    return hashlib.sha256(data).digest()


def hash_block(previous_hash: bytes, data: dict[str, Any], timestamp: int) -> bytes:
    """Create a hash for a block in the audit chain.
    
    This function is used to create tamper-evident hash chains where each
    block includes the hash of the previous block.
    
    Args:
        previous_hash: Hash of the previous block (32 bytes)
        data: Block data (must be JSON-serializable)
        timestamp: Unix timestamp
        
    Returns:
        32-byte SHA256 hash of the block
        
    Raises:
        ValueError: If previous_hash is not 32 bytes
        
    Example:
        >>> genesis_hash = bytes(32)  # All zeros for genesis block
        >>> block_data = {"decision": "approved"}
        >>> timestamp = 1703012345
        >>> block_hash = hash_block(genesis_hash, block_data, timestamp)
    """
    if len(previous_hash) != 32:
        raise ValueError("Previous hash must be exactly 32 bytes")
    
    # Serialize data deterministically
    data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
    
    # Combine: previous_hash + data + timestamp
    block_content = previous_hash + data_bytes + timestamp.to_bytes(8, 'big')
    
    # Hash the combined content
    return hashlib.sha256(block_content).digest()


def derive_key(master_key: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive a cryptographic key using HKDF-SHA256.
    
    HKDF (HMAC-based Key Derivation Function) is used to derive
    purpose-specific keys from a master key.
    
    Args:
        master_key: Master key material (at least 16 bytes recommended)
        info: Context-specific information to bind the key to a purpose
        length: Desired key length in bytes (default: 32)
        
    Returns:
        Derived key of specified length
        
    Example:
        >>> master_key = secrets.token_bytes(32)
        >>> signing_key = derive_key(master_key, b"signature_key_v1")
        >>> encryption_key = derive_key(master_key, b"encryption_key_v1")
        >>> assert signing_key != encryption_key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(master_key)


def derive_node_id(public_key_bytes: bytes) -> str:
    """Derive a human-readable node ID from a public key.
    
    The node ID is generated by hashing the public key and taking the first
    8 bytes as a hex string.
    
    Args:
        public_key_bytes: 32-byte Ed25519 public key
        
    Returns:
        Node ID in format "node_<hex_prefix>"
        
    Raises:
        ValueError: If public_key_bytes is not 32 bytes
        
    Example:
        >>> _, public_key = generate_keypair()
        >>> public_key_bytes = serialize_public_key(public_key)
        >>> node_id = derive_node_id(public_key_bytes)
        >>> assert node_id.startswith("node_")
    """
    if len(public_key_bytes) != 32:
        raise ValueError("Public key must be exactly 32 bytes")
    
    hash_digest = hashlib.sha256(public_key_bytes).digest()
    return f"node_{hash_digest[:8].hex()}"


def generate_nonce() -> bytes:
    """Generate a secure random nonce for replay protection.
    
    Nonces are 16-byte (128-bit) random values used to prevent replay
    attacks. Each nonce should be used only once.
    
    Returns:
        16-byte random nonce
        
    Example:
        >>> nonce1 = generate_nonce()
        >>> nonce2 = generate_nonce()
        >>> assert nonce1 != nonce2  # Extremely unlikely collision
        >>> assert len(nonce1) == 16
    """
    return secrets.token_bytes(16)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time.
    
    This function prevents timing attacks by ensuring comparison time
    doesn't depend on where the first difference occurs.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if byte strings are equal, False otherwise
        
    Example:
        >>> hash1 = hash_data(b"test")
        >>> hash2 = hash_data(b"test")
        >>> assert constant_time_compare(hash1, hash2)
    """
    import hmac
    return hmac.compare_digest(a, b)


class CryptoError(Exception):
    """Base exception for cryptographic errors."""
    pass


class SignatureError(CryptoError):
    """Exception raised for signature verification failures."""
    pass


class KeyDerivationError(CryptoError):
    """Exception raised for key derivation failures."""
    pass
