# Cryptography in VARX Protocol

## Overview

The VARX Protocol employs state-of-the-art cryptographic primitives to ensure security, authenticity, integrity, and non-repudiation of all governance decisions and audit records.

## Cryptographic Primitives

| Primitive | Algorithm | Purpose | Security Level |
|-----------|-----------|---------|----------------|
| Digital Signatures | Ed25519 | Message authentication and non-repudiation | 128-bit |
| Hash Functions | SHA256 | Tamper-evident hash chains | 128-bit collision resistance |
| Key Derivation | HKDF-SHA256 | Node identity and session keys | 256-bit |
| Replay Protection | Secure Nonces | Prevent message replay attacks | 128-bit randomness |

## Digital Signatures (Ed25519)

### Overview
Ed25519 is a modern elliptic curve signature scheme providing 128-bit security with small key sizes and fast operations.

**Properties:**
- **Public Key Size**: 32 bytes
- **Private Key Size**: 32 bytes
- **Signature Size**: 64 bytes
- **Performance**: ~50,000 signatures/second (single core)
- **Security**: Resistant to side-channel attacks

### Key Generation

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

# Generate private key
private_key = ed25519.Ed25519PrivateKey.generate()

# Derive public key
public_key = private_key.public_key()

# Serialize keys
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)

public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
```

### Signing Messages

```python
# Sign a message
message = b"governance_request_data"
signature = private_key.sign(message)

# Signature is 64 bytes
assert len(signature) == 64
```

### Verifying Signatures

```python
from cryptography.exceptions import InvalidSignature

try:
    public_key.verify(signature, message)
    print("Signature valid")
except InvalidSignature:
    print("Signature invalid - message tampered or wrong key")
```

### Node Identity

Each node in the VARX Protocol has a unique identity derived from its Ed25519 public key:

```python
import hashlib

def derive_node_id(public_key_bytes: bytes) -> str:
    """
    Derive a human-readable node ID from public key.
    
    Args:
        public_key_bytes: 32-byte Ed25519 public key
        
    Returns:
        Node ID in format "node_<hex_prefix>"
    """
    hash_digest = hashlib.sha256(public_key_bytes).digest()
    return f"node_{hash_digest[:8].hex()}"
```

## Hash Functions (SHA256)

### Overview
SHA256 is a cryptographic hash function producing 256-bit (32-byte) digests with strong collision resistance.

**Properties:**
- **Output Size**: 32 bytes (256 bits)
- **Security**: 128-bit collision resistance
- **Performance**: ~500 MB/s (single core)
- **Standards**: FIPS 180-4 compliant

### Hash Chain Construction

The audit trail uses SHA256 to create a tamper-evident hash chain:

```python
import hashlib
import json

def hash_block(previous_hash: bytes, data: dict, timestamp: int) -> bytes:
    """
    Create hash for a block in the chain.
    
    Args:
        previous_hash: Hash of the previous block (32 bytes)
        data: Block data (dictionary)
        timestamp: Unix timestamp
        
    Returns:
        SHA256 hash of the block (32 bytes)
    """
    # Serialize data deterministically
    data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
    
    # Combine previous hash + data + timestamp
    block_content = previous_hash + data_bytes + timestamp.to_bytes(8, 'big')
    
    # Hash the combined content
    return hashlib.sha256(block_content).digest()
```

### Merkle Tree for Efficient Verification

For large audit logs, Merkle trees enable efficient verification of individual records:

```
        Root Hash
       /         \
    H(AB)       H(CD)
    /  \        /  \
  H(A) H(B)  H(C) H(D)
   |    |     |    |
   A    B     C    D
```

```python
def merkle_root(hashes: list[bytes]) -> bytes:
    """
    Compute Merkle root from list of hashes.
    
    Args:
        hashes: List of SHA256 hashes
        
    Returns:
        Merkle root hash
    """
    if len(hashes) == 1:
        return hashes[0]
    
    # Pair up hashes and hash the pairs
    next_level = []
    for i in range(0, len(hashes), 2):
        if i + 1 < len(hashes):
            combined = hashlib.sha256(hashes[i] + hashes[i+1]).digest()
        else:
            combined = hashes[i]  # Odd one out
        next_level.append(combined)
    
    return merkle_root(next_level)
```

## Key Derivation (HKDF-SHA256)

### Overview
HKDF (HMAC-based Key Derivation Function) derives cryptographic keys from shared secrets or master keys.

**Use Cases:**
- Deriving session keys from master keys
- Generating per-purpose keys from node identity
- Key rotation and versioning

### Implementation

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive_key(master_key: bytes, info: bytes, length: int = 32) -> bytes:
    """
    Derive a cryptographic key using HKDF-SHA256.
    
    Args:
        master_key: Master key material (at least 16 bytes)
        info: Context-specific information
        length: Desired key length in bytes
        
    Returns:
        Derived key
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,  # Optional: add salt for additional security
        info=info,
    )
    return hkdf.derive(master_key)
```

### Example: Session Key Derivation

```python
# Derive different keys for different purposes
master_key = b"node_master_key_material"

signing_key = derive_key(master_key, b"signature_key_v1")
encryption_key = derive_key(master_key, b"encryption_key_v1")
audit_key = derive_key(master_key, b"audit_key_v1")
```

## Replay Protection (Secure Nonces)

### Overview
Nonces (numbers used once) prevent replay attacks where an attacker retransmits valid messages.

**Requirements:**
- **Uniqueness**: Never repeat within validity window
- **Unpredictability**: Cannot be guessed by attackers
- **Verification**: Recipients can detect replays

### Nonce Generation

```python
import secrets
import time

def generate_nonce() -> tuple[bytes, int]:
    """
    Generate a secure nonce with timestamp.
    
    Returns:
        (nonce, timestamp) tuple where nonce is 16 random bytes
    """
    nonce = secrets.token_bytes(16)  # 128-bit random nonce
    timestamp = int(time.time())
    return nonce, timestamp
```

### Nonce Validation

```python
class NonceValidator:
    """Validates nonces to prevent replay attacks."""
    
    def __init__(self, validity_window: int = 300):
        """
        Initialize validator.
        
        Args:
            validity_window: Time window in seconds for nonce validity
        """
        self.validity_window = validity_window
        self.seen_nonces: set[bytes] = set()
        self.last_cleanup = time.time()
    
    def validate(self, nonce: bytes, timestamp: int) -> bool:
        """
        Validate a nonce.
        
        Args:
            nonce: The nonce to validate
            timestamp: Message timestamp
            
        Returns:
            True if nonce is valid and not replayed
        """
        current_time = int(time.time())
        
        # Check timestamp is within validity window
        if abs(current_time - timestamp) > self.validity_window:
            return False
        
        # Check if nonce was already used
        if nonce in self.seen_nonces:
            return False
        
        # Add nonce to seen set
        self.seen_nonces.add(nonce)
        
        # Periodic cleanup of old nonces
        if current_time - self.last_cleanup > self.validity_window:
            self._cleanup_old_nonces()
        
        return True
    
    def _cleanup_old_nonces(self):
        """Remove expired nonces from memory."""
        # In production, implement time-based expiration
        self.seen_nonces.clear()
        self.last_cleanup = time.time()
```

## Message Authentication

### Complete Message Structure

All messages in the VARX Protocol include cryptographic authentication:

```python
from dataclasses import dataclass
from typing import Any

@dataclass
class AuthenticatedMessage:
    """A cryptographically authenticated message."""
    
    # Message content
    payload: dict[str, Any]
    
    # Sender identification
    sender_id: str
    sender_public_key: bytes  # 32 bytes
    
    # Replay protection
    nonce: bytes  # 16 bytes
    timestamp: int
    
    # Cryptographic proof
    signature: bytes  # 64 bytes
    
    def verify(self) -> bool:
        """Verify message signature."""
        # Reconstruct signed content
        content = self._serialize_for_signing()
        
        # Verify Ed25519 signature
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            self.sender_public_key
        )
        
        try:
            public_key.verify(self.signature, content)
            return True
        except InvalidSignature:
            return False
    
    def _serialize_for_signing(self) -> bytes:
        """Serialize message content for signing."""
        import json
        data = {
            'payload': self.payload,
            'sender_id': self.sender_id,
            'nonce': self.nonce.hex(),
            'timestamp': self.timestamp
        }
        return json.dumps(data, sort_keys=True).encode('utf-8')
```

## Security Considerations

### Key Management

**Best Practices:**
1. Store private keys in secure enclaves or HSMs
2. Use key derivation for purpose-specific keys
3. Implement key rotation policies
4. Secure key backup and recovery procedures

**Avoid:**
- Storing keys in plaintext
- Reusing keys across contexts
- Logging or transmitting private keys

### Cryptographic Agility

The protocol is designed for cryptographic agility:

```python
from enum import Enum

class SignatureAlgorithm(Enum):
    """Supported signature algorithms."""
    ED25519 = "ed25519"
    ED448 = "ed448"  # Future: Higher security
    DILITHIUM = "dilithium"  # Future: Post-quantum

class HashAlgorithm(Enum):
    """Supported hash algorithms."""
    SHA256 = "sha256"
    SHA512 = "sha512"  # Future: Higher security
    SHA3_256 = "sha3-256"  # Future: Alternative
```

### Side-Channel Protection

**Timing Attacks:**
- Use constant-time comparison for secrets
- Avoid data-dependent branches in crypto code

```python
import hmac

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time."""
    return hmac.compare_digest(a, b)
```

**Power Analysis:**
- Use hardware crypto accelerators when available
- Implement blinding techniques for sensitive operations

## Compliance and Standards

### Regulatory Standards
- **FIPS 140-2/3**: Cryptographic module validation
- **NIST SP 800-series**: Key management guidelines
- **Common Criteria**: Security evaluation standards

### Best Practices
- **OWASP Cryptographic Storage**: Secure key storage
- **RFC 8032**: Ed25519 specification
- **RFC 5869**: HKDF specification
- **FIPS 180-4**: SHA-256 specification

## Testing and Validation

### Cryptographic Test Vectors

```python
# Example test vectors for Ed25519
TEST_VECTORS = [
    {
        'private_key': bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
        'public_key': bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
        'message': b'',
        'signature': bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
    }
]
```

### Security Auditing

All cryptographic implementations should undergo:
1. Code review by cryptography experts
2. Automated testing with known test vectors
3. Fuzzing to detect edge cases
4. Third-party security audits

## References

- [NIST SP 800-133 Rev. 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-133r2.pdf) - Key Management Recommendations
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) - Edwards-Curve Digital Signature Algorithm (EdDSA)
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) - HKDF: HMAC-based Key Derivation Function
- [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) - Secure Hash Standard (SHS)
